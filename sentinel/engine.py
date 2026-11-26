"""Bounded, non-destructive HTTP configuration checks. No exploit execution."""
from dataclasses import dataclass, asdict, field
from urllib.parse import urlsplit, urlunsplit
from datetime import datetime, timezone
import http.client
import ssl
import re
from .evidence import sanitize
from .cookie_review import cookie_observations, RULESET as COOKIE_RULESET
from .header_review import header_observations, RULESET as HEADER_RULESET
from .pinned_http import resolve_once, PinnedConnector

@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    connect_host: str = ''

    @classmethod
    def parse(cls, value):
        value = value.strip()
        if not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
            raise ValueError('Enter a URL without whitespace or control characters.')
        try:
            p = urlsplit(value)
            if p.scheme not in ('http', 'https') or not p.hostname:
                raise ValueError('Use a complete http:// or https:// URL.')
            if p.username is not None or p.password is not None or p.query or p.fragment or '?' in value or '#' in value:
                raise ValueError('Credentials, query parameters and fragments are not accepted.')
            if '\\' in value:
                raise ValueError('Backslashes are not accepted.')
            host = p.hostname.encode('idna').decode('ascii')
            port = p.port or (443 if p.scheme == 'https' else 80)
            if p.port == 0:
                raise ValueError('Invalid port.')
            path = p.path or '/'
            if not path.startswith('/') or path.startswith('//') or not path.isascii():
                raise ValueError('Use an ASCII, percent-encoded absolute path.')
            netloc = ('[' + host + ']' if ':' in host else host)
            if p.port is not None:
                netloc += ':' + str(port)
            return cls(urlunsplit((p.scheme, netloc, path, '', '')), p.scheme, host, port, path)
        except (UnicodeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc

@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    evidence: str
    remediation: str
    confidence: str = 'medium'
    source: str = 'sentinel'

@dataclass
class Scan:
    target: str
    started: str
    status: str
    http_status: int | None
    tls: str | None
    findings: list
    error: str = ''
    coverage: dict = field(default_factory=dict)
    profile: str = 'web-v2'
    dns_domain: str = ''

    def to_dict(self):
        return sanitize(asdict(self))


def inspect_headers(target, status, headers, tls=None, cert=None):
    # Only retain derived evidence; no cookie values, redirect URLs or response body.
    h = {}
    for key, value in headers:
        h.setdefault(key.lower(), []).append(value)
    out = []
    def add(id, severity, title, evidence, remediation):
        out.append(Finding(id, severity, title, evidence, remediation))
    if target.scheme == 'http':
        add('HTTP','medium','HTTP transport used','The requested URL uses unencrypted HTTP.','Serve sensitive pages via HTTPS and redirect HTTP to HTTPS. Check the redirect separately.')
    if target.scheme == 'https':
        vals = h.get('strict-transport-security', [])
        if not vals or not any(re.search(r'(?:^|;)\s*max-age\s*=\s*[1-9]\d*\s*(?:;|$)', v, re.I) for v in vals):
            add('HSTS','low','HSTS absent or disabled','No positive max-age was observed in Strict-Transport-Security.','After verifying HTTPS coverage, enable HSTS with an appropriate max-age. Consider subdomain coverage separately.')
    html = any('text/html' in v.lower() for v in h.get('content-type', []))
    if html and 200 <= status < 300:
        if not any(v.strip().lower() == 'nosniff' for v in h.get('x-content-type-options', [])):
            add('NOSNIFF','low','MIME sniffing protection absent','No X-Content-Type-Options: nosniff on this HTML response.','Set X-Content-Type-Options: nosniff and serve correct Content-Type values.')
        if not h.get('content-security-policy'):
            add('CSP','low','Content Security Policy absent','No enforced CSP header on this HTML response.','Develop a restrictive CSP, test with report-only first, then enforce. Avoid broad unsafe exceptions.')
        if not any(re.search(r'(?:^|;)\s*frame-ancestors\s+\S', v, re.I) for v in h.get('content-security-policy', [])) and not any(v.strip().lower() in ('deny','sameorigin') for v in h.get('x-frame-options', [])):
            add('FRAME','low','Framing restriction not observed','No recognized X-Frame-Options or CSP frame-ancestors directive.','For pages that should not be embedded, use CSP frame-ancestors with appropriate allowed origins.')
        if not h.get('referrer-policy'):
            add('REFERRER','info','Explicit referrer policy absent','No Referrer-Policy header on this HTML response.','Consider strict-origin-when-cross-origin or a stricter policy as appropriate. Modern browsers already have defaults.')
    cookies = h.get('set-cookie', [])
    insecure = httponly = samesite = 0
    for cookie in cookies:
        attrs = {a.strip().split('=',1)[0].lower() for a in cookie.split(';')[1:]}
        insecure += 'secure' not in attrs
        httponly += 'httponly' not in attrs
        samesite += 'samesite' not in attrs
    for id, count, attr, fix in [('COOKIE_SECURE',insecure,'Secure','Set Secure on sensitive cookies served over HTTPS.'),('COOKIE_HTTPONLY',httponly,'HttpOnly','Set HttpOnly on cookies that do not require JavaScript access.'),('COOKIE_SAMESITE',samesite,'SameSite','Set an explicit appropriate SameSite policy; use Secure when SameSite=None.')]:
        if count:
            add(id,'info',f'Cookies without {attr}',f'{count} of {len(cookies)} Set-Cookie headers lack this attribute; cookie purpose is unknown.',fix)
    if 'server' in h or 'x-powered-by' in h:
        add('DISCLOSURE','info','Server identification header present','Server or X-Powered-By header observed (value not retained).','Consider minimizing unnecessary technology disclosure; keep software patched regardless.')
    if 300 <= status < 400 and h.get('location'):
        add('REDIRECT','info','Redirect not followed','A redirect was returned; the destination was not requested or stored.','If authorized, add the destination as a separate target and assess it.')
    if cert and cert.get('notAfter'):
        try:
            days = (ssl.cert_time_to_seconds(cert['notAfter']) - datetime.now(timezone.utc).timestamp()) / 86400
            if days < 30:
                add('CERT_EXPIRY','medium' if days < 7 else 'low','Certificate expires soon',f'Approximately {max(0,int(days))} whole days remain.','Renew the certificate and verify automated renewal.')
        except (ValueError, OverflowError):
            pass
    return out + cookie_observations(headers) + header_observations(target, status, headers)


def scan(value, authorized=False, timeout=8, cancel=None, dns_domain=''):
    if authorized is not True:
        raise PermissionError('Explicit authorization is required for this assessment.')
    target = Target.parse(value)
    started = datetime.now(timezone.utc).isoformat(timespec='seconds')
    conn = None
    connector = None
    endpoints = ()
    tls = None
    from .posture import observations
    if cancel and cancel.is_set():
        return Scan(target.url, started, 'cancelled', None, None, [], 'Cancelled before connection.')
    if dns_domain:
        from .dnscheck import domain_name
        dns_domain = domain_name(dns_domain)
    try:
        timeout = min(15, max(1, float(timeout)))
        endpoints = resolve_once(target.host, target.port)
        if cancel and cancel.is_set():
            return Scan(target.url, started, 'cancelled', None, None, [], 'Cancelled after resolution; no connection made.')
        connector = PinnedConnector(target.host, target.port, endpoints, cancel)
        if target.scheme == 'https':
            conn = http.client.HTTPSConnection(target.host, target.port, timeout=timeout, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
        conn._create_connection = connector
        conn.connect()
        cert = None
        cipher = None
        if target.scheme == 'https':
            tls = conn.sock.version()
            cert = conn.sock.getpeercert()
            cipher = conn.sock.cipher()
        # Single request to explicitly approved URL; no redirects, no auth, no body read.
        if cancel and cancel.is_set():
            return Scan(target.url, started, 'cancelled', None, tls, [], 'Cancelled before HTTP request.')
        conn.request('GET', target.path, headers={'User-Agent':'Sentinel-Assessment/0.2', 'Accept':'text/html, */*;q=0.1', 'Connection':'close'})
        response = conn.getresponse()
        headers=response.getheaders()
        status=response.status
        findings = inspect_headers(target, status, headers, tls, cert) + observations(headers, status, tls, cipher)
        conn.close()
        coverage={'http':'completed','tls':'verified connection' if tls else 'not applicable','dns':'not requested',
                  'cookie_ruleset': COOKIE_RULESET, 'header_ruleset': HEADER_RULESET}
        coverage.update({'connection_address': connector.selected,
                         'resolved_addresses': [e.address for e in endpoints],
                         'scope_note': 'One connected address from a single DNS snapshot; other addresses not assessed.'})
        result=Scan(target.url, started, 'completed', status, tls, findings, coverage=coverage, dns_domain=dns_domain)
        if cancel and cancel.is_set():
            result.status='cancelled'; result.error='Cancelled after HTTP response; remaining checks not run.'; return result
        if dns_domain:
            from .dnscheck import query_domain
            dns=query_domain(dns_domain, authorized=True, cancel=cancel)
            result.coverage['dns']=dns['status']; result.coverage['dns_checks']=dns['checks']; result.findings.extend(dns['findings'])
            if dns['status']!='completed': result.status='partial'; result.error=dns['error'] or 'Some DNS checks were not completed.'
            if cancel and cancel.is_set(): result.status='cancelled'; result.error='Cancelled during DNS checks.'
        return result
    except ssl.SSLCertVerificationError:
        f = Finding('TLS_VERIFY','high','TLS certificate verification failed','The platform trust store rejected the certificate or hostname. No HTTP request was sent.','Check certificate validity, hostname, chain and trusted CA configuration. Never bypass verification as a fix.')
        return Scan(target.url, started, 'partial', None, None, [f], 'Certificate verification failed; HTTP checks not performed.', coverage={'http':'not performed','tls':'verification failed','dns':'not performed'}, dns_domain=dns_domain)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        if cancel and cancel.is_set():
            return Scan(target.url, started, 'cancelled', None, tls, [], 'Cancelled during connection.', dns_domain=dns_domain)
        return Scan(target.url, started, 'failed', None, tls, [], type(exc).__name__ + ': connection or protocol error; no clean bill of health.', coverage={'http':'unknown','tls':'unknown','dns':'not performed'}, dns_domain=dns_domain)
    finally:
        if conn is not None:
            conn.close()


def compare(previous, current):
    if previous['target'] != current['target']:
        raise ValueError('Only identical URLs may be compared.')
    if previous.get('profile','web-v1') != current.get('profile','web-v1') or previous.get('dns_domain','') != current.get('dns_domain',''):
        return {'comparable':False, 'new':[], 'still_present':[], 'not_observed':[]}
    if previous['status'] != 'completed' or current['status'] != 'completed' or previous['http_status'] != current['http_status']:
        return {'comparable':False, 'new':[], 'still_present':[], 'not_observed':[]}
    if any(previous.get('coverage', {}).get(rule) != current.get('coverage', {}).get(rule)
           for rule in ('cookie_ruleset', 'header_ruleset')):
        return {'comparable':False, 'new':[], 'still_present':[], 'not_observed':[]}
    old_address = previous.get('coverage', {}).get('connection_address')
    new_address = current.get('coverage', {}).get('connection_address')
    if old_address != new_address:
        return {'comparable':False, 'new':[], 'still_present':[], 'not_observed':[]}
    p = {f['id'] for f in previous['findings']}; c = {f['id'] for f in current['findings']}
    return {'comparable':True,'new':sorted(c-p),'still_present':sorted(p&c),'not_observed':sorted(p-c)}
