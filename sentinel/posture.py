"""Passive analysis of already received headers and negotiated TLS metadata."""
import re

def observations(headers, status, tls, cipher):
    from .engine import Finding
    h = {}
    for k,v in headers:
        h.setdefault(k.lower(), []).append(v)
    out = []
    def add(i,s,t,e,r): out.append(Finding(i,s,t,e,r))
    if tls in ('TLSv1','TLSv1.1','SSLv3'):
        add('TLS_LEGACY','high','Legacy TLS negotiated','The verified connection negotiated an obsolete protocol.','Disable legacy TLS and require TLS 1.2 or newer.')
    if cipher and cipher[2] < 128:
        add('TLS_BITS','medium','Low negotiated cipher strength','Negotiated cipher reports fewer than 128 secret bits.','Configure modern authenticated encryption cipher suites.')
    html = any(v.split(';')[0].strip().lower() in ('text/html','application/xhtml+xml') for v in h.get('content-type',[]))
    if html and 200 <= status < 300:
        if not h.get('permissions-policy'):
            add('PERMISSIONS_POLICY','info','Permissions Policy not observed','No Permissions-Policy header on the HTML response.','Restrict browser features not needed by the application; test feature availability.')
        if not h.get('cross-origin-opener-policy'):
            add('COOP','info','Opener policy not explicitly set','No Cross-Origin-Opener-Policy on the HTML response.','Consider same-origin or an appropriate policy after testing sign-in and popup flows.')
        if h.get('content-security-policy-report-only') and not h.get('content-security-policy'):
            add('CSP_REPORT_ONLY','info','CSP is report-only','Report-only policy does not enforce restrictions.','Review violation reports and deploy an enforced policy when ready.')
        if any(v.strip().lower() in ('unsafe-url','no-referrer-when-downgrade') for v in h.get('referrer-policy',[])):
            add('REFERRER_PERMISSIVE','low','Potentially permissive referrer policy','A policy allowing more URL information was observed.','Review need for cross-origin referrers; prefer strict-origin-when-cross-origin or stricter.')
    for c in h.get('set-cookie',[]):
        attrs={}
        for a in c.split(';')[1:]:
            k,_,v=a.strip().partition('='); attrs[k.lower()]=v.strip().lower()
        if attrs.get('samesite')=='none' and 'secure' not in attrs:
            add('COOKIE_NONE_INSECURE','low','SameSite=None without Secure','At least one cookie declares SameSite=None without Secure.','Use Secure with SameSite=None over HTTPS; review cross-site cookie need.')
            break
    if any(v.strip()=='*' for v in h.get('access-control-allow-origin',[])):
        add('CORS_WILDCARD','info','Wildcard cross-origin policy observed','The response advertises Access-Control-Allow-Origin: *. No cross-origin probe was performed.','Confirm this resource is intentionally public; use a specific allowlist for private endpoints.')
    if any(v.strip()=='*' for v in h.get('access-control-allow-origin',[])) and any(v.strip().lower()=='true' for v in h.get('access-control-allow-credentials',[])):
        add('CORS_CONFLICT','info','Conflicting CORS configuration','Wildcard origin and credentials=true appeared together. Browsers reject credentialed wildcard requests.','Use explicit trusted origins when credentials are necessary; review CORS behavior.')
    if any(v.strip()=='1' or v.strip().startswith('1;') for v in h.get('x-xss-protection',[])):
        add('LEGACY_XSS_HEADER','info','Legacy browser XSS filter enabled','X-XSS-Protection enables an obsolete browser filter.','Prefer a restrictive CSP; consider removing the obsolete header or setting it to 0.')
    if len(h.get('content-type',[]))>1:
        add('DUP_CONTENT_TYPE','info','Multiple Content-Type headers','Multiple content type fields were returned; interpretation may vary.','Return one unambiguous Content-Type header.')
    return out
