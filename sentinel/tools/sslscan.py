"""sslscan: check which TLS versions, ciphers and certificate a server offers."""
from datetime import datetime, timezone
from xml.etree import ElementTree as ET
import re

from ..engine import Finding
from . import runner
from .base import Profile, ToolSpec

INSTALL_HINT = ('sslscan is not installed. On Kali/Debian/Ubuntu run: sudo apt install sslscan\n'
                'On Windows use WSL or run Sentinel on Kali.')

PROFILES = {'standard': Profile('standard', 'Standard', 'Connects several times to list every protocol and cipher the server accepts.',
                                (), 300, 'protocols, ciphers, certificate, Heartbleed, compression, renegotiation')}
FIX_TLS = 'Disable old protocol versions in the web server or load balancer and offer TLS 1.2 and TLS 1.3 only.'


def _flag(el, attr):
    return el is not None and el.get(attr) in ('1', 'true', 'True')


def _cipher_level(name, bits):
    n = name.upper()
    triple = '3DES' in n or 'EDE3' in n or 'CBC3' in n
    if re.search(r'NULL|EXP|ANON|ADH|AECDH|RC4|RC2|MD5', n) or (not triple and re.search(r'(^|[-_])DES(-|_|$)', n)) or bits <= 56:
        return 'high'
    if triple or bits < 128:
        return 'medium'
    return None


def _parse_date(text):
    try:
        return datetime.strptime(' '.join(text.split()), '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def parse_xml(text, private=False, now=None):
    if '<!entity' in text.lower():
        raise ValueError('Unexpected XML entity declaration.')
    root = ET.fromstring(text)
    st = root if root.tag == 'ssltest' else root.find('.//ssltest')
    if st is None:
        raise ValueError('No ssltest element.')
    now = now or datetime.now(timezone.utc)
    out = []
    add = lambda *a: out.append(Finding(*a))
    enabled = {}
    for p in st.findall('protocol'):
        enabled[(p.get('type', ''), p.get('version', ''))] = p.get('enabled') in ('1', 'true')
    for (typ, ver), on in enabled.items():
        if on and typ == 'ssl':
            add(f'TLS_SSL{ver}', 'high', f'SSL {ver} is enabled', f'The server still accepts the obsolete SSL {ver} protocol.', FIX_TLS)
        if on and typ == 'tls' and ver in ('1.0', '1.1'):
            add(f'TLS_{ver}', 'medium', f'TLS {ver} is enabled', f'The server still accepts TLS {ver}, which is deprecated.', FIX_TLS)
    if enabled and not enabled.get(('tls', '1.2')) and not enabled.get(('tls', '1.3')):
        add('TLS_NO_MODERN', 'high', 'No modern TLS version offered', 'Neither TLS 1.2 nor TLS 1.3 was accepted.', FIX_TLS)
    elif enabled and ('tls', '1.3') in enabled and not enabled[('tls', '1.3')]:
        add('TLS_NO_13', 'info', 'TLS 1.3 is not offered', 'TLS 1.2 works, but TLS 1.3 is faster and removes legacy options.', 'Enable TLS 1.3 if your server software supports it.')
    weak = {}
    for c in st.findall('cipher'):
        if c.get('status') not in ('accepted', 'preferred'):
            continue
        try:
            bits = int(c.get('bits', '256'))
        except ValueError:
            bits = 256
        name = runner.clean(c.get('cipher', ''), 60)
        lvl = _cipher_level(name, bits)
        if lvl:
            weak.setdefault(lvl, set()).add(name)
    for lvl, names in sorted(weak.items()):
        shown = ', '.join(sorted(names)[:6]) + (' …' if len(names) > 6 else '')
        add(f'TLS_WEAK_CIPHERS_{lvl.upper()}', lvl, f'{len(names)} weak cipher suite(s) accepted',
            f'The server accepts: {shown}.', 'Remove weak ciphers (NULL, EXPORT, RC4, DES, 3DES, anonymous) and keep only modern AEAD suites such as AES-GCM and ChaCha20.')
    if _flag(st.find('heartbleed'), 'vulnerable'):
        add('TLS_HEARTBLEED', 'high', 'Heartbleed vulnerability reported', 'sslscan reports the server answers malformed heartbeat requests.', 'Update OpenSSL immediately, then replace the certificate and private key and rotate any secrets.')
    reneg = st.find('renegotiation')
    if _flag(reneg, 'supported') and reneg.get('secure') in ('0', 'false'):
        add('TLS_INSECURE_RENEG', 'medium', 'Insecure TLS renegotiation', 'The server supports renegotiation without the secure extension.', 'Update the TLS library and web server.')
    if _flag(st.find('compression'), 'supported'):
        add('TLS_COMPRESSION', 'medium', 'TLS compression enabled', 'Compression can leak secrets (CRIME attack).', 'Disable TLS compression.')
    cert = st.find('certificates/certificate')
    if cert is not None:
        after = _parse_date(cert.findtext('not-valid-after', ''))
        if after:
            days = (after - now).days
            if days < 0:
                add('CERT_EXPIRED', 'high', 'Certificate has expired', f'The certificate expired on {after:%Y-%m-%d}.', 'Renew the certificate now and automate renewal (for example with ACME/Let\'s Encrypt).')
            elif days < 30:
                add('CERT_EXPIRING', 'medium', 'Certificate expires soon', f'The certificate expires in {days} day(s), on {after:%Y-%m-%d}.', 'Renew it and automate renewal.')
        if (cert.findtext('self-signed', '') or '').strip().lower() in ('true', '1'):
            add('CERT_SELF_SIGNED', 'low' if private else 'medium', 'Self-signed certificate', 'The certificate is not issued by a trusted authority, so browsers will warn.', 'Use a certificate from a trusted CA, or an internal CA your devices trust.')
        sig = (cert.findtext('signature-algorithm', '') or '').lower()
        if 'sha1' in sig or 'md5' in sig:
            add('CERT_WEAK_SIG', 'medium', 'Certificate uses a weak signature', f'Signature algorithm: {runner.clean(sig, 40)}.', 'Reissue the certificate with SHA-256 or stronger.')
        pk = cert.find('pk')
        try:
            if pk is not None and (pk.get('type') or '').upper() == 'RSA' and int(pk.get('bits', '4096')) < 2048:
                add('CERT_SHORT_KEY', 'medium', 'Certificate key is too short', f"RSA key is {pk.get('bits')} bits.", 'Reissue the certificate with an RSA key of at least 2048 bits, or an ECDSA key.')
        except ValueError:
            pass
    out.sort(key=lambda f: ({'high': 0, 'medium': 1, 'low': 2, 'info': 3}[f.severity], f.id))
    return out, {'protocols_seen': len(enabled)}, ''


def _parse(text, private):
    return parse_xml(text, private)


def build(binary, target, profile, outfile):
    address = target.connect_host or target.host
    host = '[%s]' % address if ':' in address else address
    return [binary, '--no-colour', '--sni-name=' + target.host, '--xml=' + outfile, f'{host}:{target.port}']


SPEC = ToolSpec('sslscan', 'sslscan TLS check', 'Checks the encryption settings and certificate of an HTTPS site.', 'web',
                ('sslscan',), INSTALL_HINT, PROFILES, build, _parse, outfile='.xml', schemes=('https',),
                note='Makes multiple TLS probes, including Heartbleed and renegotiation checks; it does not send HTTP requests.')
