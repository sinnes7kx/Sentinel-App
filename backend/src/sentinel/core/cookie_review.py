"""Passive cookie configuration review; never store names or values."""
from collections import Counter

RULESET = 'cookie-review-v1'


def cookie_observations(headers):
    from .engine import Finding
    counts = Counter()
    for key, value in headers:
        if key.lower() != 'set-cookie':
            continue
        first, *parts = value.split(';')
        name, separator, _ = first.strip().partition('=')
        if not separator or not name or any(c.isspace() for c in name):
            continue
        attrs = {}
        for part in parts:
            k, _, v = part.strip().partition('=')
            attrs.setdefault(k.strip().lower(), []).append(v.strip())
        # Duplicate values are ambiguous; report separately rather than assume
        # which attribute a particular browser accepts.
        if any(len(attrs.get(k, [])) > 1 for k in ('domain', 'path', 'samesite')):
            counts['COOKIE_DUP_ATTR'] += 1
        same = attrs.get('samesite', [])
        if len(same) == 1 and same[0].lower() not in ('strict', 'lax', 'none'):
            counts['COOKIE_INVALID_SAMESITE'] += 1
        if name.lower().startswith('__secure-') and 'secure' not in attrs:
            counts['COOKIE_SECURE_PREFIX'] += 1
        if name.lower().startswith('__host-'):
            paths = attrs.get('path', [])
            if 'secure' not in attrs or 'domain' in attrs or not paths or (len(paths) == 1 and paths[0] != '/'):
                counts['COOKIE_HOST_PREFIX'] += 1
    rules = (
        ('COOKIE_DUP_ATTR', 'Repeated cookie attributes',
         'Return only one Domain, Path and SameSite attribute per cookie.'),
        ('COOKIE_INVALID_SAMESITE', 'Unrecognized SameSite setting',
         'Use Strict, Lax or None as appropriate. None also requires Secure.'),
        ('COOKIE_SECURE_PREFIX', 'Secure-prefixed cookie missing Secure',
         'Set Secure for __Secure- cookies and serve them over HTTPS.'),
        ('COOKIE_HOST_PREFIX', 'Host-prefixed cookie configuration mismatch',
         'Set Secure and Path=/, omit Domain, and serve __Host- cookies over HTTPS.'),
    )
    return [Finding(rule, 'low' if rule != 'COOKIE_DUP_ATTR' else 'info', title,
                    str(counts[rule]) + ' Set-Cookie header(s) matched this configuration rule. '
                    'Cookie purpose and browser acceptance were not tested.', fix, confidence='medium')
            for rule, title, fix in rules if counts[rule]]
