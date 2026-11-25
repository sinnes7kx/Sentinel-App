"""Review browser policy header configuration from an existing HTTP response.

Observations are deliberately limited to recognizable header syntax; this is
not a browser policy evaluator. Never retain raw header values or directives.
"""
import re

RULESET = 'header-review-v1'


def header_observations(target, status, headers):
    from .engine import Finding
    values = {}
    for key, value in headers:
        values.setdefault(key.lower(), []).append(value)
    findings = []

    def add(rule, title, evidence, fix, severity='info'):
        findings.append(Finding(rule, severity, title, evidence, fix))

    if target.scheme == 'https':
        hsts = values.get('strict-transport-security', [])
        if len(hsts) > 1:
            add('HSTS_MULTIPLE', 'Multiple HSTS headers',
                'More than one Strict-Transport-Security field was observed. Effective browser handling was not tested.',
                'Return one consistent HSTS header.')
        for value in hsts:
            ages = [p.partition('=')[2].strip() for p in value.split(';')
                    if p.partition('=')[0].strip().lower() == 'max-age']
            if len(ages) > 1 or any(not re.fullmatch(r'[0-9]+|"[0-9]+"', age) for age in ages):
                add('HSTS_AGE_SYNTAX', 'HSTS max-age configuration needs review',
                    'A policy contains repeated or unrecognized max-age syntax.',
                    'Use one max-age directive with a nonnegative integer number of seconds.', 'low')
                break

    html = any(v.split(';', 1)[0].strip().lower() in ('text/html', 'application/xhtml+xml')
               for v in values.get('content-type', []))
    if not html or not 200 <= status < 300:
        return findings

    csp = values.get('content-security-policy', [])
    policies = [p for field in csp for p in field.split(',')]
    if csp and not any(p.strip(' ;\t') for p in policies):
        add('CSP_EMPTY', 'Empty enforced content security policy',
            'An enforced CSP header is present but contains no policy directives.',
            'Configure an actual enforced policy appropriate for the page.', 'low')

    repeated = False
    for policy in policies:
        seen = set()
        for directive in policy.split(';'):
            words = directive.split()
            if not words:
                continue
            name = words[0].lower()
            if not re.fullmatch(r'[a-z][a-z0-9-]*', name):
                continue
            if name in seen:
                repeated = True
            seen.add(name)
    if repeated:
        add('CSP_DUP_DIRECTIVE', 'Repeated CSP directive',
            'At least one individual enforced policy repeats a directive name. Effective browser policy was not evaluated.',
            'Use one occurrence of each directive within a policy; review the intended sources.')

    frame = [token.strip().lower() for field in values.get('x-frame-options', [])
             for token in field.split(',')]
    if frame and any(token not in ('deny', 'sameorigin') for token in frame):
        add('FRAME_HEADER_SYNTAX', 'Unrecognized framing header value',
            'At least one X-Frame-Options value is not DENY or SAMEORIGIN. CSP may provide separate protection.',
            'Use DENY or SAMEORIGIN when appropriate, or an enforced CSP frame-ancestors directive.')
    if 'deny' in frame and 'sameorigin' in frame:
        add('FRAME_HEADER_CONFLICT', 'Conflicting framing header values',
            'Both DENY and SAMEORIGIN appeared in X-Frame-Options. Effective browser handling was not tested.',
            'Return one consistent framing policy.')
    return findings
