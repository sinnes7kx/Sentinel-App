"""One-click website checkup: Sentinel's built-in header/TLS/DNS-free checks plus every installed web tool."""
from datetime import datetime, timezone

from .. import engine
from ..engine import Scan
from . import nikto, runner, sslscan, whatweb
from .base import Profile, ToolMissing, execute, find_binary, parse_scope
from .scope import require_authorization

STEPS = ((whatweb.SPEC, 'passive'), (sslscan.SPEC, 'standard'), (nikto.SPEC, 'safe'))
ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
# Nikto repeats header checks the built-in assessor already reports, so hide those copies.
HEADER_DUPES = ('x-frame-options', 'x-content-type-options', 'strict-transport-security', 'content-security-policy', 'x-xss-protection')


class Suite:
    id = 'web-checkup'
    name = 'Website checkup (recommended)'
    blurb = 'Runs Sentinel\'s own header and certificate checks, then WhatWeb, sslscan and a safe Nikto pass if they are installed.'
    kind = 'web'
    schemes = ()
    install_hint = ''
    note = 'Sends a few dozen to a few thousand requests to the site. Tools that are not installed are skipped and listed in the coverage.'
    profiles = {'standard': Profile('standard', 'Standard', 'Safe settings for every tool. No attack payloads.', (), 3600, 'built-in checks + installed web tools')}

    def installed(self):
        return True

    def scan(self, value, profile='standard', attested=False, confirm='', cancel=None, resolver=None,
             run=runner.run, lookup=find_binary, web_scan=engine.scan):
        if attested is not True:
            raise PermissionError('Confirm ownership or written permission before testing.')
        if profile not in self.profiles:
            raise ValueError('Unknown scan profile.')
        if cancel is not None and cancel.is_set():
            return Scan(str(value), datetime.now(timezone.utc).isoformat(), 'cancelled', None, None, [],
                        'Cancelled before resolution.', profile='web-checkup-' + profile)
        target, scope, label = parse_scope(self, value, resolver)
        require_authorization(scope, attested, confirm)
        started = datetime.now(timezone.utc).isoformat(timespec='seconds')
        cancelled = lambda: cancel is not None and cancel.is_set()
        findings, coverage, errors, status = [], {}, [], 'completed'
        base = web_scan(target.url, True, cancel=cancel)
        findings += base.findings
        coverage['built-in checks'] = base.status
        if base.status == 'cancelled':
            status = 'cancelled'
        elif base.status != 'completed':
            status = 'partial'; errors.append('Built-in checks: ' + (base.error or base.status))
        for spec, prof in STEPS:
            if status == 'cancelled' or cancelled():
                status = 'cancelled'; break
            if spec.schemes == ('https',) and target.scheme != 'https':
                coverage[spec.id] = 'skipped (needs https://)'; continue
            binary = lookup(spec)
            if not binary:
                coverage[spec.id] = 'not installed'; status = 'partial'; errors.append(spec.name + ' is not installed.'); continue
            try:
                r = execute(spec, target.url, prof, True, confirm, cancel, resolver=resolver, run=run, binary=binary)
            except (ValueError, ToolMissing) as e:
                coverage[spec.id] = 'not run'; status = 'partial'; errors.append(str(e)); continue
            coverage[spec.id] = r.status
            kept = [f for f in r.findings if not (spec.id == 'nikto' and any(h in (f.title + f.evidence).lower() for h in HEADER_DUPES))]
            if len(kept) != len(r.findings):
                coverage['duplicates hidden'] = coverage.get('duplicates hidden', 0) + len(r.findings) - len(kept)
            findings += kept
            if r.status == 'cancelled':
                status = 'cancelled'; break
            if r.status != 'completed':
                status = 'partial'; errors.append(f'{spec.name}: {r.error}')
        findings.sort(key=lambda f: (ORDER.get(f.severity, 9), f.id))
        if status == 'cancelled':
            errors.append('Cancelled; results are incomplete.')
        return Scan(label, started, status, base.http_status, base.tls, findings, ' '.join(errors),
                    coverage=coverage, profile='web-checkup-' + profile)


SUITE = Suite()
