"""One-click website checkup: Sentinel's built-in header/TLS/DNS-free checks plus every installed web tool."""
from datetime import datetime, timezone
from ipaddress import ip_address
import re

from .. import engine
from ..engine import Scan
from . import nikto, runner, sslscan, whatweb
from .base import Profile, ToolMissing, execute, find_binary, parse_scope
from .scope import require_authorization
from .backends import Backend


def managed_candidate(spec, target, scope, saved):
    if (saved is None or saved.kind != 'docker' or
            not re.fullmatch(r'sha256:[0-9a-f]{64}', saved.environment)):
        return None
    if spec.id not in ('whatweb', 'sslscan'):
        return None
    if spec.id == 'whatweb' and scope.kind != 'ip':
        return None
    addresses = scope.addresses if scope.kind == 'host' else (scope.value,)
    if not addresses:
        return None
    for value in addresses:
        address = ip_address(value)
        if (address.is_loopback or address.is_link_local or address.is_unspecified or
                address.is_multicast or address.is_reserved or
                getattr(address, 'ipv4_mapped', None) is not None):
            return None
    return saved

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
             run=runner.run, lookup=find_binary, web_scan=engine.scan, managed=None):
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
            selected = Backend() if binary else managed_candidate(spec, target, scope, managed)
            if selected is None:
                coverage[spec.id] = 'not installed'; status = 'partial'
                if spec.id == 'nikto':
                    errors.append('Nikto is not installed natively; automatic Nikto setup is not available yet.')
                elif managed is not None:
                    errors.append(spec.name + ': saved toolkit cannot be used for this target; use a supported native check.')
                else:
                    errors.append(spec.name + ': no native executable or approved managed toolkit. Open Tool setup and prepare/test the toolkit.')
                continue
            coverage[spec.id + '_engine'] = selected.kind
            try:
                # Reuse the already authorized DNS snapshot for numeric TLS targeting.
                frozen = (lambda host: scope.addresses) if scope.kind == 'host' else resolver
                r = execute(spec, target.url, prof, True, confirm, cancel, resolver=frozen if selected.kind == 'docker' else resolver, run=run, binary=binary, backend=selected)
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
