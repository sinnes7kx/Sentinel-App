"""Conservative, read-only evidence comparison for native website retests.

No network operation, database mutation or claim of verified remediation.
Only same-source, same-rule observations from comparable native assessments
are paired. Distinct evidence variants under a rule are kept separate.
"""
from dataclasses import dataclass
from collections import defaultdict
import ipaddress
import json

from .evidence import sanitize
from .finding_views import RISK_ORDER

PROFILES = {'web-v2', 'web-standard-v1'}


@dataclass(frozen=True)
class Change:
    source: str
    rule: str
    state: str
    previous: tuple
    current: tuple


@dataclass(frozen=True)
class Review:
    comparable: bool
    reason: str
    changes: tuple = ()


def _peer(result):
    coverage = result.get('coverage', {})
    try:
        peer = ipaddress.ip_address(coverage.get('connection_address', ''))
        addresses = {ipaddress.ip_address(a) for a in coverage.get('resolved_addresses', [])}
    except (ValueError, TypeError):
        return None
    return peer if peer in addresses else None


def _reason(previous, current):
    if previous.get('target') != current.get('target'):
        return 'Different target URLs.'
    if previous.get('profile') not in PROFILES or previous.get('profile') != current.get('profile'):
        return 'Only matching native Quick or Standard profiles are supported.'
    if previous.get('coverage', {}).get('cookie_ruleset') != current.get('coverage', {}).get('cookie_ruleset'):
        return 'Cookie check coverage changed. Run a fresh baseline before comparing results.'
    if previous.get('coverage', {}).get('header_ruleset') != current.get('coverage', {}).get('header_ruleset'):
        return 'Browser header check coverage changed. Run a fresh baseline before comparing results.'
    if previous.get('dns_domain') or current.get('dns_domain'):
        return 'Optional DNS assessments require a separate evidence review.'
    if any(r.get('status') != 'completed' for r in (previous, current)):
        return 'At least one assessment is incomplete.'
    if any(r.get('coverage', {}).get('http') != 'completed' for r in (previous, current)):
        return 'Complete HTTP coverage is required.'
    if previous.get('http_status') is None or previous.get('http_status') != current.get('http_status'):
        return 'HTTP response status changed or was not recorded.'
    if _peer(previous) is None or _peer(previous) != _peer(current):
        return 'The connected endpoint changed or was not verified.'
    if any(r.get('coverage', {}).get('tls') not in ('verified connection', 'not applicable')
           for r in (previous, current)):
        return 'TLS coverage is not recorded or incomplete.'
    if previous['coverage']['tls'] != current['coverage']['tls']:
        return 'TLS coverage differs.'
    return ''


def _groups(result):
    grouped = defaultdict(dict)
    for raw in result.get('findings', []):
        source = raw.get('source')
        rule = raw.get('id')
        # Never assume unknown provenance matches a known source.
        if not isinstance(source, str) or not source or not isinstance(rule, str) or not rule:
            raise ValueError('A finding lacks a source or rule identifier.')
        signature = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        grouped[(source, rule)][signature] = sanitize(raw)
    return grouped


def review(previous, current):
    reason = _reason(previous, current)
    if reason:
        return Review(False, reason)
    try:
        before, after = _groups(previous), _groups(current)
    except ValueError as exc:
        return Review(False, str(exc))
    changes = []
    for source, rule in sorted(before.keys() | after.keys()):
        key = (source, rule)
        old, new = before.get(key, {}), after.get(key, {})
        if len(old) > 1 or len(new) > 1:
            state = 'Multiple variants — review manually'
        elif not old:
            state = 'Newly observed'
        elif not new:
            state = 'Not observed on retest'
        elif old.keys() == new.keys():
            state = 'Still observed'
        else:
            state = 'Still observed — evidence changed'
        changes.append(Change(source, rule, state, tuple(old.values()), tuple(new.values())))
    def priority(change):
        return min((RISK_ORDER.get(f.get('severity', '').lower(), 5)
                    for f in change.previous + change.current), default=5)
    return Review(True, '', tuple(sorted(changes, key=priority)))


def review_text(result):
    if not result.comparable:
        return 'RETEST REVIEW NOT COMPARABLE\n\n' + result.reason
    lines = ['RETEST EVIDENCE REVIEW', '',
             'Matching URL, native profile, connected address and HTTP status.',
             'Not observed does not prove remediation; review coverage and context.', '']
    if not result.changes:
        lines.append('No observations in either assessment. This is not proof of security.')
    for change in result.changes:
        lines.extend([change.state.upper(), f'{change.source} / {change.rule}'])
        for label, rows in (('Earlier', change.previous), ('Current', change.current)):
            if not rows:
                lines.append(label + ': no observation')
            for row in rows:
                lines.extend([f"{label}: {row.get('title', '')} ({row.get('severity', 'unknown')}, confidence {row.get('confidence', 'unknown')})",
                              'Evidence: ' + row.get('evidence', ''),
                              'Remediation: ' + row.get('remediation', '')])
        lines.append('')
    return '\n'.join(lines)
