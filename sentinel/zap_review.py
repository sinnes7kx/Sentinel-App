"""Normalize ZAP Traditional JSON into bounded, local-only evidence summaries.

Imported alerts are scanner-reported observations, not verified vulnerabilities.
Do not copy raw instances, request/response bodies, URLs, or payloads.
"""
import json
import re
from collections import Counter
from html.parser import HTMLParser

from .evidence import redact

MAX_BYTES = 5 * 1024 * 1024
MAX_ALERTS = 500
RISK = {'0': 'info', '1': 'low', '2': 'medium', '3': 'high'}
CONFIDENCE = {'0': 'false positive', '1': 'low', '2': 'medium', '3': 'high', '4': 'confirmed'}


class _Plain(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def plain(value, limit=800):
    if not isinstance(value, str):
        return ''
    parser = _Plain()
    parser.feed(value[:limit * 4])
    return redact(' '.join(' '.join(parser.parts).split()))[:limit]


def parse_report(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
        raise ValueError('Choose a nonempty ZAP report of at most 5 MB.')
    try:
        report = json.loads(raw.decode('utf-8-sig'))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError('Invalid ZAP Traditional JSON report.') from exc
    if not isinstance(report, dict) or not isinstance(report.get('site'), list):
        raise ValueError('Choose a ZAP Traditional JSON report.')
    findings = []
    counts = Counter()
    total = 0
    for site in report['site']:
        if not isinstance(site, dict) or not isinstance(site.get('alerts'), list):
            raise ValueError('Expected ZAP site and alert objects.')
        for alert in site['alerts']:
            if not isinstance(alert, dict):
                raise ValueError('Expected ZAP alert objects.')
            total += 1
            risk = RISK.get(str(alert.get('riskcode')), 'unknown')
            confidence = CONFIDENCE.get(str(alert.get('confidence')), 'unknown')
            counts[risk] += 1
            if len(findings) >= MAX_ALERTS:
                continue
            plugin = str(alert.get('pluginid', ''))
            if not re.fullmatch(r'[0-9]{1,10}', plugin):
                plugin = 'unknown'
            instances = alert.get('instances', [])
            if not isinstance(instances, list):
                raise ValueError('Expected a ZAP instances list.')
            findings.append({
                'id': 'ZAP_' + plugin,
                'title': plain(alert.get('alert') or alert.get('name'), 160) or 'Unnamed ZAP alert',
                'severity': risk,
                'confidence': confidence,
                'source': 'zap-import',
                'instances': len(instances),
                'remediation': plain(alert.get('solution')),
            })
    return {'site_count': len(report['site']), 'alert_count': total,
            'risk_counts': dict(counts), 'alerts': findings,
            'truncated': total > len(findings)}


def detail_summary(raw):
    report = parse_report(raw)
    rows = {'Sites in report': report['site_count'],
            'Alert types reported': report['alert_count'],
            'Risk counts': report['risk_counts'],
            'Review limitation': 'Imported scanner observations only. Not a new scan or independent verification.'}
    if report['truncated']:
        rows['Detail limit'] = 'Only the first 500 alert records are displayed.'
    for i, alert in enumerate(report['alerts'], 1):
        rows[f"{i}. {alert['title']}"] = (
            f"{alert['id']} | {alert['severity']} | reported confidence: {alert['confidence']} | "
            f"{alert['instances']} reported instances"
            + (' | Suggested remediation: ' + alert['remediation'] if alert['remediation'] else ''))
    return rows
