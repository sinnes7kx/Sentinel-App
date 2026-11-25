"""Clearly labeled synthetic examples; no real advisories or scan results."""
import json
from .cve_review import evaluate
from .zap_review import detail_summary


def cve_example():
    document = {'version': '2.0', 'vulnerabilities': [
        {'cve': {'id': 'CVE-2000-0000', 'configurations': [
            {'nodes': [{'operator': 'OR', 'cpeMatch': [
                {'vulnerable': True,
                 'criteria': 'cpe:2.3:a:practice:demo_app:1.0:*:*:*:*:*:*:*'}]}]}]}}
    ]}
    return evaluate(document, 'practice', 'demo_app', '1.0')


def zap_example():
    document = {'site': [{'alerts': [
        {'pluginid': '0', 'alert': 'Example: missing browser protection',
         'riskcode': '1', 'confidence': '2', 'instances': [],
         'solution': 'Ask the website owner to review its browser security settings.'}
    ]}]}
    return detail_summary(json.dumps(document).encode('utf-8'))
