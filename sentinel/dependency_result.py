"""Map offline advisory matches into the same project history as network checks."""
from datetime import datetime, timezone
from .engine import Scan, Finding


def scan_record(result):
    findings = []
    for package in result['packages']:
        if package['status'] == 'affected':
            findings.append(Finding(
                'DEP_' + package['name'], 'info', package['name'] + ' matches supplied advisories',
                'Version ' + package['version'] + ': ' + ', '.join(package['advisory_ids']) +
                '. Severity is not inferred from an advisory identifier. Feed trust and freshness are unverified.',
                'Review the advisory and test a supported update. This match does not prove exploitability.',
                confidence='medium', source='local-dependencies'))
    scan = Scan('inventory-sha256:' + result['inventory_sha256'], datetime.now(timezone.utc).isoformat(),
                'partial', None, None, findings, 'Only the supplied local advisory feed was evaluated.',
                coverage={'summary': result['summary'], 'advisories_sha256': result['advisories_sha256'],
                          'limitations': result['limitations']}, profile=result['profile']).to_dict()
    for key in ('job_id', 'events'):
        if key in result:
            scan[key] = result[key]
    return scan
