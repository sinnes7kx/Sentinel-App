"""Conservative offline NVD 2.0 advisory review for an explicitly identified app.

Only simple independent application CPE criteria are evaluated. Version ranges,
platform conditions, escaped CPE names and wildcard product names are not
interpreted. No target probing or feed download.
"""
import json
import re
from .dependencies import read_local
from .engine import Finding, Scan
from datetime import datetime, timezone

TOKEN = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}')
CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}')
RANGES = ('versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding')


def identify(vendor, product, version):
    parts = tuple(s.strip().lower() for s in (vendor, product, version))
    if not all(TOKEN.fullmatch(s) for s in parts):
        raise ValueError('Enter exact NVD CPE vendor, product and version tokens.')
    return parts


def evaluate(document, vendor, product, version, cancel=None):
    vendor, product, version = identify(vendor, product, version)
    if not isinstance(document, dict) or document.get('version') != '2.0' or not isinstance(document.get('vulnerabilities'), list):
        raise ValueError('Choose an NVD CVE JSON 2.0 response or feed.')
    matches, review = set(), set()
    seen = set()
    skipped = 0
    for wrapper in document['vulnerabilities']:
        if cancel is not None and cancel.is_set():
            raise InterruptedError('Advisory review cancelled.')
        cve = wrapper.get('cve') if isinstance(wrapper, dict) else None
        if not isinstance(cve, dict) or not isinstance(cve.get('id'), str) or not CVE.fullmatch(cve['id']):
            raise ValueError('Invalid CVE record in supplied feed.')
        id_ = cve['id']
        if id_ in seen:
            raise ValueError('Duplicate CVE records; reconcile the supplied feed.')
        seen.add(id_)
        if cve.get('vulnStatus') == 'Rejected':
            continue
        configs = cve.get('configurations', [])
        if not isinstance(configs, list):
            raise ValueError('Invalid applicability configurations.')
        for cfg in configs:
            if not isinstance(cfg, dict) or not isinstance(cfg.get('nodes'), list):
                raise ValueError('Invalid applicability configuration.')
            nodes = cfg['nodes']
            simple = (len(nodes) == 1 and cfg.get('operator', 'OR') == 'OR'
                      and not cfg.get('negate', False))
            for node in nodes:
                if not isinstance(node, dict) or not isinstance(node.get('cpeMatch'), list):
                    raise ValueError('Invalid applicability node.')
                independent = simple and node.get('operator') == 'OR' and not node.get('negate', False) and not node.get('children')
                for entry in node['cpeMatch']:
                    if not isinstance(entry, dict) or not isinstance(entry.get('criteria'), str):
                        raise ValueError('Invalid CPE criterion.')
                    parts = entry['criteria'].lower().split(':')
                    if len(parts) != 13 or parts[:3] != ['cpe', '2.3', 'a']:
                        skipped += 1
                        continue
                    if parts[3:5] != [vendor, product]:
                        continue
                    if entry.get('vulnerable') is not True:
                        continue
                    if (not independent or any(k in entry for k in RANGES)
                            or any(x != '*' for x in parts[6:])
                            or not TOKEN.fullmatch(parts[5])):
                        review.add(id_)
                    elif parts[5] == version:
                        matches.add(id_)
    return {'matches': sorted(matches), 'review': sorted(review - matches),
            'records': len(seen), 'unsupported_criteria': skipped,
            'product': vendor + ':' + product, 'version': version}


def assess(path, vendor, product, version, cancel=None):
    text, digest = read_local(path)
    result = evaluate(json.loads(text), vendor, product, version, cancel)
    findings = [Finding('NVD_' + cve, 'info', cve + ' — supplied advisory match',
                        'Exact application CPE version criterion matches the supplied software identity. '
                        'Installed build and patch status are not independently verified.',
                        'Review the vendor advisory and confirm the installed build and applicable fixes.',
                        confidence='medium', source='local-nvd') for cve in result['matches']]
    coverage = dict(result, feed_sha256=digest,
                    limitations='Only exact version, independent application criteria; ranges and platform conditions require manual review. '
                    'Feed completeness, authenticity, freshness and software identity are not verified.')
    return Scan('software:' + result['product'] + ':' + result['version'],
                datetime.now(timezone.utc).isoformat(), 'partial', None, None, findings,
                'Only supplied exact-version criteria evaluated. Non-matches do not establish safety.',
                coverage=coverage, profile='local-nvd-exact-v1').to_dict()
