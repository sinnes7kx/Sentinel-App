"""Offline PyPI version and affected-range matching against local OSV records.

No installation, imports of assessed packages, URL retrieval or feed updates.
Unsupported input remains visible as partial coverage, never a clean result.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from .version_match import match_affected, require_packaging


PIN = re.compile(r'([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)')
NAME = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?')
LIMIT = 10 * 1024 * 1024


def normalize_name(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def read_local(path):
    with Path(path).open('rb') as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError('Input exceeds the 10 MiB per-file limit.')
    return data.decode('utf-8-sig'), hashlib.sha256(data).hexdigest()


def parse_requirements(text):
    packages, unsupported = set(), []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Never echo rejected lines: index URLs may contain credentials.
        line = re.split(r'\s+#', line, maxsplit=1)[0].strip()
        match = PIN.fullmatch(line)
        if match:
            packages.add((normalize_name(match[1]), match[2]))
        else:
            unsupported.append({'line': number, 'reason': 'Only name==exact-version pins are supported.'})
    return sorted(packages), unsupported


def parse_pip_inspect(text):
    """Read pip inspect's inventory only; never expose direct_url or metadata text."""
    data = json.loads(text)
    if not isinstance(data, dict) or data.get('version') != '1' or not isinstance(data.get('installed'), list):
        raise ValueError('Expected pip inspect report format version 1.')
    packages, unsupported = set(), []
    for number, item in enumerate(data['installed'], 1):
        metadata = item.get('metadata') if isinstance(item, dict) else None
        name = metadata.get('name') if isinstance(metadata, dict) else None
        version = metadata.get('version') if isinstance(metadata, dict) else None
        if (not isinstance(name, str) or not isinstance(version, str)
                or not NAME.fullmatch(name) or not PIN.fullmatch(name + '==' + version)):
            unsupported.append({'item': number, 'reason': 'Invalid installed package name or version.'})
        elif item.get('direct_url') is not None:
            unsupported.append({'item': number, 'reason': 'Direct URL/editable installation has unverified PyPI provenance.'})
        else:
            packages.add((normalize_name(name), version))
    return sorted(packages), unsupported


def validate_records(records):
    if not isinstance(records, list):
        raise ValueError('Advisories must be a JSON array of OSV records.')
    ids = set()
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get('id'), str) or not re.fullmatch(r'[A-Za-z0-9:_.-]+', record['id']):
            raise ValueError('Each advisory requires an id.')
        if record['id'] in ids:
            raise ValueError('Duplicate advisory ids are ambiguous; reconcile the local feed first.')
        ids.add(record['id'])
        if not isinstance(record.get('affected'), list):
            raise ValueError('Each advisory requires an affected list.')
        for affected in record['affected']:
            if not isinstance(affected, dict) or not isinstance(affected.get('package'), dict):
                raise ValueError('Invalid affected package.')
            package = affected['package']
            if not all(isinstance(package.get(k), str) and package[k] for k in ('name', 'ecosystem')):
                raise ValueError('Affected package requires name and ecosystem.')
            versions = affected.get('versions', [])
            if not isinstance(versions, list) or not all(isinstance(v, str) for v in versions):
                raise ValueError('Affected versions must be strings.')
            if not isinstance(affected.get('ranges', []), list):
                raise ValueError('Affected ranges must be a list.')
            for specification in affected.get('ranges', []):
                if not isinstance(specification, dict) or not isinstance(specification.get('type'), str):
                    raise ValueError('Each range requires a type.')
                events = specification.get('events')
                if not isinstance(events, list) or not events:
                    raise ValueError('Each range requires nonempty events.')
                for event in events:
                    if (not isinstance(event, dict) or len(event) != 1
                            or not set(event) <= {'introduced', 'fixed', 'last_affected', 'limit'}
                            or not all(isinstance(v, str) and v for v in event.values())):
                        raise ValueError('Invalid range event.')


def assess(requirements, advisories, inventory_format='requirements', cancel=None):
    def checkpoint():
        if cancel is not None and cancel.is_set():
            raise InterruptedError('Dependency assessment cancelled.')
    checkpoint()
    require_packaging()
    inventory, inventory_hash = read_local(requirements)
    feed, feed_hash = read_local(advisories)
    if inventory_format == 'requirements':
        packages, unsupported = parse_requirements(inventory)
    elif inventory_format == 'pip-inspect':
        packages, unsupported = parse_pip_inspect(inventory)
    else:
        raise ValueError('Unsupported inventory format.')
    records = json.loads(feed)
    validate_records(records)
    # Index once: large local feeds should not be scanned once per dependency.
    index = {}
    for record in records:
        checkpoint()
        if record.get('withdrawn'):
            continue
        for affected in record['affected']:
            package = affected['package']
            if package['ecosystem'] == 'PyPI':
                index.setdefault(normalize_name(package['name']), {}).setdefault(record['id'], []).append(affected)
    results = []
    for name, version in packages:
        checkpoint()
        matches, unresolved, evaluated, details = [], [], [], []
        relevant = index.get(name, {})
        for advisory_id, entries in sorted(relevant.items()):
            checkpoint()
            decisions = [match_affected(version, entry) for entry in entries]
            if any(matched is True for matched, _ in decisions):
                state = 'affected'
                matches.append(advisory_id)
                reasons = sorted({reason for matched, why in decisions if matched is True for reason in why})
            elif any(matched is None for matched, _ in decisions):
                state = 'unknown'
                unresolved.append(advisory_id)
                reasons = sorted({reason for matched, why in decisions if matched is None for reason in why})
            else:
                state = 'no_match_in_supplied_advisory'
                evaluated.append(advisory_id)
                reasons = ['outside_supplied_affected_versions']
            details.append({'advisory_id': advisory_id, 'status': state, 'reasons': reasons})
        results.append({'name': name, 'version': version,
                        'status': 'affected' if matches else ('unknown' if unresolved or not relevant else 'no_match_in_supplied_feed'),
                        'advisory_ids': matches,
                        'unresolved_advisory_ids': unresolved,
                        'evaluated_nonmatching_advisory_ids': evaluated,
                        'advisory_results': details,
                        'coverage': 'matching package records' if relevant else 'no package records in supplied feed'})
    return {'profile': 'local-pypi-ranges-v2', 'status': 'partial',
            'inventory_format': inventory_format,
            'inventory_sha256': inventory_hash, 'advisories_sha256': feed_hash,
            'advisory_count': len(records), 'packages': results,
            'unsupported_requirements': unsupported,
            'unsupported_inventory_entries': unsupported,
            'summary': {'packages': len(results), 'affected': sum(p['status'] == 'affected' for p in results),
                        'unknown': sum(p['status'] == 'unknown' for p in results),
                        'no_match_in_supplied_feed': sum(p['status'] == 'no_match_in_supplied_feed' for p in results),
                        'unsupported_inventory_entries': len(unsupported)},
            'limitations': ['Only PyPI PEP 440 versions and OSV ECOSYSTEM ranges are evaluated.',
                            'Local builds, Git/SemVer ranges and requirement environment markers are not evaluated.',
                            'Inventory completeness, feed authenticity and freshness are not verified.',
                            'A non-match applies only to the supplied advisories, not overall package safety.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--requirements', type=Path)
    inputs.add_argument('--pip-inspect', type=Path, help='Local pip inspect JSON report')
    parser.add_argument('--advisories', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = assess(args.requirements or args.pip_inspect, args.advisories,
                        'requirements' if args.requirements else 'pip-inspect')
    except RuntimeError as exc:
        parser.error(str(exc))
    except (ValueError, OSError) as exc:
        # Avoid echoing input contents, private filesystem paths or feed text.
        parser.error('Cannot assess local inputs: ' + type(exc).__name__)
    from .evidence import sanitize
    print(json.dumps(sanitize(result), indent=2))
    return 1 if any(p['advisory_ids'] for p in result['packages']) else 2


if __name__ == '__main__':
    raise SystemExit(main())
