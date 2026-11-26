"""Check recorded read responses against an explicit object-level access policy."""
import json
import re

TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,95}')
MAX_ITEMS = 1000


def identifier(value):
    return isinstance(value, str) and TOKEN.fullmatch(value) is not None


def identifiers(values):
    return isinstance(values, list) and len(values) <= MAX_ITEMS and all(map(identifier, values))


def assess_reads(text):
    report = json.loads(text)
    if not isinstance(report, dict) or report.get('schema') != 'sentinel-object-reads-v1':
        raise ValueError('Choose a Sentinel object-read evidence file. Save the example for its format.')
    readers = report.get('readers')
    if not isinstance(readers, dict) or not 1 <= len(readers) <= MAX_ITEMS:
        raise ValueError('Provide a readers policy for 1–1000 objects.')
    for obj, subjects in readers.items():
        if not identifier(obj) or not identifiers(subjects):
            raise ValueError('Each readers entry needs an object ID and a list of permitted subject IDs.')
    cases = report.get('cases')
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_ITEMS:
        raise ValueError('Provide 1–1000 recorded read cases.')

    violations = allowed = denied = inconclusive = mismatches = 0
    details = {}
    for index, case in enumerate(cases, 1):
        if not isinstance(case, dict):
            raise ValueError(f'Case {index} must be a JSON object.')
        actor, obj = case.get('subject'), case.get('object')
        status, returned = case.get('http_status'), case.get('returned_objects')
        if not identifier(actor) or not identifier(obj) or obj not in readers:
            raise ValueError(f'Case {index} requires a subject and an object listed in the readers policy.')
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError(f'Case {index} requires an integer HTTP status from 100 to 599.')
        if 'returned_objects' not in case or (returned is not None and not identifiers(returned)):
            raise ValueError(f'Case {index} requires returned_objects as an ID list or null for unknown.')
        key = f'{index}. {actor} → {obj} (HTTP {status})'
        observed = set(returned or ())
        exposed = sorted(item for item in observed if item in readers and actor not in readers[item])
        if exposed:
            violations += 1
            message = 'FAIL · Response contained a restricted object: ' + ', '.join(exposed[:5])
        elif returned is None or observed.difference(readers):
            inconclusive += 1
            message = 'INCONCLUSIVE · Missing response evidence or missing policy for a returned object.'
        elif actor in readers[obj] and 200 <= status < 300 and obj in observed:
            allowed += 1
            message = 'PASS · Authorized read returned the expected object.'
        elif status in (403, 404) and not observed:
            if actor in readers[obj]:
                mismatches += 1
                message = 'MISMATCH · The policy permits this read, but the object was withheld.'
            else:
                denied += 1
                message = 'PASS · Restricted object withheld.'
        else:
            inconclusive += 1
            message = 'INCONCLUSIVE · The response does not establish the expected read decision.'
        details[key] = message
    result = {'Recorded reads': len(cases), 'Unauthorized disclosures': violations,
              'Permitted reads observed': allowed, 'Denied reads observed': denied,
              'Permitted reads withheld': mismatches, 'Inconclusive reads': inconclusive}
    if violations:
        result['Remediation'] = 'Enforce the subject’s read permission on each returned object before serializing the response.'
    if not denied:
        result['Denial coverage'] = 'No recorded case demonstrated a correctly denied read.'
    result['Case results'] = details
    return result
