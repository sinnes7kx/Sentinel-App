import json
import tempfile
import unittest
from pathlib import Path
from threading import Event
from sentinel.cve_review import evaluate, assess


def entry(version='1.2.3', **changes):
    return dict({'vulnerable': True, 'criteria': 'cpe:2.3:a:fixture:app:' + version + ':*:*:*:*:*:*:*'}, **changes)


def record(number, criteria, **config):
    return {'cve': {'id': f'CVE-2099-{number:04}', 'configurations': [
        dict({'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': criteria}]}, **config)]}}


def feed(*records):
    return {'version': '2.0', 'vulnerabilities': list(records)}


class CVEReviewTests(unittest.TestCase):
    def test_exact_identity_only(self):
        result = evaluate(feed(record(1, [entry()]), record(2, [entry('1.2.4')]),
                               record(3, [entry(vulnerable=False)])), 'fixture', 'app', '1.2.3')
        self.assertEqual(result['matches'], ['CVE-2099-0001'])
        self.assertEqual(result['review'], [])
        self.assertEqual(result['records'], 3)

    def test_ranges_conditions_and_negation_require_review(self):
        result = evaluate(feed(record(1, [entry('*', versionEndExcluding='2.0')]),
                               record(2, [entry()], operator='AND'),
                               record(3, [entry()], negate=True),
                               record(4, [entry(criteria='cpe:2.3:a:fixture:app:1.2.3:*:*:*:*:linux:*:*')])),
                          'fixture', 'app', '1.2.3')
        self.assertEqual(result['matches'], [])
        self.assertEqual(len(result['review']), 4)

    def test_rejected_duplicate_and_cancelled(self):
        rejected = record(1, [entry()])
        rejected['cve']['vulnStatus'] = 'Rejected'
        self.assertEqual(evaluate(feed(rejected), 'fixture', 'app', '1.2.3')['matches'], [])
        with self.assertRaises(ValueError):
            evaluate(feed(record(2, [entry()]), record(2, [entry()])), 'fixture', 'app', '1.2.3')
        cancel = Event()
        cancel.set()
        with self.assertRaises(InterruptedError):
            evaluate(feed(record(1, [entry()])), 'fixture', 'app', '1.2.3', cancel)

    def test_local_feed_result_has_no_unverified_risk_rating(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.json'
            path.write_text(json.dumps(feed(record(1, [entry()]))), encoding='utf-8')
            result = assess(path, 'fixture', 'app', '1.2.3')
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['findings'][0]['severity'], 'info')
            self.assertEqual(len(result['coverage']['feed_sha256']), 64)
            self.assertNotIn(str(path), str(result))
