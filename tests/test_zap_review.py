import json
import tempfile
import unittest
from pathlib import Path

from sentinel.zap_review import parse_report, detail_summary, MAX_BYTES, MAX_ALERTS
from sentinel.local_tools import review_report


def fixture(alerts):
    return json.dumps({'site': [{'name': 'https://fixture.invalid/', 'alerts': alerts}]}).encode()


def alert(**kw):
    return dict({'pluginid': '10038', 'alert': 'CSP missing', 'riskcode': '2',
                 'confidence': '2', 'solution': '<p>Set an appropriate CSP.</p>',
                 'instances': [{'uri': 'https://fixture.invalid/?token=private-fixture',
                                'evidence': 'PRIVATE-RAW-EVIDENCE', 'requestHeader': 'PRIVATE-HEADER'}]}, **kw)


class ZapReviewTests(unittest.TestCase):
    def test_reported_risk_confidence_and_remediation(self):
        report = parse_report(fixture([alert()]))
        row = report['alerts'][0]
        self.assertEqual((row['id'], row['severity'], row['confidence'], row['instances']),
                         ('ZAP_10038', 'medium', 'medium', 1))
        self.assertEqual(row['remediation'], 'Set an appropriate CSP.')
        self.assertFalse(report['truncated'])

    def test_no_raw_instance_data(self):
        result = str(detail_summary(fixture([alert()])))
        for marker in ('private-fixture', 'PRIVATE-RAW-EVIDENCE', 'PRIVATE-HEADER', 'fixture.invalid'):
            self.assertNotIn(marker, result)
        self.assertIn('Not a new scan', result)

    def test_unknown_codes_not_promoted(self):
        row = parse_report(fixture([alert(pluginid='invalid', riskcode='9', confidence='9')]))['alerts'][0]
        self.assertEqual((row['id'], row['severity'], row['confidence']), ('ZAP_unknown', 'unknown', 'unknown'))

    def test_bounded_details_preserve_total(self):
        report = parse_report(fixture([alert()] * (MAX_ALERTS + 1)))
        self.assertEqual(report['alert_count'], MAX_ALERTS + 1)
        self.assertEqual(len(report['alerts']), MAX_ALERTS)
        self.assertTrue(report['truncated'])

    def test_invalid_reports(self):
        for raw in (b'', b'{}', b'not json', b'x' * (MAX_BYTES + 1),
                    fixture([None]), fixture([alert(instances='invalid')])):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                parse_report(raw)

    def test_local_report_route(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'zap.json'
            path.write_bytes(fixture([alert()]))
            rows = review_report(path, 'zap-detail')
            self.assertEqual(rows['Alert types reported'], 1)
            self.assertIn('CSP missing', str(rows))
            self.assertEqual(review_report(path, 'zap')['Medium'], 1)
