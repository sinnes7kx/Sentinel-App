import json
from pathlib import Path
import unittest

from sentinel.bola import assess_reads
from sentinel.local_tools import review_report


class ObjectReadEvidenceTests(unittest.TestCase):
    example = Path(__file__).resolve().parents[1] / 'sentinel/examples/object-reads.json'

    def assess(self, **updates):
        evidence = json.loads(self.example.read_text())
        evidence['cases'][1].update(updates)
        return assess_reads(json.dumps(evidence))

    def test_shipped_example_runs_through_local_report_path(self):
        result = review_report(self.example, 'bola')
        self.assertEqual(result['Permitted reads observed'], 1)
        self.assertEqual(result['Denied reads observed'], 1)
        self.assertEqual(result['Unauthorized disclosures'], 0)

    def test_forbidden_object_detected_even_in_error_or_mixed_response(self):
        for status in (200, 403):
            result = self.assess(http_status=status, returned_objects=['demo/invoice-2', 'demo/invoice-1'])
            self.assertEqual(result['Unauthorized disclosures'], 1)
            self.assertIn('demo/invoice-1', list(result['Case results'].values())[1])

    def test_ambiguous_evidence_never_passes(self):
        for status, observed in [(200, []), (403, None), (200, ['unknown']), (500, []), (401, [])]:
            result = self.assess(http_status=status, returned_objects=observed)
            self.assertEqual(result['Inconclusive reads'], 1)
            self.assertEqual(result['Denied reads observed'], 0)

    def test_denial_for_authorized_subject(self):
        result = self.assess(subject='demo/user-a')
        self.assertEqual(result['Permitted reads withheld'], 1)

    def test_malformed_evidence_rejected(self):
        for edits in [{'object':'unknown'}, {'http_status':True}, {'returned_objects':'invoice'},
                      {'subject':'user\nspoof'}, {'returned_objects':[None]}]:
            with self.subTest(edits=edits), self.assertRaises(ValueError):
                self.assess(**edits)
