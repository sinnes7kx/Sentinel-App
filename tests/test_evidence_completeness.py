import json
import unittest

from sentinel.tools import sslscan, whatweb


class EvidenceCompletenessTests(unittest.TestCase):
    def test_whatweb_rejects_missing_records(self):
        for output in ('[]', '{}', '[{"target":"fixture"}]', '[null]'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                whatweb.parse_json(output)

    def test_whatweb_marks_capped_findings(self):
        plugins = {f'Fixture{i}': {'string': ['present']} for i in range(45)}
        findings, coverage, note = whatweb.parse_json(json.dumps([{'plugins': plugins}]))
        self.assertEqual(len(findings), 40)
        self.assertEqual(coverage['technologies'], 45)
        self.assertIn('Only the first', note)

    def test_sslscan_requires_protocol_evidence(self):
        with self.assertRaises(ValueError):
            sslscan.parse_xml('<document><ssltest/></document>')

    def test_missing_protocols_not_reported_as_disabled(self):
        findings, _, note = sslscan.parse_xml(
            '<document><ssltest><protocol type="tls" version="1.0" enabled="0"/></ssltest></document>')
        self.assertNotIn('TLS_NO_MODERN', {f.id for f in findings})
        self.assertIn('incomplete', note)

    def test_missing_tls12_does_not_imply_tls12_works(self):
        findings, _, note = sslscan.parse_xml(
            '<document><ssltest><protocol type="tls" version="1.3" enabled="0"/></ssltest></document>')
        self.assertNotIn('TLS_NO_13', {f.id for f in findings})
        self.assertIn('incomplete', note)
