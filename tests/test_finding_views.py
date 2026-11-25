import copy
import unittest

from sentinel.finding_views import finding_views, findings_summary, finding_detail
from sentinel.report import html_report


def finding(**changes):
    return dict({'id': 'EXAMPLE', 'title': 'Example observation', 'severity': 'low',
                 'confidence': 'medium', 'source': 'fixture',
                 'evidence': 'Observed response', 'remediation': 'Review configuration'},
                **changes)


class FindingViewTests(unittest.TestCase):
    def test_exact_repeats_group_without_mutating_saved_record(self):
        f = finding()
        result = {'findings': [f, dict(f), finding(severity='high')]}
        before = copy.deepcopy(result)
        views = finding_views(result)
        self.assertEqual([(v.index, v.occurrences) for v in views], [(2, 1), (0, 2)])
        self.assertEqual(result, before)
        self.assertEqual(findings_summary(result), {
            'observations': 3, 'distinct': 2, 'exact_repeats': 1,
            'severity': {'critical': 0, 'high': 1, 'medium': 0, 'low': 1, 'info': 0, 'unknown': 0}})

    def test_conflicting_evidence_or_source_stays_separate(self):
        rows = [finding(), finding(source='other'), finding(evidence='Different response'),
                finding(confidence='high'), finding(remediation='Different fix'),
                finding(location='/other')]
        self.assertEqual(len(finding_views({'findings': rows})), len(rows))

    def test_priority_does_not_promote_confidence(self):
        rows = [finding(severity='info', confidence='high'),
                finding(severity='critical', confidence='low')]
        views = finding_views({'findings': rows})
        self.assertEqual(views[0].finding['confidence'], 'low')
        self.assertIn('independent confirmation', finding_detail(views[0]))

    def test_legacy_records_and_unknown_risk(self):
        f = finding(severity='unrated')
        del f['confidence']
        del f['source']
        result = {'findings': [f]}
        self.assertIn('legacy', finding_detail(finding_views(result)[0]))
        self.assertEqual(findings_summary(result)['severity']['unknown'], 1)

    def test_empty_assessment(self):
        self.assertEqual(finding_views({'findings': []}), [])
        self.assertEqual(findings_summary({'findings': []})['distinct'], 0)

    def test_evidence_redaction_and_html_escaping(self):
        f = finding(title='<script>fixture</script>', evidence='password=hidden-value')
        result = {'target': 'http://fixture.invalid/', 'started': '2026-01-01',
                  'status': 'partial', 'http_status': 200, 'tls': None, 'error': '',
                  'findings': [f, dict(f)], 'coverage': {}}
        html = html_report(result)
        self.assertIn('2 observations; 1 distinct findings; 1 identical repeats', html)
        self.assertIn('Identical observations: 2', html)
        self.assertIn('&lt;script&gt;fixture&lt;/script&gt;', html)
        self.assertNotIn('<script>', html)
        self.assertNotIn('hidden-value', html)
        self.assertNotIn('hidden-value', finding_detail(finding_views(result)[0]))
        self.assertEqual(result['findings'][0]['evidence'], 'password=hidden-value')
