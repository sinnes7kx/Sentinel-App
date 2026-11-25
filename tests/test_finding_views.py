import copy
import unittest

from sentinel.finding_views import finding_views, findings_summary, finding_detail, priority_note
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


    def test_priority_uses_reported_risk_without_promoting_confidence(self):
        f = finding(severity='critical', confidence='low')
        self.assertEqual(priority_note(f)[0], 'Review immediately')
        self.assertEqual(priority_note(finding(severity='info'))[0], 'Review context')
        self.assertEqual(priority_note(finding(severity='unrated'))[0], 'Needs classification')
        detail = finding_detail(finding_views({'findings': [f]})[0])
        self.assertIn('Review immediately', detail)
        self.assertIn('independent confirmation', detail)

    def test_report_priority_order_and_links(self):
        result = {'target':'http://fixture.invalid/', 'started':'2026-01-01',
                  'status':'completed', 'http_status':200, 'tls':None, 'error':'',
                  'coverage':{}, 'findings':[finding(title='Minor issue'), finding(title='Major issue', severity='high')]}
        before = copy.deepcopy(result)
        html = html_report(result)
        self.assertLess(html.index('href="#finding-1"'), html.index('href="#finding-0"'))
        self.assertIn('id="finding-1"', html)
        self.assertIn('id="finding-0"', html)
        self.assertIn('Review promptly', html)
        self.assertIn('Results at a glance', html)
        self.assertEqual(result, before)

    def test_incomplete_and_empty_reports_do_not_imply_security(self):
        result = {'target':'http://fixture.invalid/', 'started':'2026-01-01',
                  'status':'partial', 'http_status':None, 'tls':None, 'error':'Incomplete',
                  'coverage':{}, 'findings':[]}
        self.assertIn('Assessment incomplete.', html_report(result))
        result['status'] = 'completed'
        self.assertIn('does not establish that the target is secure', html_report(result))
        self.assertIn('No finding-specific actions recorded', html_report(result))


    def test_report_risk_classes_are_allowlisted(self):
        levels = ('critical', 'high', 'medium', 'low', 'info', 'unrated" onclick="bad')
        result = {'target': 'http://fixture.invalid/', 'started': '2026-01-01',
                  'status': 'completed', 'http_status': 200, 'tls': None, 'error': '',
                  'coverage': {}, 'findings': [finding(severity=level) for level in levels]}
        html = html_report(result)
        for level in ('critical', 'high', 'medium', 'low', 'info', 'unknown'):
            self.assertIn('class="tile risk-' + level + '"', html)
            self.assertIn('class="severity risk-' + level + '"', html)
            self.assertIn('class="risk-' + level + '"', html)
        self.assertNotIn('onclick="bad', html)
