import copy
import unittest

from sentinel.retest_review import review, review_text


def finding(rule, **kw):
    return dict({'id': rule, 'source': 'sentinel', 'title': rule, 'severity': 'low',
                 'confidence': 'medium', 'evidence': 'Observed', 'remediation': 'Review'}, **kw)


def result(findings=(), **kw):
    return dict({'target': 'https://fixture.invalid/', 'profile': 'web-v2',
                 'dns_domain': '', 'status': 'completed', 'http_status': 200,
                 'coverage': {'http': 'completed', 'tls': 'verified connection',
                              'connection_address': '127.0.0.1',
                              'resolved_addresses': ['127.0.0.1']},
                 'findings': list(findings)}, **kw)


class RetestReviewTests(unittest.TestCase):
    def test_states_and_original_evidence(self):
        before = result([finding('A'), finding('B'), finding('C')])
        after = result([finding('A'), finding('B', evidence='Changed'), finding('D')])
        original = copy.deepcopy((before, after))
        output = review(before, after)
        self.assertTrue(output.comparable)
        states = {c.rule: c.state for c in output.changes}
        self.assertEqual(states, {'A': 'Still observed', 'B': 'Still observed — evidence changed',
                                  'C': 'Not observed on retest', 'D': 'Newly observed'})
        self.assertIn('does not prove remediation', review_text(output))
        self.assertIn('Changed', review_text(output))
        self.assertEqual((before, after), original)

    def test_no_cross_source_merging(self):
        out = review(result([finding('A')]), result([finding('A', source='other')]))
        self.assertEqual(len(out.changes), 2)
        self.assertEqual({c.state for c in out.changes}, {'Newly observed', 'Not observed on retest'})

    def test_ambiguous_variants_remain_separate(self):
        out = review(result([finding('A'), finding('A', evidence='Different')]), result([finding('A')]))
        self.assertEqual(out.changes[0].state, 'Multiple variants — review manually')
        self.assertEqual(len(out.changes[0].previous), 2)

    def test_exact_repeats_do_not_create_variants(self):
        out = review(result([finding('A'), finding('A')]), result([finding('A')]))
        self.assertEqual(out.changes[0].state, 'Still observed')

    def test_scope_and_coverage_fail_closed(self):
        before = result([finding('A')])
        for after in (result(target='https://other.invalid/'), result(profile='web-standard-v1'),
                      result(profile='sslscan-standard'), result(dns_domain='fixture.invalid'),
                      result(status='partial'), result(status='cancelled'), result(http_status=302),
                      result(coverage={}), result(coverage=dict(before['coverage'], connection_address='127.0.0.2',
                                                               resolved_addresses=['127.0.0.2'])),
                      result(coverage=dict(before['coverage'], http='unknown'))):
            with self.subTest(after=after):
                out = review(before, after)
                self.assertFalse(out.comparable)
                self.assertFalse(out.changes)

    def test_missing_provenance_blocks_comparison(self):
        f = finding('A')
        del f['source']
        self.assertFalse(review(result([f]), result()).comparable)

    def test_empty_results_do_not_certify_security(self):
        self.assertIn('not proof of security', review_text(review(result(), result())))

    def test_priority_and_redaction(self):
        before = result([finding('low'), finding('high', severity='high', evidence='password=secret-value')])
        out = review(before, result())
        self.assertEqual(out.changes[0].rule, 'high')
        self.assertNotIn('secret-value', review_text(out))
