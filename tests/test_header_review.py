import unittest

from sentinel.engine import Target, compare
from sentinel.header_review import header_observations
from sentinel.retest_review import review


class HeaderReviewTests(unittest.TestCase):
    def findings(self, *headers, status=200, scheme='https', html=True):
        fields = [('Content-Type', 'text/html')] if html else []
        return header_observations(Target.parse(scheme + '://example.test/'), status,
                                   fields + list(headers))

    def test_empty_policy_and_framing_conflict(self):
        findings = self.findings(('Content-Security-Policy', ' ; '),
                                 ('X-Frame-Options', 'DENY'),
                                 ('X-Frame-Options', 'SAMEORIGIN'))
        self.assertEqual({f.id for f in findings}, {'CSP_EMPTY', 'FRAME_HEADER_CONFLICT'})

    def test_duplicate_directive_and_unrecognized_frame_value(self):
        findings = self.findings(('Content-Security-Policy', "default-src 'self'; DEFAULT-SRC https://private.example"),
                                 ('X-Frame-Options', 'ALLOW-FROM https://private.example'))
        self.assertEqual({f.id for f in findings}, {'CSP_DUP_DIRECTIVE', 'FRAME_HEADER_SYNTAX'})
        self.assertNotIn('private.example', str(findings))

    def test_separate_policies_not_duplicate(self):
        self.assertEqual(self.findings(('Content-Security-Policy', "default-src 'self', default-src 'none'"),
                                       ('X-Frame-Options', 'DENY, DENY'),
                                       ('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')), [])

    def test_hsts_conflicts_and_scope(self):
        fields = (('Strict-Transport-Security', 'max-age=31536000; max-age=invalid'),
                  ('Strict-Transport-Security', 'max-age=0'))
        self.assertEqual({f.id for f in self.findings(*fields, html=False)},
                         {'HSTS_MULTIPLE', 'HSTS_AGE_SYNTAX'})
        self.assertEqual(self.findings(*fields, scheme='http'), [])
        self.assertEqual(self.findings(('Strict-Transport-Security', 'max-age="31536000"')), [])

    def test_html_only_checks(self):
        fields = (('Content-Security-Policy', ''), ('X-Frame-Options', 'invalid'))
        self.assertEqual(self.findings(*fields, html=False), [])
        self.assertEqual(self.findings(*fields, status=302), [])
        self.assertEqual(self.findings(('Content-Security-Policy-Report-Only', '')), [])

    def test_coverage_change_rejects_comparison(self):
        old = {'target':'https://example.test/', 'profile':'web-v2', 'status':'completed',
               'http_status':200, 'coverage':{'http':'completed', 'tls':'verified connection',
                                             'connection_address':'192.0.2.1', 'resolved_addresses':['192.0.2.1'],
                                             'cookie_ruleset':'cookie-review-v1'}, 'findings':[]}
        new = dict(old, coverage=dict(old['coverage'], header_ruleset='header-review-v1'))
        self.assertFalse(compare(old, new)['comparable'])
        self.assertFalse(review(old, new).comparable)
        self.assertTrue(compare(new, new)['comparable'])
        self.assertTrue(review(new, new).comparable)
