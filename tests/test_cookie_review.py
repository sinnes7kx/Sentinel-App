import unittest
from sentinel.cookie_review import cookie_observations
from sentinel.engine import compare
from sentinel.retest_review import review


class CookieReviewTests(unittest.TestCase):
    def findings(self, *cookies):
        return cookie_observations([('Set-Cookie', c) for c in cookies])

    def test_prefix_rules_and_redaction(self):
        findings = self.findings('__Host-private-name=private-token; Secure; Domain=private-domain; Path=/',
                                 '__Secure-private-name=another-token; SameSite=Lax')
        self.assertEqual({f.id for f in findings}, {'COOKIE_HOST_PREFIX', 'COOKIE_SECURE_PREFIX'})
        for secret in ('private-name', 'private-token', 'private-domain', 'another-token'):
            self.assertNotIn(secret, str(findings))

    def test_correct_prefixes_and_samesite(self):
        self.assertEqual(self.findings('__Host-session=value; Secure; Path=/; SameSite=Lax',
                                       '__Secure-token=value; Secure; SameSite=None',
                                       'ordinary=value; Path=/; SameSite=Strict'), [])

    def test_invalid_and_duplicate_attributes(self):
        findings = self.findings('a=x; SameSite=unknown', 'b=x; SameSite=',
                                 'c=x; Path=/; Path=/other; SameSite=Lax; SameSite=Strict')
        by_id = {f.id: f for f in findings}
        self.assertEqual(set(by_id), {'COOKIE_DUP_ATTR', 'COOKIE_INVALID_SAMESITE'})
        self.assertTrue(by_id['COOKIE_INVALID_SAMESITE'].evidence.startswith('2 '))
        self.assertTrue(by_id['COOKIE_DUP_ATTR'].evidence.startswith('1 '))

    def test_host_prefix_path_and_domain(self):
        findings = self.findings('__Host-a=x; Secure',
                                 '__host-b=x; Secure; Path=/other',
                                 '__Host-c=x; Secure; Path=/; Domain=',
                                 '__Host-d=x; Path=/')
        self.assertTrue(findings[0].evidence.startswith('4 '))

    def test_rule_coverage_change_rejects_comparison(self):
        old = {'target':'https://example.test/', 'profile':'web-v2', 'status':'completed',
               'http_status':200, 'coverage':{'http':'completed', 'tls':'verified connection',
                                              'connection_address':'192.0.2.1', 'resolved_addresses':['192.0.2.1']},
               'findings':[]}
        new = dict(old, coverage=dict(old['coverage'], cookie_ruleset='cookie-review-v1'))
        self.assertFalse(compare(old, new)['comparable'])
        self.assertFalse(review(old, new).comparable)
        self.assertTrue(compare(new, new)['comparable'])
        self.assertTrue(review(new, new).comparable)
