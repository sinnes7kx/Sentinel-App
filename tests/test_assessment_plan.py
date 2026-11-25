import unittest
from unittest.mock import patch

from sentinel.assessment_plan import website_plan
from sentinel.readiness import Readiness
from sentinel.tools import sslscan, whatweb


def row(name, state):
    return Readiness(name, state, '')


class AssessmentPlanTests(unittest.TestCase):
    def test_quick_is_builtin_only(self):
        plan = website_plan('https://example.test', 'Quick', [])
        self.assertEqual(plan.target, 'https://example.test/')
        self.assertEqual(len(plan.steps), 1)
        self.assertEqual(plan.steps[0].engine, 'Built-in Python')

    def test_native_preferred_over_version_probe(self):
        plan = website_plan('https://192.0.2.1/', 'Standard', [
            row(sslscan.SPEC.name, 'Detected'), row('Docker / sslscan', 'Version reported'),
            row('Docker / whatweb', 'Version reported')])
        self.assertEqual(plan.steps[1].engine, 'Native candidate')
        self.assertEqual(plan.steps[2].engine, 'Docker candidate')

    def test_client_detection_is_not_a_tool_candidate(self):
        plan = website_plan('https://192.0.2.1/', 'Standard', [
            row('Docker runtime', 'Responding'), row('Prepared Docker image', 'Detected')])
        self.assertEqual(plan.steps[1].engine, 'Not available / verified')
        self.assertEqual(plan.steps[2].engine, 'Not available / verified')

    def test_hostname_external_identification_is_deferred(self):
        plan = website_plan('https://example.test/', 'Standard', [
            row(whatweb.SPEC.name, 'Detected'), row('WSL / whatweb', 'Version reported')])
        self.assertEqual(plan.steps[2].engine, 'Deferred')

    def test_local_address_does_not_recommend_other_runtime(self):
        rows = [row('Docker / sslscan', 'Version reported'), row('WSL / whatweb', 'Version reported')]
        for target in ('https://localhost/', 'https://127.0.0.1/', 'https://[::1]/'):
            with self.subTest(target=target):
                plan = website_plan(target, 'Standard', rows)
                self.assertEqual(plan.steps[1].engine, 'Not available / verified')
                self.assertIn(plan.steps[2].engine, ('Deferred', 'Not available / verified'))

    def test_http_is_not_upgraded(self):
        plan = website_plan('http://192.0.2.1/', 'Standard', [])
        self.assertEqual(plan.steps[1].engine, 'Not applicable')
        self.assertTrue(plan.target.startswith('http://'))

    def test_planning_does_not_resolve_or_connect(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
             patch('socket.create_connection', side_effect=AssertionError('Connection forbidden')):
            website_plan('https://example.test/', 'Standard', [])

    def test_invalid_url_and_profile_fail(self):
        for target in ('https://', 'https://user:secret@example.test/', 'https://example.test/?q=1'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                website_plan(target, 'Quick', [])
        with self.assertRaises(ValueError):
            website_plan('https://example.test/', 'Deep', [])
