import unittest
from threading import Event
from unittest.mock import patch
from sentinel.access_lab import demonstrate
from sentinel.finding_views import impact_note


class AccessLabTests(unittest.TestCase):
    def test_live_local_fixture_distinguishes_allowed_and_denied(self):
        result = demonstrate()
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(result['rows']), 3)
        self.assertEqual([r['weak_status'] for r in result['rows']], [200, 200, 200])
        self.assertEqual([r['protected_status'] for r in result['rows']], [200, 403, 403])
        self.assertEqual([r['protected_record_visible'] for r in result['rows']], [True, False, False])
        self.assertTrue(all(r['expected'] for r in result['rows']))

    def test_cancel_before_start_does_not_bind(self):
        cancel = Event()
        cancel.set()
        with patch('sentinel.access_lab.HTTPServer') as server:
            self.assertEqual(demonstrate(cancel)['status'], 'cancelled')
        server.assert_not_called()

    def test_impact_does_not_claim_script_execution_or_private_access(self):
        self.assertIn('does not establish', impact_note({'id': 'CSP'}))
        self.assertIn('anonymous requests', impact_note({'id': 'CORS_CREDENTIAL_REFLECTION'}))
        self.assertIn('does not establish', impact_note({'id': 'unknown'}))
