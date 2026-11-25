import unittest
from threading import Event
from unittest.mock import Mock

from sentinel.verified_setup import prepare_verified
from sentinel.tools.backends import Backend

IMAGE = 'sha256:' + 'a' * 64
PREPARED = {'status': 'completed', 'backend': 'docker', 'environment': IMAGE, 'message': 'Prepared'}


class VerifiedSetupTests(unittest.TestCase):
    def test_uses_prepared_image_for_offline_verification(self):
        cancel = Event()
        prepare = Mock(return_value=PREPARED)
        verify = Mock(return_value={'status': 'completed', 'rows': [], 'message': 'Passed'})
        result = prepare_verified('toolkit', cancel, prepare=prepare, verify=verify)
        prepare.assert_called_once_with('toolkit', cancel)
        verify.assert_called_once()
        self.assertIs(verify.call_args.args[0], cancel)
        self.assertEqual(verify.call_args.kwargs['preference'](), Backend('docker', IMAGE))
        self.assertEqual(result['status'], 'completed')
        self.assertIn('offline version checks passed', result['message'])

    def test_verification_failure_is_not_success(self):
        result = prepare_verified('all', Event(), prepare=Mock(return_value=PREPARED),
                                  verify=Mock(return_value={'status': 'partial', 'rows': [], 'message': 'Failed'}))
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['environment'], IMAGE)
        self.assertEqual(result['next_action'], 'retry')

    def test_cancel_after_preparation_stops_verification(self):
        cancel = Event()
        cancel.set()
        verify = Mock()
        result = prepare_verified('toolkit', cancel, prepare=Mock(return_value=PREPARED), verify=verify)
        self.assertEqual(result['status'], 'cancelled')
        verify.assert_not_called()

    def test_other_setup_and_incomplete_preparation_are_unchanged(self):
        verify = Mock()
        for kind, outcome in [('zap', PREPARED), ('nmap', {'status': 'completed'}),
                              ('toolkit', {'status': 'partial'})]:
            self.assertEqual(prepare_verified(kind, Event(), prepare=Mock(return_value=outcome),
                                              verify=verify), outcome)
        verify.assert_not_called()
