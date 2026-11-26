import unittest
from threading import Event
from unittest.mock import Mock

from sentinel.setup_recovery import recovery
from sentinel.tool_setup import setup
from sentinel.tools.runner import RunResult


class SetupRecoveryTests(unittest.TestCase):
    def test_restart_required_propagates_through_recommended_setup(self):
        result = setup('all', Event(), platform='nt', find_nmap=lambda: False,
                       install=Mock())
        self.assertEqual(result['next_action'], 'restart_app')
        self.assertEqual(recovery(result).heading, 'Restart Sentinel')
        self.assertFalse(recovery(result).retry)

    def test_docker_requires_start(self):
        result = setup('toolkit', Event(), platform='nt', find_docker=lambda: 'docker',
                       invoke=Mock(return_value=RunResult(1, '', 'not running')))
        advice = recovery(result)
        self.assertEqual(advice.heading, 'Start Docker Desktop')
        self.assertTrue(advice.retry)

    def test_cancelled_health_check_not_reported_as_docker_failure(self):
        cancel = Event()
        def invoke(*args):
            cancel.set()
            return RunResult(None, '', '', cancelled=True)
        result = setup('docker', cancel, platform='nt', find_docker=lambda: 'docker', invoke=invoke)
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(recovery(result).heading, 'Setup stopped')

    def test_success_and_unknown_failure(self):
        self.assertFalse(recovery({'status': 'completed'}).retry)
        self.assertTrue(recovery({'status': 'failed'}).retry)
        self.assertEqual(recovery({'status': 'partial', 'next_action': 'restore_files'}).heading,
                         'Restore Sentinel files')
