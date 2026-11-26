import unittest
from threading import Event
from unittest.mock import Mock

from sentinel.tool_selfcheck import check_installation, check_zap_installation
from sentinel.zap_setup import ZAP_REPOSITORY
from sentinel.tools.backends import Backend
from sentinel.tools.runner import RunResult

IMAGE = 'sha256:' + 'a' * 64


class InstallationTests(unittest.TestCase):
    def run_check(self, invoke, cancel=None, saved=None):
        return check_installation(cancel or Event(), invoke=invoke,
                                  which=lambda _: 'docker', platform='nt',
                                  preference=lambda: saved or Backend('docker', IMAGE))

    def test_success_and_fixed_offline_arguments(self):
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            command = argv[3]
            if command == 'version':
                return RunResult(0, 'linux', '')
            if command == 'image':
                return RunResult(0, IMAGE, '')
            if command == 'run':
                self.assertIn('--network=none', argv)
                self.assertIn('--pull=never', argv)
                self.assertIn('--cap-drop=ALL', argv)
                self.assertEqual(argv[-2:], [IMAGE, '--version'])
                return RunResult(0, 'Version: 2.1.2', '')
            return RunResult(0, '', '')
        result = self.run_check(invoke)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual([r['state'] for r in result['rows']], ['Version verified'] * 2)
        self.assertEqual([a[3] for a in calls], ['version', 'image', 'run', 'rm', 'container', 'run', 'rm', 'container'])

    def test_cleanup_failure_stops_remaining_checks(self):
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            return RunResult(1, '', '') if argv[3] == 'container' else RunResult(0, {'version':'linux', 'image':IMAGE, 'run':'2.1.2'}.get(argv[3], ''), '')
        result = self.run_check(invoke)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['rows'][0]['state'], 'Unverified')
        self.assertEqual(sum(a[3] == 'run' for a in calls), 1)

    def test_unprepared_and_missing_image_never_launch(self):
        invoke = Mock()
        result = self.run_check(invoke, saved=Backend('wsl', 'Kali'))
        self.assertEqual(result['status'], 'partial')
        invoke.assert_not_called()
        calls = []
        def missing(argv, *_):
            calls.append(argv)
            return RunResult(0, 'linux', '') if argv[3] == 'version' else RunResult(1, '', '')
        self.assertEqual(self.run_check(missing)['status'], 'partial')
        self.assertEqual([a[3] for a in calls], ['version', 'image'])

    def test_cancellation_during_run_still_cleans_up(self):
        cancel = Event()
        calls = []
        def invoke(argv, timeout, event):
            calls.append((argv[3], event))
            if argv[3] == 'run':
                cancel.set()
                return RunResult(None, '', '', cancelled=True)
            return RunResult(0, {'version':'linux', 'image':IMAGE}.get(argv[3], ''), '')
        result = self.run_check(invoke, cancel)
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(calls[-2:], [('rm', None), ('container', None)])


class ZapInstallationTests(unittest.TestCase):
    def check(self, invoke, which=lambda _: 'docker', cancel=None):
        return check_zap_installation(cancel or Event(), invoke=invoke, which=which, platform='nt')

    def test_missing_image_never_downloads(self):
        calls = []
        def invoke(argv, *_):
            calls.append(argv)
            return RunResult(0, 'linux', '') if argv[3] == 'version' else RunResult(1, '', 'missing')
        result = self.check(invoke)
        self.assertEqual(result['status'], 'partial')
        self.assertIn('no download', result['message'])
        self.assertEqual([a[3] for a in calls], ['version', 'image'])

    def test_existing_image_verified_without_download(self):
        calls = []
        def invoke(argv, *_):
            calls.append(argv)
            if argv[3] == 'version':
                return RunResult(0, 'linux', '')
            if argv[3] == 'image':
                return RunResult(0, IMAGE + ' ' + ZAP_REPOSITORY + '@sha256:' + 'b' * 64, '')
            if argv[3] == 'run':
                self.assertIn('--network=none', argv)
                self.assertIn('--pull=never', argv)
                self.assertEqual(argv[-3:], [IMAGE, 'zap.sh', '-version'])
                return RunResult(0, '2.17.1', '')
            return RunResult(0, '', '')
        result = self.check(invoke)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['rows'][0]['state'], 'Version verified')
        self.assertEqual([a[3] for a in calls], ['version', 'image', 'run', 'rm', 'container'])

    def test_missing_docker_and_cancel_never_launch(self):
        invoke = Mock()
        self.assertEqual(self.check(invoke, which=lambda _: None)['status'], 'partial')
        cancel = Event()
        cancel.set()
        self.assertEqual(self.check(invoke, cancel=cancel)['status'], 'cancelled')
        invoke.assert_not_called()
