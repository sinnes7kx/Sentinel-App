import unittest
from threading import Event
from unittest.mock import Mock

from sentinel.zap_setup import prepare_zap, ZAP_IMAGE, ZAP_REPOSITORY
from sentinel.tools.runner import RunResult

PREFIX = ['docker', '--host', 'npipe:////./pipe/docker_engine']
ID = 'sha256:' + 'a' * 64
DIGEST = ZAP_REPOSITORY + '@sha256:' + 'b' * 64


class ZapSetupTests(unittest.TestCase):
    def fake(self, missing=False, bad_cleanup=False, version='2.17.0'):
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            self.assertEqual(argv[:3], PREFIX)
            command = argv[3]
            if command == 'image':
                if missing and len(calls) == 1:
                    return RunResult(1, '', 'missing')
                return RunResult(0, ID + ' ' + DIGEST, '')
            if command == 'pull':
                self.assertEqual(argv[4:], [ZAP_IMAGE])
                return RunResult(0, '', '')
            if command == 'run':
                for flag in ('--network=none', '--pull=never', '--cap-drop=ALL'):
                    self.assertIn(flag, argv)
                self.assertEqual(argv[-3:], [ID, 'zap.sh', '-version'])
                return RunResult(0, version, '')
            if command == 'rm':
                return RunResult(0, '', '')
            if command == 'container':
                return RunResult(1 if bad_cleanup else 0, '', '')
            raise AssertionError(argv)
        return calls, invoke

    def test_reuses_local_upstream_image_and_checks_version(self):
        calls, invoke = self.fake()
        result = prepare_zap(PREFIX, Event(), invoke)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['zap_image'], ID)
        self.assertEqual(result['zap_version'], '2.17.0')
        self.assertEqual([c[3] for c in calls], ['image', 'run', 'rm', 'container'])

    def test_missing_image_downloads_only_fixed_upstream(self):
        calls, invoke = self.fake(missing=True)
        result = prepare_zap(PREFIX, Event(), invoke)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual([c[3] for c in calls], ['image', 'pull', 'image', 'run', 'rm', 'container'])

    def test_unverified_image_never_executes(self):
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            return RunResult(0, ID + ' other/repository@sha256:' + 'b' * 64, '')
        self.assertEqual(prepare_zap(PREFIX, Event(), invoke)['status'], 'partial')
        self.assertEqual([c[3] for c in calls], ['image', 'pull', 'image'])

    def test_cleanup_or_version_failure_is_partial(self):
        for options in ({'bad_cleanup': True}, {'version': 'not a version'}):
            with self.subTest(options=options):
                _, invoke = self.fake(**options)
                self.assertEqual(prepare_zap(PREFIX, Event(), invoke)['status'], 'partial')

    def test_cancel_before_download(self):
        cancel = Event()
        cancel.set()
        invoke = Mock()
        self.assertEqual(prepare_zap(PREFIX, cancel, invoke)['status'], 'cancelled')
        invoke.assert_not_called()

    def test_refresh_checks_upstream_even_when_local_image_exists(self):
        calls, invoke = self.fake()
        result = prepare_zap(PREFIX, Event(), invoke, refresh=True)
        self.assertEqual(result['status'], 'completed')
        self.assertIn('Image unchanged.', result['message'])
        self.assertEqual([c[3] for c in calls], ['image', 'pull', 'image', 'run', 'rm', 'container'])

    def test_refresh_failure_never_claims_success_or_runs_old_image(self):
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            return RunResult(0, ID + ' ' + DIGEST, '') if argv[3] == 'image' else RunResult(1, '', 'failed')
        result = prepare_zap(PREFIX, Event(), invoke, refresh=True)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual([c[3] for c in calls], ['image', 'pull'])

    def test_refresh_detects_changed_image(self):
        updated = 'sha256:' + 'd' * 64
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            if argv[3] == 'image':
                return RunResult(0, (ID if len(calls) == 1 else updated) + ' ' + DIGEST, '')
            if argv[3] == 'run':
                self.assertEqual(argv[-3], updated)
                return RunResult(0, '2.17.1', '')
            return RunResult(0, '', '')
        result = prepare_zap(PREFIX, Event(), invoke, refresh=True)
        self.assertEqual(result['status'], 'completed')
        self.assertIn('Image changed.', result['message'])
        self.assertEqual(result['zap_image'], updated)
