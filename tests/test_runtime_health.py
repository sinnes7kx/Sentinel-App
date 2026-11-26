import unittest
from threading import Event
from sentinel.runtime_health import diagnostics
from sentinel.tools.backends import Backend
from sentinel.tools.runner import RunResult

IMAGE = 'sha256:' + 'a' * 64


class RuntimeHealthTests(unittest.TestCase):
    def test_cancel_before_start_never_launches(self):
        cancel = Event()
        cancel.set()
        def fail(*args):
            self.fail('Unexpected subprocess')
        result = diagnostics(cancel, invoke=fail, which=lambda n: n,
                             preference=lambda: Backend(), platform='nt')
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(result['rows'], [])

    def test_docker_client_is_not_runtime(self):
        result = diagnostics(Event(), invoke=lambda *args: RunResult(1, '', 'private error'),
                             which=lambda n: n if n == 'docker' else None,
                             preference=lambda: Backend(), platform='nt')
        self.assertEqual(result['rows'][0]['state'], 'Unverified')
        self.assertNotIn('private error', str(result))

    def test_prepared_docker_version_probes_are_isolated(self):
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            if 'version' in argv:
                return RunResult(0, 'linux 28.0.1', '')
            if 'inspect' in argv:
                return RunResult(0, IMAGE, '')
            if 'run' in argv:
                return RunResult(0, 'Version: 2.1.2', '')
            return RunResult(0, '', '')
        result = diagnostics(Event(), invoke=invoke, which=lambda n: n if n == 'docker' else None,
                             preference=lambda: Backend('docker', IMAGE), platform='nt')
        runs = [a for a in calls if 'run' in a]
        self.assertEqual(len(runs), 2)
        self.assertEqual(len([a for a in calls if 'rm' in a]), 2)
        for argv in runs:
            self.assertIn('--network=none', argv)
            self.assertIn('--pull=never', argv)
            self.assertIn('--cap-drop=ALL', argv)
            self.assertEqual(argv[-1], '--version')
            self.assertIn('npipe:////./pipe/docker_engine', argv)
        self.assertEqual(sum(r['state'] == 'Version reported' for r in result['rows']), 2)
        self.assertFalse(any(r['state'] == 'Ready' for r in result['rows']))

    def test_missing_image_is_not_launched(self):
        calls = []
        def invoke(argv, *_):
            calls.append(argv)
            return RunResult(0, 'linux 28.0.1', '') if 'version' in argv else RunResult(1, '', '')
        result = diagnostics(Event(), invoke=invoke, which=lambda n: n if n == 'docker' else None,
                             preference=lambda: Backend('docker', IMAGE), platform='nt')
        self.assertFalse(any('run' in a for a in calls))
        self.assertEqual(result['rows'][1]['state'], 'Unverified')

    def test_wsl_uses_prepared_distribution_and_fixed_commands(self):
        calls = []
        def invoke(argv, *_):
            calls.append(argv)
            if '--list' in argv:
                return RunResult(0, 'K\x00a\x00l\x00i\x00\r\x00\n\x00', '')
            return RunResult(0, 'unrecognized output', '')
        result = diagnostics(Event(), invoke=invoke, which=lambda n: n if n == 'wsl.exe' else None,
                             preference=lambda: Backend('wsl', 'Kali'), platform='nt')
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1][1:4], ['--distribution', 'Kali', '--exec'])
        self.assertTrue(all('timeout' in a and a[-1] == '--version' for a in calls[1:]))
        self.assertEqual(sum(r['state'] == 'Unverified' for r in result['rows']), 2)

    def test_cancellation_cleans_up_container(self):
        event = Event()
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append((argv, cancel))
            if 'version' in argv:
                return RunResult(0, 'linux 28.0.1', '')
            if 'inspect' in argv:
                return RunResult(0, IMAGE, '')
            if 'run' in argv:
                event.set()
                return RunResult(None, '', '', cancelled=True)
            return RunResult(0, '', '')
        result = diagnostics(event, invoke=invoke, which=lambda n: n,
                             preference=lambda: Backend('docker', IMAGE), platform='nt')
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(len([a for a, _ in calls if 'run' in a]), 1)
        self.assertEqual(calls[-1][0][-3:-1], ['rm', '--force'])
        self.assertIsNone(calls[-1][1])
