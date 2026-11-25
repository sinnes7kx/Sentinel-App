import unittest
from threading import Event

from sentinel.tools.backends import Backend, docker_cleanup, local_docker_prefix
from sentinel.tools.runner import RunResult
from sentinel.tools import whatweb


class DockerLifecycleTests(unittest.TestCase):
    def test_local_endpoints_are_explicit(self):
        self.assertEqual(local_docker_prefix('nt'), ['docker', '--host', 'npipe:////./pipe/docker_engine'])
        self.assertEqual(local_docker_prefix('posix'), ['docker', '--host', 'unix:///var/run/docker.sock'])

    def test_auto_removed_container_is_verified(self):
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append((argv, cancel))
            return RunResult(1, '', 'No such container') if argv[3] == 'rm' else RunResult(0, '', '')
        self.assertTrue(docker_cleanup(local_docker_prefix(), 'sentinel-fixture', invoke))
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(cancel is None for _, cancel in calls))
        self.assertIn('name=^/sentinel-fixture$', calls[1][0])

    def test_uncertain_cleanup_is_not_verified(self):
        for output in (RunResult(0, 'sentinel-fixture', ''), RunResult(1, '', ''),
                       RunResult(None, '', '', timed_out=True), RunResult(0, '', '', truncated=True)):
            with self.subTest(output=output):
                def invoke(argv, timeout, cancel):
                    return output if argv[3] == 'container' else RunResult(0, '', '')
                self.assertFalse(docker_cleanup(local_docker_prefix(), 'sentinel-fixture', invoke))

    def test_unverified_cleanup_cannot_report_complete(self):
        def invoke(argv, timeout, cancel):
            if argv[3] == 'run':
                return RunResult(0, '[{"plugins":{"Apache":{}}}]', '')
            return RunResult(1, '', 'daemon unavailable')
        result = whatweb.SPEC.scan('http://127.0.0.1/', 'passive', True,
                                   backend=Backend('docker', 'sha256:' + 'a' * 64), run=invoke)
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.findings, [])
        self.assertIn('Unverified', result.coverage['container_cleanup'])
        self.assertIn('Not enforced', result.coverage['network_isolation'])

    def test_cancelled_run_still_checks_cleanup(self):
        event = Event()
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append((argv, cancel))
            if argv[3] == 'run':
                event.set()
                return RunResult(None, '', '', cancelled=True)
            return RunResult(0, '', '')
        result = whatweb.SPEC.scan('http://127.0.0.1/', 'passive', True, cancel=event,
                                   backend=Backend('docker', 'sha256:' + 'a' * 64), run=invoke)
        self.assertEqual(result.status, 'cancelled')
        self.assertEqual(result.coverage['container_cleanup'], 'Container absent at verification')
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(cancel is None for _, cancel in calls[1:]))
