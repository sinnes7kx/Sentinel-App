import io
import json
from pathlib import Path
from queue import Queue
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from sentinel.orchestration import Orchestrator
from sentinel.evidence import sanitize
from sentinel.store import Store
from sentinel.logging_setup import MetadataFormatter
from sentinel.tools import nmap, whatweb
from sentinel.tools.base import execute
from sentinel.tools.backends import Backend
from sentinel.tools.runner import run, RunResult
from sentinel.engine import Target

XML = '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="23"><state state="open"/></port></ports></host></nmaprun>'


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.engine = Orchestrator(pending=1)
        self.results = Queue()
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()
        self.engine.shutdown()
        self.engine.worker.join(3)
        self.assertFalse(self.engine.worker.is_alive())

    def submit(self, operation, cancel=None):
        return self.engine.submit(operation, lambda result, error: self.results.put((result, error)), cancel)

    def hold_worker(self):
        started = threading.Event()
        def operation():
            started.set()
            self.release.wait(3)
            return {'status': 'completed'}
        job = self.submit(operation)
        self.assertTrue(started.wait(2))
        return job

    def test_serial_queue_bound_and_cancel_before_execution(self):
        first = self.hold_worker()
        called = []
        second = self.submit(lambda: called.append(True))
        with self.assertRaises(RuntimeError):
            self.submit(lambda: None)
        second.cancel.set()
        self.release.set()
        self.results.get(timeout=3)
        _, error = self.results.get(timeout=3)
        self.assertEqual(called, [])
        self.assertEqual(second.state, 'cancelled')
        self.assertEqual(first.state, 'completed')
        self.assertIn('cancelled', error)

    def test_result_is_redacted_with_real_progress_events(self):
        self.submit(lambda: {'status': 'completed', 'evidence': 'password=not-public'})
        result, error = self.results.get(timeout=3)
        self.assertIsNone(error)
        self.assertNotIn('not-public', json.dumps(result))
        self.assertEqual([e['state'] for e in result['events']], ['queued', 'running', 'completed'])
        self.assertEqual(len(result['job_id']), 32)

    def test_cancellation_cannot_be_overwritten_by_success(self):
        job = self.hold_worker()
        job.cancel.set()
        self.release.set()
        result, _ = self.results.get(timeout=3)
        self.assertEqual(result['status'], 'cancelled')

    def test_shutdown_cancels_all_and_rejects_new_work(self):
        first = self.hold_worker()
        second = self.submit(lambda: None)
        self.engine.shutdown()
        self.assertTrue(first.cancel.is_set())
        self.assertTrue(second.cancel.is_set())
        with self.assertRaises(RuntimeError):
            self.submit(lambda: None)

    def test_exception_text_is_not_exposed(self):
        def fail():
            raise ValueError('secret credentials')
        self.submit(fail)
        result, error = self.results.get(timeout=3)
        self.assertIsNone(result)
        self.assertNotIn('secret credentials', error)
        self.assertIn('ValueError', error)


class EvidenceTests(unittest.TestCase):
    def test_nested_secrets_and_private_key(self):
        source = {'password': 'a', 'items': ['https://u:secret@host/', 'token=hunter2&x=1',
                  'Authorization: Bearer hidden\nOK', '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----']}
        result = json.dumps(sanitize(source))
        for secret in ('hunter2', 'Bearer hidden', 'u:secret', '\\nsecret'):
            self.assertNotIn(secret, result)
        self.assertEqual(source['password'], 'a')
        self.assertEqual(sanitize(source)['password'], '[REDACTED]')

    def test_store_preserves_old_records_and_redacts_new_and_loaded_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'history.sqlite3'
            store = Store(path)
            project = store.project('Example')
            result = {'target': '127.0.0.1', 'started': '2026-01-01', 'evidence': 'password=hidden'}
            scan_id = store.save(project, result)
            self.assertNotIn('hidden', store.conn.execute('SELECT result FROM scans').fetchone()[0])
            store.close()
            store = Store(path)
            self.assertEqual(store.history(project)[0][0], scan_id)
            store.close()

    def test_logs_only_contain_allowlisted_metadata(self):
        import logging
        record = logging.LogRecord('sentinel', 20, '', 1, 'token=hidden', (), None)
        record.job_id = 'abc'; record.state = 'running'
        result = json.loads(MetadataFormatter().format(record))
        self.assertEqual(set(result), {'time', 'level', 'job_id', 'state'})
        self.assertNotIn('hidden', json.dumps(result))

    def test_dependency_history_uses_shared_schema_and_hash_scope(self):
        from sentinel.dependencies import assess
        from sentinel.dependency_result import scan_record
        result = scan_record(assess('examples/dependencies/requirements.txt', 'examples/dependencies/advisories-synthetic.json'))
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(result['target'].startswith('inventory-sha256:'))
        self.assertEqual(result['findings'][0]['source'], 'local-dependencies')
        self.assertEqual(result['findings'][0]['severity'], 'info')


class ExecutionTests(unittest.TestCase):
    def test_no_resolution_without_authorization_or_after_cancel(self):
        resolver = unittest.mock.Mock(side_effect=AssertionError('DNS must not run'))
        with self.assertRaises(PermissionError):
            execute(nmap.SPEC, 'test.invalid', 'quick', resolver=resolver)
        cancel = threading.Event(); cancel.set()
        result = execute(nmap.SPEC, 'test.invalid', 'quick', True, cancel=cancel, resolver=resolver)
        self.assertEqual(result.status, 'cancelled')
        resolver.assert_not_called()

    def test_hostname_is_pinned_to_approved_address(self):
        calls = []
        def invoke(argv, *args):
            calls.append(argv)
            return RunResult(0, XML, '')
        result = execute(nmap.SPEC, 'test.invalid', 'quick', True, resolver=lambda h: ['127.0.0.1'], run=invoke, binary='nmap')
        self.assertEqual(calls[0][-1], '127.0.0.1')
        self.assertEqual(result.target, 'test.invalid')
        self.assertEqual(result.findings[0].confidence, 'low')

    def test_nonzero_and_truncation_never_report_complete(self):
        for response in (RunResult(2, XML, ''), RunResult(0, XML, '', truncated=True)):
            result = execute(nmap.SPEC, '127.0.0.1', 'quick', True, run=lambda *args: response, binary='nmap')
            self.assertEqual(result.status, 'partial')

    def test_whatweb_does_not_follow_redirects(self):
        argv = whatweb.build('whatweb', Target.parse('http://127.0.0.1/'), 'passive', 'out.json')
        self.assertIn('--follow-redirect=never', argv)
        self.assertIn('--max-threads=1', argv)

    def test_real_subprocess_output_bound(self):
        with patch('sentinel.tools.runner.MAX_OUTPUT', 1000):
            result = run([sys.executable, '-c', 'import sys; sys.stdout.write("x"*10000); sys.stderr.write("y"*10000)'], 10)
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.stdout), 1000)
        self.assertEqual(len(result.stderr), 1000)

    def test_real_running_subprocess_cancellation(self):
        cancel = threading.Event()
        timer = threading.Timer(.3, cancel.set)
        timer.start()
        try:
            result = run([sys.executable, '-c', 'import time; time.sleep(30)'], 10, cancel)
            self.assertTrue(result.cancelled)
            self.assertIsNotNone(result.returncode)
        finally:
            timer.cancel()


class BackendTests(unittest.TestCase):
    def test_configuration_rejects_unknown_tools_and_mutable_images(self):
        for backend, tool in ((Backend('bad'), 'nmap'), (Backend('docker', 'latest'), 'nmap'),
                              (Backend('wsl', '--exec'), 'nmap'), (Backend('wsl', 'Ubuntu'), 'nikto')):
            with self.assertRaises(ValueError):
                backend.validate(tool)

    def test_docker_limits_paths_and_cleanup(self):
        backend = Backend('docker', 'example/tool@sha256:' + 'a'*64)
        backend.validate('sslscan')
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            return RunResult(0, '', '')
        backend.run(['sslscan', '--xml=C:\\Temp\\job\\out.xml', '127.0.0.1:443'], 30, None, 'C:\\Temp\\job', invoke)
        self.assertIn('--xml=/work/out.xml', calls[0])
        for flag in ('--pull=never', '--memory=512m', '--cpus=1', '--cap-drop=ALL'):
            self.assertIn(flag, calls[0])
        self.assertEqual(calls[1][:3], ['docker', 'rm', '--force'])
        self.assertEqual(calls[1][-1], calls[0][calls[0].index('--name')+1])

    def test_docker_cleanup_even_if_launcher_fails(self):
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            if len(calls) == 1:
                raise OSError('launcher error')
            return RunResult(0, '', '')
        with self.assertRaises(OSError):
            Backend('docker', 'x').run(['nmap', '127.0.0.1'], 1, None, '/tmp/job', invoke)
        self.assertEqual(len(calls), 2)

    def test_wsl_uses_exec_fixed_distribution_and_remote_deadline(self):
        calls = []
        def invoke(argv, timeout, cancel):
            calls.append(argv)
            return RunResult(0, '', '')
        Backend('wsl', 'Ubuntu').run(['sslscan', '--xml=C:\\Temp\\job\\out.xml', '127.0.0.1:443'], 30, None, 'C:\\Temp\\job', invoke)
        self.assertEqual(calls[0][:5], ['wsl.exe', '--distribution', 'Ubuntu', '--exec', 'timeout'])
        self.assertIn('--xml=/mnt/c/Temp/job/out.xml', calls[0])


if __name__ == '__main__':
    unittest.main()
