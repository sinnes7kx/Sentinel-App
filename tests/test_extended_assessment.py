import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock

from sentinel.engine import Scan
from sentinel.extended_assessment import extended_scan


class ExtendedTests(unittest.TestCase):
    def base(self):
        return Scan('http://fixture.invalid/', '2026-01-01', 'completed', 200, None, [],
                    coverage={'http': 'completed', 'connection_address': '127.0.0.1',
                              'resolved_addresses': ['127.0.0.1']})

    def test_authorization_before_any_contact(self):
        base = Mock()
        probe = Mock()
        with self.assertRaises(PermissionError):
            extended_scan('http://fixture.invalid/', base_scan=base, probe=probe)
        base.assert_not_called()
        probe.assert_not_called()

    def test_missing_peer_never_probes(self):
        base = self.base()
        base.coverage['resolved_addresses'] = []
        probe = Mock()
        result = extended_scan(base.target, True, base_scan=Mock(return_value=base), probe=probe)
        self.assertEqual(result.status, 'partial')
        probe.assert_not_called()

    def test_changed_status_is_inconclusive(self):
        base = self.base()
        probe = Mock(return_value=(302, True, True))
        result = extended_scan(base.target, True, base_scan=Mock(return_value=base), probe=probe)
        self.assertEqual(result.coverage['cors_review']['status'], 'inconclusive')
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.findings, [])
        probe.assert_called_once()

    def test_cancel_stops_after_first_probe(self):
        base = self.base()
        cancel = threading.Event()
        def probe(*args):
            cancel.set()
            return (200, True, True)
        result = extended_scan(base.target, True, cancel=cancel,
                               base_scan=Mock(return_value=base), probe=probe)
        self.assertEqual(result.status, 'cancelled')
        self.assertEqual(result.coverage['cors_review']['requests_attempted'], 1)
        self.assertEqual(result.findings, [])


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        origin = self.headers.get('Origin')
        self.server.hits.append((self.path, bool(self.headers.get('Cookie')),
                                 bool(self.headers.get('Authorization'))))
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        if origin and self.path == '/reflect':
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Credentials', 'true')
        elif origin and self.path == '/restricted':
            self.send_header('Access-Control-Allow-Origin', 'https://trusted.invalid')
        self.end_headers()

    def log_message(self, *args):
        pass


class RealHTTPTests(unittest.TestCase):
    def test_same_path_anonymous_and_restricted_policy(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.hits = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f'http://127.0.0.1:{server.server_port}'
            reflected = extended_scan(base + '/reflect', True)
            restricted = extended_scan(base + '/restricted', True)
            self.assertEqual(reflected.profile, 'web-extended-v1')
            self.assertEqual(reflected.coverage['cors_review']['credentialed_reflections'], 2)
            self.assertIn('CORS_CREDENTIAL_REFLECTION', {f.id for f in reflected.findings})
            self.assertNotIn('CORS_CREDENTIAL_REFLECTION', {f.id for f in restricted.findings})
            self.assertEqual(restricted.coverage['cors_review']['reflected_origins'], 0)
            self.assertEqual(server.hits, [('/reflect', False, False)] * 3 +
                                         [('/restricted', False, False)] * 3)
            self.assertNotIn('trusted.invalid', str(restricted.to_dict()))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
