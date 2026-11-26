import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from sentinel.engine import Scan
from sentinel.standard_assessment import standard_scan


class StandardTests(unittest.TestCase):
    def base(self, status='completed', tls='TLSv1.3'):
        return Scan('https://fixture.invalid/', '2026-01-01', status, 200, tls, [],
                    coverage={'connection_address': '127.0.0.1',
                              'resolved_addresses': ['127.0.0.1', '127.0.0.2']})

    def test_authorization_before_base_scan(self):
        base = Mock()
        with self.assertRaises(PermissionError):
            standard_scan('https://fixture.invalid/', base_scan=base)
        base.assert_not_called()

    def test_uses_same_peer_and_reuses_initial_negotiation(self):
        probe = Mock(return_value='verified negotiation')
        result = standard_scan('https://fixture.invalid/', True,
                               base_scan=Mock(return_value=self.base()), probe=probe)
        self.assertEqual(result.profile, 'web-standard-v1')
        self.assertEqual(result.status, 'completed')
        probe.assert_called_once()
        target, endpoint, version, _ = probe.call_args.args
        self.assertEqual(target.host, 'fixture.invalid')
        self.assertEqual(endpoint.address, '127.0.0.1')
        self.assertEqual(endpoint.port, 443)
        self.assertEqual(version, 'TLSv1_2')
        self.assertIn('initial connection', result.coverage['additional_tls']['TLSv1_3'])

    def test_inconclusive_negotiation_is_not_disabled(self):
        result = standard_scan('https://fixture.invalid/', True,
                               base_scan=Mock(return_value=self.base()),
                               probe=Mock(return_value='inconclusive'))
        self.assertEqual(result.status, 'partial')
        self.assertEqual(result.coverage['additional_tls']['TLSv1_2'], 'inconclusive')

    def test_no_followup_after_initial_failure(self):
        probe = Mock()
        result = standard_scan('https://fixture.invalid/', True,
                               base_scan=Mock(return_value=self.base('failed')), probe=probe)
        self.assertEqual(result.status, 'failed')
        probe.assert_not_called()

    def test_no_followup_for_http(self):
        probe = Mock()
        result = standard_scan('http://fixture.invalid/', True,
                               base_scan=Mock(return_value=self.base(tls=None)), probe=probe)
        self.assertEqual(result.coverage['additional_tls']['status'], 'not applicable (HTTP URL)')
        probe.assert_not_called()

    def test_missing_snapshot_blocks_followup(self):
        base = self.base()
        base.coverage['resolved_addresses'] = ['127.0.0.2']
        probe = Mock()
        result = standard_scan('https://fixture.invalid/', True,
                               base_scan=Mock(return_value=base), probe=probe)
        self.assertEqual(result.status, 'partial')
        probe.assert_not_called()

    def test_cancel_stops_followup(self):
        cancel = threading.Event()
        cancel.set()
        probe = Mock()
        result = standard_scan('https://fixture.invalid/', True, cancel,
                               base_scan=Mock(return_value=self.base()), probe=probe)
        self.assertEqual(result.status, 'cancelled')
        probe.assert_not_called()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which('openssl'), 'openssl required for local TLS fixture')
class RealTLS(unittest.TestCase):
    def test_tls12_only_local_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory)/'cert.pem', Path(directory)/'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                            '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '2',
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                           check=True, capture_output=True, timeout=30)
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            make_context = ssl.create_default_context
            try:
                with patch('ssl.create_default_context', side_effect=lambda: make_context(cafile=str(cert))):
                    result = standard_scan(f'https://localhost:{server.server_port}/', True)
                self.assertEqual(result.http_status, 200)
                self.assertEqual(result.coverage['connection_address'], '127.0.0.1')
                self.assertIn('verified negotiation', result.coverage['additional_tls']['TLSv1_2'])
                self.assertEqual(result.coverage['additional_tls']['TLSv1_3'], 'inconclusive')
                self.assertEqual(result.status, 'partial')
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
