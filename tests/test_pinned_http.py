import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from sentinel.engine import scan, compare
from sentinel.pinned_http import resolve_once


def record(address, port):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', sockaddr)


class Handler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        self.hits.append((self.path, self.headers['Host']))
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://other.invalid/elsewhere')
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def log_message(self, *args):
        pass


class PinnedHttpTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        Handler.hits.clear()
        self.port = self.server.server_port
        self.url = f'http://fixture.invalid:{self.port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_one_resolution_preserves_http_host_and_peer(self):
        # A second resolution would return a different address. It must never occur.
        with patch('socket.getaddrinfo', side_effect=[
            [record('127.0.0.1', self.port)], [record('127.0.0.2', self.port)]
        ]) as resolver:
            result = scan(self.url, True)
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.coverage['connection_address'], '127.0.0.1')
        self.assertEqual(result.coverage['resolved_addresses'], ['127.0.0.1'])
        self.assertEqual(Handler.hits, [('/', f'fixture.invalid:{self.port}')])

    def test_literal_never_resolves(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('No DNS allowed')):
            result = scan(f'http://127.0.0.1:{self.port}/', True)
        self.assertEqual(result.status, 'completed')

    def test_redirect_does_not_contact_second_hostname(self):
        with patch('socket.getaddrinfo', return_value=[record('127.0.0.1', self.port)]) as resolver:
            result = scan(self.url + '/redirect', True)
        self.assertEqual(result.http_status, 302)
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(len(Handler.hits), 1)
        self.assertNotIn('other.invalid', str(result.to_dict()))

    def test_no_dns_without_permission(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('No DNS allowed')):
            with self.assertRaises(PermissionError):
                scan(self.url)

    def test_mixed_public_local_answers_fail_without_connecting(self):
        with patch('socket.getaddrinfo', return_value=[
            record('8.8.8.8', self.port), record('127.0.0.1', self.port)
        ]), patch('socket.socket', side_effect=AssertionError('No connection allowed')):
            result = scan(self.url, True)
        self.assertEqual(result.status, 'failed')
        self.assertEqual(Handler.hits, [])

    def test_unsupported_endpoints_are_rejected(self):
        for host in ('0.0.0.0', '::', '224.0.0.1', '169.254.169.254',
                     '::ffff:169.254.169.254', 'fe80::1%3'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                resolve_once(host, 80)

    def test_cancel_after_resolution_prevents_connection(self):
        cancel = threading.Event()
        def resolver(*args):
            cancel.set()
            return [record('127.0.0.1', self.port)]
        with patch('socket.getaddrinfo', side_effect=resolver), \
             patch('socket.socket', side_effect=AssertionError('No connection allowed')):
            result = scan(self.url, True, cancel=cancel)
        self.assertEqual(result.status, 'cancelled')

    def test_retest_rejects_different_or_unknown_connection_address(self):
        result = scan(f'http://127.0.0.1:{self.port}/', True).to_dict()
        changed = dict(result, coverage=dict(result['coverage'], connection_address='127.0.0.2'))
        self.assertFalse(compare(result, changed)['comparable'])
        self.assertFalse(compare(result, dict(result, coverage={}))['comparable'])
        self.assertTrue(compare(result, result)['comparable'])
