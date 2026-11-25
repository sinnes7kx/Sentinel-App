import html
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from unittest.mock import Mock
from sentinel.live_input import inspect_input


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        parsed = urlsplit(self.path)
        self.server.hits.append((parsed.path, bool(self.headers.get('Cookie')),
                                 bool(self.headers.get('Authorization'))))
        if parsed.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/trap')
            self.end_headers()
            return
        value = parse_qs(parsed.query).get('q', [''])[0]
        text = html.escape(value) if parsed.path == '/safe' else (
            'no reflection' if parsed.path == '/none' else value)
        body = ('<html><body>' + text + '</body></html>').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LiveInputTests(unittest.TestCase):
    def test_no_network_without_authorization_or_after_cancel(self):
        resolver = Mock()
        with self.assertRaises(PermissionError):
            inspect_input('http://fixture.invalid/', 'q', resolver=resolver)
        cancel = threading.Event()
        cancel.set()
        self.assertEqual(inspect_input('http://fixture.invalid/', 'q', True,
                                      cancel, resolver=resolver)['status'], 'cancelled')
        resolver.assert_not_called()

    def test_live_responses_and_no_redirect_or_credentials(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        server.hits = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            root = 'http://127.0.0.1:' + str(server.server_port)
            for path, verdict in (('/weak', 'Raw markup reflected'),
                                  ('/safe', 'Encoded marker observed'),
                                  ('/none', 'No exact reflection observed')):
                result = inspect_input(root + path, 'q', True)
                self.assertEqual(result['status'], 'completed')
                self.assertEqual(result['verdict'], verdict)
                self.assertEqual(result['requests'], 2)
                self.assertNotIn('sentinel-', str(result))
            result = inspect_input(root + '/redirect', 'q', True)
            self.assertEqual(result['requests'], 1)
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(server.hits, [(path, False, False) for path in
                             ('/weak', '/weak', '/safe', '/safe', '/none', '/none', '/redirect')])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
