import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock

from sentinel.site_map import map_site, Page, linked_page
from sentinel.engine import Target


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.hits.append(self.path)
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/trap')
            self.end_headers()
            return
        body = ({
            '/': '<a href="/about">About</a><a href="/redirect">Redirect</a>'
                 '<a href="/logout">Log out</a><a href="/search?q=x">Query</a>'
                 '<a href="https://example.invalid/">External</a>',
            '/about': '<a href="/">Home</a><form><input name="q" value="secret">'
                      '<input type="hidden" name="token" value="secret"></form>',
        }.get(self.path, '')).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SiteMapTests(unittest.TestCase):
    def test_public_links_and_form_summary(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        server.hits = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = map_site('http://127.0.0.1:' + str(server.server_port) + '/', True)
            self.assertEqual(server.hits, ['/', '/about', '/redirect'])
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['rows'][1]['parent'], '/')
            self.assertEqual(result['rows'][1]['forms'], 1)
            self.assertEqual(result['rows'][1]['inputs'], ['q'])
            self.assertNotIn('secret', str(result))
            self.assertEqual(result['rows'][2]['http'], 302)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_authorization_and_cancellation_precede_resolution(self):
        resolver = Mock()
        with self.assertRaises(PermissionError):
            map_site('https://example.invalid/', resolver=resolver)
        cancel = threading.Event()
        cancel.set()
        self.assertEqual(map_site('https://example.invalid/', True, cancel,
                                  resolver=resolver)['status'], 'cancelled')
        resolver.assert_not_called()

    def test_scope_and_parser_limits(self):
        root = Target.parse('https://example.invalid/')
        for href in ('http://example.invalid/a', 'https://example.invalid:444/a',
                     '//other.invalid/a', '/a?q=1', '/a%2fb', '/file.zip', '/logout'):
            self.assertIsNone(linked_page(root, root, href))
        self.assertEqual(linked_page(root, root, '/about#section').path, '/about')
        parser = Page()
        parser.feed('<form><input name="q" type><input name="password" type="password"></form>')
        self.assertEqual(parser.inputs, {'q'})
