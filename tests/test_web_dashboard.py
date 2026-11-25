import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

from sentinel.web import Dashboard


class FixturePage(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def log_message(self, *_):
        pass


class DashboardTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dashboard = self.start_server(Dashboard(database=Path(directory.name) / 'test.sqlite3'))
        self.fixture = self.start_server(ThreadingHTTPServer(('127.0.0.1', 0), FixturePage))
        self.target = f'http://127.0.0.1:{self.fixture.server_port}/'

    def start_server(self, server):
        self.addCleanup(server.server_close)
        thread = Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02})
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        return server

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.dashboard.server_port, timeout=3)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def post(self, path, body, mime='application/json', origin=None):
        return self.request('POST', path, body, {
            'Content-Type': mime,
            'Origin': origin or self.dashboard.origin,
        })

    def test_assessment_history_and_exports(self):
        status, page = self.request('GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(b'Run assessment', page)
        payload = json.dumps({'url': self.target, 'authorized': True})
        status, raw = self.post('/api/assessment', payload)
        self.assertEqual(status, 200, raw)
        run = json.loads(raw)
        self.assertEqual(run['result']['http_status'], 200)
        self.assertTrue(any(f['id'] == 'HTTP' for f in run['result']['findings']))
        status, raw = self.request('GET', '/api/history')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)[0]['id'], run['id'])
        route = f"/api/history/{run['id']}"
        self.assertEqual(json.loads(self.request('GET', route + '/json')[1]), run['result'])
        self.assertIn(b'Observed evidence', self.request('GET', route + '/html')[1])

    def test_checks_origin_host_and_explicit_authorization(self):
        payload = json.dumps({'url': self.target, 'authorized': True})
        status, _ = self.post('/api/assessment', payload, origin='https://unrelated.example')
        self.assertEqual(status, 403)
        status, _ = self.post('/api/assessment', json.dumps({'url': self.target, 'authorized': 'true'}))
        self.assertEqual(status, 403)
        status, _ = self.request('GET', '/api/history', headers={'Host': 'unrelated.example'})
        self.assertEqual(status, 403)
        self.assertEqual(self.request('GET', '/api/history'), (200, b'[]'))

    def test_summarizes_exports_and_rejects_unexpected_xml_declarations(self):
        samples = {
            'zap': (b'{"site":[{"alerts":[{"riskcode":"1"}]}]}', 'Low'),
            'nmap': ((Path(__file__).parent / 'fixtures' / 'real_nmap_7.94.xml').read_bytes(), 'Hosts in report'),
            'wireshark': (b'"No.","Protocol","Info"\r\n"1","TCP","sample, packet"\r\n', 'Top protocols'),
        }
        for tool, (body, expected) in samples.items():
            with self.subTest(tool=tool):
                status, raw = self.post('/api/review/' + tool, body, 'application/octet-stream')
                self.assertEqual(status, 200, raw)
                self.assertIn(expected, json.loads(raw))
        status, _ = self.post('/api/review/nmap', b'<!DOCTYPE nmaprun SYSTEM "file.xml"><nmaprun scanner="nmap"/>',
                              'application/octet-stream')
        self.assertEqual(status, 400)
        self.assertEqual(self.request('GET', '/api/history'), (200, b'[]'))
