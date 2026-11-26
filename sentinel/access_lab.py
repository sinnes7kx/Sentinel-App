"""Local-only access control demonstration using disposable synthetic records.

The server is created by Sentinel, binds to IPv4 loopback on a random port,
and is closed after each demonstration. No arbitrary URL, credentials,
payload input, external services or real user records are supported.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.client import HTTPConnection
from threading import Event, Thread
from secrets import token_hex
import json


def demonstrate(cancel=None):
    cancel = cancel if cancel is not None else Event()
    results = []
    # Ephemeral identifiers used only by this internal fixture.
    alice, bob = token_hex(16), token_hex(16)
    marker = token_hex(12)

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path not in ('/example/weak', '/example/protected'):
                self.send_error(404)
                return
            session = self.headers.get('X-Lab-Session')
            allowed = self.path == '/example/weak' or session == alice
            body = json.dumps({'example': marker} if allowed else {'denied': True}).encode()
            self.send_response(200 if allowed else 403)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    if cancel.is_set():
        return {'status': 'cancelled', 'rows': []}

    def request(port, path, session):
        conn = HTTPConnection('127.0.0.1', port, timeout=2)
        try:
            conn.request('GET', path, headers={'X-Lab-Session': session} if session else {})
            response = conn.getresponse()
            data = response.read(1024)
            return response.status, json.loads(data).get('example') == marker
        finally:
            conn.close()

    with HTTPServer(('127.0.0.1', 0), Fixture) as server:
        thread = Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        thread.start()
        try:
            for label, session in (('Record owner', alice), ('Different test user', bob),
                                   ('Not signed in', None)):
                if cancel.is_set():
                    break
                weak = request(server.server_port, '/example/weak', session)
                if cancel.is_set():
                    break
                protected = request(server.server_port, '/example/protected', session)
                expected = (200, True) if session == alice else (403, False)
                results.append({'scenario': label, 'weak_status': weak[0],
                                'weak_record_visible': weak[1], 'protected_status': protected[0],
                                'protected_record_visible': protected[1],
                                'expected': weak == (200, True) and protected == expected})
        finally:
            server.shutdown()
            thread.join(timeout=3)
    status = 'cancelled' if cancel.is_set() else (
        'completed' if len(results) == 3 and all(row['expected'] for row in results) else 'partial')
    return {'status': status, 'rows': results}
