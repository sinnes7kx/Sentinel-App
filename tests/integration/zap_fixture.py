"""Synthetic web page for passive ZAP integration tests only."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/':
            self.send_response(404)
            self.end_headers()
            return
        page = b'<!doctype html><html><head><title>Sentinel test fixture</title></head><body>Fixture</body></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=UTF-8')
        self.send_header('Content-Length', str(len(page)))
        # Deliberately omit CSP and X-Content-Type-Options in this fixture.
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *_):
        pass


if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1', 8080), Handler)
    print('SENTINEL_ZAP_FIXTURE_READY', flush=True)
    server.serve_forever()
