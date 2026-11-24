"""Synthetic local-only HTTP fixture. Never binds to a public interface."""
from http.server import BaseHTTPRequestHandler, HTTPServer
class Demo(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','text/html; charset=utf-8')
        if self.path == '/fixed':
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'")
            self.send_header('Referrer-Policy','no-referrer')
        self.end_headers()
        self.wfile.write(b'<!doctype html><title>Sentinel local fixture</title><h1>Synthetic local test page</h1>')
if __name__ == '__main__':
    print('Local fixture: http://127.0.0.1:8765/  (Ctrl+C to stop)')
    HTTPServer(('127.0.0.1',8765),Demo).serve_forever()
