"""Synthetic HTTP/TLS fixture. Runs only on the lab container's loopback."""
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = 'SentinelFixture/1.0'
    sys_version = ''

    def do_GET(self):
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://127.0.0.1:8081/forbidden')
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('X-Powered-By', 'PHP/7.4.3')
        self.end_headers()
        if self.path != '/redirect':
            self.wfile.write(b'<html><title>Sentinel fixture</title></html>')

    def log_message(self, *_):
        pass


class RedirectTrap(BaseHTTPRequestHandler):
    def do_GET(self):
        print('UNEXPECTED_REDIRECT', flush=True)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_):
        pass


def main():
    servers = [ThreadingHTTPServer(('127.0.0.1', 8080), Handler),
               ThreadingHTTPServer(('127.0.0.1', 8081), RedirectTrap),
               ThreadingHTTPServer(('127.0.0.1', 8443), Handler)]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain('/fixture/cert.pem', '/fixture/key.pem')
    servers[2].socket = context.wrap_socket(servers[2].socket, server_side=True)
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print('SENTINEL_FIXTURE_READY', flush=True)
    threading.Event().wait()


if __name__ == '__main__':
    main()
