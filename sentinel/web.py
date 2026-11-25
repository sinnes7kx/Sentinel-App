"""Loopback browser interface for Sentinel's website checks and report review."""
import argparse
from contextlib import closing
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.util import find_spec
import json
from pathlib import Path
import sqlite3
from threading import Lock
import webbrowser

from .dnscheck import domain_name
from .engine import Target, scan
from .report import html_report
from .review import MAX_REPORT, summarize
from .store import Store


ASSETS = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/app.css': ('app.css', 'text/css; charset=utf-8'),
    '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
}
PROJECT = 'My website'


class Dashboard(ThreadingHTTPServer):
    def __init__(self, port=0, database=None):
        super().__init__(('127.0.0.1', port), DashboardHandler)
        self.authority = f'127.0.0.1:{self.server_port}'
        self.origin = 'http://' + self.authority
        self.database = database
        self.assessment_lock = Lock()

    def store(self):
        return closing(Store(self.database))


class DashboardHandler(BaseHTTPRequestHandler):
    timeout = 8

    def log_message(self, *_):
        # File names, history IDs and targets do not belong in access logs.
        return

    def reply(self, body, content_type, status=HTTPStatus.OK, filename=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        if filename:
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def json_reply(self, value, status=HTTPStatus.OK, filename=None):
        self.reply(json.dumps(value).encode('ascii'), 'application/json', status, filename)

    def error(self, message, status):
        self.json_reply({'error': message}, status)

    def allowed(self, write=False):
        if (self.headers.get_all('Host') != [self.server.authority]
                or self.headers.get('Sec-Fetch-Site') == 'cross-site'
                or (write and self.headers.get_all('Origin') != [self.server.origin])):
            self.error('Open Sentinel using the local address printed in the terminal.', HTTPStatus.FORBIDDEN)
            return False
        return True

    def read_body(self, mime, limit):
        lengths = self.headers.get_all('Content-Length', [])
        if (self.headers.get_content_type() != mime or self.headers.get('Transfer-Encoding')
                or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                or len(lengths[0]) > 9):
            raise ValueError('Unsupported request format.')
        size = int(lengths[0])
        if not 0 < size <= limit:
            raise ValueError(f'Choose a nonempty file or request of at most {limit:,} bytes.')
        body = self.rfile.read(size)
        if len(body) != size:
            raise ValueError('Incomplete request.')
        return body

    def do_GET(self):
        if not self.allowed():
            return
        try:
            if self.path in ASSETS:
                filename, mime = ASSETS[self.path]
                self.reply(Path(__file__).with_name('web_ui').joinpath(filename).read_bytes(), mime)
            elif self.path == '/api/options':
                self.json_reply({'dns': find_spec('dns') is not None})
            elif self.path == '/api/history':
                with self.server.store() as store:
                    history = store.history(store.project(PROJECT), limit=20)
                self.json_reply([
                    {'id': scan_id, 'target': result['target'], 'started': result['started'], 'status': result['status']}
                    for scan_id, result in history
                ])
            elif self.path.startswith('/api/history/'):
                self.history_result(self.path.removeprefix('/api/history/'))
            else:
                self.error('Page not found.', HTTPStatus.NOT_FOUND)
        except (OSError, ValueError, RuntimeError, sqlite3.Error):
            self.error('Sentinel could not load this page or assessment.', HTTPStatus.INTERNAL_SERVER_ERROR)

    def history_result(self, route):
        scan_id, _, export = route.partition('/')
        if not scan_id.isascii() or not scan_id.isdecimal() or len(scan_id) > 18 or export not in ('', 'html', 'json'):
            self.error('Assessment not found.', HTTPStatus.NOT_FOUND)
            return
        with self.server.store() as store:
            result = store.result(store.project(PROJECT), int(scan_id))
        if result is None:
            self.error('Assessment not found.', HTTPStatus.NOT_FOUND)
        elif export == 'html':
            self.reply(html_report(result).encode('utf-8'), 'text/html; charset=utf-8', filename='sentinel-report.html')
        else:
            self.json_reply(result, filename='sentinel-report.json' if export else None)

    def do_POST(self):
        if not self.allowed(write=True):
            return
        try:
            if self.path == '/api/assessment':
                self.assess(json.loads(self.read_body('application/json', 8192)))
            elif self.path.startswith('/api/review/'):
                tool = self.path.removeprefix('/api/review/')
                self.json_reply(summarize(tool, self.read_body('application/octet-stream', MAX_REPORT)))
            else:
                self.error('Page not found.', HTTPStatus.NOT_FOUND)
        except (UnicodeError, RecursionError, json.JSONDecodeError):
            self.error('Sentinel could not read this request.', HTTPStatus.BAD_REQUEST)
        except ValueError as exc:
            self.error(str(exc), HTTPStatus.BAD_REQUEST)
        except (OSError, RuntimeError, sqlite3.Error):
            self.error('Sentinel could not complete this request.', HTTPStatus.INTERNAL_SERVER_ERROR)

    def assess(self, request):
        if not isinstance(request, dict) or request.get('authorized') is not True:
            self.error('Confirm you have permission to check this website and any selected domain.', HTTPStatus.FORBIDDEN)
            return
        url, dns = request.get('url'), request.get('dns', '')
        if not isinstance(url, str) or not isinstance(dns, str):
            raise ValueError('Enter a website URL and, if selected, a DNS domain.')
        target = Target.parse(url)
        dns = domain_name(dns) if dns else ''
        if target.host == '127.0.0.1' and target.port == self.server.server_port:
            raise ValueError('Enter the address of the website you want to check.')
        if not self.server.assessment_lock.acquire(blocking=False):
            self.error('An assessment is already running.', HTTPStatus.CONFLICT)
            return
        try:
            result = scan(target.url, authorized=True, dns_domain=dns).to_dict()
            with self.server.store() as store:
                scan_id = store.save(store.project(PROJECT), result)
            self.json_reply({'id': scan_id, 'result': result})
        finally:
            self.server.assessment_lock.release()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Start the local Sentinel browser dashboard.')
    parser.add_argument('--no-browser', action='store_true', help='Print the local address without opening a browser.')
    args = parser.parse_args(argv)
    with Dashboard() as server:
        print(f'Sentinel is ready at {server.origin}/. Press Ctrl+C to stop.', flush=True)
        if not args.no_browser:
            webbrowser.open(server.origin + '/')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
