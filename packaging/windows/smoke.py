"""Exercise the installed Windows desktop against loopback-only fixtures."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time

# Use the application and dependencies from the per-user installation.
install = Path(sys.executable).resolve().parents[1]
sys.path.insert(0, str(install))
from sentinel.app import App
from sentinel.tools_window import ToolsWindow
from sentinel.tools import sslscan, whatweb


class Handler(BaseHTTPRequestHandler):
    server_version = 'SentinelFixture/1.0'

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><title>Sentinel fixture</title></html>')

    def log_message(self, *args):
        pass


def finish(app, window):
    deadline = time.monotonic() + 90
    while window.busy and time.monotonic() < deadline:
        app.update()
        time.sleep(.02)
    assert not window.busy, 'Desktop operation timed out'


def check():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ['LOCALAPPDATA'] = tmp
        cert, key = [str(Path(tmp) / name) for name in ('cert.pem', 'key.pem')]
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '7',
                        '-subj', '/CN=localhost', '-keyout', key, '-out', cert], check=True, capture_output=True)
        app = App()
        try:
            window = ToolsWindow(app)
            assert window.backend.get() == 'native' and window.tool.id == 'whatweb'
            for tool, scheme, profile in [(whatweb.SPEC, 'http', 'passive'), (sslscan.SPEC, 'https', 'standard')]:
                with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
                    if scheme == 'https':
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        context.load_cert_chain(cert, key)
                        server.socket = context.wrap_socket(server.socket, server_side=True)
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    try:
                        window.tool_name.set(tool.name)
                        window.tool_changed()
                        window.profile.set(profile)
                        window.target.set(f'{scheme}://127.0.0.1:{server.server_port}/')
                        window.auth.set(True)
                        window.start()
                        finish(app, window)
                        result = window.result
                        assert result and result['status'] == 'completed', window.detail.get('1.0', 'end')
                        findings = result['findings']
                        if tool.id == 'sslscan':
                            assert any(f['id'] == 'CERT_SELF_SIGNED' for f in findings), findings
                        else:
                            assert any('SentinelFixture' in f['evidence'] for f in findings), findings
                        print(tool.id, 'completed through native desktop', flush=True)
                    finally:
                        server.shutdown()
                        thread.join()
            utilities = window.open_bola()
            source = install / 'sentinel/examples/object-reads.json'
            evidence = json.loads(source.read_text())
            evidence['cases'][1].update(http_status=200, returned_objects=['demo/invoice-1'])
            sample = Path(tmp) / 'bola-fixture.json'
            sample.write_text(json.dumps(evidence))
            utilities.bola_path.set(str(sample))
            utilities.start_bola()
            finish(app, utilities)
            assert 'Unauthorized disclosures  1' in utilities.bola_output.get('1.0', 'end')
            print('Object-read policy violation identified through installed desktop')
        finally:
            app.close()


if __name__ == '__main__':
    check()
