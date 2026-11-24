"""Real Tk -> shared worker -> loopback HTTP -> SQLite integration."""
import os
import tempfile
import threading
import time
import tkinter as tk
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from sentinel.app import App
from sentinel.store import Store
from sentinel.tools_window import ToolsWindow


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def log_message(self, *args):
        pass


class ApplicationTests(unittest.TestCase):
    def test_shared_scheduler_actual_http_history_and_scope_reset(self):
        try:
            probe = tk.Tk(); probe.destroy()
        except tk.TclError:
            if os.environ.get('SENTINEL_REQUIRE_GUI'):
                raise
            self.skipTest('Tk/Tcl display unavailable')
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                with patch('sentinel.app.Store', side_effect=lambda: Store(Path(directory)/'history.sqlite3')):
                    app = App()
                app.withdraw()
                try:
                    tools = ToolsWindow(app); tools.withdraw()
                    self.assertIs(tools.orchestrator, app.orchestrator)
                    tools.auth.set(True); tools.target.set('127.0.0.1')
                    self.assertFalse(tools.auth.get())
                    timer = tools.poll_timer
                    tools.destroy()
                    self.assertNotIn(timer, app.tk.call('after', 'info'))
                    app.url.set(f'http://127.0.0.1:{server.server_port}/')
                    app.auth.set(True); app.run()
                    deadline = time.monotonic() + 6
                    while app.busy and time.monotonic() < deadline:
                        app.update(); time.sleep(.01)
                    self.assertFalse(app.busy)
                    records = app.store.history(app.store.project(app.project.get()))
                    self.assertEqual(records[0][1]['status'], 'completed')
                    self.assertEqual([e['state'] for e in records[0][1]['events']], ['queued', 'running', 'completed'])
                finally:
                    app.cancel_event.set(); app.orchestrator.shutdown(); app.store.close(); app.destroy()
                    app.orchestrator.worker.join(3)
        finally:
            server.shutdown(); server.server_close(); thread.join()
