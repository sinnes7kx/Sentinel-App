"""Real Tk -> shared worker -> loopback HTTP -> SQLite integration."""
import gc
import hashlib
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
from sentinel.tools.backends import Backend
from sentinel.tools import TOOLS


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def log_message(self, *args):
        pass


class ApplicationTests(unittest.TestCase):
    def test_shared_scheduler_actual_http_history_and_scope_reset(self):
        # Dispose destroyed Tk objects here before a later server thread triggers GC.
        self.addCleanup(gc.collect)
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
                    app.nav_buttons['Project history'].invoke()
                    self.assertEqual(app.workspace_tabs.select(), str(app.history_page))
                    app.nav_buttons['Findings'].invoke()
                    self.assertEqual(app.workspace_tabs.select(), str(app.findings_page))
                    self.assertIn('New assessment', app.nav_buttons)
                    tools = ToolsWindow(app); tools.withdraw()
                    self.assertIs(tools.orchestrator, app.orchestrator)
                    self.assertEqual(tools.tabs.select(), str(tools.setup_page))
                    tools.tabs.select(tools.results_page)
                    self.assertEqual(tools.tabs.select(), str(tools.results_page))
                    tools.tabs.select(tools.setup_page)
                    self.assertIn('local executable', tools.engine_hint.get())
                    tools.auth.set(True); tools.target.set('127.0.0.1')
                    self.assertFalse(tools.auth.get())
                    tools.auth.set(True)
                    tools.target.set(tools.target.get())
                    self.assertTrue(tools.auth.get())
                    tools.backend.set('wsl')
                    self.assertFalse(tools.auth.get())
                    with patch('sentinel.tools_window.wsl.distributions', return_value=['kali-linux', 'Debian']):
                        tools.detect_wsl()
                        deadline = time.monotonic() + 5
                        while tools.wsl_busy and time.monotonic() < deadline:
                            app.update(); time.sleep(.01)
                    self.assertEqual(tools.environment.get(), 'kali-linux')
                    self.assertIn('2 distribution', tools.wsl_status.get())
                    with patch('sentinel.tools_window.wsl.available_tools', return_value=['timeout', 'sslscan']):
                        tools.check_wsl()
                        deadline = time.monotonic() + 5
                        while tools.wsl_busy and time.monotonic() < deadline:
                            app.update(); time.sleep(.01)
                    self.assertIn('Available — sslscan', tools.wsl_status.get())
                    self.assertIn('Missing — nmap, whatweb', tools.wsl_status.get())
                    tools.backend.set('docker')
                    tools.environment.set('fixture-image')
                    tools.backend.set('wsl')
                    self.assertEqual(tools.environment.get(), 'kali-linux')
                    tools.bundled = True
                    tools.tool_name.set(next(t.name for t in TOOLS if t.id == 'whatweb'))
                    tools.tool_changed()
                    tools.auth.set(True)
                    with patch('sentinel.tools_window.bundle.saved_backend', return_value=Backend('docker', 'sha256:' + 'a' * 64)):
                        tools.use_saved_toolkit()
                    self.assertEqual(tools.backend.get(), 'docker')
                    self.assertEqual(tools.environment.get(), 'sha256:' + 'a' * 64)
                    self.assertFalse(tools.auth.get())
                    self.assertIn('not verified', tools.wsl_status.get())
                    self.assertFalse(tools.busy)
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
                    self.assertEqual(app.assessment_count.get(), '1')
                    self.assertEqual(app.observation_count.get(), str(len(records[0][1]['findings'])))

                    self.assertEqual(app.highest.get(), 'Medium')
                    self.assertFalse(app.result_buttons[0].instate(['disabled']))
                    self.assertEqual(float(app.progress['value']), 100)
                    app.findings.selection_set(app.findings.get_children()[0])
                    app.finding_selected()
                    self.assertEqual(app.selection_title.get(), records[0][1]['findings'][0]['title'])
                    first_scan = app.current_id
                    index = int(app.findings.selection()[0])
                    app.remediation_state.set('Investigating')
                    app.save_remediation()
                    self.assertEqual(app.store.remediation(app.history_project_id, first_scan)[index]['state'], 'Investigating')
                    app.load_history(first_scan)
                    app.findings.selection_set(str(index))
                    app.finding_selected()
                    self.assertEqual(app.remediation_state.get(), 'Investigating')
                    app.nav_buttons['Project history'].invoke()
                    self.assertEqual(app.workspace_tabs.select(), str(app.history_page))
                    app.nav_buttons['Findings'].invoke()
                    self.assertEqual(app.workspace_tabs.select(), str(app.findings_page))
                    self.assertTrue(app.auth.get(), 'Unchanged scope retains explicit permission')
                    app.run()  # No second checkbox interaction.
                    deadline = time.monotonic() + 6
                    while app.busy and time.monotonic() < deadline:
                        app.update(); time.sleep(.01)
                    self.assertFalse(app.busy)
                    self.assertEqual(len(app.store.history(app.store.project(app.project.get()))), 2)
                    self.assertTrue(app.auth.get())
                    app.assessment_profile.set('Standard')
                    self.assertFalse(app.auth.get())
                    app.assessment_profile.set('Quick')
                    self.assertFalse(app.auth.get(), 'Returning to old scope must not restore permission')
                    app.auth.set(True)
                    app.dns.set('fixture.invalid')
                    self.assertFalse(app.auth.get())
                    app.dns.set('')
                    app.auth.set(True)
                    app.project.set('Another project')
                    self.assertFalse(app.auth.get())
                    app.project.set('My website')
                    app.auth.set(True)
                    app.auth.set(False)  # Explicit revocation.
                    with patch('sentinel.app.messagebox.showerror') as error:
                        app.run()
                        error.assert_called_once()
                    self.assertFalse(app.busy)
                    utilities = app.open_local_utilities()
                    utilities.withdraw()
                    self.assertIs(utilities.orchestrator, app.orchestrator)
                    fixture = Path(directory) / 'capture.csv'
                    data = b'No.,Protocol\n1,TLS\n'
                    fixture.write_bytes(data)
                    utilities.integrity_path.set(str(fixture))
                    utilities.expected_digest.set(hashlib.sha256(data).hexdigest())
                    utilities.start_integrity()
                    deadline = time.monotonic() + 5
                    while utilities.busy and time.monotonic() < deadline:
                        app.update(); time.sleep(.01)
                    self.assertIn('SHA-256 · Match', utilities.integrity_output.get('1.0', 'end'))
                    utilities.report_format.set('Wireshark · Packet-list CSV')
                    utilities.report_path.set(str(fixture))
                    utilities.start_review()
                    deadline = time.monotonic() + 5
                    while utilities.busy and time.monotonic() < deadline:
                        app.update(); time.sleep(.01)
                    self.assertIn('Packets in export  1', utilities.report_output.get('1.0', 'end'))
                    self.assertEqual(len(app.store.history(app.store.project(app.project.get()))), 2)
                finally:
                    app.cancel_event.set(); app.orchestrator.shutdown(); app.store.close(); app.destroy()
                    app.orchestrator.worker.join(3)
        finally:
            server.shutdown(); server.server_close(); thread.join()
