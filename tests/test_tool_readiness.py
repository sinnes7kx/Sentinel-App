import gc
import os
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.app import App, DesktopUnavailable
from sentinel.store import Store
from sentinel.tools import nmap
from sentinel.tools_window import ToolsWindow


class ToolReadinessTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(gc.collect)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with patch('sentinel.app.Store', side_effect=lambda: Store(Path(directory.name) / 'history.db')):
            try:
                self.app = App()
            except DesktopUnavailable:
                if os.environ.get('SENTINEL_REQUIRE_GUI'):
                    raise
                self.skipTest('Tk display unavailable')
        self.addCleanup(self.app.orchestrator.worker.join, 3)
        self.addCleanup(self.app.close)
        self.window = ToolsWindow(self.app)
        self.window.tool_name.set(nmap.SPEC.name)
        self.window.tool_changed()
        self.window.backend.set('wsl')
        self.window.environment.set('kali-linux')

    def start_and_wait(self, target):
        self.window.target.set(target)
        self.window.auth.set(True)
        self.window.start()
        deadline = time.monotonic() + 5
        while self.window.busy and time.monotonic() < deadline:
            self.app.update()
            time.sleep(.01)
        self.assertFalse(self.window.busy)
        self.assertFalse(self.app.store.history(self.app.store.project(self.app.project.get())))

    def test_url_is_rejected_before_wsl_or_dns(self):
        with patch('sentinel.tools_window.wsl.available_tools') as probe, \
             patch('socket.getaddrinfo') as dns, patch('tkinter.messagebox.showerror') as alert:
            self.start_and_wait('https://example.invalid/')
            self.assertIn('A port scan needs a host name or IP', alert.call_args.args[1])
            probe.assert_not_called()
            dns.assert_not_called()

    def test_missing_binary_names_available_tools_before_target_contact(self):
        with patch('sentinel.tools_window.wsl.available_tools', return_value=['sslscan', 'timeout']), \
             patch('socket.getaddrinfo') as dns, patch.object(type(nmap.SPEC), 'scan') as scan:
            self.start_and_wait('lab.invalid')
            self.assertIn('kali-linux is missing nmap', self.window.status.get())
            self.assertIn('sslscan', self.window.detail.get('1.0', 'end'))
            dns.assert_not_called()
            scan.assert_not_called()

    def test_required_confirmation_reaches_window_without_scan(self):
        with patch('sentinel.tools_window.wsl.available_tools', return_value=['nmap', 'timeout']), \
             patch('sentinel.tools.backends.Backend.run') as execute:
            self.start_and_wait('8.8.8.8')
            self.assertIn('confirmation box', self.window.status.get())
            execute.assert_not_called()
