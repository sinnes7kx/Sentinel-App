import unittest
from unittest.mock import patch

from sentinel.scan_confirmation import confirm_website, confirm_tool
from sentinel.tools.backends import Backend
from sentinel.tools import TOOLS


class ScanConfirmationTests(unittest.TestCase):
    def test_website_shows_exact_scope_and_defaults_to_cancel(self):
        with patch('sentinel.scan_confirmation.messagebox.askokcancel', return_value=False) as dialog:
            self.assertFalse(confirm_website(None, 'https://example.test/path', 'Standard', 'example.test'))
        message = dialog.call_args.args[1]
        self.assertIn('https://example.test/path', message)
        self.assertIn('DNS domain: example.test', message)
        self.assertIn('Standard', message)
        self.assertEqual(dialog.call_args.kwargs['default'], 'cancel')

    def test_local_tool_requires_one_confirmation(self):
        tool = next(t for t in TOOLS if t.id == 'whatweb')
        with patch('sentinel.scan_confirmation.messagebox.askokcancel', return_value=True) as dialog:
            self.assertEqual(confirm_tool(None, tool, 'http://127.0.0.1/', 'passive', Backend()), '')
            self.assertIn('http://127.0.0.1/', dialog.call_args.args[1])
        with patch('sentinel.scan_confirmation.messagebox.askokcancel', return_value=False):
            self.assertIsNone(confirm_tool(None, tool, 'http://127.0.0.1/', 'passive', Backend()))

    def test_hostname_confirmation_preserves_guard_without_dns(self):
        tool = next(t for t in TOOLS if t.id == 'whatweb')
        with patch('sentinel.scan_confirmation.simpledialog.askstring', return_value='example.test') as dialog, \
             patch('sentinel.scan_confirmation.parse_net_target') as resolve:
            self.assertEqual(confirm_tool(None, tool, 'https://example.test/', 'passive', Backend()), 'example.test')
            resolve.assert_not_called()
            self.assertIn('https://example.test/', dialog.call_args.args[1])
        with patch('sentinel.scan_confirmation.simpledialog.askstring', return_value='wrong.test'):
            with self.assertRaises(PermissionError):
                confirm_tool(None, tool, 'https://example.test/', 'passive', Backend())
        with patch('sentinel.scan_confirmation.simpledialog.askstring', return_value=None):
            self.assertIsNone(confirm_tool(None, tool, 'https://example.test/', 'passive', Backend()))
