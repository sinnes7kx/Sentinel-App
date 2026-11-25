import hashlib
import tempfile
from pathlib import Path
from threading import Event
import unittest
from unittest.mock import patch

import run
from sentinel.local_tools import inspect_integrity, review_report


class LocalToolsTests(unittest.TestCase):
    def test_hashes_large_file_and_matches_either_reference(self):
        data = b'Sentinel fixture\n' * 90_000
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.bin'
            path.write_bytes(data)
            self.assertEqual(inspect_integrity(path, '  ' + sha256.upper() + '  '), {
                'Bytes read': len(data), 'SHA-256': sha256, 'SHA-512': sha512,
                'Reference digest': 'SHA-256 · Match',
            })
            self.assertEqual(inspect_integrity(path, sha512)['Reference digest'], 'SHA-512 · Match')
            self.assertEqual(inspect_integrity(path, '0' * 128)['Reference digest'], 'SHA-512 · Mismatch')
            with self.assertRaisesRegex(ValueError, 'hex digest'):
                inspect_integrity(path, 'invalid')
            cancel = Event()
            cancel.set()
            self.assertIsNone(inspect_integrity(path, cancel=cancel))

    def test_local_report_reads_real_export_shape_and_enforces_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.csv'
            path.write_bytes(b'No.,Protocol\n1,TLS\n2,DNS\n3,TLS\n')
            self.assertEqual(review_report(path, 'wireshark'), {
                'Packets in export': 3, 'Top protocols': {'TLS': 2, 'DNS': 1},
            })
            with patch('sentinel.local_tools.MAX_REPORT', 10):
                with self.assertRaisesRegex(ValueError, 'at most'):
                    review_report(path, 'wireshark')
            with self.assertRaisesRegex(ValueError, 'regular file'):
                review_report(Path(directory), 'wireshark')


class LauncherTests(unittest.TestCase):
    def test_default_and_explicit_desktop_launch(self):
        with patch('sentinel.app.main') as desktop, patch('sentinel.web.main') as web:
            run.main([])
            run.main(['--desktop'])
            self.assertEqual(desktop.call_count, 2)
            web.assert_not_called()

    def test_both_browser_launch_entry_points(self):
        with patch('sentinel.web.main') as web:
            run.main(['--web'])
            web.assert_called_once_with([])
            run.main(['--no-browser'])
            web.assert_called_with(['--no-browser'])

    def test_default_falls_back_when_tk_cannot_initialize(self):
        from sentinel.app import DesktopUnavailable

        with (patch('sentinel.app.main', side_effect=DesktopUnavailable('Tcl unavailable')),
              patch('sentinel.web.main') as web, patch('sys.stderr')):
            run.main([])
            web.assert_called_once_with([])
            with self.assertRaisesRegex(SystemExit, 'Tcl unavailable'):
                run.main(['--desktop'])
