import subprocess
import unittest
from unittest.mock import Mock

from sentinel.tools import wsl
from sentinel.tools.runner import RunResult


class WSLDiscoveryTests(unittest.TestCase):
    def test_prefers_kali_and_reads_windows_and_utf8_lists(self):
        argv = ['wsl.exe', '--list', '--quiet']
        text = 'Ubuntu\r\nkali-linux\r\nDebian\r\nUbuntu\r\n--option\r\n'
        for encoding in ('utf-16', 'utf-16-le', 'utf-8-sig'):
            with self.subTest(encoding=encoding):
                invoke = Mock(return_value=subprocess.CompletedProcess(argv, 0, text.encode(encoding), b''))
                self.assertEqual(wsl.distributions(invoke), ['kali-linux', 'Debian', 'Ubuntu'])
                self.assertEqual(invoke.call_args.args[0], argv)
                self.assertEqual(invoke.call_args.kwargs['timeout'], 8)

    def test_distinguishes_empty_list_and_windows_errors(self):
        invoke = Mock(return_value=subprocess.CompletedProcess([], 0, b'', b''))
        self.assertEqual(wsl.distributions(invoke), [])
        invoke.return_value = subprocess.CompletedProcess([], 1, b'', 'Wsl/WSL_E_DISTRO_NOT_FOUND'.encode('utf-16-le'))
        self.assertEqual(wsl.distributions(invoke), [])
        invoke.return_value = subprocess.CompletedProcess([], 1, b'', b'access denied')
        with self.assertRaisesRegex(ValueError, 'could not list'):
            wsl.distributions(invoke)
        invoke.side_effect = FileNotFoundError
        with self.assertRaisesRegex(ValueError, 'was not found'):
            wsl.distributions(invoke)
        invoke.side_effect = subprocess.TimeoutExpired('wsl.exe', 8)
        with self.assertRaisesRegex(ValueError, 'did not respond'):
            wsl.distributions(invoke)

    def test_package_probe_only_checks_supported_names(self):
        invoke = Mock(return_value=RunResult(0, 'timeout\nsslscan\nother\n', ''))
        self.assertEqual(wsl.available_tools('kali-linux', invoke=invoke), ['timeout', 'sslscan'])
        args, seconds, _ = invoke.call_args.args
        self.assertEqual(args[:5], ['wsl.exe', '--distribution', 'kali-linux', '--exec', '/bin/sh'])
        self.assertIn('command -v', args[6])
        self.assertEqual(args[8:], ['timeout', 'nmap', 'sslscan', 'whatweb'])
        self.assertEqual(seconds, 15)
        invoke.reset_mock()
        with self.assertRaisesRegex(ValueError, 'Select an installed'):
            wsl.available_tools('--help', invoke=invoke)
        invoke.assert_not_called()
