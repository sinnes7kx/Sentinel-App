import unittest
from importlib import metadata
from threading import Event
from unittest.mock import Mock

from sentinel.tool_inventory import snapshot
from sentinel.tools.backends import Backend
from sentinel.tools.runner import RunResult
from sentinel.zap_setup import ZAP_IMAGE, ZAP_REPOSITORY

IMAGE = 'sha256:' + 'a' * 64
ZAP = 'sha256:' + 'b' * 64
DIGEST = ZAP_REPOSITORY + '@sha256:' + 'c' * 64


class InventoryTests(unittest.TestCase):
    def rows(self, **kwargs):
        options = dict(which=lambda _: None, lookup=lambda _: False,
                       preference=lambda: None, platform='nt', version=lambda _: '1.0')
        options.update(kwargs)
        return {r['name']: r for r in snapshot(Event(), **options)['rows']}

    def test_missing_tools_no_processes(self):
        invoke = Mock()
        rows = self.rows(invoke=invoke)
        self.assertEqual(rows['Docker runtime']['state'], 'Not detected')
        self.assertEqual(rows['Managed Kali toolkit']['state'], 'Not configured')
        self.assertEqual(rows['Nmap (native)']['action'], 'nmap')
        self.assertEqual(rows['Nikto (native)']['action'], '')
        invoke.assert_not_called()

    def test_local_metadata_only(self):
        commands = []
        def invoke(argv, timeout, cancel):
            commands.append(argv)
            if argv[3] == 'version':
                return RunResult(0, 'linux 28.0.1', '')
            return RunResult(0, ZAP + ' ' + DIGEST if argv[-1] == ZAP_IMAGE else IMAGE, '')
        rows = self.rows(which=lambda _: 'docker', invoke=invoke,
                         preference=lambda: Backend('docker', IMAGE))
        self.assertEqual(rows['Docker runtime']['state'], 'Responding')
        self.assertEqual(rows['Managed Kali toolkit']['state'], 'Detected')
        for name in ('WhatWeb (native)', 'sslscan (native)'):
            self.assertEqual(rows[name]['state'], 'Docker alternative')
            self.assertIn('scan connectivity is not verified', rows[name]['detail'])
        self.assertEqual(rows['Nikto (native)']['state'], 'Not detected')
        self.assertEqual(rows['OWASP ZAP']['state'], 'Detected')
        self.assertIn('not enabled', rows['OWASP ZAP']['detail'])
        self.assertEqual([cmd[3] for cmd in commands], ['version', 'image', 'image'])
        self.assertTrue(all(cmd[1:3] == ['--host', 'npipe:////./pipe/docker_engine'] for cmd in commands))

    def test_unavailable_daemon_does_not_inspect_images(self):
        invoke = Mock(return_value=RunResult(1, '', 'unavailable'))
        rows = self.rows(which=lambda _: 'docker', invoke=invoke,
                         preference=lambda: Backend('docker', IMAGE))
        self.assertEqual(rows['Docker runtime']['state'], 'Needs attention')
        self.assertEqual(rows['Managed Kali toolkit']['state'], 'Unverified')
        self.assertEqual(rows['WhatWeb (native)']['state'], 'Not detected')
        self.assertIn('cannot be confirmed', rows['WhatWeb (native)']['detail'])
        self.assertEqual(rows['OWASP ZAP']['state'], 'Unverified')
        invoke.assert_called_once()

    def test_wsl_and_missing_python_metadata(self):
        def version(name):
            if name == 'dnspython':
                raise metadata.PackageNotFoundError(name)
            return '1.0'
        invoke = Mock()
        rows = self.rows(which=lambda name: 'wsl.exe' if name == 'wsl.exe' else None,
                         preference=lambda: Backend('wsl', 'Sentinel-Kali'), version=version, invoke=invoke)
        self.assertEqual(rows['Python runtime']['state'], 'Needs attention')
        self.assertEqual(rows['Managed Kali toolkit']['state'], 'Configured')
        self.assertEqual(rows['WSL']['state'], 'Client detected')
        invoke.assert_not_called()

    def test_cancelled_inventory_never_calls_daemon(self):
        cancel = Event()
        cancel.set()
        invoke = Mock()
        result = snapshot(cancel, invoke=invoke, which=lambda _: 'docker',
                          lookup=lambda _: False, preference=lambda: None,
                          version=lambda _: '1.0', platform='nt')
        self.assertEqual(result['status'], 'cancelled')
        invoke.assert_not_called()
