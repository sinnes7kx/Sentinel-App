import tempfile
import unittest
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

from sentinel.tool_setup import install_package, setup
from sentinel.tools.runner import RunResult


class AutomaticSetupTests(unittest.TestCase):
    def test_fixed_winget_id_and_visible_interactive_install(self):
        launch = Mock(return_value=SimpleNamespace(returncode=0))
        install_package('nmap', which=lambda name: 'winget.exe', launch=launch)
        args, kwargs = launch.call_args
        self.assertEqual(args[0], ['winget.exe', 'install', '--id', 'Insecure.Nmap',
                                  '--exact', '--source', 'winget', '--interactive'])
        self.assertFalse(kwargs['shell'])
        self.assertNotIn('--accept-package-agreements', args[0])
        with self.assertRaises(ValueError):
            install_package('arbitrary', launch=launch)
        self.assertEqual(launch.call_count, 1)

    def test_existing_nmap_is_not_reinstalled(self):
        install = Mock()
        result = setup('nmap', Event(), platform='nt', install=install, find_nmap=lambda: True)
        self.assertEqual(result['status'], 'completed')
        install.assert_not_called()

    def test_missing_nmap_is_installed_then_detected(self):
        install = Mock()
        found = Mock(side_effect=[False, True])
        result = setup('nmap', Event(), platform='nt', install=install, find_nmap=found)
        install.assert_called_once_with('nmap')
        self.assertEqual(result['status'], 'completed')

    def test_docker_not_running_does_not_build(self):
        invoke = Mock(return_value=RunResult(1, '', 'not running'))
        result = setup('toolkit', Event(), platform='nt', find_docker=lambda: 'docker',
                       invoke=invoke, install=Mock())
        self.assertEqual(result['status'], 'partial')
        self.assertIn('Open Docker Desktop', result['message'])
        self.assertEqual(invoke.call_count, 1)

    def test_source_toolkit_build_is_fixed_local_recipe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            recipe = path / 'Dockerfile'
            recipe.write_text('FROM synthetic-fixture')
            calls = []
            def invoke(argv, timeout, cancel):
                calls.append(argv)
                output = 'linux' if argv[3] == 'version' else 'sha256:' + 'a' * 64 if argv[3] == 'image' else ''
                return RunResult(0, output, '')
            result = setup('toolkit', Event(), platform='nt', find_docker=lambda: 'docker',
                           invoke=invoke, install=Mock(), payload=path / 'missing', dockerfile=recipe)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['environment'], 'sha256:' + 'a' * 64)
            self.assertEqual([cmd[3] for cmd in calls], ['version', 'build', 'image'])
            self.assertEqual(calls[1][-1], str(path))
            self.assertTrue(all(cmd[1:3] == ['--host', 'npipe:////./pipe/docker_engine'] for cmd in calls))

    def test_cancel_before_install_and_unsupported_platform(self):
        cancel = Event(); cancel.set()
        install = Mock()
        self.assertEqual(setup('nmap', cancel, platform='nt', install=install)['status'], 'cancelled')
        with self.assertRaises(ValueError):
            setup('nmap', Event(), platform='posix', install=install)
        install.assert_not_called()

    def test_installer_error_not_success(self):
        with self.assertRaises(ValueError):
            install_package('docker', which=lambda name: 'winget.exe',
                            launch=Mock(return_value=SimpleNamespace(returncode=1)))
