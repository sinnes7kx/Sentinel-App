import tempfile
import unittest
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

from sentinel.tool_setup import install_package, setup, saved_source_backend
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
                           invoke=invoke, install=Mock(), payload=path / 'missing', dockerfile=recipe,
                           preference=lambda _: None)
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

    def test_all_setup_stops_on_missing_nmap(self):
        install = Mock()
        invoke = Mock()
        result = setup('all', Event(), platform='nt', install=install, invoke=invoke,
                       find_nmap=lambda: False)
        self.assertEqual(result['status'], 'partial')
        self.assertIn('nmap:', result['message'])
        install.assert_called_once_with('nmap')
        invoke.assert_not_called()

    def test_all_setup_reuses_saved_image_without_build(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            recipe = path / 'Dockerfile'
            recipe.write_text('FROM synthetic-fixture')
            prefs = path / 'saved.json'
            image = 'sha256:' + 'b' * 64
            import json
            prefs.write_text(json.dumps({'kind': 'docker', 'environment': image}))
            calls = []
            def invoke(argv, timeout, cancel):
                calls.append(argv)
                return RunResult(0, 'linux' if argv[3] == 'version' else image, '')
            install = Mock()
            result = setup('all', Event(), platform='nt', install=install, invoke=invoke,
                           find_nmap=lambda: True, find_docker=lambda: 'docker',
                           payload=path / 'missing', dockerfile=recipe,
                           preference=lambda _: prefs)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['environment'], image)
            self.assertIn('nmap:', result['message'])
            self.assertIn('toolkit:', result['message'])
            self.assertEqual([cmd[3] for cmd in calls], ['version', 'image'])
            install.assert_not_called()
            prefs.write_text(json.dumps({'kind': 'docker', 'environment': 'latest'}))
            self.assertIsNone(saved_source_backend(prefs))

    def test_built_source_toolkit_is_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            recipe = path / 'Dockerfile'
            recipe.write_text('FROM synthetic-fixture')
            prefs = path / 'saved.json'
            image = 'sha256:' + 'c' * 64
            def invoke(argv, timeout, cancel):
                return RunResult(0, 'linux' if argv[3] == 'version' else image if argv[3] == 'image' else '', '')
            result = setup('toolkit', Event(), platform='nt', invoke=invoke,
                           find_docker=lambda: 'docker', payload=path / 'missing',
                           dockerfile=recipe, preference=lambda _: prefs)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(saved_source_backend(prefs).environment, image)
