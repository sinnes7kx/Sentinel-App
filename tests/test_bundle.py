import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sentinel.tools import bundle, sslscan, whatweb
from sentinel.tools.backends import Backend
from sentinel.tools.runner import RunResult


class OfflineToolkitTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.payload = Path(temp.name)
        self.archive = self.payload / 'kali-tools.tar.gz'
        self.archive.write_bytes(b'test archive')
        self.digest = bundle.file_digest(self.archive)
        (self.payload / 'rootfs.sha256').write_text(self.digest)
        self.image = 'sha256:' + 'a' * 64

    def test_corrupt_archive_never_starts_an_import(self):
        self.archive.write_bytes(b'damaged')
        with patch.object(bundle, 'call') as invoke, self.assertRaisesRegex(ValueError, 'integrity check'):
            bundle.prepare('docker', self.payload)
        invoke.assert_not_called()

    def test_import_checks_digest_reuses_image_and_runs_offline_probe(self):
        imported = False
        history = []
        def docker(argv, timeout=90):
            nonlocal imported
            history.append(argv)
            if argv[3:5] == ['image', 'inspect']:
                return (0, self.image + ' ' + self.digest) if imported else (1, '')
            if argv[3:5] == ['image', 'import']:
                self.assertIn(str(self.archive), argv)
                imported = True
            return 0, ''
        with patch.object(bundle, 'call', side_effect=docker):
            for _ in range(2):
                self.assertEqual(bundle.prepare('docker', self.payload), Backend('docker', self.image))
        self.assertEqual(sum(cmd[3:5] == ['image', 'import'] for cmd in history), 1)
        self.assertTrue(all('--pull=never' in cmd and '--network=none' in cmd
                            for cmd in history if cmd[3] == 'run'))

    def test_refuses_conflicting_local_tag(self):
        with patch.object(bundle, 'call', return_value=(0, self.image + ' different')):
            with self.assertRaisesRegex(ValueError, 'conflict'):
                bundle.prepare('docker', self.payload)

    def test_wsl_import_is_per_user_and_reused_after_tool_probe(self):
        (self.payload / 'wsl-x64.msi').write_bytes(b'msi')
        env = {'SystemRoot': str(self.payload), 'LOCALAPPDATA': str(self.payload / 'user')}
        calls = []
        def windows(argv, timeout=90):
            calls.append(argv)
            return 0, 'sentinel-kali-tools-v1' if '/bin/cat' in argv else ''
        with patch.object(bundle, 'os', SimpleNamespace(name='nt', environ=env)), \
             patch.object(bundle, 'WSL_MSI_SHA256', bundle.file_digest(self.payload / 'wsl-x64.msi')), \
             patch.object(bundle, 'call', side_effect=windows), \
             patch.object(bundle, 'registered_wsl', side_effect=[False, True]), \
             patch.object(bundle.wsl, 'available_tools', return_value=['whatweb', 'sslscan', 'timeout']):
            first = bundle.prepare('wsl', self.payload)
            self.assertEqual(bundle.prepare('wsl', self.payload), first)
        imports = [cmd for cmd in calls if '--import' in cmd]
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0][2], first.environment)
        self.assertIn(str(self.archive), imports[0])
        self.assertTrue(Path(imports[0][3]).is_relative_to(self.payload / 'user'))
        self.assertEqual(imports[0][-2:], ['--version', '2'])

    def test_wsl_reboot_stops_before_registration(self):
        msi = self.payload / 'wsl-x64.msi'
        msi.write_bytes(b'msi')
        with patch.object(bundle, 'os', SimpleNamespace(name='nt', environ={'SystemRoot': str(self.payload)})), \
             patch.object(bundle, 'WSL_MSI_SHA256', bundle.file_digest(msi)), \
             patch.object(bundle, 'call', return_value=(3010, '')), \
             patch.object(bundle, 'registered_wsl') as registered:
            with self.assertRaisesRegex(ValueError, 'Restart Windows'):
                bundle.prepare('wsl', self.payload)
            registered.assert_not_called()

    def test_preference_round_trip_and_invalid_state(self):
        path = self.payload / 'state/prefs.json'
        with patch.object(bundle, 'preference_path', return_value=path):
            self.assertEqual(bundle.saved_backend(), Backend('wsl'))
            backend = Backend('docker', self.image)
            bundle.remember(backend, path)
            self.assertEqual(bundle.saved_backend(), backend)
            path.write_text(json.dumps({'kind': 'docker', 'environment': 'tools:latest'}))
            self.assertEqual(bundle.saved_backend(), Backend('wsl'))

    def test_docker_reports_stream_without_host_drive_mount(self):
        for spec, url, profile, output, flag in (
            (whatweb.SPEC, 'http://127.0.0.1', 'passive', '[{"plugins":{"Apache":{}}}]', '--log-json=/dev/stdout'),
            (sslscan.SPEC, 'https://127.0.0.1', 'standard', '<ssltest><protocol type="tls" version="1.2" enabled="1"/><protocol type="tls" version="1.3" enabled="1"/></ssltest>', '--xml=-'),
        ):
            with self.subTest(spec=spec.id):
                def invoke(cmd, timeout, cancel):
                    if cmd[3] == 'run':
                        self.assertIn(flag, cmd)
                        self.assertNotIn('--mount', cmd)
                        if spec.id == 'whatweb':
                            self.assertIn('--env=http_proxy=', cmd)
                            self.assertIn('--env=HTTP_PROXY=', cmd)
                        self.assertIn('--no-heartbleed' if spec.id == 'sslscan' else '--quiet', cmd)
                    return RunResult(0, output if cmd[3] == 'run' else '', '')
                result = spec.scan(url, profile, True, backend=Backend('docker', self.image), run=invoke)
                self.assertEqual(result.status, 'completed')
