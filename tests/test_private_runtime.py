import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from launch_private import prepare


class PrivateRuntimeTests(unittest.TestCase):
    def test_private_install_and_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / 'isolated'
            requirements = root / 'requirements-runtime.txt'
            requirements.write_text('packaging==26.4\n', encoding='ascii')
            executable = env / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
            def create(path):
                self.assertEqual(path, env)
                executable.parent.mkdir(parents=True)
                executable.touch()
            invoke = Mock(return_value=SimpleNamespace(returncode=0))
            self.assertEqual(prepare(root, env, invoke, create), executable)
            args = invoke.call_args_list[0].args[0]
            self.assertEqual(args[:5], [str(executable), '-I', '-m', 'pip', 'install'])
            self.assertEqual(args[-2:], ['-r', str(requirements)])
            self.assertNotIn('--user', args)
            self.assertEqual(invoke.call_count, 2)
            invoke.reset_mock()
            self.assertEqual(prepare(root, env, invoke, create), executable)
            self.assertEqual(invoke.call_count, 1)
            self.assertIn('import packaging; import dns', invoke.call_args.args[0])
            requirements.write_text('packaging==26.4\ndnspython==2.8.0\n', encoding='ascii')
            invoke.reset_mock()
            prepare(root, env, invoke, create)
            self.assertEqual(invoke.call_count, 2)

    def test_failed_creation_cannot_fall_back_to_global_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'requirements-runtime.txt').write_text('packaging==26.4')
            invoke = Mock()
            with self.assertRaises(RuntimeError):
                prepare(root, root / 'missing', invoke, lambda _: None)
            invoke.assert_not_called()
