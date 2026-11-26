import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from test_local import test_environment


class LocalTestEnvironmentTests(unittest.TestCase):
    def test_detect_existing_git_openssl_without_changing_global_path(self):
        with tempfile.TemporaryDirectory() as directory:
            git = Path(directory) / 'Git' / 'usr' / 'bin'
            git.mkdir(parents=True)
            (git / 'openssl.exe').touch()
            original = {'ProgramFiles': directory, 'PATH': 'original'}
            env = test_environment(original, platform='nt', which=Mock(return_value=None))
            self.assertEqual(env['PATH'], 'original' + os.pathsep + str(git))
            self.assertEqual(original['PATH'], 'original')
            self.assertEqual(env['SENTINEL_REQUIRE_GUI'], '1')

    def test_existing_path_or_no_install_is_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            original = {'ProgramFiles': directory, 'PATH': 'original'}
            for existing in (None, 'openssl.exe'):
                env = test_environment(original, platform='nt', which=Mock(return_value=existing))
                self.assertEqual(env['PATH'], 'original')
