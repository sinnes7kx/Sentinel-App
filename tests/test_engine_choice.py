import unittest

from sentinel.engine_choice import recommend
from sentinel.tools import nmap, whatweb, sslscan, nikto, SUITE
from sentinel.tools.backends import Backend

SAVED = Backend('docker', 'sha256:' + 'a' * 64)


class EngineChoiceTests(unittest.TestCase):
    def test_native_first_and_suite_native_only(self):
        for tool in (nmap.SPEC, whatweb.SPEC, sslscan.SPEC, nikto.SPEC):
            with self.subTest(tool=tool.id):
                self.assertEqual(recommend(tool, '', True, SAVED, True).backend, Backend())
        self.assertEqual(recommend(SUITE, '', False, SAVED, True).backend, Backend())

    def test_prepared_toolkit_candidate(self):
        for tool in (whatweb.SPEC, sslscan.SPEC):
            self.assertEqual(recommend(tool, 'https://192.168.1.10/', False, SAVED, True).backend, SAVED)

    def test_no_automatic_container_for_local_or_unresolved_targets(self):
        for value in ('https://localhost/', 'https://127.0.0.1/', 'https://[::1]/',
                      'https://[::ffff:127.0.0.1]/', 'https://0.0.0.0/', 'https://169.254.1.1/',
                      'https://224.0.0.1/', 'https://example.invalid/', 'https://'):
            with self.subTest(value=value):
                self.assertIsNone(recommend(whatweb.SPEC, value, False, SAVED, True).backend)

    def test_no_unverified_backends_or_unsupported_tools(self):
        for saved, detected in ((None, True), (SAVED, False), (Backend('docker', 'latest'), True),
                                (Backend('wsl', 'Kali'), True)):
            self.assertIsNone(recommend(whatweb.SPEC, 'https://192.168.1.10/', False, saved, detected).backend)
        for tool in (nmap.SPEC, nikto.SPEC):
            self.assertIsNone(recommend(tool, '192.168.1.10', False, SAVED, True).backend)

    def test_tls_requires_https(self):
        self.assertIsNone(recommend(sslscan.SPEC, 'http://192.168.1.10/', False, SAVED, True).backend)
