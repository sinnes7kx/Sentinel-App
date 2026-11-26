import unittest
from unittest.mock import Mock, patch
from sentinel.engine import Scan
from sentinel.tools.backends import Backend
from sentinel.tools.suite import SUITE

SAVED = Backend('docker', 'sha256:' + 'a' * 64)


def base(url, authorized, cancel=None):
    return Scan(url, 'now', 'completed', 200, 'TLSv1.3', [])


def completed(spec, url, *args, **kwargs):
    return Scan(url, 'now', 'completed', None, None, [],
                coverage={'container_cleanup': 'Container absent at verification'})


class ManagedCheckupTests(unittest.TestCase):
    def test_ip_url_uses_saved_toolkit_for_supported_tools(self):
        with patch('sentinel.tools.suite.execute', side_effect=completed) as execute:
            result = SUITE.scan('https://192.168.1.10/', attested=True,
                                lookup=lambda spec: None, web_scan=base, managed=SAVED)
        self.assertEqual([call.args[0].id for call in execute.call_args_list], ['whatweb', 'sslscan'])
        self.assertTrue(all(call.kwargs['backend'] == SAVED for call in execute.call_args_list))
        self.assertEqual(result.coverage['whatweb_engine'], 'docker')
        self.assertEqual(result.coverage['nikto'], 'not installed')

    def test_hostname_uses_only_pinned_tls_managed_check(self):
        resolver = Mock(return_value=['192.168.1.10'])
        with patch('sentinel.tools.suite.execute', side_effect=completed) as execute:
            result = SUITE.scan('https://fixture.invalid/', attested=True,
                                resolver=resolver, lookup=lambda spec: None,
                                web_scan=base, managed=SAVED)
        execute.assert_called_once()
        self.assertEqual(execute.call_args.args[0].id, 'sslscan')
        self.assertEqual(execute.call_args.kwargs['resolver']('fixture.invalid'), ('192.168.1.10',))
        self.assertIn('incompatible', result.coverage['whatweb'])
        self.assertEqual(result.coverage['sslscan_engine'], 'docker')

    def test_loopback_never_uses_managed_toolkit(self):
        with patch('sentinel.tools.suite.execute') as execute:
            SUITE.scan('https://127.0.0.1/', attested=True, lookup=lambda spec: None,
                       web_scan=base, managed=SAVED)
        execute.assert_not_called()

    def test_native_tools_preferred(self):
        with patch('sentinel.tools.suite.execute', side_effect=completed) as execute:
            SUITE.scan('https://192.168.1.10/', attested=True,
                       lookup=lambda spec: '/native/' + spec.id, web_scan=base, managed=SAVED)
        self.assertEqual(len(execute.call_args_list), 3)
        self.assertTrue(all(call.kwargs['backend'] == Backend() for call in execute.call_args_list))

    def test_unverified_cleanup_stops_further_checks(self):
        with patch('sentinel.tools.suite.execute', return_value=Scan('fixture', 'now', 'partial', None, None, [])) as execute:
            result = SUITE.scan('https://192.168.1.10/', attested=True,
                                lookup=lambda spec: None, web_scan=base, managed=SAVED)
        execute.assert_called_once()
        self.assertIn('cleanup not verified', result.error)
        self.assertEqual(result.status, 'partial')
