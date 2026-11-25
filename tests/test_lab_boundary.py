import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'lab_boundary', Path(__file__).parent / 'integration' / 'lab_boundary.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
verify = module.verify_boundary


class LabBoundaryTests(unittest.TestCase):
    def snapshot(self, **changes):
        return dict({'namespace': 'net:[12345]', 'interfaces': ['lo'],
                     'ipv4_routes': [], 'ipv6_routes': []}, **changes)

    def test_loopback_only_namespace(self):
        self.assertEqual(verify(self.snapshot()), 'net:[12345]')
        self.assertEqual(verify(self.snapshot(), 'net:[12345]'), 'net:[12345]')

    def test_reject_different_namespace_or_extra_interfaces(self):
        with self.assertRaises(ValueError):
            verify(self.snapshot(), 'net:[56789]')
        for interfaces in ([], ['eth0', 'lo'], ['lo', 'tun0']):
            with self.subTest(interfaces=interfaces), self.assertRaises(ValueError):
                verify(self.snapshot(interfaces=interfaces))

    def test_ipv4_default_route_is_rejected(self):
        with self.assertRaises(ValueError):
            verify(self.snapshot(ipv4_routes=['lo 00000000 00000000 0001 0 0 0 00000000 0 0 0']))

    def test_ipv6_unreachable_default_is_allowed_but_usable_default_is_not(self):
        row = ' '.join(['0' * 32, '00', '0' * 32, '00', '0' * 32,
                        'ffffffff', '00000001', '00000000', '00200200', 'lo'])
        self.assertEqual(verify(self.snapshot(ipv6_routes=[row])), 'net:[12345]')
        with self.assertRaises(ValueError):
            verify(self.snapshot(ipv6_routes=[row.replace('00200200', '00000001')]))

    def test_non_loopback_routes_are_rejected(self):
        with self.assertRaises(ValueError):
            verify(self.snapshot(ipv4_routes=['eth0 0000007F 00000000 0001 0 0 0 000000FF 0 0 0']))
        row = ' '.join(['0' * 32, '80', '0' * 32, '00', '0' * 32,
                        '00000000', '00000001', '00000000', '00000001', 'eth0'])
        with self.assertRaises(ValueError):
            verify(self.snapshot(ipv6_routes=[row]))
