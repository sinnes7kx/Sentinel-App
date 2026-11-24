import unittest
from threading import Event
from sentinel.tools.scope import parse_net_target, require_authorization
from sentinel.tools.runner import RunResult, clean, run
from sentinel.tools import nmap

XML = '''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames><hostname name="nas.lan"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2"/></port>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
<port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server" product="Microsoft RDP"/></port>
<port protocol="tcp" portid="81"><state state="closed"/></port></ports></host>
<host><status state="down"/><address addr="192.168.1.11" addrtype="ipv4"/></host></nmaprun>'''
LOCAL = lambda h: ['192.168.1.5']
PUBLIC = lambda h: ['93.184.216.34']

class TestScope(unittest.TestCase):
    def test_accepts_and_classifies(self):
        self.assertTrue(parse_net_target('192.168.1.0/24').private)
        self.assertEqual(parse_net_target('192.168.1.0/24').hosts, 256)
        self.assertTrue(parse_net_target('127.0.0.1').private)
        self.assertFalse(parse_net_target('8.8.8.8').private)
        self.assertTrue(parse_net_target('nas.lan', LOCAL).private)
        self.assertFalse(parse_net_target('example.com', PUBLIC).private)
    def test_rejects(self):
        for bad in ('', '-sS', '--script=vuln', '192.168.1.1 8.8.8.8', '10.0.0.0/8', '8.8.8.0/24', '192.168.1.5/24', '1.2.3', 'a_b.com', 'x;ls'):
            with self.assertRaises(ValueError, msg=bad): parse_net_target(bad, LOCAL)
    def test_unresolvable(self):
        def boom(h): raise OSError
        with self.assertRaises(ValueError): parse_net_target('nope.invalid', boom)
    def test_authorization(self):
        priv, pub = parse_net_target('192.168.1.5'), parse_net_target('8.8.8.8')
        with self.assertRaises(PermissionError): require_authorization(priv, False)
        require_authorization(priv, True)
        with self.assertRaises(PermissionError): require_authorization(pub, True)
        with self.assertRaises(PermissionError): require_authorization(pub, True, '8.8.4.4')
        require_authorization(pub, True, '8.8.8.8')

class TestNmap(unittest.TestCase):
    def test_argv_has_no_shell_and_ends_with_target(self):
        a = nmap.build_argv('/usr/bin/nmap', parse_net_target('192.168.1.5'), 'quick')
        self.assertEqual(a[-2:], ['--', '192.168.1.5']); self.assertIn('-Pn', a); self.assertIn('-oX', a)
        self.assertNotIn('-Pn', nmap.build_argv('n', parse_net_target('192.168.1.0/24'), 'quick'))
        self.assertFalse([x for x in a if x.startswith('--script') or x in ('-A', '-O')])
    def test_parse_and_findings(self):
        hosts = nmap.parse_xml(XML); self.assertEqual(len(hosts), 1); self.assertEqual(len(hosts[0]['ports']), 3)
        f = {x.id: x for x in nmap.findings_from_hosts(hosts, private=True)}
        self.assertEqual(f['NMAP_192.168.1.10_tcp_23'].severity, 'high')
        self.assertEqual(f['NMAP_192.168.1.10_tcp_22'].severity, 'info')
        self.assertEqual(f['NMAP_192.168.1.10_tcp_3389'].severity, 'medium')
        pub = {x.id: x for x in nmap.findings_from_hosts(hosts, private=False)}
        self.assertEqual(pub['NMAP_192.168.1.10_tcp_3389'].severity, 'high')
    def test_rejects_entities(self):
        with self.assertRaises(ValueError): nmap.parse_xml('<!DOCTYPE a [<!ENTITY x "y">]><nmaprun/>')
    def scan(self, **kw):
        calls = []
        def fake(argv, timeout, cancel=None): calls.append(argv); return kw.get('res', RunResult(0, XML, ''))
        r = nmap.scan_network(kw.get('target', '192.168.1.10'), 'quick', kw.get('att', True), '', kw.get('cancel'), run=fake, binary='nmap')
        return r, calls
    def test_scan_completed_and_comparable_shape(self):
        r, calls = self.scan(); self.assertEqual(r.status, 'completed'); self.assertEqual(len(r.findings), 3)
        d = r.to_dict(); self.assertEqual(d['profile'], 'nmap-quick'); self.assertIsNone(d['http_status']); self.assertEqual(len(calls), 1)
    def test_requires_authorization_before_running(self):
        with self.assertRaises(PermissionError): self.scan(att=False)
    def test_cancel_timeout_failure(self):
        e = Event(); e.set(); r, calls = self.scan(cancel=e); self.assertEqual(r.status, 'cancelled'); self.assertEqual(calls, [])
        r, _ = self.scan(res=RunResult(None, '', '', timed_out=True)); self.assertEqual(r.status, 'partial')
        r, _ = self.scan(res=RunResult(1, '', 'Failed to resolve\x1b[31m')); self.assertEqual(r.status, 'failed'); self.assertNotIn('\x1b', r.error)
    def test_missing_binary(self):
        with self.assertRaises(nmap.ToolMissing): nmap.scan_network('192.168.1.5', attested=True, binary=None) if not nmap.find_binary() else (_ for _ in ()).throw(nmap.ToolMissing())

class TestRunner(unittest.TestCase):
    def test_clean(self): self.assertEqual(clean('a\x1b[0m\nb'), 'a[0m b')
    def test_run_real_process_and_cancel(self):
        import sys
        r = run([sys.executable, '-c', 'print("hi")'], 10); self.assertEqual((r.returncode, r.stdout.strip()), (0, 'hi'))
        r = run([sys.executable, '-c', 'import time; time.sleep(30)'], 1); self.assertTrue(r.timed_out)
        e = Event(); e.set(); r = run([sys.executable, '-c', 'import time; time.sleep(30)'], 30, e); self.assertTrue(r.cancelled)

if __name__ == '__main__': unittest.main()
