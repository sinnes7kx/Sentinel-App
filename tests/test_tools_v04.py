import json, unittest
from datetime import datetime, timezone
from threading import Event
from sentinel.engine import Scan, Finding
from sentinel.tools import TOOLS, nikto, whatweb, sslscan, nmap
from sentinel.tools.base import execute, ToolMissing
from sentinel.tools.runner import RunResult
from sentinel.tools.scope import parse_net_target
from sentinel.tools.suite import SUITE

LOCAL = lambda h: ['192.168.1.5']
PUBLIC = lambda h: ['93.184.216.34']
NIKTO = json.dumps([{'host': '192.168.1.5', 'vulnerabilities': [
    {'id': '999957', 'method': 'GET', 'url': '/', 'msg': 'The anti-clickjacking X-Frame-Options header is not present.'},
    {'id': '700', 'method': 'GET', 'url': '/backup.zip', 'msg': 'Potentially interesting backup/cert file found.'},
    {'id': '701', 'method': 'GET', 'url': '/.git/HEAD', 'msg': 'Git repository found.'},
    {'id': '701', 'method': 'GET', 'url': '/.git/HEAD', 'msg': 'Git repository found.'},
    {'id': '', 'method': 'GET', 'url': '/x', 'msg': ''}]}])
WHATWEB = json.dumps([{'target': 'http://x/', 'plugins': {'Apache': {'version': ['2.4.41']}, 'HTTPServer': {'string': ['Apache/2.4.41 (Ubuntu)']},
                       'PHP': {'version': ['7.4.3']}, 'Title': {'string': ['Hi']}, 'IP': {'string': ['1.2.3.4']}}}])
SSL = '''<document><ssltest host="x" port="443">
<protocol type="ssl" version="2" enabled="0"/><protocol type="ssl" version="3" enabled="0"/>
<protocol type="tls" version="1.0" enabled="1"/><protocol type="tls" version="1.1" enabled="0"/>
<protocol type="tls" version="1.2" enabled="1"/><protocol type="tls" version="1.3" enabled="0"/>
<renegotiation supported="1" secure="1"/><compression supported="1"/><heartbleed sslversion="TLSv1.2" vulnerable="0"/>
<cipher status="accepted" sslversion="TLSv1.0" bits="112" cipher="DES-CBC3-SHA"/>
<cipher status="accepted" sslversion="TLSv1.0" bits="128" cipher="RC4-SHA"/>
<cipher status="preferred" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-GCM-SHA384"/>
<certificates><certificate type="short"><subject>x</subject><self-signed>true</self-signed>
<not-valid-after>Jan  1 00:00:00 2020 GMT</not-valid-after><signature-algorithm>sha1WithRSAEncryption</signature-algorithm>
<pk error="false" type="RSA" bits="1024"/></certificate></certificates></ssltest></document>'''

def fake_runner(outputs, calls=None):
    """outputs: {binary-name: text}. Writes the tool's output file, or returns it on stdout."""
    def run(argv, timeout, cancel=None):
        if calls is not None: calls.append(argv)
        text = outputs[argv[0].rsplit('/', 1)[-1]]
        for a in argv:
            if a.endswith(('sentinel-out.json', 'sentinel-out.xml')):
                with open(a.split('=', 1)[-1], 'w') as fh: fh.write(text)
                return RunResult(0, '', '')
        return RunResult(0, text, '')
    return run

class TestParsers(unittest.TestCase):
    def test_nikto(self):
        f, info, _ = nikto.parse(NIKTO); sev = {x.title: x.severity for x in f}
        self.assertEqual(len(f), 3); self.assertEqual(f[0].severity, 'high'); self.assertIn('medium', sev.values()); self.assertEqual(f[-1].severity, 'info')
        self.assertIn('keyword-based estimate', f[0].evidence)
    def test_whatweb_json_and_line_formats(self):
        f, _, _ = whatweb.parse_json(WHATWEB); self.assertEqual(sorted(x.id for x in f), ['WHATWEB_Apache', 'WHATWEB_HTTPServer', 'WHATWEB_PHP'])
        line = '[\n' + json.dumps(json.loads(WHATWEB)[0]) + ',\n' + json.dumps(json.loads(WHATWEB)[0]) + '\n]'
        self.assertTrue(whatweb.parse_json(line)[0])
        with self.assertRaises(ValueError): whatweb.parse_json('not json')
    def test_sslscan(self):
        now = datetime(2026, 11, 24, tzinfo=timezone.utc)
        f, _, _ = sslscan.parse_xml(SSL, private=False, now=now); ids = {x.id: x.severity for x in f}
        self.assertEqual(ids['TLS_1.0'], 'medium'); self.assertEqual(ids['TLS_NO_13'], 'info'); self.assertEqual(ids['TLS_WEAK_CIPHERS_HIGH'], 'high')
        self.assertEqual(ids['TLS_WEAK_CIPHERS_MEDIUM'], 'medium'); self.assertEqual(ids['CERT_EXPIRED'], 'high'); self.assertEqual(ids['CERT_SELF_SIGNED'], 'medium')
        self.assertIn('TLS_COMPRESSION', ids); self.assertIn('CERT_WEAK_SIG', ids); self.assertIn('CERT_SHORT_KEY', ids); self.assertNotIn('TLS_HEARTBLEED', ids)
        self.assertEqual({x.id: x.severity for x in sslscan.parse_xml(SSL, True, now)[0]}['CERT_SELF_SIGNED'], 'low')
    def test_sslscan_rejects_entities(self):
        with self.assertRaises(ValueError): sslscan.parse_xml('<!DOCTYPE a [<!ENTITY x "y">]><document/>')

class TestExecute(unittest.TestCase):
    def test_each_web_tool_end_to_end(self):
        for spec, prof, text in ((nikto.SPEC, 'safe', NIKTO), (whatweb.SPEC, 'passive', WHATWEB), (sslscan.SPEC, 'standard', SSL)):
            calls = []
            r = execute(spec, 'https://nas.lan/', prof, True, '', None, resolver=LOCAL, run=fake_runner({spec.id: text}, calls), binary='/bin/' + spec.id)
            self.assertEqual(r.status, 'completed', spec.id); self.assertTrue(r.findings); self.assertEqual(r.profile, f'{spec.id}-{prof}')
            self.assertEqual(len(calls), 1); self.assertTrue(all(isinstance(a, str) for a in calls[0]))
    def test_nikto_never_enables_dangerous_groups(self):
        a = nikto.build('nikto', parse_scope_target('https://nas.lan/'), 'deeper', '/tmp/o.json')
        tuning = a[a.index('-Tuning') + 1]
        self.assertFalse(set(tuning.split(',')) & {'4', '6', '8', '9', 'a', 'c'})
    def test_https_only_and_public_confirmation(self):
        with self.assertRaises(ValueError): execute(sslscan.SPEC, 'http://nas.lan/', 'standard', True, resolver=LOCAL, binary='x')
        with self.assertRaises(PermissionError): execute(whatweb.SPEC, 'https://example.com/', 'passive', True, '', resolver=PUBLIC, binary='x')
        r = execute(whatweb.SPEC, 'https://example.com/', 'passive', True, 'example.com', resolver=PUBLIC, run=fake_runner({'w': WHATWEB}), binary='/bin/w')
        self.assertEqual(r.status, 'completed')
    def test_garbage_output_is_safe_failure(self):
        r = execute(nikto.SPEC, 'http://nas.lan/', 'safe', True, resolver=LOCAL, run=fake_runner({'nikto': '<<<garbage'}), binary='/bin/nikto')
        self.assertEqual(r.status, 'failed')
    def test_missing_tool(self):
        import sentinel.tools.base as b
        orig = b.find_binary; b.find_binary = lambda s: None
        try:
            with self.assertRaises(ToolMissing): execute(nikto.SPEC, 'http://nas.lan/', 'safe', True, resolver=LOCAL)
        finally: b.find_binary = orig

def parse_scope_target(u):
    from sentinel.engine import Target
    return Target.parse(u)

class TestSuite(unittest.TestCase):
    web = staticmethod(lambda url, authorized, cancel=None: Scan(url, 'now', 'completed', 200, 'TLSv1.3', [Finding('HSTS', 'medium', 't', 'e', 'r')]))
    def run_suite(self, present, url='https://nas.lan/', cancel=None):
        out = {'whatweb': WHATWEB, 'sslscan': SSL, 'nikto': NIKTO}
        return SUITE.scan(url, 'standard', True, '', cancel, resolver=LOCAL, run=fake_runner(out),
                          lookup=lambda s: '/bin/' + s.id if s.id in present else None, web_scan=self.web)
    def test_all_installed(self):
        r = self.run_suite({'whatweb', 'sslscan', 'nikto'}); self.assertEqual(r.status, 'completed'); self.assertEqual(r.http_status, 200)
        self.assertEqual(r.coverage['nikto'], 'completed'); self.assertGreater(len(r.findings), 8)
        sev = [f.severity for f in r.findings]; self.assertEqual(sev, sorted(sev, key=['high', 'medium', 'low', 'info'].index))
    def test_missing_tools_are_listed_not_hidden(self):
        r = self.run_suite({'whatweb'}); self.assertEqual(r.status, 'partial'); self.assertEqual(r.coverage['sslscan'], 'not installed'); self.assertIn('Nikto', r.error)
    def test_http_skips_sslscan_and_cancel(self):
        r = self.run_suite({'whatweb', 'sslscan', 'nikto'}, 'http://nas.lan/'); self.assertIn('skipped', r.coverage['sslscan']); self.assertEqual(r.status, 'completed')
        e = Event(); e.set(); self.assertEqual(self.run_suite({'whatweb'}, cancel=e).status, 'cancelled')
    def test_requires_authorization(self):
        with self.assertRaises(PermissionError): SUITE.scan('https://nas.lan/', 'standard', False, resolver=LOCAL, web_scan=self.web)

class TestRegistry(unittest.TestCase):
    def test_registry_shape(self):
        self.assertEqual([t.id for t in TOOLS], ['web-checkup', 'nmap', 'whatweb', 'sslscan', 'nikto'])
        for t in TOOLS:
            self.assertTrue(t.profiles and t.name and t.blurb and t.kind in ('net', 'web')); self.assertIsInstance(t.installed(), bool)
        for t in TOOLS[1:]:
            for p in t.profiles.values(): self.assertGreater(p.timeout, 0)

if __name__ == '__main__': unittest.main()


import os
FIX = os.path.join(os.path.dirname(__file__), 'fixtures')
rd = lambda n: open(os.path.join(FIX, n), encoding='utf-8').read()

class TestRealToolOutput(unittest.TestCase):
    """Captured from the real tools (Nmap 7.94, WhatWeb 0.5.5, sslscan 2.1.2, Nikto 2.1.5)."""
    def test_nmap(self):
        h = nmap.parse_xml(rd('real_nmap_7.94.xml')); self.assertEqual([p['port'] for p in h[0]['ports']], [8080, 8443])
    def test_whatweb(self):
        ids = {f.id for f in whatweb.parse_json(rd('real_whatweb_0.5.5.json'))[0]}
        self.assertTrue({'WHATWEB_PHP', 'WHATWEB_Python', 'WHATWEB_HTTPServer'} <= ids); self.assertNotIn('WHATWEB_Country', ids)
        self.assertNotIn(',', [f for f in whatweb.parse_json(rd('real_whatweb_0.5.5.json'))[0] if f.id == 'WHATWEB_Python'][0].title[-1])
    def test_sslscan(self):
        f = sslscan.parse_xml(rd('real_sslscan_2.1.2.xml'), True, datetime(2026, 12, 1, tzinfo=timezone.utc))[0]
        self.assertEqual({x.id for x in f}, {'CERT_EXPIRING', 'CERT_SELF_SIGNED'})   # modern TLS only, no weak ciphers
    def test_nikto_old_malformed_csv(self):
        f = nikto.parse(rd('real_nikto_2.1.5.csv'))[0]; self.assertEqual(len(f), 2); self.assertIn('x-powered-by', f[1].title.lower())
    def test_nikto_format_choice(self):
        nikto.supports_json.cache_clear()
        import sentinel.tools.nikto as nk
        orig = nk.runner.run
        try:
            nk.runner.run = lambda argv, t, c=None: RunResult(0, 'formats: csv htm xml txt', '')
            self.assertIn('csv', nk.build('/n1', parse_scope_target('http://a.lan/'), 'safe', 'o'))
            nk.runner.run = lambda argv, t, c=None: RunResult(0, 'formats: csv json xml', '')
            self.assertIn('json', nk.build('/n2', parse_scope_target('http://a.lan/'), 'safe', 'o'))
        finally: nk.runner.run = orig; nikto.supports_json.cache_clear()
    def test_suite_hides_header_duplicates(self):
        out = {'whatweb': WHATWEB, 'sslscan': SSL, 'nikto': NIKTO}
        r = SUITE.scan('https://nas.lan/', 'standard', True, resolver=LOCAL, run=fake_runner(out), lookup=lambda s: '/bin/' + s.id, web_scan=TestSuite.web)
        self.assertEqual(r.coverage['duplicates hidden'], 1); self.assertFalse([f for f in r.findings if 'X-Frame-Options' in f.title])
