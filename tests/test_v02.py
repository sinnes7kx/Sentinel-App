import unittest, threading, tempfile
from unittest.mock import patch
from types import SimpleNamespace
from sentinel.engine import scan, compare, Target
from sentinel.posture import observations
from sentinel.dnscheck import domain_name, query_domain, analyze
from sentinel.report import html_report

class Resolver:
    def __init__(self):self.calls=[]
    def resolve(self, host, kind, **kw):
        self.calls.append((host,kind,kw))
        if kind=='TXT':return [SimpleNamespace(strings=[b'v=DMARC1; p=none' if host.startswith('_dmarc.') else b'v=spf1 +all'])]
        return [object()]

class TestV02(unittest.TestCase):
    def test_posture(self):
        r=observations([('Content-Type','text/html'),('Set-Cookie','private=SECRET; SameSite=None'),('Access-Control-Allow-Origin','*'),('Access-Control-Allow-Credentials','true'),('Content-Security-Policy-Report-Only','default-src none')],200,'TLSv1',('x','x',100))
        self.assertTrue({'TLS_LEGACY','TLS_BITS','COOKIE_NONE_INSECURE','CORS_CONFLICT','CSP_REPORT_ONLY'}<={f.id for f in r});self.assertNotIn('SECRET',str(r))
    def test_domain_validation(self):
        for s in ('http://example.com','127.0.0.1','localhost','a..b','a/b.com','*.example.com','-a.example.com'):
            with self.subTest(s=s),self.assertRaises(ValueError):domain_name(s)
        self.assertEqual(domain_name('EXAMPLE.COM.'),'example.com')
    def test_dns_authorization(self):
        r=Resolver()
        with self.assertRaises(PermissionError):query_domain('example.test',resolver=r)
        self.assertEqual(r.calls,[])
    def test_dns_records(self):
        r=Resolver();result=query_domain('example.test',True,resolver=r)
        self.assertEqual(result['status'],'completed');self.assertEqual(len(r.calls),4)
        self.assertEqual([x[0] for x in r.calls],['example.test.','_dmarc.example.test.','example.test.','example.test.']);self.assertTrue(all(x[2]['search'] is False for x in r.calls))
        self.assertEqual({f.id for f in result['findings']},{'DNS_SPF_ALLOW_ALL','DNS_DMARC_MONITOR'});self.assertNotIn('v=spf1',str(result))
    def test_dns_failure_not_missing(self):
        r=Resolver();r.resolve=lambda *a,**k: (_ for _ in ()).throw(TimeoutError())
        result=query_domain('example.test',True,resolver=r);self.assertEqual(result['status'],'partial');self.assertEqual(result['findings'],[])
    def test_dns_cancel(self):
        c=threading.Event();c.set();r=Resolver();self.assertEqual(query_domain('example.test',True,c,r)['status'],'partial');self.assertFalse(r.calls)
    def test_scan_cancel(self):
        c=threading.Event();c.set()
        with patch('http.client.HTTPConnection') as conn:
            self.assertEqual(scan('http://example.test',True,cancel=c).status,'cancelled');conn.assert_not_called()
    def test_comparison_profile(self):
        r={'target':'https://example.test','status':'completed','http_status':200,'findings':[]}
        self.assertFalse(compare(r,dict(r,profile='web-v2'))['comparable']);self.assertFalse(compare(dict(r,profile='web-v2'),dict(r,profile='web-v2',dns_domain='example.test'))['comparable']);self.assertTrue(compare(r,r)['comparable'])
    def test_report_coverage(self):
        r=scan('http://example.test',True,cancel=SimpleNamespace(is_set=lambda:True)).to_dict();r['coverage']={'test':'<script>'};self.assertIn('&lt;script&gt;',html_report(r))
    def test_spf_multiple(self):
        self.assertEqual([f.id for f in analyze({'spf':{'status':'ok','values':['v=spf1 -all','v=spf1 +all']}})],['DNS_SPF_MULTIPLE'])
