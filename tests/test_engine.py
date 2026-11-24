import unittest, threading, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from sentinel.engine import Target, scan, inspect_headers, compare
from sentinel.store import Store
from sentinel.report import html_report

class Fixture(BaseHTTPRequestHandler):
    hits=[]
    def do_GET(self):
        self.hits.append(self.path)
        if self.path=='/redirect':
            self.send_response(302); self.send_header('Location','http://127.0.0.1:1/outside'); self.end_headers();return
        self.send_response(200); self.send_header('Content-Type','text/html')
        if self.path=='/fixed':
            self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'")
        self.send_header('Set-Cookie','private=super-secret-fixture');self.end_headers()
        self.wfile.write(b'<html>private-body-fixture</html>')
    def log_message(self,*args):pass

class TestEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Fixture);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.base=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def test_auth(self):
        n=len(Fixture.hits)
        with self.assertRaises(PermissionError):scan(self.base)
        self.assertEqual(len(Fixture.hits),n)
    def test_scope(self):
        for x in ['ftp://example.com','http://x/a?b=1','http://u:p@x','http://x/#z','http://x:0','http://x//other','http://x/a b','http://x\\a','http://x:99999']:
            with self.subTest(x=x),self.assertRaises(ValueError):Target.parse(x)
    def test_observations(self):
        n=len(Fixture.hits);r=scan(self.base,True).to_dict();ids={f['id'] for f in r['findings']}
        self.assertEqual(r['status'],'completed');self.assertEqual(len(Fixture.hits),n+1);self.assertTrue({'HTTP','CSP','FRAME','NOSNIFF','COOKIE_SECURE'}<=ids)
        self.assertNotIn('super-secret-fixture',str(r));self.assertNotIn('private-body-fixture',str(r))
    def test_redirect(self):
        n=len(Fixture.hits);r=scan(self.base+'/redirect',True).to_dict();self.assertEqual(len(Fixture.hits),n+1);self.assertEqual(r['http_status'],302);self.assertIn('REDIRECT',[f['id'] for f in r['findings']]);self.assertNotIn('/outside',str(r))
    def test_fixed(self):
        ids={f.id for f in scan(self.base+'/fixed',True).findings};self.assertFalse({'CSP','NOSNIFF','FRAME'}&ids)
    def test_tls_header(self):
        t=Target.parse('https://example.test');self.assertIn('HSTS',[f.id for f in inspect_headers(t,200,[])])
        self.assertNotIn('HSTS',[f.id for f in inspect_headers(t,200,[('Strict-Transport-Security','max-age=31536000; includeSubDomains')])])
    def test_non_html(self):self.assertNotIn('CSP',[f.id for f in inspect_headers(Target.parse('https://example.test'),200,[('Content-Type','application/json')])])
    def test_compare(self):
        r=scan(self.base,True).to_dict();new=dict(r,findings=[f for f in r['findings'] if f['id']!='CSP']);self.assertIn('CSP',compare(r,new)['not_observed']);self.assertFalse(compare(r,dict(new,status='failed'))['comparable'])
        with self.assertRaises(ValueError):compare(r,dict(new,target='other'))
    def test_storage(self):
        with tempfile.TemporaryDirectory() as d:
            s=Store(d+'/data.db');p=s.project('site');self.assertEqual(p,s.project('site'));r=scan(self.base,True).to_dict();s.save(p,r);self.assertEqual(s.history(p)[0][1],r);self.assertEqual(s.history(s.project('other')),[]);s.close()
    def test_report_escaping(self):
        r=scan(self.base,True).to_dict();r['target']='<script>alert(1)</script>';report=html_report(r);self.assertNotIn('<script>',report);self.assertIn('&lt;script&gt;',report)

if __name__=='__main__':unittest.main()
