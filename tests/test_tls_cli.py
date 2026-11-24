import unittest, tempfile, subprocess, shutil, ssl, threading, os, sys, json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from sentinel.engine import scan

class Fixture(BaseHTTPRequestHandler):
    hits=0
    def do_GET(self):
        type(self).hits+=1;self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
    def log_message(self,*a):pass

@unittest.skipUnless(shutil.which('openssl'),'openssl needed for temporary TLS fixture')
class TLS(unittest.TestCase):
    def test_verified_and_untrusted(self):
        with tempfile.TemporaryDirectory() as d:
            cert=Path(d)/'cert.pem';key=Path(d)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,capture_output=True)
            server=ThreadingHTTPServer(('127.0.0.1',0),Fixture);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key);server.socket=ctx.wrap_socket(server.socket,server_side=True)
            t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
            url=f'https://localhost:{server.server_port}/'
            try:
                n=Fixture.hits;bad=scan(url,True);self.assertEqual(bad.status,'partial');self.assertEqual(Fixture.hits,n);self.assertIn('TLS_VERIFY',[x.id for x in bad.findings])
                trusted=ssl.create_default_context(cafile=str(cert))
                with patch('sentinel.engine.ssl.create_default_context',return_value=trusted):good=scan(url,True)
                self.assertEqual(good.status,'completed');self.assertEqual(Fixture.hits,n+1);self.assertIn('CERT_EXPIRY',[x.id for x in good.findings]);self.assertTrue(good.tls)
            finally:server.shutdown();server.server_close();t.join()

class CLI(unittest.TestCase):
    def test_cli_requires_permission(self):
        p=subprocess.run([sys.executable,'-m','sentinel','http://127.0.0.1:1/'],capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertIn('authorized',p.stderr)
    def test_cli_local_export(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),Fixture);t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                j=Path(d)/'scan.json';h=Path(d)/'scan.html'
                p=subprocess.run([sys.executable,'-m','sentinel',f'http://127.0.0.1:{server.server_port}/','--authorized','--json-out',str(j),'--html-out',str(h)],capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(j.read_text())['status'],'completed');self.assertIn('Assessment coverage',h.read_text())
        finally:server.shutdown();server.server_close();t.join()
