"""Explicit Linux Docker integration test; no user targets or external scans.

Usage: python tests/integration/kali_lab.py after building sentinel-kali-lab-tools.
Only the lab runner injects the fixture's network namespace into actual Backend.run.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from sentinel.tools import sslscan, whatweb, runner
from sentinel.tools.base import execute
from sentinel.tools.backends import Backend

DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
TOOL_IMAGE = 'sentinel-kali-lab-tools'
FIXTURE_IMAGE = 'sentinel-kali-lab-fixture'


def docker(*args, timeout=30):
    return subprocess.check_output(DOCKER + list(args), text=True,
                                   stderr=subprocess.STDOUT, timeout=timeout).strip()


def main():
    if os.name != 'posix':
        raise RuntimeError('Use a dedicated Linux Docker test environment.')
    image_id = docker('image', 'inspect', '--format', '{{.Id}}', TOOL_IMAGE)
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise RuntimeError('Invalid toolkit image ID')
    fixture_id = docker('image', 'inspect', '--format', '{{.Id}}', FIXTURE_IMAGE)
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', fixture_id):
        raise RuntimeError('Invalid fixture image ID')
    name = 'sentinel-fixture-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)
        shutil.copy(Path(__file__).with_name('kali_fixture.py'), path / 'server.py')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(path / 'key.pem'), '-out', str(path / 'cert.pem'),
                        '-days', '2', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True, timeout=30)
        try:
            docker('run', '-d', '--name', name, '--pull=never', '--network=none',
                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                   '--memory=256m', '--cpus=1', '--pids-limit=64',
                   '--mount', f'type=bind,source={path},target=/fixture,readonly',
                   '--entrypoint', 'python3', fixture_id, '/fixture/server.py')
            deadline = time.monotonic() + 20
            while 'SENTINEL_FIXTURE_READY' not in docker('logs', name):
                if time.monotonic() >= deadline:
                    raise RuntimeError('Fixture did not become ready.')
                time.sleep(.2)
            if docker('inspect', '--format', '{{.HostConfig.NetworkMode}}', name) != 'none':
                raise RuntimeError('Fixture network is not disabled.')

            def isolated(argv, timeout, cancel):
                if argv[:2] == ['docker', 'run']:
                    if '--pull=never' not in argv or image_id not in argv:
                        raise AssertionError('Unexpected tool image or pull policy.')
                    argv = DOCKER + ['run', '--network=container:' + name] + argv[2:]
                elif argv[:3] == ['docker', 'rm', '--force']:
                    argv = DOCKER + argv[1:]
                else:
                    raise AssertionError('Unexpected subprocess.')
                return runner.run(argv, min(timeout, 120), cancel)

            backend = Backend('docker', image_id)
            result = execute(whatweb.SPEC, 'http://127.0.0.1:8080/', 'passive',
                             True, backend=backend, run=isolated)
            if result.status != 'completed' or not any(
                    f.id == 'WHATWEB_HTTPServer' for f in result.findings):
                raise AssertionError('WhatWeb did not return the expected real technology evidence: ' + result.status)
            redirect = execute(whatweb.SPEC, 'http://127.0.0.1:8080/redirect',
                               'passive', True, backend=backend, run=isolated)
            if redirect.status != 'completed':
                raise AssertionError('WhatWeb redirect fixture did not complete.')
            if 'UNEXPECTED_REDIRECT' in docker('logs', name):
                raise AssertionError('WhatWeb followed a forbidden redirect.')

            tls = execute(sslscan.SPEC, 'https://127.0.0.1:8443/', 'standard',
                          True, backend=backend, run=isolated)
            ids = {f.id for f in tls.findings}
            if tls.status != 'completed' or not {'CERT_SELF_SIGNED', 'TLS_NO_13'} <= ids:
                raise AssertionError('sslscan did not return expected fixture evidence: ' + tls.status + ' ' + str(sorted(ids)))
            if 'TLS_NO_MODERN' in ids or 'TLS_1.0' in ids or 'TLS_1.1' in ids:
                raise AssertionError('False TLS protocol finding.')
            print('PASS: WhatWeb technology evidence, redirect restriction and sslscan TLS fixture.')
            print(docker('run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL',
                         '--entrypoint', 'dpkg-query', image_id, '-W', 'whatweb', 'sslscan'))
        finally:
            subprocess.run(DOCKER + ['rm', '--force', name], timeout=15,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
