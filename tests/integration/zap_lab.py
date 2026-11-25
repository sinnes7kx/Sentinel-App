"""Explicit CI-only ZAP baseline against a synthetic loopback web server.

Requires locally prepared images. No arbitrary target, active scan, or image pull.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from threading import Event
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from sentinel.zap_review import parse_report, MAX_BYTES
from sentinel.zap_setup import prepare_zap
from sentinel.tools.backends import docker_cleanup
from sentinel.tools.runner import run
from lab_boundary import verify_boundary

DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
FIXTURE_IMAGE = 'sentinel-kali-lab-fixture'
TARGET = 'http://127.0.0.1:8080/'


def docker(*args, timeout=30):
    return subprocess.check_output(DOCKER + list(args), text=True,
                                   stderr=subprocess.STDOUT, timeout=timeout).strip()


def image_id(tag):
    value = docker('image', 'inspect', '--format', '{{.Id}}', tag)
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', value):
        raise RuntimeError('Expected a locally prepared image ID.')
    return value


def main():
    if os.name != 'posix':
        raise RuntimeError('Use a dedicated Linux CI Docker environment.')
    zap_image, fixture_image = image_id(ZAP_IMAGE), image_id(FIXTURE_IMAGE)
    # CI has already explicitly pulled the image; test the same offline probe
    # used by desktop setup without permitting a second pull.
    def local_only(argv, timeout, cancel):
        if argv[3] == 'pull':
            raise AssertionError('ZAP CI image must be prepared before the probe.')
        return run(argv, timeout, cancel)
    prepared = prepare_zap(DOCKER, Event(), local_only)
    if prepared['status'] != 'completed' or prepared.get('zap_image') != zap_image:
        raise AssertionError('ZAP setup verification failed: ' + prepared['message'])
    print('PASS: offline ZAP version check and container cleanup:', prepared['zap_version'])
    fixture = 'sentinel-zap-fixture-' + uuid.uuid4().hex
    scanner = 'sentinel-zap-scan-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)
        # Only this disposable synthetic report directory is writable by ZAP.
        path.chmod(0o755)
        output = path / 'report'
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        shutil.copy(Path(__file__).with_name('lab_boundary.py'), path / 'boundary.py')
        shutil.copy(Path(__file__).with_name('zap_fixture.py'), path / 'server.py')
        try:
            docker('run', '-d', '--name', fixture, '--pull=never', '--network=none',
                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                   '--memory=128m', '--cpus=1', '--pids-limit=32',
                   '--user', f'{os.getuid()}:{os.getgid()}',
                   '--mount', f'type=bind,source={path},target=/fixture,readonly',
                   '--entrypoint', 'python3', fixture_image, '/fixture/server.py')
            deadline = time.monotonic() + 20
            while 'SENTINEL_ZAP_FIXTURE_READY' not in docker('logs', fixture):
                if time.monotonic() >= deadline or docker('inspect', '--format', '{{.State.Status}}', fixture) != 'running':
                    raise RuntimeError('ZAP fixture did not start.')
                time.sleep(.2)
            if docker('inspect', '--format', '{{.HostConfig.NetworkMode}}', fixture) != 'none':
                raise RuntimeError('Fixture network mode changed.')
            namespace = verify_boundary(json.loads(docker('exec', fixture, 'python3', '/fixture/boundary.py')))
            # The baseline uses ZAP's ordinary spider and passive rules only.
            # It is not a no-request operation. Target is fixed to this fixture.
            response = run(DOCKER + ['run', '--name', scanner, '--rm', '--pull=never',
                           '--network=container:' + fixture, '--cap-drop=ALL',
                           '--security-opt=no-new-privileges', '--memory=1536m', '--cpus=2',
                           '--pids-limit=256',
                           '--mount', f'type=bind,source={output},target=/zap/wrk',
                           zap_image, 'zap-baseline.py', '-t', TARGET, '-m', '1',
                           '-T', '3', '-J', 'report.json', '-I'], 360)
            if response.timed_out or response.cancelled or response.truncated or response.returncode not in (0, 1, 2):
                raise RuntimeError('ZAP baseline did not complete: ' + str(response.returncode) + '\n' +
                                   response.stdout[-2000:] + '\n' + response.stderr[-2000:])
            with (output / 'report.json').open('rb') as stream:
                report = parse_report(stream.read(MAX_BYTES + 1))
            if report['truncated'] or not report['site_count']:
                raise AssertionError('Expected a complete bounded fixture report.')
            ids = {alert['id'] for alert in report['alerts']}
            if not {'ZAP_10038', 'ZAP_10021'} <= ids:
                raise AssertionError('Missing expected CSP and nosniff observations: ' + str(sorted(ids)))
            verify_boundary(json.loads(docker('exec', fixture, 'python3', '/fixture/boundary.py')), namespace)
            print('PASS: real ZAP passive baseline, expected fixture header observations, unchanged isolated boundary.')
            print('ZAP image ID:', zap_image)
        finally:
            scanner_clean = docker_cleanup(DOCKER, scanner, run)
            fixture_clean = docker_cleanup(DOCKER, fixture, run)
            if not scanner_clean or not fixture_clean:
                raise RuntimeError('Could not verify lab container cleanup.')


if __name__ == '__main__':
    main()
