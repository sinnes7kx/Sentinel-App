"""Explicit offline self-check of an already prepared managed Docker toolkit."""
import re
import shutil
import uuid

from .tool_inventory import managed_backend
from .tools.backends import local_docker_prefix, docker_cleanup
from .tools.runner import run
from .zap_setup import prepare_zap

IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
VERSION = re.compile(r'(?<![\w.])\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?![\w.])')
TOOLS = ('whatweb', 'sslscan')


def check_installation(cancel, invoke=run, which=shutil.which,
                       preference=managed_backend, platform=None):
    rows = []
    def finish(status, message):
        return {'status': status, 'message': message, 'rows': rows}

    def probe(argv, timeout=20):
        if cancel.is_set():
            return None
        try:
            result = invoke(argv, timeout, cancel)
        except (OSError, ValueError, RuntimeError):
            return None
        if result.returncode or result.cancelled or result.timed_out or result.truncated:
            return None
        return result.stdout

    if cancel.is_set():
        return finish('cancelled', 'Installation test cancelled.')
    docker = which('docker')
    if not docker:
        return finish('partial', 'Docker is not detected. Prepare the toolkit first.')
    try:
        saved = preference()
    except (OSError, ValueError, TypeError):
        saved = None
    if not saved or saved.kind != 'docker' or not IMAGE.fullmatch(saved.environment):
        return finish('partial', 'No saved Docker toolkit. Prepare the toolkit first. WSL is not tested here.')
    prefix = local_docker_prefix(platform)
    prefix[0] = docker
    server = probe(prefix + ['version', '--format', '{{.Server.Os}}'])
    if cancel.is_set():
        return finish('cancelled', 'Installation test cancelled.')
    if not server or server.strip() != 'linux':
        return finish('partial', 'Open Docker Desktop and start the Linux engine, then retry.')
    present = probe(prefix + ['image', 'inspect', '--format', '{{.Id}}', saved.environment])
    if cancel.is_set():
        return finish('cancelled', 'Installation test cancelled.')
    if not present or present.strip() != saved.environment:
        return finish('partial', 'Saved toolkit image is missing. Prepare it again.')
    for tool in TOOLS:
        if cancel.is_set():
            break
        name = 'sentinel-selfcheck-' + uuid.uuid4().hex
        try:
            output = probe(prefix + ['run', '--name', name, '--rm', '--pull=never',
                           '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                           '--memory=256m', '--cpus=1', '--pids-limit=64', '--read-only',
                           '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
                           '--entrypoint', tool, saved.environment, '--version'], 30)
        finally:
            clean = docker_cleanup(prefix, name, invoke)
        match = VERSION.search(output or '')
        state = 'Version verified' if match and clean and not cancel.is_set() else 'Unverified'
        detail = ('Reported version ' + match.group() + '; offline startup and container cleanup checked.'
                  if state == 'Version verified' else 'Offline version test or container cleanup could not be verified.')
        rows.append({'name': tool, 'state': state, 'detail': detail, 'action': 'toolkit'})
        if not clean:
            return finish('cancelled' if cancel.is_set() else 'partial',
                          'Could not confirm container removal. No further checks were started.')
    if cancel.is_set():
        return finish('cancelled', 'Installation test cancelled.')
    if all(row['state'] == 'Version verified' for row in rows) and len(rows) == len(TOOLS):
        return finish('completed', 'Toolkit version checks passed. Network access and assessment results are not tested.')
    return finish('partial', 'One or more tools could not report a version. Review the results and retry setup.')


def check_zap_installation(cancel, invoke=run, which=shutil.which, platform=None):
    """Verify a prepared ZAP image without installing Docker or downloading ZAP."""
    def finish(status, message, state='Unverified'):
        return {'status': status, 'message': message,
                'rows': [{'name': 'ZAP (offline test)', 'state': state,
                          'detail': message, 'action': 'zap'}]}

    if cancel.is_set():
        return finish('cancelled', 'ZAP installation test cancelled.')
    docker = which('docker')
    if not docker:
        return finish('partial', 'Docker is not detected. Prepare Docker first.')
    prefix = local_docker_prefix(platform)
    prefix[0] = docker
    try:
        health = invoke(prefix + ['version', '--format', '{{.Server.Os}}'], 20, cancel)
        if cancel.is_set():
            return finish('cancelled', 'ZAP installation test cancelled.')
        if (health.returncode != 0 or health.cancelled or health.timed_out
                or health.truncated or health.stdout.strip() != 'linux'):
            return finish('partial', 'Start the Docker Linux engine and retry.')
        result = prepare_zap(prefix, cancel, invoke, allow_download=False)
    except (OSError, ValueError, RuntimeError):
        return finish('partial', 'ZAP installation test could not finish. Check Docker and retry.')
    return finish(result['status'], result['message'],
                  'Version verified' if result['status'] == 'completed' else 'Unverified')
