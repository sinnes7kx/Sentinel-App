"""Explicit preparation of the upstream ZAP Docker image; no target requests."""
import re
import uuid

from .tools.backends import docker_cleanup
from .tools.runner import run

ZAP_REPOSITORY = 'ghcr.io/zaproxy/zaproxy'
ZAP_IMAGE = ZAP_REPOSITORY + ':stable'
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
VERSION = re.compile(r'(?m)^(?:ZAP[ :]+)?([0-9]+\.[0-9]+\.[0-9]+)\s*$')


def _ok(result):
    return (result.returncode == 0 and not result.cancelled and
            not result.timed_out and not result.truncated)


def prepare_zap(prefix, cancel, invoke=run):
    def outcome(status, message, **extra):
        return {'status': status, 'message': message, **extra}

    def inspect():
        result = invoke(prefix + ['image', 'inspect', '--format',
                         '{{.Id}} {{join .RepoDigests " "}}', ZAP_IMAGE], 20, cancel)
        if not _ok(result):
            return None
        parts = result.stdout.split()
        if not parts or not IMAGE_ID.fullmatch(parts[0]):
            return None
        if not any(part.startswith(ZAP_REPOSITORY + '@') and
                   IMAGE_ID.fullmatch(part.split('@', 1)[1]) for part in parts[1:]):
            return None
        return parts[0]

    if cancel.is_set():
        return outcome('cancelled', 'ZAP preparation cancelled.')
    image = inspect()
    if not image and not cancel.is_set():
        pulled = invoke(prefix + ['pull', ZAP_IMAGE], 1200, cancel)
        if not _ok(pulled):
            return outcome('cancelled' if cancel.is_set() else 'partial',
                           'ZAP download did not finish. Retry setup after checking Docker and internet access.')
        image = inspect()
    if cancel.is_set():
        return outcome('cancelled', 'ZAP preparation cancelled.')
    if not image:
        return outcome('partial', 'The local ZAP image identity could not be established.')
    name = 'sentinel-zap-version-' + uuid.uuid4().hex
    try:
        result = invoke(prefix + ['run', '--name', name, '--rm', '--pull=never',
                        '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                        '--memory=1024m', '--cpus=1', '--pids-limit=128',
                        image, 'zap.sh', '-version'], 90, cancel)
    finally:
        clean = docker_cleanup(prefix, name, invoke)
    if cancel.is_set():
        return outcome('cancelled', 'ZAP check cancelled.' +
                       ('' if clean else ' Container cleanup could not be verified.'))
    if not clean:
        return outcome('partial', 'ZAP version-check container cleanup could not be verified.')
    version = VERSION.search(result.stdout) if _ok(result) else None
    if not version:
        return outcome('partial', 'ZAP image detected but its offline version check did not complete.')
    return outcome('completed', 'ZAP ' + version.group(1) +
                   ' prepared. Offline version check passed; desktop scanning is not enabled.',
                   zap_image=image, zap_version=version.group(1))
