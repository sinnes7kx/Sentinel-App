"""Explicit runtime diagnostics, never a scan, install, image pull or target probe."""
from dataclasses import asdict
import os
import re
import shutil
import uuid

from .readiness import Readiness
from .tools import bundle, runner, wsl
from .tools.backends import is_wsl_distribution

VERSION = re.compile(r'(?<![\w.])\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?![\w.])')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')


def diagnostics(cancel, invoke=runner.run, which=shutil.which,
                preference=bundle.saved_backend, platform=os.name):
    """Return serializable rows for the existing shared background worker.

    Probe the standard local Docker socket only. Test tools only in a previously
    prepared environment; custom environments remain in the Security tools UI.
    WSL may start its distro; no isolation guarantee is made for WSL.
    """
    rows = []

    def add(name, state, explanation):
        rows.append(asdict(Readiness(name, state, explanation)))

    def probe(argv, limit=10, cleanup=False):
        if cancel.is_set() and not cleanup:
            return None
        try:
            result = invoke(argv, limit, None if cleanup else cancel)
        except (OSError, ValueError):
            return None
        if result.returncode != 0 or result.cancelled or result.timed_out or result.truncated:
            return None
        return result.stdout

    def version(name, argv):
        output = probe(argv)
        if cancel.is_set():
            return
        match = VERSION.search(output or '')
        add(name, 'Version reported' if match else 'Unverified',
            'Reported version: ' + match.group() + '. Scan compatibility not tested.'
            if match else 'Version command failed or returned an unrecognized version.')

    saved = preference()
    docker = which('docker')
    if docker and not cancel.is_set():
        endpoint = 'npipe:////./pipe/docker_engine' if platform == 'nt' else 'unix:///var/run/docker.sock'
        prefix = [docker, '--host', endpoint]
        server = probe(prefix + ['version', '--format', '{{.Server.Os}} {{.Server.Version}}'])
        if not server or not re.fullmatch(r'linux [0-9][0-9A-Za-z.+-]{0,60}', server.strip()):
            add('Docker runtime', 'Unverified', 'Standard local Linux daemon did not respond. Start Docker Desktop in Linux-container mode; custom sockets are not checked.')
        else:
            add('Docker runtime', 'Responding', 'Local Linux daemon reported version ' + server.strip().split()[1] + '.')
            if saved.kind == 'docker' and IMAGE.fullmatch(saved.environment):
                inspected = probe(prefix + ['image', 'inspect', '--format', '{{.Id}}', saved.environment])
                if not inspected or inspected.strip() != saved.environment:
                    add('Prepared Docker image', 'Unverified', 'Saved local image not found. Prepare included tools in Security tools.')
                else:
                    add('Prepared Docker image', 'Detected', 'Saved immutable image ID is present locally.')
                    for tool in bundle.BUNDLED_TOOLS:
                        if cancel.is_set():
                            break
                        name = 'sentinel-health-' + uuid.uuid4().hex
                        try:
                            version('Docker / ' + tool, prefix + ['run', '--name', name, '--rm',
                                    '--pull=never', '--network=none', '--memory=256m', '--cpus=1',
                                    '--pids-limit=64', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                                    '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
                                    '--entrypoint', tool, saved.environment, '--version'])
                        finally:
                            probe(prefix + ['rm', '--force', name], 5, cleanup=True)
            else:
                add('Prepared Docker image', 'Not configured', 'Prepare included tools to verify their versions.')
    elif not cancel.is_set():
        add('Docker runtime', 'Not detected', 'Optional; native assessments remain available.')

    launcher = which('wsl.exe') if platform == 'nt' else None
    if launcher and not cancel.is_set():
        output = probe([launcher, '--list', '--quiet'], 8)
        # runner decodes UTF-8; WSL often emits UTF-16LE with interleaved NULs.
        names = {line.strip() for line in (output or '').replace('\x00', '').lstrip('\ufeff\ufffd').splitlines()
                 if is_wsl_distribution(line.strip())}
        if not names:
            add('WSL runtime', 'Unverified', 'No registered distribution could be verified.')
        else:
            add('WSL runtime', 'Responding', 'Registered distributions detected; availability does not establish WSL 2.')
            if saved.kind == 'wsl' and saved.environment in names:
                for tool in bundle.BUNDLED_TOOLS:
                    if cancel.is_set():
                        break
                    version('WSL / ' + tool, [launcher, '--distribution', saved.environment,
                            '--exec', 'timeout', '--kill-after=2', '6', tool, '--version'])
            else:
                add('Prepared WSL toolkit', 'Not configured', 'Prepare included tools in Security tools.')
    elif not cancel.is_set():
        add('WSL runtime', 'Not detected', 'Optional Windows Linux environment.')

    return {'status': 'cancelled' if cancel.is_set() else 'completed', 'rows': rows}
