"""Read-only local inventory for the tool control center.

No target requests, installation, image pulls, container starts or WSL launches.
Detection is not a claim of scan readiness.
"""
from importlib import metadata
import os
import re
import shutil
import sys

from .tools import bundle, nmap, nikto, whatweb, sslscan, runner
from .tools.backends import local_docker_prefix
from .tool_setup import saved_source_backend
from .zap_setup import ZAP_IMAGE, ZAP_REPOSITORY, IMAGE_ID


def managed_backend():
    if (bundle.PAYLOAD / 'rootfs.sha256').is_file():
        return bundle.saved_backend()
    return saved_source_backend()


def snapshot(cancel, invoke=runner.run, which=shutil.which, lookup=None,
             preference=managed_backend, platform=None, version=metadata.version):
    platform = os.name if platform is None else platform
    lookup = lookup or (lambda spec: spec.installed())
    rows = []

    def add(name, state, detail, action=''):
        rows.append(dict(name=name, state=state, detail=detail, action=action))

    def probe(args):
        if cancel.is_set():
            return None
        try:
            result = invoke(args, 15, cancel)
        except (OSError, ValueError):
            return None
        if result.returncode != 0 or result.cancelled or result.timed_out or result.truncated:
            return None
        return result.stdout.strip()

    mode = 'Private virtual environment' if sys.prefix != sys.base_prefix else 'Current Python runtime'
    versions = []
    for package in ('packaging', 'dnspython'):
        try:
            versions.append(package + ' ' + version(package))
        except metadata.PackageNotFoundError:
            versions.append(package + ' missing')
    add('Python runtime', 'Needs attention' if any(v.endswith(' missing') for v in versions) else 'Detected',
        mode + '; Python ' + sys.version.split()[0] + '; ' + ', '.join(versions) +
        '. Package metadata only. Start_Sentinel.bat manages source dependencies.')
    for spec, name, action in ((nmap.SPEC, 'Nmap (native)', 'nmap'),
                               (nikto.SPEC, 'Nikto (native)', ''),
                               (whatweb.SPEC, 'WhatWeb (native)', 'toolkit'),
                               (sslscan.SPEC, 'sslscan (native)', 'toolkit')):
        found = lookup(spec)
        add(name, 'Detected' if found else 'Not detected',
            'Native executable located; execution unverified.' if found else
            ('Automatic Nikto setup is not available yet.' if spec.id == 'nikto' else
             'Use the setup action for the supported managed installation.'), action)
    docker = which('docker')
    prefix = local_docker_prefix(platform)
    if docker:
        prefix[0] = docker
    server = probe(prefix + ['version', '--format', '{{.Server.Os}} {{.Server.Version}}']) if docker else None
    responding = bool(server and re.fullmatch(r'linux [0-9][0-9A-Za-z.+-]{0,60}', server))
    add('Docker runtime', 'Responding' if responding else 'Needs attention' if docker else 'Not detected',
        ('Local Linux daemon: ' + server) if responding else
        ('Client detected; start the local Linux engine or restart if required.' if docker else 'Docker client not found on PATH.'), 'docker')
    try:
        saved = preference()
    except (OSError, ValueError, TypeError):
        saved = None
    if saved and saved.kind == 'docker' and IMAGE_ID.fullmatch(saved.environment):
        image = probe(prefix + ['image', 'inspect', '--format', '{{.Id}}', saved.environment]) if responding else None
        add('Managed Kali toolkit', 'Detected' if image == saved.environment else 'Unverified',
            'Saved local image ID is present; WhatWeb and sslscan execution not checked.' if image == saved.environment else
            'Saved image cannot currently be confirmed. Retry preparation.', 'toolkit')
    elif saved and saved.kind == 'wsl' and saved.environment:
        add('Managed Kali toolkit', 'Configured', 'Saved WSL settings; this inventory does not start WSL or verify tools.', 'toolkit')
    else:
        add('Managed Kali toolkit', 'Not configured', 'Prepare WhatWeb and sslscan without a separate Kali VM.', 'toolkit')
    zap = probe(prefix + ['image', 'inspect', '--format', '{{.Id}} {{join .RepoDigests " "}}', ZAP_IMAGE]) if responding else None
    parts = (zap or '').split()
    present = bool(parts and IMAGE_ID.fullmatch(parts[0]) and
                   any(p.startswith(ZAP_REPOSITORY + '@') and IMAGE_ID.fullmatch(p.split('@', 1)[1])
                       for p in parts[1:]))
    add('OWASP ZAP', 'Detected' if present else 'Not detected' if responding else 'Unverified',
        'Upstream image metadata present. Desktop scan execution is not enabled.' if present else
        'Optional image; prepare to run the offline version check. Desktop scan execution is not enabled.', 'zap')
    if platform == 'nt':
        add('WSL', 'Client detected' if which('wsl.exe') else 'Not detected',
            'Optional runtime. No distribution was started or verified.')
    return {'status': 'cancelled' if cancel.is_set() else 'completed', 'rows': rows}
