"""Explicit Windows setup of allowlisted vendor tools; never run a scan.

WinGet uses its normal package verification and interactive installer UI.
No remote scripts, arbitrary package names, or automatic license acceptance.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess

from .tools import bundle, nmap, runner
from .tools.backends import local_docker_prefix, Backend

PACKAGES = {'nmap': 'Insecure.Nmap', 'docker': 'Docker.DockerDesktop'}
DOCKERFILE = Path(__file__).resolve().parents[1] / 'packaging' / 'windows' / 'Dockerfile'


def docker_executable():
    # The assessment runner uses PATH as well; if installation updates PATH,
    # a restart may be needed before either setup or assessment can use it.
    return shutil.which('docker')


def install_package(kind, which=shutil.which, launch=subprocess.run):
    if kind not in PACKAGES:
        raise ValueError('Unsupported installer.')
    winget = which('winget.exe')
    if not winget:
        raise ValueError('Windows App Installer (WinGet) is unavailable. Update App Installer from Microsoft Store.')
    # A visible console permits repository/package agreements and vendor prompts.
    # Do not accept terms on the user's behalf or bypass hash verification.
    try:
        result = launch([winget, 'install', '--id', PACKAGES[kind], '--exact',
                         '--source', 'winget', '--interactive'],
                        shell=False, creationflags=getattr(subprocess, 'CREATE_NEW_CONSOLE', 0),
                        timeout=1800)
    except subprocess.TimeoutExpired:
        raise ValueError('Installer timed out. A vendor installer may still be open; finish or close it before retrying.') from None
    except OSError:
        raise ValueError('Could not open Windows Package Manager.') from None
    if result.returncode != 0:
        raise ValueError('WinGet did not report success. Review the installer prompts and retry. Exit code: ' + str(result.returncode))


def setup(kind, cancel, platform=None, install=install_package, invoke=runner.run,
          find_nmap=nmap.SPEC.installed, find_docker=docker_executable,
          prepare=bundle.prepare, remember=bundle.remember, payload=None, dockerfile=None):
    platform = os.name if platform is None else platform
    payload = bundle.PAYLOAD if payload is None else payload
    dockerfile = DOCKERFILE if dockerfile is None else dockerfile
    if platform != 'nt':
        raise ValueError('Automatic installation currently supports Windows only.')
    if kind not in ('nmap', 'docker', 'toolkit'):
        raise ValueError('Unknown setup option.')

    def result(status, message, **extra):
        return {'status': status, 'message': message, **extra}

    if cancel.is_set():
        return result('cancelled', 'Setup cancelled before starting.')
    if kind == 'nmap':
        if not find_nmap():
            install('nmap')
        if cancel.is_set():
            return result('cancelled', 'Setup stopped; installed components are retained.')
        if not find_nmap():
            return result('partial', 'Nmap not detected yet. Restart Sentinel after the installer finishes.')
        return result('completed', 'Nmap executable detected. Native assessments are available; scan operation is not verified.')

    executable = find_docker()
    if not executable:
        install('docker')
        executable = find_docker()
    if cancel.is_set():
        return result('cancelled', 'Setup stopped; installed components are retained.')
    if not executable:
        return result('partial', 'Docker CLI not detected yet. Restart Windows or Sentinel after setup.')
    prefix = local_docker_prefix(platform)
    prefix[0] = executable
    health = invoke(prefix + ['version', '--format', '{{.Server.Os}}'], 15, cancel)
    if health.returncode != 0 or health.cancelled or health.timed_out or health.truncated or health.stdout.strip() != 'linux':
        return result('partial', 'Docker installed or detected. Open Docker Desktop, review its terms, and start the Linux engine. Restart Windows if requested, then retry.')
    if kind == 'docker':
        return result('completed', 'Local Linux Docker engine responded. No scanner was launched.')
    if cancel.is_set():
        return result('cancelled', 'Setup cancelled before preparing Kali tools.')
    if (payload / 'rootfs.sha256').is_file():
        # Existing hash-checked packaged workflow. No separate Kali VM.
        backend = prepare('docker')
        remember(backend, bundle.preference_path())
    else:
        if not dockerfile.is_file():
            return result('partial', 'Toolkit recipe unavailable. Use the official Sentinel installer or complete source checkout.')
        tag = 'sentinel-local/source-toolkit'
        built = invoke(prefix + ['build', '--platform', 'linux/amd64', '--tag', tag,
                                 str(dockerfile.parent)], 1200, cancel)
        if built.returncode != 0 or built.cancelled or built.timed_out or built.truncated:
            return result('partial', 'Kali toolkit build did not finish. Check Docker and internet access, then retry.')
        inspected = invoke(prefix + ['image', 'inspect', '--format', '{{.Id}}', tag], 15, cancel)
        image = inspected.stdout.strip()
        if inspected.returncode != 0 or inspected.cancelled or inspected.timed_out or inspected.truncated or not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            return result('partial', 'The built image could not be verified.')
        backend = Backend('docker', image)
    if cancel.is_set():
        return result('cancelled', 'Setup cancelled; prepared components are retained.')
    return result('completed', 'Kali toolkit prepared: WhatWeb and sslscan. Scan connectivity is not verified.',
                  backend=backend.kind, environment=backend.environment)
