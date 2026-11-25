"""Explicit optional execution environments. Never install tools or pull images."""
from dataclasses import dataclass, replace
from pathlib import PureWindowsPath
import re
import os
import uuid
from . import runner

SUPPORTED = {'nmap', 'sslscan', 'whatweb'}
PROXY_VARIABLES = ('http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')


def local_docker_prefix(platform=None):
    """Use the standard local daemon, never a user's selected remote context."""
    platform = os.name if platform is None else platform
    return ['docker', '--host', 'npipe:////./pipe/docker_engine' if platform == 'nt'
            else 'unix:///var/run/docker.sock']


def docker_cleanup(prefix, name, invoke):
    """Attempt removal and verify absence with a separate daemon query."""
    try:
        invoke(prefix + ['rm', '--force', name], 15, None)
    except (OSError, ValueError, RuntimeError):
        pass
    try:
        checked = invoke(prefix + ['container', 'ls', '-a', '--filter',
                         'name=^/' + name + '
    return re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name) is not None


@dataclass(frozen=True)
class Backend:
    kind: str = 'native'
    environment: str = ''

    def validate(self, tool):
        if self.kind not in ('native', 'wsl', 'docker'):
            raise ValueError('Unknown execution backend.')
        if self.kind == 'native':
            return
        if tool not in SUPPORTED:
            raise ValueError('This backend supports Nmap, sslscan and WhatWeb individually; select one of these tools.')
        if self.kind == 'wsl' and not is_wsl_distribution(self.environment):
            raise ValueError('Enter the exact installed WSL distribution name.')
        if self.kind == 'docker' and not re.fullmatch(r'(?:[a-z0-9][a-z0-9./:_-]*@)?sha256:[0-9a-f]{64}', self.environment):
            raise ValueError('Choose a local image by immutable sha256 ID or repository@sha256 digest.')

    def run(self, argv, timeout, cancel, directory, invoke=runner.run):
        if self.kind == 'native':
            return invoke(argv, timeout, cancel)
        if cancel is not None and cancel.is_set():
            return runner.RunResult(None, '', '', cancelled=True)
        # Docker clients and WSL may inject host proxy settings into the guest.
        # WhatWeb's IP-scoped result must describe the selected endpoint.
        direct_env = [key + '=' for key in PROXY_VARIABLES] if argv[0] == 'whatweb' else []
        if self.kind == 'wsl':
            path = PureWindowsPath(directory)
            if not re.fullmatch(r'[A-Za-z]:', path.drive):
                raise ValueError('WSL output needs a local Windows drive; UNC paths are not supported.')
            mapped = '/mnt/' + path.drive[0].lower() + '/' + '/'.join(path.parts[1:])
            command = [a.replace(directory, mapped).replace('\\', '/') for a in argv]
            if direct_env:
                command = ['env', *direct_env, *command]
            # A remote deadline remains effective if the Windows launcher exits.
            return invoke(['wsl.exe', '--distribution', self.environment, '--exec',
                           'timeout', '--signal=TERM', '--kill-after=3', str(timeout), *command], timeout + 5, cancel)
        needs_mount = any(directory in arg for arg in argv)
        if needs_mount and ',' in directory:
            raise ValueError('Docker output directory must not contain a comma.')
        name = 'sentinel-' + uuid.uuid4().hex
        command = [a.replace(directory, '/work').replace('\\', '/') for a in argv]
        prefix = local_docker_prefix()
        try:
            result = invoke(prefix + ['run', '--name', name, '--rm', '--pull=never',
                           '--memory=512m', '--cpus=1', '--pids-limit=64', '--cap-drop=ALL',
                           '--security-opt=no-new-privileges', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
                           *(['--mount', f'type=bind,source={directory},target=/work'] if needs_mount else []),
                           *['--env=' + value for value in direct_env],
                           '--entrypoint', command[0], self.environment, *command[1:]], timeout, cancel)
        finally:
            # Removal alone may fail, including after normal --rm cleanup.
            verified = docker_cleanup(prefix, name, invoke)
        return replace(result, cleanup_verified=verified)
, '--format', '{{.Names}}'], 10, None)
        return (checked.returncode == 0 and not checked.cancelled and not checked.timed_out
                and not checked.truncated and not checked.stdout.strip())
    except (OSError, ValueError, RuntimeError):
        return False


def is_wsl_distribution(name):
    return re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name) is not None


@dataclass(frozen=True)
class Backend:
    kind: str = 'native'
    environment: str = ''

    def validate(self, tool):
        if self.kind not in ('native', 'wsl', 'docker'):
            raise ValueError('Unknown execution backend.')
        if self.kind == 'native':
            return
        if tool not in SUPPORTED:
            raise ValueError('This backend supports Nmap, sslscan and WhatWeb individually; select one of these tools.')
        if self.kind == 'wsl' and not is_wsl_distribution(self.environment):
            raise ValueError('Enter the exact installed WSL distribution name.')
        if self.kind == 'docker' and not re.fullmatch(r'(?:[a-z0-9][a-z0-9./:_-]*@)?sha256:[0-9a-f]{64}', self.environment):
            raise ValueError('Choose a local image by immutable sha256 ID or repository@sha256 digest.')

    def run(self, argv, timeout, cancel, directory, invoke=runner.run):
        if self.kind == 'native':
            return invoke(argv, timeout, cancel)
        if cancel is not None and cancel.is_set():
            return runner.RunResult(None, '', '', cancelled=True)
        # Docker clients and WSL may inject host proxy settings into the guest.
        # WhatWeb's IP-scoped result must describe the selected endpoint.
        direct_env = [key + '=' for key in PROXY_VARIABLES] if argv[0] == 'whatweb' else []
        if self.kind == 'wsl':
            path = PureWindowsPath(directory)
            if not re.fullmatch(r'[A-Za-z]:', path.drive):
                raise ValueError('WSL output needs a local Windows drive; UNC paths are not supported.')
            mapped = '/mnt/' + path.drive[0].lower() + '/' + '/'.join(path.parts[1:])
            command = [a.replace(directory, mapped).replace('\\', '/') for a in argv]
            if direct_env:
                command = ['env', *direct_env, *command]
            # A remote deadline remains effective if the Windows launcher exits.
            return invoke(['wsl.exe', '--distribution', self.environment, '--exec',
                           'timeout', '--signal=TERM', '--kill-after=3', str(timeout), *command], timeout + 5, cancel)
        needs_mount = any(directory in arg for arg in argv)
        if needs_mount and ',' in directory:
            raise ValueError('Docker output directory must not contain a comma.')
        name = 'sentinel-' + uuid.uuid4().hex
        command = [a.replace(directory, '/work').replace('\\', '/') for a in argv]
        try:
            return invoke(['docker', 'run', '--name', name, '--rm', '--pull=never',
                           '--memory=512m', '--cpus=1', '--pids-limit=64', '--cap-drop=ALL',
                           '--security-opt=no-new-privileges', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
                           *(['--mount', f'type=bind,source={directory},target=/work'] if needs_mount else []),
                           *['--env=' + value for value in direct_env],
                           '--entrypoint', command[0], self.environment, *command[1:]], timeout, cancel)
        finally:
            # The Docker client exiting does not imply the container stopped.
            invoke(['docker', 'rm', '--force', name], 15, None)
