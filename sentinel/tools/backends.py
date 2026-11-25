"""Explicit optional execution environments. Never install tools or pull images."""
from dataclasses import dataclass
from pathlib import PureWindowsPath
import re
import uuid
from . import runner

SUPPORTED = {'nmap', 'sslscan', 'whatweb'}


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
        if self.kind == 'docker' and not re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}', self.environment):
            raise ValueError('Choose a locally installed Docker image pinned with @sha256 and its 64-character digest.')

    def run(self, argv, timeout, cancel, directory, invoke=runner.run):
        if self.kind == 'native':
            return invoke(argv, timeout, cancel)
        if cancel is not None and cancel.is_set():
            return runner.RunResult(None, '', '', cancelled=True)
        if self.kind == 'wsl':
            path = PureWindowsPath(directory)
            if not re.fullmatch(r'[A-Za-z]:', path.drive):
                raise ValueError('WSL output needs a local Windows drive; UNC paths are not supported.')
            mapped = '/mnt/' + path.drive[0].lower() + '/' + '/'.join(path.parts[1:])
            command = [a.replace(directory, mapped).replace('\\', '/') for a in argv]
            # A remote deadline remains effective if the Windows launcher exits.
            return invoke(['wsl.exe', '--distribution', self.environment, '--exec',
                           'timeout', '--signal=TERM', '--kill-after=3', str(timeout), *command], timeout + 5, cancel)
        if ',' in directory:
            raise ValueError('Docker output directory must not contain a comma.')
        name = 'sentinel-' + uuid.uuid4().hex
        command = [a.replace(directory, '/work').replace('\\', '/') for a in argv]
        try:
            return invoke(['docker', 'run', '--name', name, '--rm', '--pull=never',
                           '--memory=512m', '--cpus=1', '--pids-limit=64', '--cap-drop=ALL',
                           '--security-opt=no-new-privileges', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
                           '--mount', f'type=bind,source={directory},target=/work',
                           '--entrypoint', command[0], self.environment, *command[1:]], timeout, cancel)
        finally:
            # The Docker client exiting does not imply the container stopped.
            invoke(['docker', 'rm', '--force', name], 15, None)
