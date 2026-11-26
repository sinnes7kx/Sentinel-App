"""Import the toolkit shipped in Windows releases. All provisioning inputs are local."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from . import wsl
from .backends import Backend, local_docker_prefix

PAYLOAD = Path(__file__).resolve().parents[2] / 'toolkit'
BUNDLED_TOOLS = ('whatweb', 'sslscan')
WSL_MSI_SHA256 = '2313efc5873e3f8552f42e77f950fabd913c0289078fa89d2100f3421a525eaa'


def file_digest(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def call(argv, timeout=90):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=timeout, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except FileNotFoundError:
        raise ValueError(f'{Path(argv[0]).name} is unavailable. Choose WSL for the included Windows runtime.') from None
    except subprocess.TimeoutExpired:
        raise ValueError(f'{Path(argv[0]).name} timed out. Check the runtime and retry setup.') from None
    return result.returncode, wsl._decode(result.stdout + result.stderr).strip()


def checked(argv, timeout=90):
    code, output = call(argv, timeout)
    if code:
        raise ValueError(f'{Path(argv[0]).name} exited with code {code}. {output[-500:]}')
    return output


def registered_wsl(name):
    # wsl --list exits with localized errors on some clean Windows installations.
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Lxss')
    except FileNotFoundError:
        return False
    with key:
        for index in range(winreg.QueryInfoKey(key)[0]):
            with winreg.OpenKey(key, winreg.EnumKey(key, index)) as entry:
                try:
                    distribution, _ = winreg.QueryValueEx(entry, 'DistributionName')
                except FileNotFoundError:
                    continue
                if distribution.casefold() == name.casefold():
                    return True
    return False


def prepare(kind, payload=PAYLOAD):
    if kind not in ('wsl', 'docker'):
        raise ValueError('Choose WSL or Docker to prepare the included tools.')
    digest = (payload / 'rootfs.sha256').read_text(encoding='ascii').strip()
    archive = payload / 'kali-tools.tar.gz'
    if not re.fullmatch(r'[0-9a-f]{64}', digest) or file_digest(archive) != digest:
        raise ValueError('The Kali archive failed its integrity check. Restore the original Sentinel package.')
    if kind == 'docker':
        # Archive import produces a local image ID. It has no registry digest.
        tag = 'sentinel-local/kali:' + digest[:20]
        prefix = local_docker_prefix()
        checked(prefix + ['version', '--format', '{{.Server.Version}}'])
        inspect = prefix + ['image', 'inspect', '--format', '{{.Id}} {{index .Config.Labels "sentinel.rootfs"}}', tag]
        code, output = call(inspect)
        if code:
            checked(prefix + ['image', 'import', '--platform', 'linux/amd64', '--change',
                     'LABEL sentinel.rootfs=' + digest, str(archive), tag], 900)
            output = checked(inspect)
        parts = output.split()
        if len(parts) != 2 or parts[1] != digest or not re.fullmatch(r'sha256:[0-9a-f]{64}', parts[0]):
            raise ValueError('The local Docker image conflicts with this toolkit. Check the Sentinel image tag.')
        environment = parts[0]
        checked(prefix + ['run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL',
                 environment, '/bin/sh', '-ec', 'command -v whatweb && command -v sslscan && command -v timeout'])
    else:
        if os.name != 'nt':
            raise ValueError('WSL setup runs on Windows.')
        system = Path(os.environ['SystemRoot']) / 'System32'
        launcher = str(system / 'wsl.exe')
        # The package also supports clean Windows installations with only the WSL stub.
        if file_digest(payload / 'wsl-x64.msi') != WSL_MSI_SHA256:
            raise ValueError('The included Microsoft WSL installer failed its integrity check.')
        code, message = call([str(system / 'WindowsPowerShell/v1.0/powershell.exe'), '-NoProfile', '-NonInteractive',
                 '-ExecutionPolicy', 'Bypass', '-File', str(payload / 'enable-wsl.ps1')], 1200)
        if code == 3010:
            raise ValueError('Restart Windows, then choose Prepare included tools again.')
        if code:
            raise ValueError('Windows could not prepare WSL. ' + message[:500])
        environment = 'Sentinel-Kali-' + digest[:20]
        if not registered_wsl(environment):
            dest = Path(os.environ['LOCALAPPDATA']) / 'Sentinel' / 'runtimes' / environment
            dest.mkdir(parents=True, exist_ok=True)
            checked([launcher, '--import', environment, str(dest), str(archive), '--version', '2'], 900)
        marker = checked([launcher, '--distribution', environment, '--exec', '/bin/cat', '/etc/sentinel-toolkit'])
        if marker != 'sentinel-kali-tools-v1' or not set(BUNDLED_TOOLS + ('timeout',)) <= set(wsl.available_tools(environment)):
            raise ValueError('The registered Sentinel distribution failed its toolkit check.')
    return Backend(kind, environment)


def remember(backend, path):
    """Atomically save only a successfully verified runtime for this release."""
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False, encoding='utf-8') as stream:
        json.dump({'kind': backend.kind, 'environment': backend.environment}, stream)
    try:
        os.replace(stream.name, path)
    finally:
        Path(stream.name).unlink(missing_ok=True)


def preference_path():
    digest = (PAYLOAD / 'rootfs.sha256').read_text(encoding='ascii').strip()
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('Invalid toolkit manifest.')
    return Path(os.environ['LOCALAPPDATA']) / 'Sentinel' / ('toolkit-' + digest[:20] + '.json')


def saved_backend():
    try:
        saved = json.loads(preference_path().read_text(encoding='utf-8'))
        backend = Backend(saved['kind'], saved['environment'])
        if backend.kind in ('wsl', 'docker'):
            backend.validate('whatweb')
            return backend
    except (OSError, ValueError, TypeError, KeyError):
        pass
    return Backend('wsl')
