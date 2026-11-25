"""Discover installed WSL distributions and inspect supported executables."""
import re
import subprocess

from . import runner
from .backends import SUPPORTED, is_wsl_distribution


def distributions(invoke=subprocess.run):
    """Return registered distributions usable by Sentinel, with Kali listed first."""
    try:
        result = invoke(['wsl.exe', '--list', '--quiet'], capture_output=True,
                        stdin=subprocess.DEVNULL, timeout=8,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except FileNotFoundError:
        raise ValueError('Windows Subsystem for Linux (WSL) was not found.') from None
    except subprocess.TimeoutExpired:
        raise ValueError('WSL did not respond while listing distributions.') from None
    except OSError:
        raise ValueError('Windows could not start WSL.') from None
    if result.returncode:
        # Some WSL versions return an error when the distribution list is empty.
        diagnostic = _decode(result.stdout + result.stderr)
        if 'WSL_E_DISTRO_NOT_FOUND' in diagnostic.upper():
            return []
        raise ValueError('WSL could not list its distributions. Check wsl --list in PowerShell.')
    names = {name for line in _decode(result.stdout).splitlines()
             if is_wsl_distribution(name := line.strip())}
    return sorted(names, key=lambda name: (name.casefold() != 'kali-linux', name.casefold(), name))


def _decode(raw):
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16', 'replace')
    if b'\0' in raw:
        return raw.decode('utf-16-le', 'replace')
    return raw.decode('utf-8-sig', 'replace')


def available_tools(distribution, cancel=None, invoke=runner.run):
    """Inspect PATH for fixed Sentinel adapters and their timeout dependency."""
    if not is_wsl_distribution(distribution):
        raise ValueError('Select an installed WSL distribution.')
    names = ('timeout', *sorted(SUPPORTED))
    script = 'for name do if command -v "$name" >/dev/null 2>&1; then printf "%s\\n" "$name"; fi; done'
    try:
        result = invoke(['wsl.exe', '--distribution', distribution, '--exec',
                         '/bin/sh', '-c', script, 'sentinel-wsl', *names], 15, cancel)
    except OSError:
        raise ValueError('Windows could not start WSL.') from None
    if result.cancelled:
        return []
    if result.returncode or result.timed_out or result.truncated:
        raise ValueError('Could not inspect this WSL distribution. Open it once to finish its setup, then retry.')
    found = set(re.split(r'\s+', result.stdout.strip()))
    return [name for name in names if name in found]
