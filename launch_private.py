"""Source launcher: create and maintain a private Python environment.

No global pip installations, no activation, no administrator access.
The packaged Windows installer already includes its own Python runtime.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def environment_path(root=ROOT):
    local = os.environ.get('LOCALAPPDATA')
    base = Path(local) / 'Sentinel' / 'python' if local else root / '.venv'
    identity = hashlib.sha256(str(root.resolve()).encode('utf-8')).hexdigest()[:16]
    return base / (identity + '-py' + str(sys.version_info.major) + '.' + str(sys.version_info.minor))


def prepare(root=ROOT, env=None, invoke=subprocess.run, create=None):
    env = environment_path(root) if env is None else Path(env)
    executable = env / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    requirements = root / 'requirements-runtime.txt'
    digest = hashlib.sha256(requirements.read_bytes()).hexdigest()
    marker = env / '.sentinel-requirements'
    if not executable.is_file():
        print('Creating Sentinel private Python environment...', flush=True)
        if create is None:
            import venv
            create = venv.EnvBuilder(with_pip=True, system_site_packages=False).create
        create(env)
    if not executable.is_file():
        raise RuntimeError('Private Python environment could not be created.')
    ready = marker.is_file() and marker.read_text(encoding='ascii').strip() == digest
    probe = [str(executable), '-I', '-c', 'import packaging; import dns']
    if not ready or invoke(probe, check=False, capture_output=True).returncode:
        print('Preparing Sentinel Python dependencies in its private environment...', flush=True)
        invoke([str(executable), '-I', '-m', 'pip', 'install', '--disable-pip-version-check',
                '-r', str(requirements)], check=True)
        invoke(probe, check=True)
        marker.write_text(digest + '\n', encoding='ascii')
    return executable


def main():
    try:
        executable = prepare()
        return subprocess.call([str(executable), '-E', '-s', str(ROOT / 'run.py'), *sys.argv[1:]],
                               cwd=str(ROOT))
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print('Sentinel private environment setup failed: ' + str(exc), file=sys.stderr)
        print('Check your internet access and Python installation, then retry. No global packages were installed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
