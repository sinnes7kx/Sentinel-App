"""Build the x64 offline installer on Linux with Docker, NSIS and Python 3.12+."""
import argparse
import gzip
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import urlopen
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from sentinel.tools.bundle import file_digest, WSL_MSI_SHA256

SOURCES = {
    'python.tgz': (
        'https://github.com/astral-sh/python-build-standalone/releases/download/20261124/'
        'cpython-3.13.18%2B20261124-x86_64-pc-windows-msvc-install_only.tar.gz',
        '9c22438c8f107dc88505394a87a61aab3504d33d1ce4e22eb177381e5e9b244f'),
    'wsl-x64.msi': ('https://github.com/microsoft/WSL/releases/download/3.0.5/wsl.3.0.5.0.x64.msi',
                    WSL_MSI_SHA256),
    'packaging.whl': ('https://files.pythonhosted.org/packages/ba/7b/5504f91c9c2733f693d7759e50ede5d27119d4da7e5836c46d3b5ff81d56/packaging-26.4-py3-none-any.whl',
                      '81383611a09c1bc0b08b76e0fd5829d7c6824c65b27a6aee339da133f4233ea2'),
    'dnspython.whl': ('https://files.pythonhosted.org/packages/ba/5a/18ad964b0086c6e62e2e7500f7edc89e3faa45033c71c1893d34eed2b2de/dnspython-2.8.0-py3-none-any.whl',
                      '01d9bbc4a2d76bf0db7c1f729812ded6d912bd318d3b1cf81d30c0f845dbf3af'),
}


def fetch(cache):
    cache.mkdir(parents=True, exist_ok=True)
    for name, (url, expected) in SOURCES.items():
        path = cache / name
        if not path.exists():
            with urlopen(url, timeout=180) as source, tempfile.NamedTemporaryFile(dir=cache, delete=False) as tmp:
                shutil.copyfileobj(source, tmp)
            Path(tmp.name).replace(path)
        if file_digest(path) != expected:
            raise ValueError(f'Checksum mismatch. Remove {path} and rebuild.')


def stage_payload(stage, cache):
    fetch(cache)
    toolkit = stage / 'toolkit'
    toolkit.mkdir()
    shutil.copy(cache / 'wsl-x64.msi', toolkit)
    shutil.copy(HERE / 'enable-wsl.ps1', toolkit)
    with tarfile.open(cache / 'python.tgz') as source:
        source.extractall(stage, members=(m for m in source if not m.name.endswith(('.pdb', '.pyc'))),
                          filter='data')
    for wheel in cache.glob('*.whl'):
        if wheel.name in SOURCES:
            with ZipFile(wheel) as archive:
                archive.extractall(stage / 'python/Lib/site-packages')
    for name in ('run.py', 'README.md', 'demo_site.py'):
        shutil.copy(ROOT / name, stage)
    shutil.copytree(ROOT / 'sentinel', stage / 'sentinel', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '-t', 'sentinel-tools-build', str(HERE)], check=True)
    container = subprocess.check_output(['docker', 'create', 'sentinel-tools-build'], text=True).strip()
    archive = toolkit / 'kali-tools.tar.gz'
    try:
        with subprocess.Popen(['docker', 'export', container], stdout=subprocess.PIPE) as process:
            with gzip.open(archive, 'wb', compresslevel=4) as stream:
                shutil.copyfileobj(process.stdout, stream)
            if process.wait():
                raise RuntimeError('Docker filesystem export failed.')
    finally:
        subprocess.run(['docker', 'rm', container], check=True)
    (toolkit / 'rootfs.sha256').write_text(file_digest(archive) + '\n', encoding='ascii')
    packages = subprocess.check_output(['docker', 'run', '--rm', 'sentinel-tools-build', 'dpkg-query',
                                        '-W', '-f', '${Package}\t${Version}\n'])
    (toolkit / 'kali-packages.tsv').write_bytes(packages)


def build(stage, output):
    with tempfile.TemporaryDirectory() as temp:
        cleanup = Path(temp) / 'uninstall.nsh'
        # Remove exactly the distributed files and empty application directories.
        with cleanup.open('w', encoding='utf-8') as stream:
            for path in sorted(stage.rglob('*'), reverse=True):
                rel = str(path.relative_to(stage)).replace('/', '\\').replace('$', '$$')
                command = 'RMDir' if path.is_dir() else 'Delete'
                stream.write(f'{command} "$INSTDIR\\{rel}"\n')
        subprocess.run(['makensis', '-V2', f'-DOUTPUT={output}', f'-DSTAGE={stage}',
                        f'-DUNINSTALL_FILES={cleanup}', str(HERE / 'installer.nsi')], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--cache', type=Path, default=Path.home() / '.cache/sentinel-build')
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        stage = Path(directory)
        stage_payload(stage, args.cache)
        build(stage, args.output.resolve())
