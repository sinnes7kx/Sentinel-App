"""Build the x64 offline installer on Linux with NSIS, 7-Zip, RubyGems and Python 3.12+."""
import argparse
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
from sentinel.tools.bundle import file_digest

SOURCES = {
    'python.tgz': (
        'https://github.com/astral-sh/python-build-standalone/releases/download/20261124/'
        'cpython-3.13.18%2B20261124-x86_64-pc-windows-msvc-install_only.tar.gz',
        '9c22438c8f107dc88505394a87a61aab3504d33d1ce4e22eb177381e5e9b244f'),
    'sslscan.zip': ('https://github.com/rbsec/sslscan/releases/download/2.2.4/sslscan-2.2.4.zip',
                    '6e803b87c84835916868c414aa6c1f0e5b85a554b37ab35c1a91a7df605cbe05'),
    'sslscan-license.txt': ('https://raw.githubusercontent.com/rbsec/sslscan/2.2.4/LICENSE',
                            '8c75a9231db8906865e29706ed63aad18fd918c92c15dbefbb13c25fe42850b4'),
    'ruby33.7z': ('https://github.com/oneclick/rubyinstaller2/releases/download/RubyInstaller-3.3.14-1/'
                  'rubyinstaller-3.3.14-1-x64.7z',
                  '03b6ed68fba9e632f0f6e93af99c1bc55315e1bfad0296a105268296cbcdb8ba'),
    'whatweb.tgz': ('https://codeload.github.com/urbanadventurer/WhatWeb/tar.gz/refs/tags/v0.6.4',
                    '611cde154ad864ffc430ac34e87ca746dbe0f0cc47a116ba06de3cb61e923b15'),
    'addressable-2.8.8.gem': ('https://rubygems.org/downloads/addressable-2.8.8.gem',
                              '7c13b8f9536cf6364c03b9d417c19986019e28f7c00ac8132da4eb0fe393b057'),
    'public_suffix-6.0.2.gem': ('https://rubygems.org/downloads/public_suffix-6.0.2.gem',
                                'bfa7cd5108066f8c9602e0d6d4114999a5df5839a63149d3e8b0f9c1d3558394'),
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
    native = stage / 'native-tools'
    native.mkdir()
    with ZipFile(cache / 'sslscan.zip') as archive:
        archive.extractall(native / 'sslscan')
    shutil.copy(cache / 'sslscan-license.txt', native / 'sslscan/LICENSE')
    with tarfile.open(cache / 'whatweb.tgz') as archive:
        archive.extractall(native, filter='data')
    (native / 'WhatWeb-0.6.4').rename(native / 'whatweb')
    shutil.copy(HERE / 'launch-whatweb.rb', native)
    subprocess.run(['7z', 'x', '-bd', '-o' + str(native), str(cache / 'ruby33.7z')], check=True,
                   stdout=subprocess.DEVNULL)
    (native / 'rubyinstaller-3.3.14-1-x64').rename(native / 'ruby')
    gems = native / 'ruby/lib/ruby/gems/3.3.0'
    subprocess.run(['gem', 'install', '--local', '--no-document', '--ignore-dependencies',
                    '--install-dir', str(gems), str(cache / 'public_suffix-6.0.2.gem'),
                    str(cache / 'addressable-2.8.8.gem')], check=True)


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
