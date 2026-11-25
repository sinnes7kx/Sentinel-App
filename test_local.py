"""Run local regression tests with the same private Python as Sentinel.

No cloud workflow, external scanner, arbitrary target or Docker build is started.
First-run dependency preparation may download the pinned Python packages.
"""
import os
import shutil
from pathlib import Path
import subprocess
import sys
from datetime import datetime
from launch_private import ROOT, prepare


def test_environment(environ=None, platform=None, which=shutil.which):
    """Find an existing OpenSSL installation for local TLS fixtures only.

    Never download software or modify the user's system PATH.
    """
    env = dict(os.environ if environ is None else environ)
    env.update(SENTINEL_REQUIRE_GUI='1', PYTHONIOENCODING='utf-8')
    platform = os.name if platform is None else platform
    if platform == 'nt' and not which('openssl', path=env.get('PATH', '')):
        # Git for Windows often includes OpenSSL outside its public PATH.
        for variable in ('ProgramFiles', 'ProgramW6432', 'ProgramFiles(x86)'):
            root = env.get(variable)
            if not root:
                continue
            candidate = Path(root) / 'Git' / 'usr' / 'bin'
            if (candidate / 'openssl.exe').is_file():
                env['PATH'] = os.pathsep.join(filter(None, (env.get('PATH'), str(candidate))))
                break
    return env


def main():
    base = Path(os.environ.get('LOCALAPPDATA') or ROOT) / 'Sentinel' / 'test-logs'
    base.mkdir(parents=True, exist_ok=True)
    path = base / ('tests-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.txt')
    print('Local test log: ' + str(path), flush=True)
    with path.open('w', encoding='utf-8') as log:
        def say(line):
            print(line, flush=True)
            log.write(line + '\n')
            log.flush()

        try:
            python = prepare()
            env = test_environment()
            say('OpenSSL fixture support: ' + ('detected' if shutil.which('openssl', path=env.get('PATH', ''))
                                              else 'not detected; live TLS fixture tests may be skipped.'))
            for args in (['-m', 'compileall', '-q', 'sentinel', 'tests'],
                         ['-m', 'unittest', 'discover', '-s', 'tests', '-v']):
                say('Running: python ' + ' '.join(args))
                with subprocess.Popen([str(python), '-s', '-B', *args],
                                      cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, encoding='utf-8',
                                      errors='replace') as proc:
                    for line in proc.stdout:
                        say(line.rstrip('\r\n'))
                    status = proc.wait()
                if status:
                    say('FAILED. Exit code: ' + str(status))
                    return status
            say('PASSED: local regression suite completed. Check any skipped tests above.')
            say('Docker integration and cross-platform matrix were not run.')
            return 0
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            say('Test setup failed: ' + type(exc).__name__ + '. Check Python and dependency preparation.')
            return 1


if __name__ == '__main__':
    sys.exit(main())
