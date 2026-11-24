"""Run an external program safely: no shell, bounded time and output, cancellable."""
from dataclasses import dataclass
import os
import re
import subprocess
import threading
import time

MAX_OUTPUT = 16_000_000
_CTRL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')


@dataclass
class RunResult:
    returncode: int | None
    stdout: str
    stderr: str
    cancelled: bool = False
    timed_out: bool = False


def clean(text, limit=120):
    """Make untrusted tool/banner text safe to show: no control characters, bounded length."""
    s = _CTRL.sub('', str(text or '')).replace('\r', ' ').replace('\n', ' ').strip()
    return s if len(s) <= limit else s[:limit - 1] + '…'


def _drain(stream, sink):
    total = 0
    for chunk in iter(lambda: stream.read(65536), b''):
        total += len(chunk)
        if total <= MAX_OUTPUT:
            sink.append(chunk)


def run(argv, timeout, cancel=None):
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if os.name == 'nt' else 0
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            shell=False, creationflags=flags)
    out, err = [], []
    threads = [threading.Thread(target=_drain, args=(proc.stdout, out), daemon=True),
               threading.Thread(target=_drain, args=(proc.stderr, err), daemon=True)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout
    cancelled = timed_out = False
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            cancelled = True
        elif time.monotonic() > deadline:
            timed_out = True
        if cancelled or timed_out:
            proc.terminate()
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
        time.sleep(0.2)
    for t in threads:
        t.join(2)
    for pipe in (proc.stdout, proc.stderr):
        pipe.close()
    dec = lambda parts: b''.join(parts).decode('utf-8', 'replace')
    return RunResult(proc.returncode, dec(out), dec(err), cancelled, timed_out)
