"""Run an external program safely: no shell, bounded time and output, cancellable."""
from dataclasses import dataclass
import os
import re
import signal
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
    truncated: bool = False


def clean(text, limit=120):
    """Make untrusted tool/banner text safe to show: no control characters, bounded length."""
    s = _CTRL.sub('', str(text or '')).replace('\r', ' ').replace('\n', ' ').strip()
    return s if len(s) <= limit else s[:limit - 1] + '…'


def _drain(stream, sink, truncated):
    total = 0
    try:
        for chunk in iter(lambda: stream.read(65536), b''):
            remaining = max(0, MAX_OUTPUT - total)
            if remaining:
                sink.append(chunk[:remaining])
            total += len(chunk)
            if total > MAX_OUTPUT:
                truncated.set()
    except OSError:
        truncated.set()
    finally:
        stream.close()


def _close_group(proc, job):
    """Stop owned descendants even when the original process already exited."""
    if job is not None:
        job.close()
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run(argv, timeout, cancel=None):
    if cancel is not None and cancel.is_set():
        return RunResult(None, '', '', cancelled=True)
    if not argv or timeout <= 0:
        raise ValueError('A command and positive timeout are required.')
    windows = os.name == 'nt'
    job = None
    if windows:
        from .windows_job import WindowsJob
        job = WindowsJob()
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0) if windows else 0,
                                start_new_session=not windows)
    except BaseException:
        if job is not None:
            job.close()
        raise
    if job is not None:
        try:
            job.assign(proc)
        except BaseException:
            # Do not proceed when ownership cannot be established.
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=3)
            finally:
                job.close()
                proc.stdout.close()
                proc.stderr.close()
            raise
    out, err = [], []
    truncated = threading.Event()
    threads = [threading.Thread(target=_drain, args=(proc.stdout, out, truncated), daemon=True),
               threading.Thread(target=_drain, args=(proc.stderr, err, truncated), daemon=True)]
    cancelled = timed_out = False
    deadline = time.monotonic() + timeout
    try:
        for thread in threads:
            thread.start()
        while proc.poll() is None:
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.05)
    finally:
        try:
            _close_group(proc, job)
        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            proc.wait(timeout=5)
            # Do not call close() on a buffered pipe still owned by a blocked
            # reader. An escaped child may retain its write handle indefinitely.
            for thread, pipe in zip(threads, (proc.stdout, proc.stderr)):
                if thread.ident is not None:
                    thread.join(2)
                if thread.is_alive():
                    truncated.set()
                else:
                    pipe.close()
    dec = lambda parts: b''.join(parts).decode('utf-8', 'replace')
    return RunResult(proc.returncode, dec(out), dec(err), cancelled, timed_out, truncated.is_set())
