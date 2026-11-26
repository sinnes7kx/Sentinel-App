"""Read-only operations on explicitly selected local files."""
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat

from .review import MAX_REPORT, summarize
from .zap_review import detail_summary


def _regular_file(path):
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('Choose a regular file.')
    return path.open('rb')


def inspect_integrity(path, expected='', cancel=None):
    """Compute both digests in one pass and optionally compare a reference digest."""
    expected = expected.strip().lower()
    if expected and (len(expected) not in (64, 128) or re.fullmatch('[0-9a-f]+', expected) is None):
        raise ValueError('Enter a 64-character SHA-256 or 128-character SHA-512 hex digest.')
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    bytes_read = 0
    with _regular_file(Path(path)) as stream:
        before = os.fstat(stream.fileno())
        while not (cancel and cancel.is_set()):
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            bytes_read += len(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
        if cancel and cancel.is_set():
            return None
        after = os.fstat(stream.fileno())
        if bytes_read != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('The file changed while being read. Try again once it is stable.')

    checksums = {'SHA-256': sha256.hexdigest(), 'SHA-512': sha512.hexdigest()}
    result = {'Bytes read': bytes_read, **checksums}
    if expected:
        algorithm = 'SHA-256' if len(expected) == 64 else 'SHA-512'
        matches = hmac.compare_digest(checksums[algorithm], expected)
        result['Reference digest'] = f'{algorithm} · ' + ('Match' if matches else 'Mismatch')
    return result


def review_report(path, format_name):
    with _regular_file(Path(path)) as stream:
        raw = stream.read(MAX_REPORT + 1)
    if not raw or len(raw) > MAX_REPORT:
        raise ValueError('Choose a nonempty report of at most 5 MB.')
    if format_name == 'zap-detail':
        return detail_summary(raw)
    return summarize(format_name, raw)
