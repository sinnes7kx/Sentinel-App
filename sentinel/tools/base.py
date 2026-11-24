"""Generic engine every wrapped tool runs through.

A tool is a ToolSpec: fixed profiles, an argv builder and a parser. execute()
does the shared, safety-critical work in one place: parse the target, enforce
scope and authorization, locate the binary, run with limits, parse untrusted
output, and return an ordinary sentinel.engine.Scan.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable
import os
import shutil
import tempfile

from ..engine import Scan, Target
from . import runner
from .scope import parse_net_target, require_authorization


class ToolMissing(RuntimeError):
    pass


@dataclass(frozen=True)
class Profile:
    id: str
    label: str
    blurb: str
    args: tuple
    timeout: int
    coverage: str


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    blurb: str
    kind: str                       # 'net' (IP/host/range) or 'web' (http/https URL)
    binaries: tuple
    install_hint: str
    profiles: dict
    build: Callable                 # (binary, target, profile_id, outfile) -> argv list
    parse: Callable                 # (text, private) -> (findings, info dict, note)
    outfile: str = ''               # suffix if the tool writes a file (e.g. '.json'); '' = read stdout
    schemes: tuple = ()             # allowed URL schemes for web tools; () = any
    win_paths: tuple = ()           # relative to Program Files, e.g. 'Nmap\\nmap.exe'
    extra_coverage: dict = field(default_factory=dict)
    note: str = ''                  # shown to the user before running

    def installed(self):
        return find_binary(self) is not None

    def scan(self, value, profile, attested=False, confirm='', cancel=None, **kw):
        return execute(self, value, profile, attested, confirm, cancel, **kw)


def find_binary(spec):
    for name in spec.binaries:
        found = shutil.which(name)
        if found:
            return found
    for rel in spec.win_paths:
        for base in (os.environ.get('ProgramFiles(x86)'), os.environ.get('ProgramFiles')):
            if base and os.path.isfile(os.path.join(base, rel)):
                return os.path.join(base, rel)
    return None


def parse_scope(spec, value, resolver=None):
    """Return (target, scope, label). `scope` is the NetTarget used for authorization."""
    resolve = (lambda h: parse_net_target(h, resolver)) if resolver else parse_net_target
    if spec.kind == 'net':
        scope = resolve(value)
        return scope, scope, scope.value
    target = Target.parse(value)
    if spec.schemes and target.scheme not in spec.schemes:
        raise ValueError(f"{spec.name} needs an {' or '.join(s + '://' for s in spec.schemes)} address.")
    return target, resolve(target.host), target.url


def execute(spec, value, profile, attested=False, typed_confirmation='', cancel=None,
            resolver=None, run=runner.run, binary=None):
    if profile not in spec.profiles:
        raise ValueError('Unknown scan profile.')
    target, scope, label = parse_scope(spec, value, resolver)
    require_authorization(scope, attested, typed_confirmation)
    binary = binary or find_binary(spec)
    if not binary:
        raise ToolMissing(spec.install_hint)
    prof = spec.profiles[profile]
    started = datetime.now(timezone.utc).isoformat(timespec='seconds')
    coverage = {'tool': spec.id, 'profile': prof.label, 'checks': prof.coverage, **spec.extra_coverage}

    def result(status, findings=(), error=''):
        return Scan(label, started, status, None, None, list(findings), error, coverage=coverage,
                    profile=f'{spec.id}-{profile}')

    if cancel is not None and cancel.is_set():
        return result('cancelled', error='Cancelled before the scan started.')
    with tempfile.TemporaryDirectory(prefix='sentinel-') as tmp:
        outfile = os.path.join(tmp, 'sentinel-out' + spec.outfile) if spec.outfile else ''
        r = run(spec.build(binary, target, profile, outfile), prof.timeout, cancel)
        if r.cancelled:
            return result('cancelled', error='Scan cancelled; results are incomplete.')
        if r.timed_out:
            return result('partial', error='The scan hit its time limit; results are incomplete.')
        text = r.stdout
        if outfile:
            try:
                with open(outfile, encoding='utf-8', errors='replace') as fh:
                    text = fh.read(runner.MAX_OUTPUT)
            except OSError:
                text = ''
    try:
        if not text.strip():
            raise ValueError('no output')
        findings, info, note = spec.parse(text, scope.private)
    except Exception:       # untrusted output: any parse problem is a safe failure, never a crash
        return result('failed', error=f'{spec.name} did not finish: ' + (runner.clean(r.stderr, 300) or f'exit code {r.returncode}'))
    coverage.update(info)
    return result('completed', findings, note)
