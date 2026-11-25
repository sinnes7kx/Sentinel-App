"""Local-only inventory for the guided assessment screen.

Presence is not execution readiness: no binary is launched, no image is pulled,
and no target is contacted. Existing tool execution retains its scope checks.
"""
from dataclasses import dataclass
import shutil
from .tools import TOOLS
from .tools.base import ToolSpec, find_binary


@dataclass(frozen=True)
class Readiness:
    name: str
    state: str
    explanation: str


def inventory(lookup=find_binary, which=shutil.which):
    rows = [Readiness('Built-in website checks', 'Available',
                      'Uses Sentinel itself; no external tools needed.')]
    for spec in TOOLS:
        if isinstance(spec, ToolSpec):
            found = bool(lookup(spec))
            rows.append(Readiness(spec.name, 'Detected' if found else 'Not detected',
                                  'Native executable located; version and operation unverified.'
                                  if found else 'May be available in a separately prepared Linux environment.'))
    for name, binary in [('Docker', 'docker'), ('Kali / WSL', 'wsl.exe')]:
        found = bool(which(binary))
        rows.append(Readiness(name, 'Client detected' if found else 'Not detected',
                              'Open Security tools to configure and check this environment.'
                              if found else 'Optional; built-in assessments still work.'))
    return tuple(rows)
