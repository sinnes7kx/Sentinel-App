"""WhatWeb: identify the technology a website reveals about itself."""
import json

from ..engine import Finding
from . import runner
from .base import Profile, ToolSpec

INSTALL_HINT = ('WhatWeb is not installed. On Kali/Debian/Ubuntu run: sudo apt install whatweb\n'
                'WhatWeb is a Ruby program; on Windows use WSL or run Sentinel on Kali.')

PROFILES = {
    'passive': Profile('passive', 'Passive (1 request)', 'Reads what the home page reveals. One normal request.',
                       ('-a', '1'), 120, 'one request to the exact URL'),
    'standard': Profile('standard', 'Standard', 'Also follows up where a technology needs a closer look. A few requests.',
                        ('-a', '3'), 300, 'a few requests to the site'),
}
NOISE = {'ip', 'country', 'title', 'html5', 'uncommonheaders', 'script', 'email', 'httponly', 'cookies', 'meta-refresh-redirect',
         'redirectlocation', 'x-frame-options', 'strict-transport-security', 'content-language', 'passwordfield', 'frame', 'x-xss-protection'}
MAX_ITEMS = 40


def _records(text):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for line in text.splitlines():
            line = line.strip().rstrip(',').lstrip('[').rstrip(']').strip()
            if line.startswith('{'):
                data.append(json.loads(line))
        if not data:
            raise
    return data if isinstance(data, list) else [data]


def parse_json(text, private=False):
    out, seen = [], set()
    for rec in _records(text):
        if not isinstance(rec, dict):
            continue
        for name, info in (rec.get('plugins') or {}).items():
            if name.lower() in NOISE or name in seen or not isinstance(info, dict):
                continue
            seen.add(name)
            bits = []
            for key in ('version', 'string', 'os', 'module'):
                vals = info.get(key)
                if isinstance(vals, list):
                    bits += [runner.clean(v, 60).rstrip(',') for v in vals[:3]]
            detail = ', '.join(b for b in bits if b)
            has_version = bool(info.get('version'))
            out.append(Finding('WHATWEB_' + runner.clean(name, 40).replace(' ', '_'), 'info',
                               'Technology identified: ' + runner.clean(name, 40) + (' ' + runner.clean(', '.join(map(str, info['version'][:2])), 40).rstrip(',') if has_version else ''),
                               f'The site reveals {runner.clean(name, 40)}' + (f' ({detail})' if detail else '') + '.',
                               'Keep this software updated. Hiding exact version numbers (for example ServerTokens, expose_php=Off) makes it harder for attackers to pick known exploits, but it is not a substitute for patching.'))
    return out[:MAX_ITEMS], {'technologies': len(out)}, ''


def build(binary, target, profile, outfile):
    return [binary, '--no-errors', '--color=never', '--log-json=' + outfile, *PROFILES[profile].args, target.url]


SPEC = ToolSpec('whatweb', 'WhatWeb technology fingerprint', 'Shows which web server, framework and CMS a site advertises, and their versions.', 'web',
                ('whatweb',), INSTALL_HINT, PROFILES, build, parse_json, outfile='.json', schemes=('http', 'https'),
                note='Identifies technologies only; it does not test for vulnerabilities.')
