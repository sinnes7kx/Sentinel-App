"""Nikto: look for risky web-server configuration and leftover files.

Only the non-attacking test groups are used. Denial-of-service, injection,
command-execution and brute-force groups are never enabled. Nikto reports
pattern matches without rating them, so Sentinel assigns conservative levels
from keywords and says so; every finding needs manual verification.
"""
import functools
import hashlib
import json
import re

from ..engine import Finding
from . import runner
from .base import Profile, ToolSpec

INSTALL_HINT = ('Nikto is not installed. On Kali/Debian/Ubuntu run: sudo apt install nikto\n'
                'Nikto is a Perl program; on Windows use WSL or run Sentinel on Kali.')

PROFILES = {
    'safe': Profile('safe', 'Safe check', 'Looks for misconfiguration and information leaks. No attack payloads.',
                    ('-Tuning', '1,2,3,b', '-maxtime', '15m'), 1200, 'interesting files, misconfiguration, information disclosure, software identification'),
    'deeper': Profile('deeper', 'Deeper check', 'Also probes for admin consoles and readable files. Noisier: prefer a test copy of your site.',
                      ('-Tuning', '1,2,3,5,7,b,d,e', '-maxtime', '30m'), 2100, 'safe groups plus file retrieval, admin consoles, web services'),
}

# (pattern, level, advice) - first match wins
RULES = [
    (r'\.git|\.svn|\.env|\.htpasswd|wp-config|id_rsa|database\.yml|credentials', 'high',
     'Remove this file from the web root immediately, then rotate any secrets it may have contained.'),
    (r'backup|\.bak|\.old|\.sql|\.zip|\.tar|\.swp|dump', 'medium',
     'Delete backup and archive files from the web root; keep them outside the publicly served folder.'),
    (r'directory indexing|directory listing|index of', 'medium',
     'Turn off automatic directory listings in the web server configuration.'),
    (r'phpinfo|server-status|server-info|test\.php|info\.php', 'medium',
     'Remove diagnostic pages or restrict them to administrators.'),
    (r'allowed http methods.*(put|delete|trace|connect)|http method.*(put|delete|trace)', 'medium',
     'Disable HTTP methods the application does not use (PUT, DELETE, TRACE, CONNECT).'),
    (r'default (file|credential|password|page)|default installation', 'low',
     'Remove default content and change default credentials.'),
    (r'admin|login|phpmyadmin|manager|console', 'low',
     'Make sure administration pages require strong authentication and are not open to the whole internet.'),
    (r'outdated|appears to be|retrieved .*banner|server banner|x-powered-by', 'info',
     'Keep server software updated. Version banners can be inaccurate, so confirm the real version before acting.'),
]
DEFAULT_ADVICE = 'Check whether this path or setting is needed. Remove or restrict it if not. Nikto matches known patterns and can be wrong, so verify it yourself.'
MAX_FINDINGS = 150


METHODS = ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PROPFIND', 'CONNECT', 'PATCH')


def _items_json(text):
    data = json.loads(text)
    for h in data if isinstance(data, list) else [data]:
        if isinstance(h, dict):
            for v in h.get('vulnerabilities') or []:
                if isinstance(v, dict):
                    yield v


_CSV_TAIL = re.compile(r'"([^"]*)","(%s)","([^"]*)","([^"]*)"\s*$' % '|'.join(METHODS))


def _items_csv(text):
    """Nikto 2.1.x has no JSON and its CSV is malformed (a missing comma and stray 'SCALAR(0x..)' text),
    so read each row from the end: id, method, url, message."""
    for line in text.splitlines():
        m = _CSV_TAIL.search(line)
        if m:
            yield {'id': m.group(1), 'method': m.group(2), 'url': m.group(3), 'msg': m.group(4)}


def parse(text, private=False):
    if text.lstrip().startswith(('[', '{')):
        items = _items_json(text)
    elif '"Nikto - v' in text or '- Nikto v' in text:
        items = _items_csv(text)
    else:
        raise ValueError('Unrecognized Nikto output')   # never report "nothing found" for output we cannot read
    out, seen = [], set()
    if True:
        for v in items:
            nid = runner.clean(v.get('id', ''), 20)
            url = runner.clean(v.get('url', ''), 150)
            msg = runner.clean(v.get('msg', ''), 400)
            method = runner.clean(v.get('method', 'GET'), 10) or 'GET'
            if not msg:
                continue
            fid = 'NIKTO_%s_%s' % (nid or 'x', hashlib.sha1((url + msg).encode('utf-8', 'replace')).hexdigest()[:8])
            if fid in seen:
                continue
            seen.add(fid)
            level, advice = 'info', DEFAULT_ADVICE
            hay = (url + ' ' + msg).lower()
            for pat, lvl, adv in RULES:
                if re.search(pat, hay):
                    level, advice = lvl, adv
                    break
            title = 'Nikto: ' + (msg if len(msg) <= 90 else msg[:89] + '…')
            out.append(Finding(fid, level, title,
                               f'Nikto test {nid or "?"}: {method} {url or "/"} - {msg}. Severity is a keyword-based estimate, not a Nikto rating.',
                               advice))
    order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
    out.sort(key=lambda f: (order[f.severity], f.id))
    total = len(out)
    return out[:MAX_FINDINGS], {'items_reported': total}, ('Only the first %d of %d items are shown.' % (MAX_FINDINGS, total) if total > MAX_FINDINGS else '')


@functools.lru_cache(maxsize=8)
def supports_json(binary):
    try:
        return 'json' in runner.run([binary, '-Help'], 15).stdout.lower()
    except OSError:
        return False


def build(binary, target, profile, outfile):
    fmt = 'json' if supports_json(binary) else 'csv'   # Nikto 2.5+ has JSON; 2.1.x only csv/xml/txt
    return [binary, '-h', target.url, '-nointeractive', '-ask', 'no', '-nolookup', '-timeout', '10',
            '-Format', fmt, '-output', outfile, *PROFILES[profile].args]


SPEC = ToolSpec('nikto', 'Nikto web server check', 'Finds risky web server settings, leftover files and exposed admin pages.', 'web',
                ('nikto',), INSTALL_HINT, PROFILES, build, parse, outfile='.json', schemes=('http', 'https'),
                extra_coverage={'excluded': 'denial of service, injection, command execution, brute force'},
                note='Sends many requests to the site. Use only on systems you are allowed to test, ideally off-peak.')
