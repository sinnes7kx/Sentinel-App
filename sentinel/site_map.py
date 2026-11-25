"""Small public-page map for an explicitly approved same-origin website.

Follows ordinary HTML links only. No guessed paths, query strings, form
submissions, authentication, redirects, scripts, or asset requests.
"""
from collections import deque
from html.parser import HTMLParser
import http.client
import re
import ssl
import time
from urllib.parse import urljoin, urlsplit

from .engine import Target
from .pinned_http import PinnedConnector, resolve_once

MAX_PAGES = 16
MAX_DEPTH = 2
MAX_BODY = 192 * 1024
MAX_LINKS = 80
SKIP = re.compile(r'(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|checkout|unsubscribe|reset|download)(?:/|$)', re.I)
INPUT_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}')


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = 0
        self.inputs = set()
        self.in_form = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and attrs.get('href') and len(self.links) < MAX_LINKS:
            self.links.append(attrs['href'][:2048])
        elif tag == 'form':
            self.forms += 1
            self.in_form = True
        elif tag in ('input', 'textarea', 'select') and self.in_form:
            name = attrs.get('name') or ''
            if (attrs.get('type', '').lower() not in ('hidden', 'password', 'file', 'submit', 'button')
                    and INPUT_NAME.fullmatch(name) and len(self.inputs) < 30):
                self.inputs.add(name)

    def handle_endtag(self, tag):
        if tag == 'form':
            self.in_form = False


def linked_page(root, current, href):
    # Reject ambiguous paths and query links rather than silently changing them.
    if not href or any(ord(c) < 33 or ord(c) == 127 for c in href) or '\\' in href:
        return None
    try:
        absolute = urljoin(current.url, href)
        parts = urlsplit(absolute)
        if parts.query or '?' in absolute or parts.username is not None or parts.password is not None:
            return None
        target = Target.parse(parts._replace(fragment='').geturl())
        if (target.scheme, target.host, target.port) != (root.scheme, root.host, root.port):
            return None
        if '%' in target.path or SKIP.search(target.path) or len(target.path) > 512:
            return None
        leaf = target.path.rsplit('/', 1)[-1]
        if '.' in leaf and not leaf.lower().endswith(('.html', '.htm', '.php', '.asp', '.aspx')):
            return None
        # Normalize explicit default ports to the starting origin's spelling.
        origin = root.url[:-len(root.path)] if root.path != '/' else root.url[:-1]
        return Target.parse(origin + target.path)
    except ValueError:
        return None


def fetch_page(target, endpoint, cancel):
    conn = (http.client.HTTPSConnection(target.host, target.port, timeout=4,
                                       context=ssl.create_default_context())
            if target.scheme == 'https' else
            http.client.HTTPConnection(target.host, target.port, timeout=4))
    conn._create_connection = PinnedConnector(target.host, target.port, (endpoint,), cancel)
    try:
        conn.connect()
        if cancel.is_set():
            return None, None
        conn.request('GET', target.path, headers={'User-Agent': 'Sentinel-Public-Map/1',
                     'Accept': 'text/html', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = conn.getresponse()
        status = response.status
        if (not 200 <= status < 300 or
                response.getheader('Content-Type', '').split(';', 1)[0].strip().lower() != 'text/html' or
                response.getheader('Content-Encoding', 'identity').lower() != 'identity'):
            return status, None
        data = bytearray()
        deadline = time.monotonic() + 5
        while len(data) <= MAX_BODY:
            if cancel.is_set() or time.monotonic() >= deadline:
                return status, None
            chunk = response.read1(min(16384, MAX_BODY + 1 - len(data)))
            if not chunk:
                if response.length not in (None, 0):
                    return status, None
                return status, bytes(data)
            data.extend(chunk)
        return status, None
    finally:
        conn.close()


def map_site(value, authorized=False, cancel=None, resolver=resolve_once, fetch=fetch_page):
    from threading import Event
    if authorized is not True:
        raise PermissionError('Approve this read-only website map first.')
    root = Target.parse(value)
    cancel = cancel if cancel is not None else Event()
    rows = []
    result = {'rows': rows, 'status': 'partial', 'message': '', 'limit': MAX_PAGES}
    if cancel.is_set():
        return dict(result, status='cancelled', message='Stopped before connecting.')
    try:
        endpoint = resolver(root.host, root.port)[0]
    except (OSError, ValueError, IndexError):
        return dict(result, message='Could not resolve the approved website.')
    pending = deque([(root, None, 0)])
    seen = {root.path}
    omitted = False
    deadline = time.monotonic() + 75
    while pending and len(rows) < MAX_PAGES and not cancel.is_set() and time.monotonic() < deadline:
        target, parent, depth = pending.popleft()
        try:
            status, body = fetch(target, endpoint, cancel)
        except (OSError, ValueError, http.client.HTTPException):
            status, body = None, None
        row = {'path': target.path, 'parent': parent, 'http': status,
               'forms': 0, 'inputs': [], 'read': False}
        rows.append(row)
        if body is not None:
            parser = Page()
            parser.feed(body.decode('utf-8', errors='replace'))
            row.update(forms=parser.forms, inputs=sorted(parser.inputs), read=True)
            for href in parser.links:
                child = linked_page(root, target, href)
                if child is None or child.path in seen:
                    continue
                if depth >= MAX_DEPTH or len(seen) >= MAX_PAGES:
                    omitted = True
                    continue
                seen.add(child.path)
                pending.append((child, target.path, depth + 1))
        if pending and cancel.wait(.3):
            break
    if cancel.is_set():
        return dict(result, status='cancelled', message='Stopped. Showing pages attempted so far.')
    if pending or omitted or any(not row['read'] for row in rows):
        return dict(result, message='Limited map: some links or pages were not read. No hidden pages or scripts checked.')
    return dict(result, status='completed', message='Finished the limited public-page map. This is not a security verdict.')
