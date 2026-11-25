"""Bounded live HTML input handling check; no script or executable payload.

Two anonymous GET requests to one explicitly approved read-only page and
one query parameter. No redirects, credentials, external resources, DOM
execution, stored data or response-body persistence.
"""
import http.client
import re
import ssl
import time
from secrets import token_hex
from urllib.parse import urlencode

from .engine import Target
from .pinned_http import PinnedConnector, resolve_once

MAX_BODY = 256 * 1024
PARAMETER = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}')


def validate(value, parameter):
    target = Target.parse(value)
    parameter = parameter.strip()
    if not PARAMETER.fullmatch(parameter):
        raise ValueError('Enter one input name, such as q or search (letters, numbers, underscore or hyphen).')
    return target, parameter


def fetch(target, endpoint, parameter, value, cancel):
    connector = PinnedConnector(target.host, target.port, (endpoint,), cancel)
    conn = (http.client.HTTPSConnection(target.host, target.port, timeout=5,
                                       context=ssl.create_default_context())
            if target.scheme == 'https' else
            http.client.HTTPConnection(target.host, target.port, timeout=5))
    conn._create_connection = connector
    try:
        conn.connect()
        if cancel is not None and cancel.is_set():
            return None
        conn.request('GET', target.path + '?' + urlencode({parameter: value}),
                     headers={'User-Agent': 'Sentinel-Input-Check/1',
                              'Accept': 'text/html', 'Accept-Encoding': 'identity',
                              'Connection': 'close'})
        response = conn.getresponse()
        status = response.status
        if not 200 <= status < 300:
            return status, None
        mime = response.getheader('Content-Type', '').split(';', 1)[0].strip().lower()
        if mime != 'text/html' or response.getheader('Content-Encoding', 'identity').lower() != 'identity':
            return status, None
        data = bytearray()
        deadline = time.monotonic() + 8
        while len(data) <= MAX_BODY:
            if (cancel is not None and cancel.is_set()) or time.monotonic() >= deadline:
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


def inspect_input(value, parameter, authorized=False, cancel=None, resolver=resolve_once, request=fetch):
    if authorized is not True:
        raise PermissionError('Confirm permission for this exact page and input.')
    target, parameter = validate(value, parameter)
    result = {'status': 'partial', 'verdict': 'Not tested', 'requests': 0,
              'baseline_http': None, 'probe_http': None, 'message': '',
              'target': target.url, 'parameter': parameter}
    def finish(status, verdict, message):
        return dict(result, status=status, verdict=verdict, message=message)
    def stopped():
        return cancel is not None and cancel.is_set()
    if stopped():
        return finish('cancelled', 'Not tested', 'Stopped before network contact.')
    # A custom HTML tag with no attributes, scripts or executable behavior.
    marker = 'sentinel-' + token_hex(8)
    probe = '<' + marker + '>'
    try:
        endpoints = resolver(target.host, target.port)
        if stopped():
            return finish('cancelled', 'Not tested', 'Stopped before HTTP requests.')
        endpoint = endpoints[0]
        result['requests'] += 1
        baseline = request(target, endpoint, parameter, marker, cancel)
        if stopped():
            return finish('cancelled', 'Not tested', 'Stopped after first request.')
        if baseline is None:
            return finish('partial', 'Not tested', 'No usable first response.')
        result['baseline_http'], first = baseline
        if first is None:
            return finish('partial', 'Not tested', 'The first response was not a successful, complete HTML page within the size limit.')
        result['requests'] += 1
        observed = request(target, endpoint, parameter, probe, cancel)
        if stopped():
            return finish('cancelled', 'Not tested', 'Stopped during second request.')
        if observed is None:
            return finish('partial', 'Not tested', 'No usable second response.')
        result['probe_http'], body = observed
        if body is None or result['probe_http'] != result['baseline_http']:
            return finish('partial', 'Inconclusive', 'The second response changed status, was not HTML or exceeded the read limit.')
        raw = probe.encode('ascii')
        encoded = ('&lt;' + marker + '&gt;').encode('ascii')
        if raw in first or encoded in first:
            return finish('partial', 'Inconclusive', 'Unexpected marker already appeared in the first response.')
        if raw in body:
            return finish('completed', 'Raw markup reflected', 'The harmless test tag appeared unchanged in the returned HTML. Review output encoding at this input. This is not proof of XSS or script execution.')
        if encoded in body:
            return finish('completed', 'Encoded marker observed', 'The test tag appeared as escaped text. This is a positive sign for this exact input and response, not proof that all XSS risks are fixed.')
        return finish('completed', 'No exact reflection observed', 'Neither the exact raw tag nor its common escaped form was found. The input may be ignored, filtered, transformed or processed elsewhere. XSS remains unverified.')
    except (OSError, ValueError, http.client.HTTPException, IndexError):
        if stopped():
            return finish('cancelled', 'Not tested', 'Stopped during network check.')
        return finish('partial', 'Not tested', 'Connection, certificate or HTTP response could not be verified. No conclusion.')
