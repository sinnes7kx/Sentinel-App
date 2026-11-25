"""Bounded cross-origin policy verification on one authorized URL.

Only anonymous GET requests with synthetic Origin values are used. No cookies,
credentials, preflight, body reads, redirects, or secondary hosts are contacted.
"""
import http.client
import ipaddress
import socket
import ssl

from .engine import Finding, Target
from .pinned_http import Endpoint, PinnedConnector
from .standard_assessment import standard_scan

ORIGINS = ('https://sentinel-check-a.invalid', 'https://sentinel-check-b.invalid')


def probe_origin(target, endpoint, origin, cancel):
    if cancel is not None and cancel.is_set():
        return None
    connector = PinnedConnector(target.host, target.port, (endpoint,), cancel)
    conn = None
    try:
        if target.scheme == 'https':
            conn = http.client.HTTPSConnection(target.host, target.port, timeout=5,
                                               context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(target.host, target.port, timeout=5)
        conn._create_connection = connector
        conn.connect()
        if cancel is not None and cancel.is_set():
            return None
        conn.request('GET', target.path, headers={'Origin': origin,
                     'User-Agent': 'Sentinel-Assessment/0.2',
                     'Accept': 'text/html, */*;q=0.1', 'Connection': 'close'})
        response = conn.getresponse()
        headers = response.getheaders()
        allowed = [v.strip() for k, v in headers if k.lower() == 'access-control-allow-origin']
        credentials = [v.strip() for k, v in headers if k.lower() == 'access-control-allow-credentials']
        return (response.status, allowed == [origin], credentials == ['true'])
    except (OSError, ValueError, http.client.HTTPException):
        return None
    finally:
        if conn is not None:
            conn.close()


def extended_scan(value, authorized=False, cancel=None, dns_domain='',
                  base_scan=standard_scan, probe=probe_origin):
    if authorized is not True:
        raise PermissionError('Explicit authorization is required for this assessment.')
    target = Target.parse(value)
    result = base_scan(target.url, authorized=True, cancel=cancel, dns_domain=dns_domain)
    result.profile = 'web-extended-v1'
    coverage = result.coverage
    review = coverage['cors_review'] = {'status': 'not run', 'requests_attempted': 0,
        'limitations': 'Two anonymous GET probes of the same URL and connected peer. '
                       'No credentials, response body, browser execution, redirects or site-wide testing.'}

    def incomplete(message):
        review['status'] = 'inconclusive'
        if result.status == 'completed':
            result.status = 'partial'
        result.error = (result.error + ' ' + message).strip()
        return result

    def cancelled():
        return cancel is not None and cancel.is_set()

    if cancelled() or result.status == 'cancelled':
        result.status = 'cancelled'
        review['status'] = 'cancelled'
        return result
    if result.status not in ('completed', 'partial') or coverage.get('http') != 'completed':
        return result
    if result.http_status is None or not 200 <= result.http_status < 300:
        review['status'] = 'not run (initial response not successful)'
        return incomplete('Cross-origin review requires a successful initial response.')
    peer = coverage.get('connection_address')
    if not peer or peer not in coverage.get('resolved_addresses', []):
        return incomplete('No verified initial peer for cross-origin review.')
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return incomplete('Invalid initial peer for cross-origin review.')
    endpoint = Endpoint(socket.AF_INET if ip.version == 4 else socket.AF_INET6, str(ip), target.port)
    observations = []
    for origin in ORIGINS:
        if cancelled():
            break
        review['requests_attempted'] += 1
        observed = probe(target, endpoint, origin, cancel)
        if observed is None or observed[0] != result.http_status:
            break
        observations.append(observed)
    if cancelled():
        result.status = 'cancelled'
        review['status'] = 'cancelled'
        result.error = 'Cancelled during cross-origin review.'
        return result
    if len(observations) != len(ORIGINS):
        return incomplete('Cross-origin responses were incomplete or returned a different HTTP status.')
    reflected = sum(row[1] for row in observations)
    credentialed = sum(row[1] and row[2] for row in observations)
    review.update(status='completed', reflected_origins=reflected, credentialed_reflections=credentialed)
    if credentialed == 2:
        result.findings.append(Finding('CORS_CREDENTIAL_REFLECTION', 'medium',
            'Cross-origin credential policy needs review',
            'Both unrelated synthetic origins were returned as allowed origins with credentials enabled. '
            'Only anonymous requests were tested; sensitive data access was not verified.',
            'Restrict allowed origins to an explicit trusted allowlist. Enable credentials only when necessary.',
            confidence='high'))
    elif reflected == 2:
        result.findings.append(Finding('CORS_ORIGIN_REFLECTION', 'low',
            'Cross-origin policy reflects unrelated origins',
            'Both synthetic origins were returned as allowed origins. No sensitive data access was tested.',
            'Verify that this resource is intended to be cross-origin accessible and restrict origins as appropriate.'))
    elif reflected:
        result.findings.append(Finding('CORS_SINGLE_REFLECTION', 'info',
            'One synthetic origin was allowed',
            'One of two synthetic origins matched the allowed-origin response. Policy behavior is not established.',
            'Review the intended cross-origin allowlist and response behavior.'))
    return result
