"""Bounded native Standard website assessment.

No external process is started. The follow-up TLS probes are restricted to the
same numeric address and port that completed the initial HTTP assessment.
"""
import ipaddress
import socket
import ssl

from .engine import Target, scan
from .pinned_http import Endpoint, PinnedConnector

VERSIONS = ('TLSv1_2', 'TLSv1_3')


def probe_version(target, endpoint, version, cancel=None, timeout=5):
    if cancel is not None and cancel.is_set():
        return 'cancelled'
    try:
        protocol = getattr(ssl.TLSVersion, version)
        context = ssl.create_default_context()
        context.minimum_version = protocol
        context.maximum_version = protocol
        connect = PinnedConnector(target.host, target.port, (endpoint,), cancel)
        with connect((target.host, target.port), timeout) as raw:
            if cancel is not None and cancel.is_set():
                return 'cancelled'
            with context.wrap_socket(raw, server_hostname=target.host) as tls:
                expected = {'TLSv1_2': 'TLSv1.2', 'TLSv1_3': 'TLSv1.3'}[version]
                return 'verified negotiation' if tls.version() == expected else 'inconclusive'
    except (OSError, ValueError, AttributeError, NotImplementedError):
        return 'cancelled' if cancel is not None and cancel.is_set() else 'inconclusive'


def standard_scan(value, authorized=False, cancel=None, dns_domain='',
                  base_scan=scan, probe=probe_version):
    if authorized is not True:
        raise PermissionError('Explicit authorization is required for this assessment.')
    target = Target.parse(value)
    result = base_scan(target.url, authorized=True, cancel=cancel, dns_domain=dns_domain)
    result.profile = 'web-standard-v1'
    result.coverage['external_tools'] = 'not included; separate scope review required'
    result.coverage['additional_tls'] = {}
    if target.scheme != 'https':
        result.coverage['additional_tls'] = {'status': 'not applicable (HTTP URL)'}
        return result
    if result.status != 'completed':
        result.coverage['additional_tls'] = {'status': 'not run; initial assessment incomplete'}
        return result
    selected = result.coverage.get('connection_address')
    if not selected or selected not in result.coverage.get('resolved_addresses', []):
        result.status = 'partial'
        result.error = 'No verified connection address; additional TLS checks not run.'
        return result
    address = ipaddress.ip_address(selected)
    endpoint = Endpoint(socket.AF_INET if address.version == 4 else socket.AF_INET6,
                        str(address), target.port)
    checks = result.coverage['additional_tls']
    for version in VERSIONS:
        if cancel is not None and cancel.is_set():
            checks[version] = 'not run (cancelled)'
        elif result.tls == {'TLSv1_2': 'TLSv1.2', 'TLSv1_3': 'TLSv1.3'}[version]:
            checks[version] = 'verified negotiation (initial connection)'
        else:
            checks[version] = probe(target, endpoint, version, cancel)
    if cancel is not None and cancel.is_set():
        result.status = 'cancelled'
        result.error = 'Cancelled during TLS protocol review; results incomplete.'
    elif any(not state.startswith('verified negotiation') for state in checks.values()):
        result.status = 'partial'
        result.error = 'Some TLS versions could not be verified. This does not prove they are disabled.'
    result.coverage['tls_review_limitations'] = (
        'Tests only TLS 1.2 and 1.3 under the local trust and cryptographic policy. '
        'No legacy protocol or cipher enumeration. Failed negotiation is inconclusive.')
    return result
