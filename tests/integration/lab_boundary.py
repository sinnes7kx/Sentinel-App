"""Read-only verification of the Linux loopback-only integration lab.

This checks the actual network namespace, not just Docker's requested mode.
It never opens a network connection or accepts user-supplied destinations.
"""
import json
import os
import socket
from pathlib import Path


def boundary_snapshot():
    return {
        'namespace': os.readlink('/proc/self/ns/net'),
        'interfaces': sorted(name for _, name in socket.if_nameindex()),
        'ipv4_routes': Path('/proc/net/route').read_text(encoding='ascii').splitlines()[1:],
        'ipv6_routes': (Path('/proc/net/ipv6_route').read_text(encoding='ascii').splitlines()
                        if Path('/proc/net/ipv6_route').exists() else []),
    }


def verify_boundary(snapshot, expected_namespace=None):
    namespace = snapshot.get('namespace')
    if not isinstance(namespace, str) or not namespace.startswith('net:[') or not namespace.endswith(']'):
        raise ValueError('Network namespace identity could not be established.')
    if expected_namespace is not None and namespace != expected_namespace:
        raise ValueError('Probe does not share the fixture network namespace.')
    if snapshot.get('interfaces') != ['lo']:
        raise ValueError('The isolated lab must have only its loopback interface.')
    for row in snapshot['ipv4_routes']:
        fields = row.split()
        if len(fields) != 11 or fields[0] != 'lo':
            raise ValueError('Unexpected IPv4 route in isolated lab.')
        if fields[1] == '00000000' and fields[7] == '00000000':
            raise ValueError('Unexpected IPv4 default route in isolated lab.')
    for row in snapshot['ipv6_routes']:
        fields = row.split()
        if len(fields) != 10 or fields[-1] != 'lo':
            raise ValueError('Unexpected IPv6 route in isolated lab.')
        # Linux can expose an unreachable default route on lo. A default
        # route that is not marked reject is not acceptable.
        if fields[0] == '0' * 32 and fields[1] == '00':
            if not int(fields[8], 16) & 0x200:
                raise ValueError('Unexpected IPv6 default route in isolated lab.')
    return namespace


if __name__ == '__main__':
    snapshot = boundary_snapshot()
    verify_boundary(snapshot)
    print(json.dumps(snapshot))
