"""Scope guard for network tools: what may be scanned, and what must be confirmed."""
from dataclasses import dataclass
import ipaddress
import re
import socket

MAX_PRIVATE_HOSTS = 256   # a /24
_HOST = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')


@dataclass(frozen=True)
class NetTarget:
    value: str      # normalized text passed to the tool
    kind: str       # 'ip' | 'cidr' | 'host'
    private: bool   # every address is loopback / private / link-local
    hosts: int      # number of addresses in scope
    addresses: tuple = ()


def _is_local(addr):
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _default_resolver(host):
    return [ai[4][0].split('%')[0] for ai in socket.getaddrinfo(host, None)]


def parse_net_target(text, resolver=_default_resolver):
    v = (text or '').strip()
    if '%' in v:
        raise ValueError('IPv6 zone identifiers are not supported; enter an unambiguous address.')
    if not v or v.startswith('-') or any(ord(c) < 33 or ord(c) == 127 for c in v):
        raise ValueError('Enter one IP address, one network such as 192.168.1.0/24, or one host name.')
    if '/' in v:
        try:
            net = ipaddress.ip_network(v, strict=True)
        except ValueError:
            raise ValueError('That network is not valid. Example: 192.168.1.0/24') from None
        if not _is_local(net):
            raise ValueError('Network ranges are only accepted for private address space. Scan public systems one host at a time.')
        if net.num_addresses > MAX_PRIVATE_HOSTS:
            raise ValueError('Ranges larger than a /24 (256 addresses) are not accepted.')
        return NetTarget(str(net), 'cidr', True, net.num_addresses)
    try:
        ip = ipaddress.ip_address(v.split('%')[0])
        return NetTarget(str(ip), 'ip', _is_local(ip), 1)
    except ValueError:
        pass
    if v.replace('.', '').isdigit() or not _HOST.match(v):
        raise ValueError('That is not a valid IP address or host name.')
    try:
        addrs = [ipaddress.ip_address(a) for a in resolver(v)]
    except (OSError, ValueError):
        raise ValueError('The host name could not be resolved.') from None
    if not addrs:
        raise ValueError('The host name could not be resolved.')
    return NetTarget(v.lower(), 'host', all(_is_local(a) for a in addrs), 1, tuple(dict.fromkeys(str(a) for a in addrs)))


def require_authorization(target, attested, typed_confirmation=''):
    """Raise PermissionError unless the person has confirmed they may test the target.

    Private/loopback targets need the checkbox. Anything else additionally needs
    the exact target typed back, so a public address is never scanned by accident.
    """
    if attested is not True:
        raise PermissionError('Confirm that you own this target or have written permission to test it.')
    if not target.private and (typed_confirmation or '').strip().lower() != target.value.lower():
        raise PermissionError(f'This target is outside your private network. Type {target.value} in the confirmation box to confirm you are authorized to test it.')
