"""Resolve once and connect only to numeric endpoints from that snapshot.

This is an application-level boundary for the built-in HTTP client, not a
firewall or a sandbox for external tools. Preserve the original HTTP Host and
TLS server name by replacing only the connection's socket factory.
"""
from dataclasses import dataclass
import ipaddress
import socket
import time


@dataclass(frozen=True)
class Endpoint:
    family: int
    address: str
    port: int

    @property
    def sockaddr(self):
        if self.family == socket.AF_INET6:
            return (self.address, self.port, 0, 0)
        return (self.address, self.port)


def resolve_once(host, port, resolver=None):
    if '%' in host:
        raise ValueError('Scoped IPv6 addresses are not supported.')
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        family = socket.AF_INET if literal.version == 4 else socket.AF_INET6
        records = [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                    (str(literal), port) if literal.version == 4 else (str(literal), port, 0, 0))]
    else:
        resolver = resolver or socket.getaddrinfo
        records = resolver(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    endpoints = []
    kinds = set()
    for family, _, _, _, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        addr = ipaddress.ip_address(sockaddr[0])
        if '%' in sockaddr[0] or (family == socket.AF_INET6 and sockaddr[3]):
            raise ValueError('Scoped IPv6 addresses are not supported.')
        if addr.version != (4 if family == socket.AF_INET else 6):
            raise ValueError('Address family mismatch.')
        # IPv4-mapped IPv6 uses IPv4 policy as well.
        policy = getattr(addr, 'ipv4_mapped', None) or addr
        if policy.is_unspecified or policy.is_multicast or policy.is_link_local:
            raise ValueError('Unspecified, multicast and link-local endpoints are not supported.')
        kinds.add('global' if policy.is_global else 'non-global')
        endpoint = Endpoint(family, str(addr), port)
        if endpoint not in endpoints:
            endpoints.append(endpoint)
        if len(endpoints) > 32:
            raise ValueError('Too many resolved endpoints.')
    if not endpoints:
        raise ValueError('No usable TCP endpoints.')
    if len(kinds) != 1:
        raise ValueError('Mixed public and non-public DNS answers are not supported.')
    return tuple(endpoints)


class PinnedConnector:
    def __init__(self, host, port, endpoints, cancel=None):
        self.host, self.port = host, port
        self.endpoints = tuple(endpoints)
        self.cancel = cancel
        self.selected = None

    def __call__(self, address, timeout, source_address=None):
        if address != (self.host, self.port) or source_address is not None:
            raise ValueError('Unexpected connection target.')
        deadline = time.monotonic() + timeout
        last = None
        for endpoint in self.endpoints:
            if self.cancel is not None and self.cancel.is_set():
                raise InterruptedError('Cancelled before socket connection.')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Connection budget exhausted.')
            sock = socket.socket(endpoint.family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            try:
                sock.settimeout(remaining)
                sock.connect(endpoint.sockaddr)
                peer = ipaddress.ip_address(sock.getpeername()[0])
                if peer != ipaddress.ip_address(endpoint.address):
                    raise ValueError('Connected peer differs from selected endpoint.')
                self.selected = endpoint.address
                return sock
            except OSError as exc:
                last = exc
                sock.close()
            except BaseException:
                sock.close()
                raise
        raise last or OSError('No resolved endpoint was reachable.')
