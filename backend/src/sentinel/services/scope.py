"""Engagement scope enforcement.

Every operation that touches a target is evaluated against an *active*
engagement, inside its authorization window, before anything is executed.
The tool layer still applies its own checks (attestation, address pinning,
range limits); this is the engagement-level gate in front of it.

Rules (fail closed):
* The engagement must exist, be ACTIVE, and the current time must lie inside
  its optional start/end window.
* Exclusions are evaluated first and deny on any *overlap* with the target —
  a range or site that merely contains an excluded asset is refused, because
  the tool would reach that asset.
* Inclusions must fully *cover* the target.
* Hostnames are matched literally (no wildcard subdomains). Resolved
  addresses are checked separately with :func:`check_resolved_addresses`.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy.orm import Session

from ..core.engine import Target
from ..core.tools.scope import parse_net_input
from ..db.base import utcnow
from ..db.models import Engagement, EngagementStatus, ScopeEntry, ScopeKind

TargetKind = Literal["web", "net"]
_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matched_entry_id: int | None = None


def _deny(reason: str, entry_id: int | None = None) -> ScopeDecision:
    return ScopeDecision(False, reason, entry_id)


# --------------------------------------------------------------------------
# Scope entry validation
# --------------------------------------------------------------------------
def normalize_scope_value(kind: ScopeKind, value: str) -> str:
    """Validate and canonicalise a scope entry before it is stored."""
    v = (value or "").strip()
    if kind is ScopeKind.URL:
        return Target.parse(v).url
    if kind is ScopeKind.IP:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            raise ValueError("Enter a single IP address.") from None
    if kind is ScopeKind.CIDR:
        try:
            return str(ipaddress.ip_network(v, strict=True))
        except ValueError:
            raise ValueError(
                "Enter a network such as 192.168.1.0/24 with the host bits set to zero."
            ) from None
    if kind is ScopeKind.HOST:
        parsed = parse_net_input(v)
        if parsed.kind != "host":
            raise ValueError("Enter a host name. Use an IP or CIDR entry for addresses.")
        return parsed.value
    raise ValueError("Unknown scope kind.")


# --------------------------------------------------------------------------
# Engagement state
# --------------------------------------------------------------------------
def check_engagement_open(engagement: Engagement | None, now: datetime | None = None) -> ScopeDecision:
    if engagement is None:
        return _deny("Engagement not found.")
    if engagement.status is not EngagementStatus.ACTIVE:
        return _deny(
            f"Engagement is {engagement.status.value}; only active engagements permit testing."
        )
    now = now or utcnow()
    if engagement.starts_at is not None and now < engagement.starts_at:
        return _deny("The engagement's authorization window has not started.")
    if engagement.ends_at is not None and now > engagement.ends_at:
        return _deny("The engagement's authorization window has ended.")
    return ScopeDecision(True, "Engagement is active and inside its authorization window.")


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class _Subject:
    url: Target | None = None
    host: str | None = None          # literal hostname (not an IP)
    ip: _IPAddress | None = None
    net: _IPNetwork | None = None


def _ip_or_none(text: str) -> _IPAddress | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _subject(target: str, kind: TargetKind) -> _Subject:
    if kind == "web":
        t = Target.parse(target)
        host = t.host.lower()
        ip = _ip_or_none(host)
        return _Subject(url=t, host=None if ip else host, ip=ip)
    if kind == "net":
        t = parse_net_input(target)
        if t.kind == "ip":
            return _Subject(ip=ipaddress.ip_address(t.value))
        if t.kind == "cidr":
            return _Subject(net=ipaddress.ip_network(t.value))
        return _Subject(host=t.value.lower())
    raise ValueError("Unknown target kind.")


def _path_within(path: str, base: str) -> bool:
    base = base.rstrip("/")
    return base == "" or path == base or path.startswith(base + "/")


def _same_origin(a: Target, b: Target) -> bool:
    return (a.scheme, a.host.lower(), a.port) == (b.scheme, b.host.lower(), b.port)


def _covers(entry: ScopeEntry, s: _Subject) -> bool:
    """Inclusion: does this entry authorise everything the target reaches?"""
    kind = entry.kind
    if kind is ScopeKind.URL:
        if s.url is None:
            return False
        e = Target.parse(entry.value)
        return _same_origin(e, s.url) and _path_within(s.url.path, e.path)
    if kind is ScopeKind.HOST:
        return s.host is not None and s.host == entry.value.lower()
    if kind is ScopeKind.IP:
        return s.ip is not None and s.ip == ipaddress.ip_address(entry.value)
    if kind is ScopeKind.CIDR:
        net = ipaddress.ip_network(entry.value)
        if s.ip is not None:
            return s.ip.version == net.version and s.ip in net
        if s.net is not None:
            return s.net.version == net.version and s.net.subnet_of(net)
    return False


def _overlaps(entry: ScopeEntry, s: _Subject) -> bool:
    """Exclusion: could testing the target touch this excluded asset?"""
    kind = entry.kind
    if kind is ScopeKind.URL:
        if s.url is None:
            return False
        e = Target.parse(entry.value)
        return _same_origin(e, s.url) and (
            _path_within(s.url.path, e.path) or _path_within(e.path, s.url.path)
        )
    if kind is ScopeKind.HOST:
        return s.host is not None and s.host == entry.value.lower()
    if kind is ScopeKind.IP:
        ip = ipaddress.ip_address(entry.value)
        if s.ip is not None:
            return s.ip == ip
        return s.net is not None and s.net.version == ip.version and ip in s.net
    if kind is ScopeKind.CIDR:
        net = ipaddress.ip_network(entry.value)
        if s.ip is not None:
            return s.ip.version == net.version and s.ip in net
        if s.net is not None:
            return s.net.version == net.version and s.net.overlaps(net)
    return False


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def evaluate_engagement(
    engagement: Engagement | None,
    target: str,
    kind: TargetKind,
    now: datetime | None = None,
) -> ScopeDecision:
    state = check_engagement_open(engagement, now)
    if not state.allowed:
        return state
    assert engagement is not None
    try:
        subject = _subject(target, kind)
    except ValueError as exc:
        return _deny(str(exc))

    for entry in engagement.scope:
        if entry.excluded and _overlaps(entry, subject):
            return _deny(f"Target overlaps an excluded scope entry ({entry.value}).", entry.id)
    for entry in engagement.scope:
        if not entry.excluded and _covers(entry, subject):
            return ScopeDecision(True, f"Covered by scope entry {entry.value}.", entry.id)
    return _deny("Target is not covered by the engagement scope.")


def evaluate(
    session: Session,
    engagement_id: int,
    target: str,
    kind: TargetKind,
    now: datetime | None = None,
) -> ScopeDecision:
    return evaluate_engagement(session.get(Engagement, engagement_id), target, kind, now)


def check_resolved_addresses(
    engagement: Engagement, addresses: Iterable[str]
) -> ScopeDecision:
    """Refuse when DNS resolved a hostname target onto an excluded address."""
    for raw in addresses:
        ip = _ip_or_none(str(raw).split("%")[0])
        if ip is None:
            return _deny(f"Resolver returned an unparseable address ({raw}).")
        subject = _Subject(ip=ip)
        for entry in engagement.scope:
            if entry.excluded and _overlaps(entry, subject):
                return _deny(
                    f"Hostname resolved to {ip}, which is excluded by scope entry {entry.value}.",
                    entry.id,
                )
    return ScopeDecision(True, "No resolved address is excluded.")
