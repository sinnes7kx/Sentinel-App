"""Engagement scope enforcement: fail closed, exclusions win, windows respected."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinel.db.models import Engagement, EngagementStatus, Project, ScopeEntry, ScopeKind
from sentinel.services.scope import (
    check_resolved_addresses,
    evaluate,
    evaluate_engagement,
    normalize_scope_value,
)


def make_engagement(*entries, status=EngagementStatus.ACTIVE, starts=None, ends=None):
    eng = Engagement(name="e", status=status, starts_at=starts, ends_at=ends)
    for kind, value, excluded in entries:
        eng.scope.append(ScopeEntry(kind=kind, value=value, excluded=excluded))
    return eng


URL, HOST, IP, CIDR = ScopeKind.URL, ScopeKind.HOST, ScopeKind.IP, ScopeKind.CIDR


# ----------------------------------------------------------------- engagement state
@pytest.mark.parametrize("status", [EngagementStatus.DRAFT, EngagementStatus.CLOSED])
def test_inactive_engagement_denies(status):
    eng = make_engagement((URL, "https://app.test/", False), status=status)
    d = evaluate_engagement(eng, "https://app.test/", "web")
    assert not d.allowed and status.value in d.reason


def test_window_enforced():
    now = datetime(2026, 6, 1, tzinfo=UTC)
    eng = make_engagement(
        (URL, "https://app.test/", False),
        starts=now - timedelta(days=1),
        ends=now + timedelta(days=1),
    )
    assert evaluate_engagement(eng, "https://app.test/", "web", now=now).allowed
    assert not evaluate_engagement(eng, "https://app.test/", "web", now=now + timedelta(days=2)).allowed
    assert not evaluate_engagement(eng, "https://app.test/", "web", now=now - timedelta(days=2)).allowed


def test_missing_engagement_denies():
    assert not evaluate_engagement(None, "https://app.test/", "web").allowed


def test_empty_scope_denies():
    assert not evaluate_engagement(make_engagement(), "https://app.test/", "web").allowed


# ----------------------------------------------------------------- URL scope
def test_url_scope_covers_subpaths_only():
    eng = make_engagement((URL, "https://app.test/api", False))
    assert evaluate_engagement(eng, "https://app.test/api", "web").allowed
    assert evaluate_engagement(eng, "https://app.test/api/users", "web").allowed
    assert not evaluate_engagement(eng, "https://app.test/apix", "web").allowed
    assert not evaluate_engagement(eng, "https://app.test/", "web").allowed


@pytest.mark.parametrize(
    "target",
    ["http://app.test/api", "https://app.test:8443/api", "https://other.test/api"],
)
def test_url_scope_requires_same_origin(target):
    eng = make_engagement((URL, "https://app.test/api", False))
    assert not evaluate_engagement(eng, target, "web").allowed


def test_excluded_subpath_blocks_parent_site():
    """A whole-site tool on / would reach /admin, so / is refused."""
    eng = make_engagement(
        (URL, "https://app.test/", False),
        (URL, "https://app.test/admin", True),
    )
    assert not evaluate_engagement(eng, "https://app.test/", "web").allowed
    assert not evaluate_engagement(eng, "https://app.test/admin/x", "web").allowed
    assert evaluate_engagement(eng, "https://app.test/shop", "web").allowed


# ----------------------------------------------------------------- network scope
def test_cidr_covers_contained_ip_and_subnet():
    eng = make_engagement((CIDR, "10.0.0.0/24", False))
    assert evaluate_engagement(eng, "10.0.0.7", "net").allowed
    assert evaluate_engagement(eng, "10.0.0.0/28", "net").allowed
    assert not evaluate_engagement(eng, "10.0.1.7", "net").allowed


def test_excluded_ip_blocks_range_containing_it():
    eng = make_engagement((CIDR, "10.0.0.0/24", False), (IP, "10.0.0.5", True))
    assert not evaluate_engagement(eng, "10.0.0.0/24", "net").allowed
    assert not evaluate_engagement(eng, "10.0.0.5", "net").allowed
    assert evaluate_engagement(eng, "10.0.0.6", "net").allowed


def test_host_scope_is_literal_and_case_insensitive():
    eng = make_engagement((HOST, "app.test", False))
    assert evaluate_engagement(eng, "APP.test", "net").allowed
    assert evaluate_engagement(eng, "https://app.test/x", "web").allowed
    assert not evaluate_engagement(eng, "sub.app.test", "net").allowed


def test_url_scope_does_not_authorise_port_scan():
    eng = make_engagement((URL, "https://app.test/", False))
    assert not evaluate_engagement(eng, "app.test", "net").allowed


def test_malformed_target_denied_not_raised():
    eng = make_engagement((CIDR, "10.0.0.0/24", False))
    d = evaluate_engagement(eng, "-oN /tmp/x", "net")
    assert not d.allowed


def test_resolved_address_exclusion():
    eng = make_engagement((HOST, "app.test", False), (CIDR, "10.9.0.0/16", True))
    assert check_resolved_addresses(eng, ["10.0.0.1"]).allowed
    d = check_resolved_addresses(eng, ["10.0.0.1", "10.9.3.4"])
    assert not d.allowed and "10.9.3.4" in d.reason


# ----------------------------------------------------------------- normalisation
@pytest.mark.parametrize(
    "kind,value,expected",
    [
        (URL, " https://App.test/a ", "https://app.test/a"),
        (IP, " 10.0.0.1 ", "10.0.0.1"),
        (IP, "0:0:0:0:0:0:0:1", "::1"),
        (CIDR, "192.168.1.0/24", "192.168.1.0/24"),
        (HOST, "App.Test", "app.test"),
    ],
)
def test_normalize_valid(kind, value, expected):
    assert normalize_scope_value(kind, value) == expected


@pytest.mark.parametrize(
    "kind,value",
    [
        (URL, "https://app.test/?q=1"),
        (IP, "not-an-ip"),
        (IP, "010.0.0.1"),
        (CIDR, "192.168.1.1/24"),
        (HOST, "10.0.0.1"),
        (HOST, "-oN"),
    ],
)
def test_normalize_rejects(kind, value):
    with pytest.raises(ValueError):
        normalize_scope_value(kind, value)


# ----------------------------------------------------------------- persisted path
def test_evaluate_reads_engagement_from_database(session):
    project = Project(name="p")
    eng = Engagement(project=project, name="e", status=EngagementStatus.ACTIVE)
    eng.scope.append(ScopeEntry(kind=URL, value="https://app.test/"))
    session.add(project)
    session.commit()
    d = evaluate(session, eng.id, "https://app.test/login", "web")
    assert d.allowed and d.matched_entry_id == eng.scope[0].id
