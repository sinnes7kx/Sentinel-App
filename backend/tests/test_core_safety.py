"""Regression guards for the ported safety-critical domain core.

These behaviours are what make Sentinel safe to point at real systems; a
refactor that loosens any of them must fail here.
"""
from __future__ import annotations

import pytest

from sentinel.core.engine import Target
from sentinel.core.evidence import sanitize
from sentinel.core.tools.scope import parse_net_input, require_authorization


@pytest.mark.parametrize("cidr", ["8.8.8.0/24", "1.1.1.0/30"])
def test_public_cidr_rejected(cidr):
    with pytest.raises(ValueError):
        parse_net_input(cidr)


def test_private_range_larger_than_24_rejected():
    with pytest.raises(ValueError):
        parse_net_input("10.0.0.0/16")


def test_loopback_classified_private():
    t = parse_net_input("127.0.0.1")
    assert t.kind == "ip" and t.private


@pytest.mark.parametrize("bad", ["-oN /tmp/x", "a b", "http://host/", "host%eth0"])
def test_argument_injection_and_malformed_targets_rejected(bad):
    with pytest.raises(ValueError):
        parse_net_input(bad)


def test_unattested_target_rejected():
    with pytest.raises(PermissionError):
        require_authorization(parse_net_input("127.0.0.1"), attested=False)


def test_public_target_requires_typed_confirmation():
    public = parse_net_input("93.184.216.34")
    with pytest.raises(PermissionError):
        require_authorization(public, attested=True, typed_confirmation="")
    require_authorization(public, attested=True, typed_confirmation="93.184.216.34")


@pytest.mark.parametrize(
    "bad", ["http://x/?q=1", "https://u:p@x/", "ftp://x/", "https://x/#frag", "https://x\\y/"]
)
def test_url_validation_rejects_unsafe_forms(bad):
    with pytest.raises(ValueError):
        Target.parse(bad)


def test_url_validation_accepts_plain_url():
    t = Target.parse("https://example.com/a")
    assert (t.scheme, t.host, t.port, t.path) == ("https", "example.com", 443, "/a")


def test_redaction_scrubs_nested_secrets():
    red = sanitize({"authorization": "Bearer abc123", "nested": {"password": "hunter2"}})
    assert "abc123" not in str(red) and "hunter2" not in str(red)
