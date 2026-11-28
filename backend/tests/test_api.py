"""Application startup, the local API's authentication boundary and system endpoints."""
from __future__ import annotations

from sqlalchemy import inspect

from sentinel.config import get_settings
from sentinel.db.session import get_engine
from sentinel.security import TOKEN_HEADER


def test_health_is_open(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_api_requires_token(client):
    assert client.get("/api/system/status").status_code == 401


def test_wrong_token_rejected(client):
    r = client.get("/api/system/status", headers={TOKEN_HEADER: "not-the-token"})
    assert r.status_code == 401


def test_non_ascii_token_is_401_not_500(client):
    r = client.get("/api/system/status", headers={TOKEN_HEADER: "tökén".encode()})
    assert r.status_code == 401


def test_valid_token_passes_gate(client, auth):
    assert client.get("/api/system/status", headers=auth).status_code == 200


def test_foreign_host_header_rejected(client, auth):
    """DNS-rebinding defence: a page on evil.test resolving to 127.0.0.1."""
    r = client.get("/api/system/status", headers={**auth, "host": "evil.test"})
    assert r.status_code == 400


def test_startup_migrates_platform_db_not_legacy(client):
    settings = get_settings()
    assert settings.db_path.exists()
    assert settings.db_path.name == "sentinel_platform.sqlite3"
    assert not settings.legacy_db_path.exists()  # never created or touched
    assert "audit_events" in inspect(get_engine()).get_table_names()


def test_system_status(client, auth):
    body = client.get("/api/system/status", headers=auth).json()
    assert body["job_engine_running"] is True
    assert body["version"] == "0.1.0"
    assert body["active_jobs"] >= 0 and body["pending_recovery_actions"] >= 0


def test_tool_registry_lists_real_adapters(client, auth):
    tools = client.get("/api/system/tools", headers=auth).json()
    ids = {t["id"] for t in tools}
    assert {"web-checkup", "nmap", "whatweb", "sslscan", "nikto"} <= ids
    for tool in tools:
        assert tool["kind"] in ("web", "net")
        assert isinstance(tool["installed"], bool)
        assert tool["profiles"], tool["id"]  # fixed profiles only; no free-form flags


def test_wsl_detection_reports_without_failing(client, auth):
    r = client.get("/api/system/wsl", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["available"], bool)
    if not body["available"]:
        assert body["error"]


def test_wsl_tools_rejects_bad_distribution_name(client, auth):
    r = client.get("/api/system/wsl/bad;name/tools", headers=auth)
    assert r.status_code == 422
