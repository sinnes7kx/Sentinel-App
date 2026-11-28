"""Application startup and the local API's authentication boundary."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from sentinel.config import get_settings
from sentinel.db.session import get_engine
from sentinel.main import app
from sentinel.security import TOKEN_HEADER


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:  # runs lifespan: migrations + engine init
        yield c


def test_health_is_open(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_api_requires_token(client):
    r = client.get("/api/anything")
    assert r.status_code == 401


def test_wrong_token_rejected(client):
    r = client.get("/api/anything", headers={TOKEN_HEADER: "not-the-token"})
    assert r.status_code == 401


def test_valid_token_passes_gate(client):
    token = get_settings().session_token()
    r = client.get("/api/anything", headers={TOKEN_HEADER: token})
    assert r.status_code == 404  # past the gate; route simply doesn't exist


def test_startup_migrates_platform_db_not_legacy(client):
    settings = get_settings()
    assert settings.db_path.exists()
    assert settings.db_path.name == "sentinel_platform.sqlite3"
    assert not settings.legacy_db_path.exists()  # never created or touched
    assert "audit_events" in inspect(get_engine()).get_table_names()
