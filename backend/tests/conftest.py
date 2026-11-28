"""Shared fixtures.

The data directory is redirected to a throwaway location *before* any
``sentinel`` import, so tests never touch the operator's real database,
session token or the legacy Tkinter app's data.
"""
from __future__ import annotations

import os
import tempfile

os.environ["SENTINEL_DATA_DIR"] = tempfile.mkdtemp(prefix="sentinel-test-")

import pytest  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

from sentinel.db.base import make_engine  # noqa: E402
from sentinel.db.migrate import upgrade_to_head  # noqa: E402


@pytest.fixture
def db_url(tmp_path) -> str:
    return f"sqlite:///{(tmp_path / 'test.sqlite3').as_posix()}"


@pytest.fixture
def engine(db_url):
    """A fresh database migrated to head through the real Alembic path."""
    upgrade_to_head(db_url)
    eng = make_engine(db_url)
    yield eng
    eng.dispose()


@pytest.fixture(scope="module")
def client():
    """The real application, lifespan included, addressed as 127.0.0.1 so the
    Host-header filter treats it like the desktop shell would."""
    from fastapi.testclient import TestClient

    from sentinel.main import app

    with TestClient(app, base_url="http://127.0.0.1") as c:
        yield c


@pytest.fixture(scope="module")
def auth(client) -> dict[str, str]:
    from sentinel.config import get_settings
    from sentinel.security import TOKEN_HEADER

    return {TOKEN_HEADER: get_settings().session_token()}


@pytest.fixture
def factory(engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def session(factory) -> Session:
    with factory() as s:
        yield s
