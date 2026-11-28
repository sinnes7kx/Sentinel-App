"""Runtime configuration and the local data directory.

Sentinel is a locally hosted, single-operator desktop application. The backend
binds to the loopback interface only and authenticates callers with a
per-install session token. Nothing is sent to any cloud service.
"""
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(base) / "Sentinel"


class Settings(BaseSettings):
    """Process configuration. Override with SENTINEL_* environment variables."""

    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=None)

    # Loopback only. Never bind a routable interface: the API can launch tools.
    host: str = "127.0.0.1"
    port: int = 8787

    # Absolute data directory for the SQLite database, session token and logs.
    data_dir: Path = _default_data_dir()

    # Cross-origin dev origins allowed to call the API (the Vite dev server).
    dev_origins: tuple[str, ...] = ("http://127.0.0.1:5173", "http://localhost:5173")

    # Host headers accepted by the API. Anything else (e.g. an attacker's
    # domain rebound to 127.0.0.1) is rejected before routing.
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")

    @property
    def allowed_ws_origins(self) -> frozenset[str]:
        """Browser origins permitted to open the event WebSocket. WebSockets
        are not covered by CORS, so the Origin header is checked explicitly."""
        return frozenset(
            {
                *self.dev_origins,
                f"http://127.0.0.1:{self.port}",
                f"http://localhost:{self.port}",
            }
        )

    @property
    def db_path(self) -> Path:
        # Distinct from the legacy Tkinter app's ``sentinel.sqlite3`` in the same
        # directory: that file is never migrated in place, only imported read-only.
        return self.data_dir / "sentinel_platform.sqlite3"

    @property
    def legacy_db_path(self) -> Path:
        return self.data_dir / "sentinel.sqlite3"

    @property
    def db_url(self) -> str:
        return f"sqlite:///{self.db_path.as_posix()}"

    @property
    def token_path(self) -> Path:
        return self.data_dir / "session.token"

    def ensure_data_dir(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def session_token(self) -> str:
        """Return the per-install token, generating and persisting it once.

        The token gates every API call made by a non-browser client. It is kept
        in the user's local data directory under default account permissions.
        """
        self.ensure_data_dir()
        path = self.token_path
        try:
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        except FileNotFoundError:
            pass
        token = secrets.token_urlsafe(32)
        path.write_text(token, encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # Best effort on Windows; account-level file permissions apply.
        return token


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
