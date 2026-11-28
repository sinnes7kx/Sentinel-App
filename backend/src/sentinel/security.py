"""Local API authentication.

Defense in depth for a loopback service: the OS already prevents remote hosts
from reaching the port, Host-header filtering defeats DNS rebinding, and the
session token prevents other local processes (or a drive-by browser request
from a malicious page) from driving the API.
"""
from __future__ import annotations

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

TOKEN_HEADER = "X-Sentinel-Token"

# Reachable without a token: liveness only. The token is never served over the
# API — the desktop shell injects it, and the Vite dev proxy adds it from the
# local token file, so a drive-by localhost page cannot obtain it.
_OPEN_PATHS = frozenset({"/api/health"})


def token_matches(supplied: str | None, expected: str) -> bool:
    """Constant-time comparison that is safe for arbitrary header bytes."""
    if not supplied:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


class SessionTokenMiddleware(BaseHTTPMiddleware):
    """Reject any /api HTTP request that does not carry the session token.

    WebSocket connections bypass BaseHTTPMiddleware entirely; the WebSocket
    endpoint authenticates itself with :func:`token_matches`.
    """

    def __init__(self, app, token: str):
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/api") and path not in _OPEN_PATHS:
            if not token_matches(request.headers.get(TOKEN_HEADER), self._token):
                return JSONResponse(
                    {"detail": "Missing or invalid session token."},
                    status_code=401,
                )
        return await call_next(request)
