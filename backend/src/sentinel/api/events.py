"""Live event stream (job lifecycle and progress) over WebSocket.

WebSockets are not covered by CORS and bypass the HTTP token middleware, so
this endpoint enforces both checks itself:

* ``Origin`` — if a browser sends one, it must be an allowed Sentinel origin
  (blocks cross-site WebSocket hijacking).
* Session token — via the ``X-Sentinel-Token`` header (dev proxy, native
  clients) or a ``sentinel-token.<token>`` subprotocol (desktop shell webview,
  since browsers cannot set WebSocket headers).

Unauthorised connections are closed before the handshake completes.
"""
from __future__ import annotations

import asyncio
import json

import anyio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import __version__
from ..config import get_settings
from ..db.base import utcnow
from ..security import TOKEN_HEADER, token_matches

router = APIRouter(tags=["events"])

SUBPROTOCOL = "sentinel.v1"
TOKEN_SUBPROTOCOL_PREFIX = "sentinel-token."
POLICY_VIOLATION = 1008
UNSUPPORTED_DATA = 1003


def _supplied_token(ws: WebSocket) -> str:
    header = ws.headers.get(TOKEN_HEADER)
    if header:
        return header
    for proto in ws.scope.get("subprotocols") or []:
        if proto.startswith(TOKEN_SUBPROTOCOL_PREFIX):
            return proto[len(TOKEN_SUBPROTOCOL_PREFIX):]
    return ""


async def _pump(ws: WebSocket, queue: asyncio.Queue, scope: anyio.CancelScope) -> None:
    try:
        while True:
            await ws.send_json(await queue.get())
    except Exception:  # peer gone mid-send: end the whole connection
        scope.cancel()


async def _listen(ws: WebSocket, scope: anyio.CancelScope) -> None:
    try:
        while True:
            message = await ws.receive_json()
            if isinstance(message, dict) and message.get("type") == "ping":
                await ws.send_json({"type": "pong", "at": utcnow().isoformat()})
    except WebSocketDisconnect:
        pass
    except (json.JSONDecodeError, KeyError, ValueError):
        try:  # malformed client data: close cleanly instead of crashing
            await ws.close(code=UNSUPPORTED_DATA)
        except RuntimeError:
            pass
    finally:
        scope.cancel()


@router.websocket("/ws")
async def events(ws: WebSocket) -> None:
    origin = ws.headers.get("origin")
    if origin is not None and origin not in get_settings().allowed_ws_origins:
        await ws.close(code=POLICY_VIOLATION)
        return
    if not token_matches(_supplied_token(ws), ws.app.state.session_token):
        await ws.close(code=POLICY_VIOLATION)
        return

    jobs = ws.app.state.jobs
    queue = jobs.subscribe()
    try:
        offered = ws.scope.get("subprotocols") or []
        await ws.accept(subprotocol=SUBPROTOCOL if SUBPROTOCOL in offered else None)
        await ws.send_json({"type": "hello", "version": __version__, "at": utcnow().isoformat()})

        # Structured concurrency: when either side ends, or the connection
        # itself is cancelled (server shutdown), both loops are torn down
        # together — no orphaned tasks left waiting on the event queue.
        async with anyio.create_task_group() as tg:
            tg.start_soon(_pump, ws, queue, tg.cancel_scope)
            tg.start_soon(_listen, ws, tg.cancel_scope)
    finally:
        jobs.unsubscribe(queue)
