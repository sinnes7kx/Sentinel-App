"""Event WebSocket: authentication, origin policy and live job streaming."""
from __future__ import annotations

import pytest
from starlette.testclient import WebSocketDenialResponse
from starlette.websockets import WebSocketDisconnect

from sentinel.security import TOKEN_HEADER

# Starlette's test client ignores base_url for WebSockets and would send
# Host: testserver, which the Host filter rightly rejects. Use an absolute URL.
WS_URL = "ws://127.0.0.1/api/ws"


def connect(client, headers=None, **kwargs):
    # The test client mutates the headers mapping it is given; always copy so
    # the shared ``auth`` fixture is never polluted with upgrade headers.
    return client.websocket_connect(WS_URL, headers=dict(headers or {}), **kwargs)


def assert_policy_close(exc_info):
    """Closed by the endpoint's own check before the handshake (servers send
    this to browsers as HTTP 403) — not by the Host filter's 400 denial."""
    closed = exc_info.value
    assert not isinstance(closed, WebSocketDenialResponse)
    assert closed.code == 1008


def test_ws_requires_token(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with connect(client):
            pass
    assert_policy_close(exc)


def test_ws_rejects_foreign_origin(client, auth):
    with pytest.raises(WebSocketDisconnect) as exc:
        with connect(client, {**auth, "origin": "https://evil.test"}):
            pass
    assert_policy_close(exc)


def test_ws_rejects_foreign_host(client, auth):
    with pytest.raises(WebSocketDenialResponse) as exc:
        with client.websocket_connect("ws://evil.test/api/ws", headers=dict(auth)):
            pass
    assert exc.value.status_code == 400


def test_ws_allows_dev_origin(client, auth):
    with connect(client, {**auth, "origin": "http://127.0.0.1:5173"}) as ws:
        assert ws.receive_json()["type"] == "hello"


def test_ws_token_via_subprotocol(client, auth):
    token = auth[TOKEN_HEADER]
    with connect(client, subprotocols=["sentinel.v1", f"sentinel-token.{token}"]) as ws:
        assert ws.receive_json()["type"] == "hello"
        assert ws.accepted_subprotocol == "sentinel.v1"


def test_ws_wrong_subprotocol_token(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with connect(client, subprotocols=["sentinel-token.wrong"]):
            pass
    assert_policy_close(exc)


def test_ws_ping_pong(client, auth):
    with connect(client, auth) as ws:
        ws.receive_json()  # hello
        ws.send_json({"type": "ping"})
        assert ws.receive_json()["type"] == "pong"


def test_malformed_client_message_closes_cleanly(client, auth):
    with connect(client, auth) as ws:
        ws.receive_json()  # hello
        ws.send_text("{not json")
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == 1003


def test_subscriptions_released_after_disconnect(client, auth):
    jobs = client.app.state.jobs
    before = len(jobs._subscribers)
    for _ in range(5):
        with connect(client, auth) as ws:
            ws.receive_json()
    assert len(jobs._subscribers) == before


def test_auth_fixture_not_polluted(auth):
    assert set(auth) == {TOKEN_HEADER}


def test_ws_streams_job_lifecycle(client, auth):
    jobs = client.app.state.jobs

    def handler(params, ctx):
        ctx.emit("progress", step="half", password="hunter2")
        return None

    jobs.register("test.echo", handler, timeout_s=10)
    with connect(client, auth) as ws:
        assert ws.receive_json()["type"] == "hello"
        job_id = client.portal.call(jobs.submit, "test.echo", {})

        statuses, events = [], []
        while "succeeded" not in statuses:
            msg = ws.receive_json()
            if msg.get("job_id") != job_id:
                continue
            if msg["type"] == "job.status":
                statuses.append(msg["status"])
            else:
                events.append(msg)
        assert statuses == ["queued", "running", "succeeded"]
        assert [e["event"] for e in events] == ["progress"]
        assert events[0]["data"]["password"] == "[REDACTED]"

    job = client.get(f"/api/jobs/{job_id}", headers=auth).json()
    assert job["status"] == "succeeded" and job["finished_at"] is not None
    assert job_id in [j["id"] for j in client.get("/api/jobs", headers=auth).json()]
