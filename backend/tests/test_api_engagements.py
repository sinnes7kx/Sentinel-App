"""Engagement authorization lifecycle through the HTTP API."""
from __future__ import annotations

import uuid

from sentinel.db.models import RecoveryAction
from sentinel.db.session import session_factory


def _project(client, auth) -> dict:
    r = client.post("/api/projects", json={"name": f"p-{uuid.uuid4().hex[:8]}"}, headers=auth)
    assert r.status_code == 201, r.text
    return r.json()


def _engagement(client, auth, **extra) -> dict:
    project = _project(client, auth)
    r = client.post(f"/api/projects/{project['id']}/engagements",
                    json={"name": "Q4 web", **extra}, headers=auth)
    assert r.status_code == 201, r.text
    return r.json()


def _active_engagement(client, auth) -> dict:
    e = _engagement(client, auth, authorized_by="CISO", authorization_reference="SOW-1")
    base = f"/api/engagements/{e['id']}"
    assert client.post(f"{base}/scope", json={"kind": "url", "value": "https://app.test/"},
                       headers=auth).status_code == 201
    r = client.post(f"{base}/status", json={"status": "active"}, headers=auth)
    assert r.status_code == 200, r.text
    return r.json()


def test_project_create_list_and_duplicate(client, auth):
    name = f"acme-{uuid.uuid4().hex[:6]}"
    assert client.post("/api/projects", json={"name": name}, headers=auth).status_code == 201
    assert client.post("/api/projects", json={"name": name}, headers=auth).status_code == 409
    names = [p["name"] for p in client.get("/api/projects", headers=auth).json()]
    assert name in names


def test_project_input_validation(client, auth):
    assert client.post("/api/projects", json={"name": "  "}, headers=auth).status_code == 422
    r = client.post("/api/projects", json={"name": "x", "admin": True}, headers=auth)
    assert r.status_code == 422  # unknown fields refused


def test_engagement_lifecycle(client, auth):
    e = _engagement(client, auth)
    base = f"/api/engagements/{e['id']}"
    assert e["status"] == "draft" and e["scope"] == []

    # Cannot activate without an authorization record and scope.
    r = client.post(f"{base}/status", json={"status": "active"}, headers=auth)
    assert r.status_code == 422
    assert "authorized" in r.json()["detail"] and "in-scope" in r.json()["detail"]

    # Scope values are validated and canonicalised.
    for bad in ({"kind": "url", "value": "https://app.test/?q=1"},
                {"kind": "cidr", "value": "10.0.0.1/24"},
                {"kind": "host", "value": "-oN"}):
        assert client.post(f"{base}/scope", json=bad, headers=auth).status_code == 422
    r = client.post(f"{base}/scope", json={"kind": "url", "value": "https://App.test/"}, headers=auth)
    assert r.status_code == 201 and r.json()["value"] == "https://app.test/"
    assert client.post(f"{base}/scope", json={"kind": "url", "value": "https://app.test/"},
                       headers=auth).status_code == 409
    excl = client.post(f"{base}/scope", json={"kind": "url", "value": "https://app.test/admin",
                                              "excluded": True}, headers=auth).json()

    # Partial updates, with null/invalid values refused.
    assert client.patch(base, json={"authorized_by": "CISO", "authorization_reference": "SOW-1"},
                        headers=auth).status_code == 200
    assert client.patch(base, json={"name": None}, headers=auth).status_code == 422
    assert client.patch(base, json={"starts_at": "2026-06-02T00:00:00Z",
                                    "ends_at": "2026-06-01T00:00:00Z"},
                        headers=auth).status_code == 422

    assert client.post(f"{base}/status", json={"status": "active"}, headers=auth).json()["status"] == "active"

    # An active engagement's authorization is immutable.
    assert client.patch(base, json={"name": "renamed"}, headers=auth).status_code == 409
    assert client.post(f"{base}/scope", json={"kind": "host", "value": "x.test"},
                       headers=auth).status_code == 409
    assert client.delete(f"{base}/scope/{excl['id']}", headers=auth).status_code == 409

    # Scope dry-run.
    def check(target, kind="web"):
        return client.post(f"{base}/scope/check", json={"target": target, "kind": kind},
                           headers=auth).json()
    # The site root would reach /admin, so it is refused; a sibling path is fine.
    assert check("https://app.test/")["allowed"] is False
    assert check("https://app.test/shop")["allowed"] is True
    assert "excluded" in check("https://app.test/admin/users")["reason"]
    assert check("https://other.test/")["allowed"] is False

    # Pause, amend, resume.
    assert client.post(f"{base}/status", json={"status": "draft"}, headers=auth).status_code == 200
    assert client.delete(f"{base}/scope/{excl['id']}", headers=auth).status_code == 204
    assert client.post(f"{base}/status", json={"status": "active"}, headers=auth).status_code == 200
    assert check("https://app.test/")["allowed"] is True  # exclusion removed

    # Closed is final.
    assert client.post(f"{base}/status", json={"status": "closed"}, headers=auth).status_code == 200
    assert client.post(f"{base}/status", json={"status": "active"}, headers=auth).status_code == 409
    r = client.patch(base, json={"name": "x"}, headers=auth)
    assert r.status_code == 409 and "read-only" in r.json()["detail"]

    # Every step is in the audit trail.
    actions = [ev["action"] for ev in client.get("/api/audit?limit=200", headers=auth).json()
               if ev["subject_type"] == "engagement" and ev["subject_id"] == str(e["id"])]
    for expected in ("engagement.created", "engagement.scope_added", "engagement.updated",
                     "engagement.status_changed", "engagement.scope_removed"):
        assert expected in actions


def test_naive_datetimes_refused(client, auth):
    project = _project(client, auth)
    r = client.post(f"/api/projects/{project['id']}/engagements",
                    json={"name": "e", "starts_at": "2026-01-01T09:00:00"}, headers=auth)
    assert r.status_code == 422


def test_activation_refused_after_window_ended(client, auth):
    e = _engagement(client, auth, authorized_by="CISO", authorization_reference="SOW-2",
                    starts_at="2020-01-01T00:00:00Z", ends_at="2020-02-01T00:00:00Z")
    base = f"/api/engagements/{e['id']}"
    client.post(f"{base}/scope", json={"kind": "ip", "value": "10.0.0.1"}, headers=auth)
    r = client.post(f"{base}/status", json={"status": "active"}, headers=auth)
    assert r.status_code == 422 and "ended" in r.json()["detail"]


def test_pending_recovery_blocks_close_and_restore_is_honest(client, auth):
    e = _active_engagement(client, auth)
    with session_factory()() as s:
        row = RecoveryAction(
            engagement_id=e["id"],
            resource="https://app.test/api/profiles/7",
            operation="update_field",
            original_state={"first_name": "Alice"},
            rollback_procedure="unregistered.procedure",
        )
        s.add(row)
        s.commit()
        action_id = row.id

    base = f"/api/engagements/{e['id']}"
    r = client.post(f"{base}/status", json={"status": "closed"}, headers=auth)
    assert r.status_code == 409 and "pending recovery" in r.json()["detail"]

    pending = client.get(f"/api/recovery?pending=true&engagement_id={e['id']}", headers=auth).json()
    assert [p["id"] for p in pending] == [action_id]
    assert pending[0]["captured_fields"] == ["first_name"]
    assert "original_state" not in pending[0] and "Alice" not in str(pending[0])

    # No handler is registered, so restore cannot be verified — and says so.
    r = client.post(f"/api/recovery/{action_id}/restore", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "manual_intervention_required"
    assert client.post(f"{base}/status", json={"status": "closed"},
                       headers=auth).status_code == 409


def test_not_found_paths(client, auth):
    assert client.get("/api/engagements/999999", headers=auth).status_code == 404
    assert client.get("/api/projects/999999/engagements", headers=auth).status_code == 404
    assert client.get("/api/jobs/nope", headers=auth).status_code == 404
    assert client.post("/api/jobs/nope/cancel", headers=auth).status_code == 404
    assert client.post("/api/recovery/999999/restore", headers=auth).status_code == 404
