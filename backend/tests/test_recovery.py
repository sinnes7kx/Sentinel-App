"""Sentinel Restore: journal-before-apply, verified restoration, honest failures."""
from __future__ import annotations

from collections.abc import Iterable

import pytest
from sqlalchemy import select

from sentinel.db.models import (
    AuditEvent,
    Engagement,
    EngagementStatus,
    Project,
    RecoveryAction,
    RecoveryStatus,
    ScopeEntry,
    ScopeKind,
)
from sentinel.services import recovery
from sentinel.services.recovery import RecoveryRefused, RecoveryService

RESOURCE = "https://app.test/api/profiles/test-user-7"
PROCEDURE = "test.restore_fields"


class FakeApp:
    """Stands in for a designated test application's persisted state."""

    def __init__(self):
        self.records = {RESOURCE: {"first_name": "Alice", "role": "user"}}


class FakeRestoreHandler:
    def __init__(self, app: FakeApp, *, sabotage=False, unreadable=False, broken=False):
        self.app = app
        self.sabotage = sabotage
        self.unreadable = unreadable
        self.broken = broken

    def restore(self, resource, original_state):
        if self.broken:
            raise ConnectionError("target unreachable")
        if not self.sabotage:
            self.app.records[resource].update(original_state)

    def read_state(self, resource, keys: Iterable[str]):
        if self.unreadable:
            raise TimeoutError("no response")
        return {k: self.app.records[resource].get(k) for k in keys}


class RenameProfile:
    """A permitted temporary change: rename a designated test profile."""

    operation = "update_field"
    rollback_procedure = PROCEDURE
    scope_kind = "web"

    def __init__(self, app: FakeApp, new_name="Mallory", *, fail_apply=False,
                 resource=RESOURCE, irreversible=""):
        self.app = app
        self.new_name = new_name
        self.fail_apply = fail_apply
        self.resource = resource
        self.scope_target = resource
        self.irreversible_consequences = irreversible

    def capture(self):
        return {"first_name": self.app.records[self.resource]["first_name"]}

    def apply(self):
        if self.fail_apply:
            raise RuntimeError("server returned 500")
        self.app.records[self.resource]["first_name"] = self.new_name
        return {"first_name": self.new_name}


@pytest.fixture
def app():
    return FakeApp()


@pytest.fixture
def handler(app):
    h = FakeRestoreHandler(app)
    recovery.register_handler(PROCEDURE, h)
    yield h
    recovery.unregister_handler(PROCEDURE)


@pytest.fixture
def service(factory):
    return RecoveryService(factory)


def _engagement(session, *, status=EngagementStatus.ACTIVE, allow=True, scope="https://app.test/"):
    project = Project(name=f"p-{status.value}-{allow}-{scope}")
    eng = Engagement(project=project, name="e", status=status, allow_state_changes=allow)
    eng.scope.append(ScopeEntry(kind=ScopeKind.URL, value=scope))
    session.add(project)
    session.commit()
    return eng.id


def _audit_actions(session):
    return [e.action for e in session.scalars(select(AuditEvent).order_by(AuditEvent.id))]


def test_full_cycle_is_verified(session, service, app, handler):
    eid = _engagement(session)
    action_id = service.execute(eid, RenameProfile(app))
    assert app.records[RESOURCE]["first_name"] == "Mallory"

    row = session.get(RecoveryAction, action_id)
    assert row.original_state == {"first_name": "Alice"}
    assert row.applied_state == {"first_name": "Mallory"}
    assert row.status is RecoveryStatus.AVAILABLE

    result = service.restore(action_id)
    assert result.status is RecoveryStatus.RESTORATION_VERIFIED
    assert result.verified_at is not None
    assert app.records[RESOURCE]["first_name"] == "Alice"
    assert service.pending() == []

    session.expire_all()
    assert _audit_actions(session) == [
        "recovery.captured",
        "recovery.applied",
        "recovery.restore_started",
        "recovery.restoration_verified",
    ]


def test_original_state_is_journaled_before_apply(session, service, app, handler):
    eid = _engagement(session)
    with pytest.raises(RuntimeError):
        service.execute(eid, RenameProfile(app, fail_apply=True))
    row = session.scalars(select(RecoveryAction)).one()
    assert row.original_state == {"first_name": "Alice"}
    assert row.applied_at is None
    assert "Apply failed" in row.verification_detail
    assert service.restore(row.id).status is RecoveryStatus.RESTORATION_VERIFIED


def test_unverifiable_restore_is_never_reported_as_success(session, service, app, handler):
    eid = _engagement(session)
    action_id = service.execute(eid, RenameProfile(app))
    handler.sabotage = True  # restore "runs" but the server keeps the change
    result = service.restore(action_id)
    assert result.status is RecoveryStatus.RESTORATION_FAILED
    assert "first_name" in result.verification_detail
    assert "Mallory" not in result.verification_detail  # field names only, never values
    assert [a.id for a in service.pending()] == [action_id]


def test_unreadable_resource_requires_manual_intervention(session, service, app, handler):
    eid = _engagement(session)
    action_id = service.execute(eid, RenameProfile(app))
    handler.unreadable = True
    result = service.restore(action_id)
    assert result.status is RecoveryStatus.MANUAL_INTERVENTION_REQUIRED
    assert result.verified_at is None


def test_failed_restore_call(session, service, app, handler):
    eid = _engagement(session)
    action_id = service.execute(eid, RenameProfile(app))
    handler.broken = True
    assert service.restore(action_id).status is RecoveryStatus.RESTORATION_FAILED


def test_refused_without_registered_handler(session, service, app):
    eid = _engagement(session)
    with pytest.raises(RecoveryRefused, match="restore handler"):
        service.execute(eid, RenameProfile(app))
    assert app.records[RESOURCE]["first_name"] == "Alice"
    assert session.scalars(select(RecoveryAction)).first() is None


@pytest.mark.parametrize(
    "kwargs,needle",
    [
        ({"allow": False}, "does not permit"),
        ({"status": EngagementStatus.CLOSED}, "closed"),
        ({"scope": "https://other.test/"}, "not covered"),
    ],
)
def test_refused_outside_authorization(session, service, app, handler, kwargs, needle):
    eid = _engagement(session, **kwargs)
    with pytest.raises(RecoveryRefused, match=needle):
        service.execute(eid, RenameProfile(app))
    assert app.records[RESOURCE]["first_name"] == "Alice"  # nothing touched
    assert session.scalars(select(RecoveryAction)).first() is None


def test_missing_handler_at_restore_time(session, service, app, handler):
    eid = _engagement(session)
    action_id = service.execute(eid, RenameProfile(app))
    recovery.unregister_handler(PROCEDURE)
    result = service.restore(action_id)
    assert result.status is RecoveryStatus.MANUAL_INTERVENTION_REQUIRED


def test_crash_during_restore_is_made_retryable(session, service, app, handler):
    eid = _engagement(session)
    action_id = service.execute(eid, RenameProfile(app))
    row = session.get(RecoveryAction, action_id)
    row.status = RecoveryStatus.IN_PROGRESS  # simulate a crash mid-restore
    session.commit()

    assert service.reconcile_after_crash() == 1
    session.expire_all()
    assert session.get(RecoveryAction, action_id).status is RecoveryStatus.AVAILABLE
    assert service.restore(action_id).status is RecoveryStatus.RESTORATION_VERIFIED


def test_irreversible_consequences_survive_restoration(session, service, app, handler):
    eid = _engagement(session)
    action_id = service.execute(
        eid, RenameProfile(app, irreversible="Profile name was visible to other test users.")
    )
    result = service.restore(action_id)
    assert result.status is RecoveryStatus.RESTORATION_VERIFIED
    assert "Irreversible consequences remain" in result.verification_detail
    assert result.irreversible_consequences
