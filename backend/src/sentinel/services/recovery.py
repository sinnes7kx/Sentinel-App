"""Sentinel Restore — the recovery journal.

Contract (ROADMAP §4 "Sentinel Restore", §11):

1. A state-changing operation is refused unless a restore handler for its
   rollback procedure is registered *before* execution ("recovery must be
   designed and validated before enabling state-changing modules").
2. The engagement must be active, inside its window, explicitly permit state
   changes, and cover the resource in scope.
3. The original state is captured and **committed to the journal before the
   change is applied**, so cleanup can resume after a crash.
4. Restoration is only reported as RESTORATION_VERIFIED after the resource is
   independently re-read and every captured field matches the original. A
   restore that ran but could not be verified is never shown as success.
5. Declared irreversible consequences (e.g. information already disclosed)
   are kept on the record; restoring state does not erase them.

Journal rows store original values verbatim because they are needed to
restore exactly. Status details and audit records only ever name fields,
never their values.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ..db.base import utcnow
from ..db.models import Engagement, RecoveryAction, RecoveryStatus
from . import audit
from .scope import TargetKind, check_engagement_open, evaluate_engagement

TERMINAL_STATES = frozenset(
    {
        RecoveryStatus.RESTORATION_VERIFIED,
        RecoveryStatus.NOT_REQUIRED,
        RecoveryStatus.IRREVERSIBLE,
    }
)

_MISSING = object()


class StateChange(Protocol):
    """A bounded, permitted modification of a designated test resource."""

    resource: str                    # identifier of the designated test resource
    scope_target: str                # URL/host the operation touches (scope-checked)
    scope_kind: TargetKind
    operation: str                   # e.g. "update_field"
    rollback_procedure: str          # name of the registered RestoreHandler
    irreversible_consequences: str   # declared up front; "" when none

    def capture(self) -> dict[str, Any]: ...
    def apply(self) -> dict[str, Any]: ...


class RestoreHandler(Protocol):
    """Restores a resource from a journal row, independently of the original
    in-memory operation — this is what makes crash recovery possible."""

    def restore(self, resource: str, original_state: dict[str, Any]) -> None: ...
    def read_state(self, resource: str, keys: Iterable[str]) -> dict[str, Any]: ...


_HANDLERS: dict[str, RestoreHandler] = {}


def register_handler(name: str, handler: RestoreHandler) -> None:
    _HANDLERS[name] = handler


def unregister_handler(name: str) -> None:
    _HANDLERS.pop(name, None)


def has_handler(name: str) -> bool:
    return name in _HANDLERS


class RecoveryRefused(PermissionError):
    """The operation was not started; nothing was changed."""


class RecoveryService:
    def __init__(self, session_factory: sessionmaker[Session]):
        self._sf = session_factory

    # ------------------------------------------------------------------ execute
    def execute(
        self,
        engagement_id: int,
        change: StateChange,
        *,
        job_id: str | None = None,
        finding_id: int | None = None,
    ) -> int:
        """Capture, journal, then apply. Returns the journal row id."""
        if not has_handler(change.rollback_procedure):
            raise RecoveryRefused(
                f"No validated restore handler is registered for "
                f"'{change.rollback_procedure}'; state-changing execution is disabled."
            )

        with self._sf() as s:
            engagement = s.get(Engagement, engagement_id)
            self._require_permitted(engagement, change)
            original = change.capture()
            action = RecoveryAction(
                engagement_id=engagement_id,
                job_id=job_id,
                finding_id=finding_id,
                resource=change.resource,
                operation=change.operation,
                original_state=original,
                rollback_procedure=change.rollback_procedure,
                status=RecoveryStatus.AVAILABLE,
                irreversible_consequences=change.irreversible_consequences,
            )
            s.add(action)
            s.flush()
            audit.record(
                s,
                "recovery.captured",
                "recovery_action",
                action.id,
                {"resource": change.resource, "operation": change.operation,
                 "fields": sorted(original)},
            )
            s.commit()  # durable BEFORE the target is modified
            action_id = action.id

        try:
            applied = change.apply()
        except Exception as exc:
            with self._sf() as s:
                row = s.get(RecoveryAction, action_id)
                row.verification_detail = (
                    f"Apply failed ({type(exc).__name__}); the change may be partial. "
                    "Restore remains available."
                )
                audit.record(s, "recovery.apply_failed", "recovery_action", action_id,
                             {"error": type(exc).__name__})
                s.commit()
            raise

        with self._sf() as s:
            row = s.get(RecoveryAction, action_id)
            row.applied_state = applied
            row.applied_at = utcnow()
            audit.record(s, "recovery.applied", "recovery_action", action_id,
                         {"fields": sorted(applied)})
            s.commit()
        return action_id

    def _require_permitted(self, engagement: Engagement | None, change: StateChange) -> None:
        state = check_engagement_open(engagement)
        if not state.allowed:
            raise RecoveryRefused(state.reason)
        assert engagement is not None
        if not engagement.allow_state_changes:
            raise RecoveryRefused(
                "This engagement does not permit state-changing verification."
            )
        decision = evaluate_engagement(engagement, change.scope_target, change.scope_kind)
        if not decision.allowed:
            raise RecoveryRefused(decision.reason)

    # ------------------------------------------------------------------ restore
    def restore(self, action_id: int, actor: str = "operator") -> RecoveryAction:
        """Restore and independently verify. Never raises for a failed restore;
        the outcome is recorded on the journal row and returned."""
        with self._sf() as s:
            row = s.get(RecoveryAction, action_id)
            if row is None:
                raise LookupError("Recovery action not found.")
            if row.status in TERMINAL_STATES:
                return row
            handler = _HANDLERS.get(row.rollback_procedure)
            if handler is None:
                return self._finish(
                    action_id,
                    RecoveryStatus.MANUAL_INTERVENTION_REQUIRED,
                    f"No restore handler is registered for '{row.rollback_procedure}'. "
                    "Restore the resource manually using the journaled original state.",
                    actor,
                )
            row.status = RecoveryStatus.IN_PROGRESS
            audit.record(s, "recovery.restore_started", "recovery_action", action_id, actor=actor)
            s.commit()
            resource = row.resource
            original = dict(row.original_state)
            irreversible = row.irreversible_consequences

        try:
            handler.restore(resource, original)
        except Exception as exc:
            return self._finish(
                action_id,
                RecoveryStatus.RESTORATION_FAILED,
                f"Restore failed ({type(exc).__name__}). The resource may still be modified.",
                actor,
            )

        with self._sf() as s:
            row = s.get(RecoveryAction, action_id)
            row.status = RecoveryStatus.RESTORED
            row.restored_at = utcnow()
            s.commit()

        try:
            current = handler.read_state(resource, original.keys())
        except Exception as exc:
            return self._finish(
                action_id,
                RecoveryStatus.MANUAL_INTERVENTION_REQUIRED,
                f"Restore ran, but independent verification could not read the resource "
                f"({type(exc).__name__}). Treat the restore as unconfirmed.",
                actor,
            )

        mismatched = sorted(k for k, v in original.items() if current.get(k, _MISSING) != v)
        if mismatched:
            return self._finish(
                action_id,
                RecoveryStatus.RESTORATION_FAILED,
                f"Verification found {len(mismatched)} field(s) that still differ from the "
                f"original state: {', '.join(mismatched)}.",
                actor,
            )
        detail = (
            f"Independently re-read the resource; all {len(original)} captured field(s) "
            "match the original state."
        )
        if irreversible:
            detail += f" Irreversible consequences remain: {irreversible}"
        return self._finish(action_id, RecoveryStatus.RESTORATION_VERIFIED, detail, actor,
                            verified=True)

    def _finish(
        self,
        action_id: int,
        status: RecoveryStatus,
        detail: str,
        actor: str,
        *,
        verified: bool = False,
    ) -> RecoveryAction:
        with self._sf() as s:
            row = s.get(RecoveryAction, action_id)
            row.status = status
            row.verification_detail = detail
            if verified:
                row.verified_at = utcnow()
            audit.record(s, f"recovery.{status.value}", "recovery_action", action_id, actor=actor)
            s.commit()
            return row

    # ------------------------------------------------------------------ queries
    def pending(self, engagement_id: int | None = None) -> list[RecoveryAction]:
        """Journal rows that still need attention (not verified / not terminal)."""
        with self._sf() as s:
            stmt = select(RecoveryAction).where(RecoveryAction.status.not_in(TERMINAL_STATES))
            if engagement_id is not None:
                stmt = stmt.where(RecoveryAction.engagement_id == engagement_id)
            return list(s.scalars(stmt.order_by(RecoveryAction.id)))

    def reconcile_after_crash(self) -> int:
        """Called at startup. A restore interrupted mid-flight is made retryable
        (restores re-apply the original state, so repeating one is safe)."""
        with self._sf() as s:
            stuck = list(
                s.scalars(
                    select(RecoveryAction).where(
                        RecoveryAction.status == RecoveryStatus.IN_PROGRESS
                    )
                )
            )
            for row in stuck:
                row.status = RecoveryStatus.AVAILABLE
                row.verification_detail = (
                    "A restore was interrupted when Sentinel stopped. Run restore again."
                )
            if stuck:
                audit.record(s, "recovery.reconciled", "recovery_action", "",
                             {"interrupted_restores": len(stuck)}, actor="system")
            s.commit()
            return len(stuck)
