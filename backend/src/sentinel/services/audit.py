"""Append-only audit trail.

Callers add events inside their own transaction so the audit record and the
change it describes commit (or roll back) together. Details are redacted.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..core.evidence import sanitize
from ..db.models import AuditEvent


def record(
    session: Session,
    action: str,
    subject_type: str = "",
    subject_id: object = "",
    details: dict[str, Any] | None = None,
    actor: str = "operator",
) -> AuditEvent:
    event = AuditEvent(
        action=action,
        subject_type=subject_type,
        subject_id=str(subject_id),
        details=sanitize(details or {}),
        actor=actor,
    )
    session.add(event)
    return event
