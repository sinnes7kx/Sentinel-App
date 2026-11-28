"""Schema, migration and integrity guarantees of the persistence layer."""
from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from sentinel.db.base import Base
from sentinel.db.models import (
    Assessment,
    AssessmentStatus,
    AuditEvent,
    Confidence,
    Engagement,
    EngagementStatus,
    Finding,
    Project,
    RecoveryAction,
    RecoveryStatus,
    ScopeEntry,
    ScopeKind,
    Severity,
    VerificationStatus,
)

EXPECTED_TABLES = {
    "projects",
    "engagements",
    "scope_entries",
    "assessments",
    "findings",
    "jobs",
    "recovery_actions",
    "evidence_items",
    "audit_events",
}


def test_migration_creates_all_tables(engine):
    assert EXPECTED_TABLES <= set(inspect(engine).get_table_names())


def test_models_match_migrations(engine):
    """Fails if a model changes without a matching Alembic revision."""
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


def test_foreign_keys_enforced(engine):
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


def _project_with_assessment(session) -> tuple[Project, Engagement, Assessment]:
    project = Project(name="Acme internal")
    engagement = Engagement(
        project=project,
        name="Q4 web",
        status=EngagementStatus.ACTIVE,
        authorized_by="CISO",
        authorization_reference="SOW-2026-114",
    )
    engagement.scope.append(ScopeEntry(kind=ScopeKind.URL, value="https://app.test/"))
    assessment = Assessment(
        project=project,
        engagement_id=None,
        target="https://app.test/",
        tool="web",
        profile="web-v2",
        status=AssessmentStatus.COMPLETED,
        coverage={"http": "completed"},
    )
    session.add_all([project, engagement, assessment])
    session.flush()
    assessment.engagement_id = engagement.id
    session.commit()
    return project, engagement, assessment


def test_roundtrip_and_independent_classifications(session):
    _, engagement, assessment = _project_with_assessment(session)
    finding = Finding(
        assessment=assessment,
        code="CSP",
        title="Content Security Policy absent",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
    )
    session.add(finding)
    session.commit()

    loaded = session.get(Finding, finding.id)
    # Defaults: detected, not verified; recovery not required.
    assert loaded.verification_status is VerificationStatus.DETECTED
    assert loaded.recovery_status is RecoveryStatus.NOT_REQUIRED
    assert loaded.severity is Severity.LOW and loaded.confidence is Confidence.MEDIUM
    assert engagement.scope[0].kind is ScopeKind.URL
    # Stored as the plain string value, not the enum name.
    raw = session.execute(text("SELECT severity FROM findings")).scalar()
    assert raw == "low"


def test_invalid_lifecycle_value_rejected_by_database(session):
    _, _, assessment = _project_with_assessment(session)
    with pytest.raises(IntegrityError):
        session.execute(
            text(
                "INSERT INTO findings (assessment_id, code, title, severity, confidence, "
                "source, evidence, remediation, verification_status, recovery_status, created_at) "
                "VALUES (:a, 'X', 'x', 'low', 'medium', 's', '', '', 'proven_by_vibes', "
                "'not_required', '2026-01-01')"
            ),
            {"a": assessment.id},
        )
    session.rollback()


def test_audit_log_is_append_only(session):
    event = AuditEvent(action="engagement.created", subject_type="engagement", subject_id="1")
    session.add(event)
    session.commit()

    with pytest.raises(DBAPIError, match="append-only"):
        session.execute(text("UPDATE audit_events SET action = 'tampered'"))
    session.rollback()

    with pytest.raises(DBAPIError, match="append-only"):
        session.execute(text("DELETE FROM audit_events"))
    session.rollback()

    assert session.execute(text("SELECT action FROM audit_events")).scalar() == "engagement.created"


def test_timestamps_round_trip_as_utc_instants(session):
    from datetime import UTC, datetime, timedelta, timezone

    cest = timezone(timedelta(hours=2))
    start = datetime(2026, 6, 1, 9, 0, tzinfo=cest)  # 07:00 UTC
    project = Project(name="tz")
    eng = Engagement(project=project, name="e", starts_at=start)
    session.add(project)
    session.commit()
    session.expire_all()

    loaded = session.get(Engagement, eng.id).starts_at
    assert loaded == start  # same instant
    assert loaded.tzinfo is UTC and loaded.hour == 7


def test_naive_timestamps_refused(session):
    from datetime import datetime

    from sqlalchemy.exc import StatementError

    project = Project(name="naive")
    session.add(Engagement(project=project, name="e", starts_at=datetime(2026, 6, 1, 9, 0)))
    with pytest.raises(StatementError, match="Naive datetime"):
        session.commit()
    session.rollback()


def test_engagement_with_recovery_journal_cannot_be_deleted(session):
    _, engagement, _ = _project_with_assessment(session)
    session.add(
        RecoveryAction(
            engagement_id=engagement.id,
            resource="https://app.test/api/profiles/test-user-1",
            operation="update_field",
            original_state={"first_name": "Alice"},
            rollback_procedure="restore_field",
        )
    )
    session.commit()

    with pytest.raises(IntegrityError):
        session.execute(text("DELETE FROM engagements WHERE id = :i"), {"i": engagement.id})
    session.rollback()
