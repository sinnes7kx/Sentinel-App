"""Persistent data model.

Classifications follow ROADMAP §10: severity, confidence, verification status
and recovery status are independent columns and are never inferred from one
another. Enumerations are stored as their string values with a CHECK
constraint, so an invalid lifecycle state cannot be written even by raw SQL.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, utcnow


# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationStatus(str, enum.Enum):
    """Verification lifecycle (ROADMAP §10). Only evidence advances it."""

    INFORMATIONAL = "informational"
    SUSPECTED = "suspected"
    DETECTED = "detected"
    VERIFIED = "verified"
    IMPACT_DEMONSTRATED = "impact_demonstrated"
    REMEDIATED = "remediated"
    RETESTED = "retested"


class RecoveryStatus(str, enum.Enum):
    """Recovery lifecycle (ROADMAP §10). RESTORATION_VERIFIED requires an
    independent post-restore check; RESTORED alone is not success."""

    NOT_REQUIRED = "not_required"
    AVAILABLE = "available"
    IN_PROGRESS = "in_progress"
    RESTORED = "restored"
    RESTORATION_VERIFIED = "restoration_verified"
    RESTORATION_FAILED = "restoration_failed"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"
    IRREVERSIBLE = "irreversible"


class EngagementStatus(str, enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    CLOSED = "closed"


class ScopeKind(str, enum.Enum):
    IP = "ip"
    CIDR = "cidr"
    HOST = "host"
    URL = "url"


class AssessmentStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class EvidenceKind(str, enum.Enum):
    HTTP_TRANSACTION = "http_transaction"
    TOOL_OUTPUT = "tool_output"
    SCREENSHOT = "screenshot"
    STATE_SNAPSHOT = "state_snapshot"
    NOTE = "note"


def _enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        length=32,
        values_callable=lambda members: [m.value for m in members],
    )


def _uuid() -> str:
    return str(uuid.uuid4())


_TS = DateTime(timezone=True)


# --------------------------------------------------------------------------
# Projects, engagements and scope
# --------------------------------------------------------------------------
class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(_TS, default=utcnow)

    engagements: Mapped[list[Engagement]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    assessments: Mapped[list[Assessment]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Engagement(Base):
    """An authorized testing engagement: who approved it, when, and what is in scope."""

    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[EngagementStatus] = mapped_column(
        _enum(EngagementStatus, "engagement_status"), default=EngagementStatus.DRAFT
    )
    # Attestation record. Sentinel records authorization; it cannot prove it.
    authorized_by: Mapped[str] = mapped_column(String(200), default="")
    authorization_reference: Mapped[str] = mapped_column(String(500), default="")
    starts_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    # Whether bounded, state-changing live verification is permitted at all.
    allow_state_changes: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(_TS, default=utcnow)

    project: Mapped[Project] = relationship(back_populates="engagements")
    scope: Mapped[list[ScopeEntry]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )


class ScopeEntry(Base):
    __tablename__ = "scope_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[ScopeKind] = mapped_column(_enum(ScopeKind, "scope_kind"))
    value: Mapped[str] = mapped_column(String(500))
    # Exclusions always win over inclusions.
    excluded: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str] = mapped_column(Text, default="")

    engagement: Mapped[Engagement] = relationship(back_populates="scope")


# --------------------------------------------------------------------------
# Assessments and findings
# --------------------------------------------------------------------------
class Assessment(Base):
    __tablename__ = "assessments"
    __table_args__ = (Index("ix_assessments_project_started", "project_id", "started_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    engagement_id: Mapped[int | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), nullable=True, index=True
    )
    target: Mapped[str] = mapped_column(String(500))
    tool: Mapped[str] = mapped_column(String(64))
    profile: Mapped[str] = mapped_column(String(64))
    status: Mapped[AssessmentStatus] = mapped_column(
        _enum(AssessmentStatus, "assessment_status"), default=AssessmentStatus.QUEUED
    )
    started_at: Mapped[datetime] = mapped_column(_TS, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tls: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # What was and was not checked. Incomplete coverage is never "clean".
    coverage: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")

    project: Mapped[Project] = relationship(back_populates="assessments")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    code: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"))
    confidence: Mapped[Confidence] = mapped_column(_enum(Confidence, "confidence"))
    source: Mapped[str] = mapped_column(String(64), default="sentinel")
    evidence: Mapped[str] = mapped_column(Text, default="")  # redacted summary
    remediation: Mapped[str] = mapped_column(Text, default="")
    verification_status: Mapped[VerificationStatus] = mapped_column(
        _enum(VerificationStatus, "verification_status"),
        default=VerificationStatus.DETECTED,
    )
    recovery_status: Mapped[RecoveryStatus] = mapped_column(
        _enum(RecoveryStatus, "finding_recovery_status"),
        default=RecoveryStatus.NOT_REQUIRED,
    )
    created_at: Mapped[datetime] = mapped_column(_TS, default=utcnow)

    assessment: Mapped[Assessment] = relationship(back_populates="findings")


# --------------------------------------------------------------------------
# Jobs
# --------------------------------------------------------------------------
class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(64))
    status: Mapped[JobStatus] = mapped_column(
        _enum(JobStatus, "job_status"), default=JobStatus.QUEUED, index=True
    )
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    assessment_id: Mapped[int | None] = mapped_column(
        ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(_TS, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")


# --------------------------------------------------------------------------
# Recovery journal (Sentinel Restore)
# --------------------------------------------------------------------------
class RecoveryAction(Base):
    """One permitted, journaled state change and everything needed to undo it.

    Written *before* the change is applied (ROADMAP §11) so cleanup can resume
    after a crash. The engagement cannot be deleted while journal rows exist.
    """

    __tablename__ = "recovery_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="RESTRICT"), index=True
    )
    job_id: Mapped[str | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    resource: Mapped[str] = mapped_column(String(500))   # designated test resource
    operation: Mapped[str] = mapped_column(String(64))   # e.g. "update_field"
    original_state: Mapped[dict[str, Any]] = mapped_column(JSON)
    applied_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    rollback_procedure: Mapped[str] = mapped_column(String(64))
    status: Mapped[RecoveryStatus] = mapped_column(
        _enum(RecoveryStatus, "recovery_status"), default=RecoveryStatus.AVAILABLE, index=True
    )
    # Declared before execution; irreversible consequences are never "restored".
    irreversible_consequences: Mapped[str] = mapped_column(Text, default="")
    verification_detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(_TS, default=utcnow)
    applied_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    restored_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(_TS, nullable=True)


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------
class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[EvidenceKind] = mapped_column(_enum(EvidenceKind, "evidence_kind"))
    assessment_id: Mapped[int | None] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=True, index=True
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    recovery_action_id: Mapped[int | None] = mapped_column(
        ForeignKey("recovery_actions.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(300), default="")
    content_type: Mapped[str] = mapped_column(String(100), default="text/plain")
    # Integrity: SHA-256 of the stored (already redacted) bytes.
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    inline_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_path: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(_TS, default=utcnow)


# --------------------------------------------------------------------------
# Audit log (append-only; enforced by triggers in the baseline migration)
# --------------------------------------------------------------------------
class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(_TS, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(200), default="operator")
    action: Mapped[str] = mapped_column(String(100))
    subject_type: Mapped[str] = mapped_column(String(64), default="")
    subject_id: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
