"""Request and response models for the local API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    model_validator,
)

from ..db.models import (
    EngagementStatus,
    JobStatus,
    RecoveryStatus,
    ScopeKind,
)


class _ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------- projects
class ProjectCreate(_Strict):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)


class ProjectOut(_ORM):
    id: int
    name: str
    description: str
    created_at: datetime


# ---------------------------------------------------------------- scope
class ScopeEntryIn(_Strict):
    kind: ScopeKind
    value: str = Field(min_length=1, max_length=500)
    excluded: bool = False
    note: str = Field(default="", max_length=2000)


class ScopeEntryOut(_ORM):
    id: int
    kind: ScopeKind
    value: str
    excluded: bool
    note: str


class ScopeCheckIn(_Strict):
    target: str = Field(min_length=1, max_length=2000)
    kind: Literal["web", "net"]


class ScopeDecisionOut(BaseModel):
    allowed: bool
    reason: str
    matched_entry_id: int | None = None


# ---------------------------------------------------------------- engagements
def _check_window(starts: datetime | None, ends: datetime | None) -> None:
    if starts is not None and ends is not None and ends <= starts:
        raise ValueError("The authorization window must end after it starts.")


class EngagementCreate(_Strict):
    name: str = Field(min_length=1, max_length=200)
    authorized_by: str = Field(default="", max_length=200)
    authorization_reference: str = Field(default="", max_length=500)
    starts_at: AwareDatetime | None = None
    ends_at: AwareDatetime | None = None
    allow_state_changes: bool = False

    @model_validator(mode="after")
    def _window(self):
        _check_window(self.starts_at, self.ends_at)
        return self


class EngagementUpdate(_Strict):
    """Partial update; only fields present in the request are applied."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    authorized_by: str | None = Field(default=None, max_length=200)
    authorization_reference: str | None = Field(default=None, max_length=500)
    starts_at: AwareDatetime | None = None
    ends_at: AwareDatetime | None = None
    allow_state_changes: bool | None = None


class EngagementStatusChange(_Strict):
    status: EngagementStatus


class EngagementOut(_ORM):
    id: int
    project_id: int
    name: str
    status: EngagementStatus
    authorized_by: str
    authorization_reference: str
    starts_at: datetime | None
    ends_at: datetime | None
    allow_state_changes: bool
    created_at: datetime
    scope: list[ScopeEntryOut]


# ---------------------------------------------------------------- jobs
class JobOut(_ORM):
    id: str
    kind: str
    status: JobStatus
    params: dict[str, Any]
    assessment_id: int | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str


class CancelAccepted(BaseModel):
    job_id: str
    cancel_requested: bool = True


# ---------------------------------------------------------------- recovery
class RecoveryActionOut(_ORM):
    id: int
    engagement_id: int
    job_id: str | None
    finding_id: int | None
    resource: str
    operation: str
    rollback_procedure: str
    status: RecoveryStatus
    irreversible_consequences: str
    verification_detail: str
    created_at: datetime
    applied_at: datetime | None
    restored_at: datetime | None
    verified_at: datetime | None
    # Original values stay in the journal; the API lists field names only.
    original_state: dict[str, Any] = Field(exclude=True)

    @computed_field
    @property
    def captured_fields(self) -> list[str]:
        return sorted(self.original_state)


# ---------------------------------------------------------------- audit
class AuditEventOut(_ORM):
    id: int
    at: datetime
    actor: str
    action: str
    subject_type: str
    subject_id: str
    details: dict[str, Any]


# ---------------------------------------------------------------- system
class ToolProfileOut(BaseModel):
    id: str
    label: str
    blurb: str
    timeout_s: int
    coverage: str


class ToolOut(BaseModel):
    id: str
    name: str
    blurb: str
    kind: Literal["web", "net"]
    note: str
    installed: bool
    profiles: list[ToolProfileOut]


class WslStatus(BaseModel):
    available: bool
    distributions: list[str] = []
    error: str = ""


class WslTools(BaseModel):
    distribution: str
    tools: list[str]


class SystemStatus(BaseModel):
    version: str
    job_engine_running: bool
    job_kinds: list[str]
    active_jobs: int
    pending_recovery_actions: int
