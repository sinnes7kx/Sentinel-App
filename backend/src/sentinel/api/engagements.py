"""Projects, engagements and engagement scope.

Authorization lifecycle:
* New engagements start as DRAFT. Scope, authorizer, reference, window and
  the state-change permission can only be edited while DRAFT.
* DRAFT -> ACTIVE requires an authorizer, an authorization reference, at least
  one in-scope entry and an unexpired window.
* ACTIVE -> DRAFT pauses testing so the authorization can be amended.
* -> CLOSED is final, and is refused while recovery actions are still pending.
Every change is written to the append-only audit log.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.base import utcnow
from ..db.models import Engagement, EngagementStatus, Project, ScopeEntry
from ..services import audit
from ..services.recovery import RecoveryService
from ..services.scope import evaluate_engagement, normalize_scope_value
from .deps import get_db, get_recovery, not_found
from .schemas import (
    EngagementCreate,
    EngagementOut,
    EngagementStatusChange,
    EngagementUpdate,
    ProjectCreate,
    ProjectOut,
    ScopeCheckIn,
    ScopeDecisionOut,
    ScopeEntryIn,
    ScopeEntryOut,
)

router = APIRouter(tags=["engagements"])

D, A, C = EngagementStatus.DRAFT, EngagementStatus.ACTIVE, EngagementStatus.CLOSED
TRANSITIONS: dict[EngagementStatus, frozenset[EngagementStatus]] = {
    D: frozenset({A, C}),
    A: frozenset({D, C}),
    C: frozenset(),
}
_NOT_NULL = ("name", "authorized_by", "authorization_reference", "allow_state_changes")


def _project(db: Session, project_id: int) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise not_found("Project")
    return project


def _engagement(db: Session, engagement_id: int) -> Engagement:
    engagement = db.get(Engagement, engagement_id)
    if engagement is None:
        raise not_found("Engagement")
    return engagement


def _require_draft(engagement: Engagement) -> None:
    if engagement.status is C:
        raise HTTPException(409, "Closed engagements are read-only.")
    if engagement.status is not D:
        raise HTTPException(
            409,
            "An active engagement's authorization and scope cannot be changed. "
            "Pause it (set its status to draft) first.",
        )


def activation_problems(engagement: Engagement) -> list[str]:
    problems = []
    if not engagement.authorized_by.strip():
        problems.append("Record who authorized this engagement.")
    if not engagement.authorization_reference.strip():
        problems.append("Record the authorization reference (contract, SOW or written approval).")
    if not any(not e.excluded for e in engagement.scope):
        problems.append("Add at least one in-scope entry.")
    if engagement.ends_at is not None and engagement.ends_at <= utcnow():
        problems.append("The authorization window has already ended.")
    return problems


# ---------------------------------------------------------------- projects
@router.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.scalars(select(Project).order_by(Project.name)).all()


@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    if db.scalar(select(Project.id).where(Project.name == body.name)) is not None:
        raise HTTPException(409, "A project with this name already exists.")
    project = Project(name=body.name, description=body.description)
    db.add(project)
    db.flush()
    audit.record(db, "project.created", "project", project.id, {"name": project.name})
    db.commit()
    return project


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: int, db: Session = Depends(get_db)):
    return _project(db, project_id)


# ---------------------------------------------------------------- engagements
@router.get("/projects/{project_id}/engagements", response_model=list[EngagementOut])
def list_engagements(project_id: int, db: Session = Depends(get_db)):
    _project(db, project_id)
    return db.scalars(
        select(Engagement).where(Engagement.project_id == project_id).order_by(Engagement.id)
    ).all()


@router.post("/projects/{project_id}/engagements", response_model=EngagementOut, status_code=201)
def create_engagement(project_id: int, body: EngagementCreate, db: Session = Depends(get_db)):
    _project(db, project_id)
    engagement = Engagement(project_id=project_id, status=D, **body.model_dump())
    db.add(engagement)
    db.flush()
    audit.record(db, "engagement.created", "engagement", engagement.id,
                 {"name": engagement.name, "allow_state_changes": engagement.allow_state_changes})
    db.commit()
    db.refresh(engagement)
    return engagement


@router.get("/engagements/{engagement_id}", response_model=EngagementOut)
def get_engagement(engagement_id: int, db: Session = Depends(get_db)):
    return _engagement(db, engagement_id)


@router.patch("/engagements/{engagement_id}", response_model=EngagementOut)
def update_engagement(engagement_id: int, body: EngagementUpdate, db: Session = Depends(get_db)):
    engagement = _engagement(db, engagement_id)
    _require_draft(engagement)
    changes = body.model_dump(exclude_unset=True)
    for key in _NOT_NULL:
        if key in changes and changes[key] is None:
            raise HTTPException(422, f"'{key}' cannot be null.")
    starts = changes.get("starts_at", engagement.starts_at)
    ends = changes.get("ends_at", engagement.ends_at)
    if starts is not None and ends is not None and ends <= starts:
        raise HTTPException(422, "The authorization window must end after it starts.")
    for key, value in changes.items():
        setattr(engagement, key, value)
    audit.record(db, "engagement.updated", "engagement", engagement.id, {"fields": sorted(changes)})
    db.commit()
    return engagement


@router.post("/engagements/{engagement_id}/status", response_model=EngagementOut)
def change_status(
    engagement_id: int,
    body: EngagementStatusChange,
    db: Session = Depends(get_db),
    recovery: RecoveryService = Depends(get_recovery),
):
    engagement = _engagement(db, engagement_id)
    target = body.status
    if target is engagement.status:
        return engagement
    if target not in TRANSITIONS[engagement.status]:
        raise HTTPException(
            409, f"Cannot change an engagement from {engagement.status.value} to {target.value}."
        )
    if target is A:
        problems = activation_problems(engagement)
        if problems:
            raise HTTPException(422, "Cannot activate: " + " ".join(problems))
    if target is C:
        pending = recovery.pending(engagement.id)
        if pending:
            raise HTTPException(
                409,
                f"Restore or resolve {len(pending)} pending recovery action(s) before closing "
                "this engagement.",
            )
    previous = engagement.status
    engagement.status = target
    audit.record(db, "engagement.status_changed", "engagement", engagement.id,
                 {"from": previous.value, "to": target.value})
    db.commit()
    return engagement


# ---------------------------------------------------------------- scope
@router.post(
    "/engagements/{engagement_id}/scope", response_model=ScopeEntryOut, status_code=201
)
def add_scope_entry(engagement_id: int, body: ScopeEntryIn, db: Session = Depends(get_db)):
    engagement = _engagement(db, engagement_id)
    _require_draft(engagement)
    try:
        value = normalize_scope_value(body.kind, body.value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if any(
        e.kind is body.kind and e.value == value and e.excluded == body.excluded
        for e in engagement.scope
    ):
        raise HTTPException(409, "This scope entry already exists.")
    entry = ScopeEntry(
        engagement_id=engagement.id, kind=body.kind, value=value,
        excluded=body.excluded, note=body.note,
    )
    db.add(entry)
    db.flush()
    audit.record(db, "engagement.scope_added", "engagement", engagement.id,
                 {"entry_id": entry.id, "kind": body.kind.value, "value": value,
                  "excluded": body.excluded})
    db.commit()
    return entry


@router.delete("/engagements/{engagement_id}/scope/{entry_id}", status_code=204)
def remove_scope_entry(engagement_id: int, entry_id: int, db: Session = Depends(get_db)):
    engagement = _engagement(db, engagement_id)
    _require_draft(engagement)
    entry = db.get(ScopeEntry, entry_id)
    if entry is None or entry.engagement_id != engagement.id:
        raise not_found("Scope entry")
    audit.record(db, "engagement.scope_removed", "engagement", engagement.id,
                 {"entry_id": entry.id, "kind": entry.kind.value, "value": entry.value,
                  "excluded": entry.excluded})
    db.delete(entry)
    db.commit()
    return Response(status_code=204)


@router.post("/engagements/{engagement_id}/scope/check", response_model=ScopeDecisionOut)
def check_scope(engagement_id: int, body: ScopeCheckIn, db: Session = Depends(get_db)):
    """Dry-run the scope gate for a target. Read-only; nothing is contacted."""
    decision = evaluate_engagement(_engagement(db, engagement_id), body.target, body.kind)
    return ScopeDecisionOut(
        allowed=decision.allowed,
        reason=decision.reason,
        matched_entry_id=decision.matched_entry_id,
    )
