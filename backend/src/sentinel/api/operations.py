"""Jobs, recovery journal and audit log endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AuditEvent, Job, RecoveryAction
from ..services.jobs import TERMINAL_STATES as JOB_TERMINAL
from ..services.jobs import JobManager
from ..services.recovery import TERMINAL_STATES as RECOVERY_TERMINAL
from ..services.recovery import RecoveryService
from .deps import get_db, get_jobs, get_recovery, not_found
from .schemas import AuditEventOut, CancelAccepted, JobOut, RecoveryActionOut

router = APIRouter()


# ---------------------------------------------------------------- jobs
@router.get("/jobs", response_model=list[JobOut], tags=["jobs"])
def list_jobs(limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    return db.scalars(select(Job).order_by(Job.created_at.desc()).limit(limit)).all()


@router.get("/jobs/{job_id}", response_model=JobOut, tags=["jobs"])
def get_job(job_id: str, db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if job is None:
        raise not_found("Job")
    return job


@router.post("/jobs/{job_id}/cancel", response_model=CancelAccepted, status_code=202,
             tags=["jobs"])
def cancel_job(job_id: str, db: Session = Depends(get_db), jobs: JobManager = Depends(get_jobs)):
    job = db.get(Job, job_id)
    if job is None:
        raise not_found("Job")
    if job.status in JOB_TERMINAL:
        raise HTTPException(409, f"The job has already finished ({job.status.value}).")
    if not jobs.cancel(job_id):
        raise HTTPException(409, "The job is not active in this session.")
    return CancelAccepted(job_id=job_id)


# ---------------------------------------------------------------- recovery
@router.get("/recovery", response_model=list[RecoveryActionOut], tags=["recovery"])
def list_recovery(
    pending: bool = False,
    engagement_id: int | None = None,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    stmt = select(RecoveryAction)
    if pending:
        stmt = stmt.where(RecoveryAction.status.not_in(RECOVERY_TERMINAL))
    if engagement_id is not None:
        stmt = stmt.where(RecoveryAction.engagement_id == engagement_id)
    return db.scalars(stmt.order_by(RecoveryAction.id.desc()).limit(limit)).all()


@router.get("/recovery/{action_id}", response_model=RecoveryActionOut, tags=["recovery"])
def get_recovery_action(action_id: int, db: Session = Depends(get_db)):
    row = db.get(RecoveryAction, action_id)
    if row is None:
        raise not_found("Recovery action")
    return row


@router.post("/recovery/{action_id}/restore", response_model=RecoveryActionOut,
             tags=["recovery"])
def restore(action_id: int, recovery: RecoveryService = Depends(get_recovery)):
    """Restore and independently verify. The outcome — including failure — is
    in the returned status; it is never reported as verified without a check."""
    try:
        return recovery.restore(action_id)
    except LookupError:
        raise not_found("Recovery action") from None


# ---------------------------------------------------------------- audit
@router.get("/audit", response_model=list[AuditEventOut], tags=["audit"])
def list_audit(
    limit: int = Query(100, ge=1, le=1000),
    before_id: int | None = None,
    db: Session = Depends(get_db),
):
    stmt = select(AuditEvent)
    if before_id is not None:
        stmt = stmt.where(AuditEvent.id < before_id)
    return db.scalars(stmt.order_by(AuditEvent.id.desc()).limit(limit)).all()
