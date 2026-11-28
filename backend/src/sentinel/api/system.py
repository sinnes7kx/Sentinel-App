"""Platform status, tool registry and WSL/Kali discovery (read-only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__
from ..core.tools import TOOLS
from ..core.tools import wsl as wsl_discovery
from ..db.models import Job, JobStatus, RecoveryAction
from ..services.recovery import TERMINAL_STATES as RECOVERY_TERMINAL
from .deps import get_db
from .schemas import SystemStatus, ToolOut, ToolProfileOut, WslStatus, WslTools

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/status", response_model=SystemStatus)
def status(request: Request, db: Session = Depends(get_db)):
    jobs = request.app.state.jobs
    active = db.scalar(
        select(func.count()).select_from(Job)
        .where(Job.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]))
    )
    pending = db.scalar(
        select(func.count()).select_from(RecoveryAction)
        .where(RecoveryAction.status.not_in(RECOVERY_TERMINAL))
    )
    return SystemStatus(
        version=__version__,
        job_engine_running=jobs.running,
        job_kinds=jobs.kinds,
        active_jobs=active or 0,
        pending_recovery_actions=pending or 0,
    )


def _installed(spec) -> bool:
    try:
        return bool(spec.installed())
    except Exception:
        return False


@router.get("/tools", response_model=list[ToolOut])
def tools():
    """Registered tool adapters with their fixed, reviewed profiles."""
    return [
        ToolOut(
            id=spec.id,
            name=spec.name,
            blurb=spec.blurb,
            kind=spec.kind,
            note=getattr(spec, "note", ""),
            installed=_installed(spec),
            profiles=[
                ToolProfileOut(
                    id=p.id, label=p.label, blurb=p.blurb, timeout_s=p.timeout, coverage=p.coverage
                )
                for p in spec.profiles.values()
            ],
        )
        for spec in TOOLS
    ]


@router.get("/wsl", response_model=WslStatus)
def wsl_status():
    """Detect WSL and registered distributions (Kali listed first). Never installs."""
    try:
        return WslStatus(available=True, distributions=wsl_discovery.distributions())
    except ValueError as exc:
        return WslStatus(available=False, error=str(exc))


@router.get("/wsl/{distribution}/tools", response_model=WslTools)
def wsl_tools(distribution: str):
    """Report which supported adapters are on PATH inside a distribution."""
    try:
        return WslTools(distribution=distribution,
                        tools=wsl_discovery.available_tools(distribution))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
