"""Shared FastAPI dependencies."""
from __future__ import annotations

from fastapi import HTTPException, Request

from ..db.session import get_db
from ..services.jobs import JobManager
from ..services.recovery import RecoveryService

__all__ = ["get_db", "get_jobs", "get_recovery", "not_found"]


def get_jobs(request: Request) -> JobManager:
    return request.app.state.jobs


def get_recovery(request: Request) -> RecoveryService:
    return request.app.state.recovery


def not_found(what: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"{what} not found.")
