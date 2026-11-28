"""Liveness and build-info endpoint (token-less, read-only)."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from .. import __version__

router = APIRouter(tags=["health"])


class Health(BaseModel):
    status: str
    service: str
    version: str


@router.get("/health", response_model=Health)
async def health() -> Health:
    return Health(status="ok", service="sentinel-backend", version=__version__)
