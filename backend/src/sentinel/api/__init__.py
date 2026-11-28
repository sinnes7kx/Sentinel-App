"""FastAPI routers for the Sentinel local API."""
from __future__ import annotations

from fastapi import APIRouter

from . import health

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
