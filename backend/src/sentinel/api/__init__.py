"""FastAPI routers for the Sentinel local API."""
from __future__ import annotations

from fastapi import APIRouter

from . import engagements, events, health, operations, system

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(system.router)
api_router.include_router(engagements.router)
api_router.include_router(operations.router)
api_router.include_router(events.router)
