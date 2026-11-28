"""FastAPI application factory and local entry point.

Run (development):  python -m sentinel.main   (with src/ on PYTHONPATH)
The app binds to loopback only and authenticates with the per-install token.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .api import api_router
from .config import get_settings
from .db.migrate import upgrade_to_head
from .db.session import dispose_engine, init_engine, session_factory
from .security import SessionTokenMiddleware
from .services.jobs import JobManager
from .services.recovery import RecoveryService


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.ensure_data_dir()
    # Materialize the session token on startup so the dev proxy can read it.
    settings.session_token()
    # Bring the schema to head before serving any request.
    upgrade_to_head(settings.db_url)
    init_engine(settings.db_url)
    factory = session_factory()

    # Crash recovery first: surface interrupted restores and jobs before any
    # new work can start (ROADMAP §11).
    recovery = RecoveryService(factory)
    recovery.reconcile_after_crash()
    jobs = JobManager(factory, workers=1)
    await jobs.start()

    app.state.recovery = recovery
    app.state.jobs = jobs
    try:
        yield
    finally:
        await jobs.stop()
        dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Sentinel",
        version=__version__,
        summary="Authorized security assessment platform — local API",
        lifespan=lifespan,
    )
    app.add_middleware(SessionTokenMiddleware, token=settings.session_token())
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.dev_origins),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router)
    return app


app = create_app()


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "sentinel.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
