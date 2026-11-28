"""Alembic environment for Sentinel."""
from __future__ import annotations

from logging.config import fileConfig

from alembic import context

from sentinel.config import get_settings
from sentinel.db import models  # noqa: F401  (registers tables on the metadata)
from sentinel.db.base import Base, make_engine

config = context.config

# Only configure logging when invoked via the CLI with an ini file; the app
# runs migrations programmatically and keeps its own logging configuration.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    explicit = config.get_main_option("sqlalchemy.url")
    if explicit:
        return explicit
    settings = get_settings()
    settings.ensure_data_dir()  # fresh install: the directory may not exist yet
    return settings.db_url


def _configure_and_run(**kwargs) -> None:
    # Batch mode lets future migrations ALTER SQLite tables safely.
    context.configure(target_metadata=target_metadata, render_as_batch=True, **kwargs)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    _configure_and_run(url=_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})


def run_migrations_online() -> None:
    engine = make_engine(_url())
    try:
        with engine.connect() as connection:
            _configure_and_run(connection=connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
