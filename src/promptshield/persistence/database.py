"""Database engine and session factory (SQLite / PostgreSQL)."""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

logger = logging.getLogger(__name__)

DEFAULT_DATABASE_URL = "sqlite:///promptshield.db"


def get_database_url() -> str:
    """Resolve ``DATABASE_URL`` (default SQLite file)."""
    return (
        os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL).strip()
        or DEFAULT_DATABASE_URL
    )


@lru_cache(maxsize=4)
def get_engine(url: str | None = None) -> Engine:
    """Create (or return cached) SQLAlchemy engine for ``url``."""
    db_url = url or get_database_url()
    connect_args: dict[str, Any] = {}
    engine_kwargs: dict[str, Any] = {"future": True}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        # Share in-memory DB across connections (tests).
        if ":memory:" in db_url:
            from sqlalchemy.pool import StaticPool

            engine_kwargs["poolclass"] = StaticPool
    engine = create_engine(db_url, connect_args=connect_args, **engine_kwargs)
    if db_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_fk(dbapi_conn, _connection_record) -> None:  # type: ignore[no-untyped-def]
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    logger.info("Database engine ready url=%s", _redact_url(db_url))
    return engine


def _redact_url(url: str) -> str:
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        if "@" in rest:
            creds, host = rest.rsplit("@", 1)
            return f"{scheme}://***@{host}"
    return url


def get_session_factory(url: str | None = None) -> sessionmaker[Session]:
    """Return a sessionmaker bound to the engine for ``url``."""
    engine = get_engine(url)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db(url: str | None = None) -> Engine:
    """Create all tables if they do not exist."""
    from promptshield.persistence.models import Base

    engine = get_engine(url)
    Base.metadata.create_all(engine)
    return engine


def reset_engine_cache() -> None:
    """Clear cached engines (tests)."""
    get_engine.cache_clear()
