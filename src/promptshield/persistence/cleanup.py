"""Retention policy enforcement for analyses and audit events."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from promptshield.persistence.database import get_session_factory, init_db
from promptshield.persistence.unit_of_work import SqlAlchemyUnitOfWork

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 90


def get_retention_days() -> int:
    """Read ``PROMPTSHIELD_RETENTION_DAYS`` (default 90)."""
    raw = os.environ.get("PROMPTSHIELD_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS))
    try:
        days = int(raw)
    except ValueError:
        days = DEFAULT_RETENTION_DAYS
    return max(1, days)


def enforce_retention_policy(
    retention_days: int | None = None,
    *,
    database_url: str | None = None,
) -> dict[str, Any]:
    """Delete analyses (and cascade findings) and orphan-safe audit events older than N days.

    Returns:
        Summary dict with deleted counts.
    """
    days = retention_days if retention_days is not None else get_retention_days()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    init_db(database_url)
    factory = get_session_factory(database_url)
    with SqlAlchemyUnitOfWork(factory) as uow:
        # Events without cascade from deleted analyses may remain if SET NULL
        deleted_events = uow.events.delete_older_than(cutoff)
        deleted_analyses = uow.analyses.delete_older_than(cutoff)
        uow.commit()
    logger.info(
        "retention_enforced days=%s deleted_analyses=%s deleted_events=%s",
        days,
        deleted_analyses,
        deleted_events,
    )
    return {
        "retention_days": days,
        "cutoff": cutoff.isoformat(),
        "deleted_analyses": deleted_analyses,
        "deleted_events": deleted_events,
    }
