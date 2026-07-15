"""Usage tracking per organization / calendar month."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select

from promptshield.persistence.models import UsageRecord
from promptshield.persistence.unit_of_work import UnitOfWork

if TYPE_CHECKING:
    from promptshield.service import ServiceAnalysisResult

logger = logging.getLogger(__name__)


def track_usage(
    uow: UnitOfWork,
    organization_id: uuid.UUID | str | None,
    outcome: ServiceAnalysisResult,
) -> None:
    """Increment monthly usage counters for the organization.

    Safe no-op when ``organization_id`` is missing.
    """
    if organization_id is None:
        return
    try:
        org_uuid = (
            organization_id
            if isinstance(organization_id, uuid.UUID)
            else uuid.UUID(str(organization_id))
        )
    except (ValueError, TypeError):
        return

    now = datetime.now(timezone.utc)
    year, month = now.year, now.month
    session = uow.session  # type: ignore[attr-defined]
    row = session.scalars(
        select(UsageRecord).where(
            UsageRecord.organization_id == org_uuid,
            UsageRecord.year == year,
            UsageRecord.month == month,
        )
    ).first()
    if row is None:
        row = UsageRecord(
            id=uuid.uuid4(),
            organization_id=org_uuid,
            year=year,
            month=month,
            analysis_count=0,
            blocked_count=0,
            secret_count=0,
        )
        session.add(row)

    row.analysis_count = int(row.analysis_count or 0) + 1
    if outcome.blocked:
        row.blocked_count = int(row.blocked_count or 0) + 1
    secrets = sum(1 for f in outcome.findings if f.category == "secret")
    if secrets:
        row.secret_count = int(row.secret_count or 0) + secrets
    logger.debug(
        "usage_tracked org=%s y=%s m=%s analysis=%s blocked=%s secrets=%s",
        org_uuid,
        year,
        month,
        row.analysis_count,
        row.blocked_count,
        row.secret_count,
    )
