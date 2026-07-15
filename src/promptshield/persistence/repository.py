"""Repository classes for analyses and audit events."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, selectinload

from promptshield.persistence.models import Analysis, AuditEvent, FindingRecord


class AnalysisRepository:
    """CRUD and query helpers for :class:`Analysis`."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, analysis: Analysis) -> Analysis:
        self._session.add(analysis)
        return analysis

    def get(self, analysis_id: uuid.UUID) -> Analysis | None:
        stmt = (
            select(Analysis)
            .where(Analysis.id == analysis_id)
            .options(selectinload(Analysis.findings))
        )
        return self._session.scalars(stmt).first()

    def list(
        self,
        *,
        tenant_id: str | None = None,
        organization_id: uuid.UUID | str | None = None,
        risk_level: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        category: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Analysis]:
        stmt: Select[Any] = select(Analysis).options(selectinload(Analysis.findings))
        stmt = self._scope(stmt, tenant_id=tenant_id, organization_id=organization_id)
        if risk_level:
            stmt = stmt.where(Analysis.risk_level == risk_level.upper())
        if date_from:
            stmt = stmt.where(Analysis.timestamp >= date_from)
        if date_to:
            stmt = stmt.where(Analysis.timestamp <= date_to)
        if category:
            stmt = (
                stmt.join(FindingRecord)
                .where(FindingRecord.category == category)
                .distinct()
            )
        stmt = stmt.order_by(Analysis.timestamp.desc()).limit(limit).offset(offset)
        return list(self._session.scalars(stmt).unique().all())

    def count(
        self,
        *,
        tenant_id: str | None = None,
        organization_id: uuid.UUID | str | None = None,
        risk_level: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> int:
        stmt = select(func.count()).select_from(Analysis)
        stmt = self._scope(stmt, tenant_id=tenant_id, organization_id=organization_id)
        if risk_level:
            stmt = stmt.where(Analysis.risk_level == risk_level.upper())
        if date_from:
            stmt = stmt.where(Analysis.timestamp >= date_from)
        if date_to:
            stmt = stmt.where(Analysis.timestamp <= date_to)
        return int(self._session.scalar(stmt) or 0)

    @staticmethod
    def _scope(stmt: Any, *, tenant_id: str | None, organization_id: Any) -> Any:
        if organization_id is not None:
            try:
                oid = (
                    organization_id
                    if isinstance(organization_id, uuid.UUID)
                    else uuid.UUID(str(organization_id))
                )
                return stmt.where(Analysis.organization_id == oid)
            except (ValueError, TypeError):
                pass
        if tenant_id:
            return stmt.where(Analysis.tenant_id == tenant_id)
        return stmt

    def stats(
        self,
        *,
        tenant_id: str = "default",
        organization_id: uuid.UUID | str | None = None,
        days: int = 30,
    ) -> dict[str, Any]:
        """Aggregate statistics for dashboards."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        base = select(Analysis).where(Analysis.timestamp >= since)
        base = self._scope(base, tenant_id=tenant_id, organization_id=organization_id)
        rows = list(self._session.scalars(base).all())
        total = len(rows)
        by_level: dict[str, int] = {}
        by_policy: dict[str, int] = {}
        score_sum = 0
        blocks = 0
        warns = 0
        for row in rows:
            by_level[row.risk_level] = by_level.get(row.risk_level, 0) + 1
            by_policy[row.policy_action] = by_policy.get(row.policy_action, 0) + 1
            score_sum += row.risk_score
            if row.policy_action == "block":
                blocks += 1
            elif row.policy_action == "warn":
                warns += 1

        cat_stmt = (
            select(FindingRecord.category, func.count())
            .join(Analysis)
            .where(Analysis.timestamp >= since)
            .group_by(FindingRecord.category)
            .order_by(func.count().desc())
            .limit(10)
        )
        if organization_id is not None:
            try:
                oid = (
                    organization_id
                    if isinstance(organization_id, uuid.UUID)
                    else uuid.UUID(str(organization_id))
                )
                cat_stmt = cat_stmt.where(Analysis.organization_id == oid)
            except (ValueError, TypeError):
                cat_stmt = cat_stmt.where(Analysis.tenant_id == tenant_id)
        else:
            cat_stmt = cat_stmt.where(Analysis.tenant_id == tenant_id)
        top_categories = [
            {"category": cat, "count": int(cnt)}
            for cat, cnt in self._session.execute(cat_stmt).all()
        ]

        # Daily trend
        trend: list[dict[str, Any]] = []
        for i in range(min(days, 90)):
            day_start = (datetime.now(timezone.utc) - timedelta(days=i)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            day_end = day_start + timedelta(days=1)
            day_count = sum(
                1 for r in rows if day_start <= _as_utc(r.timestamp) < day_end
            )
            trend.append({"date": day_start.date().isoformat(), "count": day_count})
        trend.reverse()

        return {
            "tenant_id": tenant_id,
            "organization_id": str(organization_id) if organization_id else None,
            "period_days": days,
            "total_analyses": total,
            "by_risk_level": by_level,
            "by_policy_action": by_policy,
            "blocks": blocks,
            "warns": warns,
            "average_risk_score": round(score_sum / total, 2) if total else 0.0,
            "top_categories": top_categories,
            "trend": trend,
        }

    def delete_older_than(self, cutoff: datetime) -> int:
        rows = list(
            self._session.scalars(
                select(Analysis).where(Analysis.timestamp < cutoff)
            ).all()
        )
        for row in rows:
            self._session.delete(row)
        return len(rows)


class AuditEventRepository:
    """CRUD helpers for :class:`AuditEvent`."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, event: AuditEvent) -> AuditEvent:
        self._session.add(event)
        return event

    def list(
        self,
        *,
        tenant_id: str | None = None,
        organization_id: uuid.UUID | str | None = None,
        event_type: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEvent]:
        stmt = select(AuditEvent)
        if organization_id is not None:
            try:
                oid = (
                    organization_id
                    if isinstance(organization_id, uuid.UUID)
                    else uuid.UUID(str(organization_id))
                )
                stmt = stmt.where(AuditEvent.organization_id == oid)
            except (ValueError, TypeError):
                if tenant_id:
                    stmt = stmt.where(AuditEvent.tenant_id == tenant_id)
        elif tenant_id:
            stmt = stmt.where(AuditEvent.tenant_id == tenant_id)
        if event_type:
            stmt = stmt.where(AuditEvent.event_type == event_type)
        if date_from:
            stmt = stmt.where(AuditEvent.timestamp >= date_from)
        if date_to:
            stmt = stmt.where(AuditEvent.timestamp <= date_to)
        stmt = stmt.order_by(AuditEvent.timestamp.desc()).limit(limit).offset(offset)
        return list(self._session.scalars(stmt).all())

    def delete_older_than(self, cutoff: datetime) -> int:
        rows = list(
            self._session.scalars(
                select(AuditEvent).where(AuditEvent.timestamp < cutoff)
            ).all()
        )
        for row in rows:
            self._session.delete(row)
        return len(rows)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
