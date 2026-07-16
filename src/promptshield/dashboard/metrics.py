"""Dashboard metrics computed from the persistence layer."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from promptshield.compliance import CATEGORY_FRAMEWORKS
from promptshield.persistence.database import get_session_factory
from promptshield.persistence.models import Analysis
from promptshield.persistence.unit_of_work import SqlAlchemyUnitOfWork

# Framework display names for compliance widget
_FRAMEWORKS = ("GDPR", "SOC2", "PCI-DSS", "ISO27001")


def _utc_today_start() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _filter_org(stmt: Any, tenant_id: str) -> Any:
    """Scope by organization_id when tenant_id is a UUID, else tenant_id string."""
    try:
        oid = uuid.UUID(str(tenant_id))
        return stmt.where(Analysis.organization_id == oid)
    except (ValueError, TypeError):
        return stmt.where(Analysis.tenant_id == tenant_id)


def dashboard_summary(*, tenant_id: str = "default") -> dict[str, Any]:
    """Today's KPIs, risk distribution, top detectors and categories."""
    today = _utc_today_start()
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        session = uow.session
        today_q = (
            select(Analysis)
            .where(Analysis.timestamp >= today)
            .options(selectinload(Analysis.findings))
        )
        today_rows = list(session.scalars(_filter_org(today_q, tenant_id)).all())
        # Risk distribution: last 30 days
        since_30 = datetime.now(timezone.utc) - timedelta(days=30)
        period_q = (
            select(Analysis)
            .where(Analysis.timestamp >= since_30)
            .options(selectinload(Analysis.findings))
        )
        period_rows = list(session.scalars(_filter_org(period_q, tenant_id)).all())

        blocked = sum(1 for r in today_rows if r.policy_action == "block")
        warned = sum(1 for r in today_rows if r.policy_action == "warn")
        secrets = 0
        score_sum = 0
        for r in today_rows:
            score_sum += r.risk_score
            secrets += sum(1 for f in r.findings if f.category == "secret")

        risk_distribution: dict[str, int] = {"GREEN": 0, "YELLOW": 0, "RED": 0}
        for r in period_rows:
            lvl = (r.risk_level or "GREEN").upper()
            if lvl in risk_distribution:
                risk_distribution[lvl] += 1
            else:
                risk_distribution[lvl] = risk_distribution.get(lvl, 0) + 1

        det_counts: dict[str, int] = defaultdict(int)
        cat_counts: dict[str, int] = defaultdict(int)
        for r in period_rows:
            for f in r.findings:
                det_counts[f.detector_name] += 1
                cat_counts[f.category or "unknown"] += 1

        top_detectors = [
            {"name": n, "count": c}
            for n, c in sorted(det_counts.items(), key=lambda x: -x[1])[:8]
        ]
        top_categories = [
            {"category": n, "count": c}
            for n, c in sorted(cat_counts.items(), key=lambda x: -x[1])[:8]
        ]

        total_today = len(today_rows)
        return {
            "today": {
                "total_analyses": total_today,
                "blocked": blocked,
                "warned": warned,
                "secrets_detected": secrets,
                "average_risk_score": round(score_sum / total_today, 2)
                if total_today
                else 0.0,
            },
            "risk_distribution": risk_distribution,
            "top_detectors": top_detectors,
            "top_categories": top_categories,
        }


def dashboard_trend(*, tenant_id: str = "default", days: int = 30) -> dict[str, Any]:
    """Daily series for charts (total, blocked, secrets, avg risk)."""
    days = max(1, min(days, 90))
    since = datetime.now(timezone.utc) - timedelta(days=days - 1)
    since = since.replace(hour=0, minute=0, second=0, microsecond=0)

    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        q = (
            select(Analysis)
            .where(Analysis.timestamp >= since)
            .options(selectinload(Analysis.findings))
        )
        rows = list(uow.session.scalars(_filter_org(q, tenant_id)).all())

    buckets: dict[str, list[Analysis]] = defaultdict(list)
    for r in rows:
        day = _as_utc(r.timestamp).date().isoformat()
        buckets[day].append(r)

    labels: list[str] = []
    total: list[int] = []
    blocked: list[int] = []
    secrets: list[int] = []
    risk_avg: list[float] = []

    for i in range(days):
        day = (since + timedelta(days=i)).date().isoformat()
        labels.append(day)
        day_rows = buckets.get(day, [])
        total.append(len(day_rows))
        blocked.append(sum(1 for r in day_rows if r.policy_action == "block"))
        sec = 0
        sc = 0
        for r in day_rows:
            sc += r.risk_score
            sec += sum(1 for f in r.findings if f.category == "secret")
        secrets.append(sec)
        risk_avg.append(round(sc / len(day_rows), 2) if day_rows else 0.0)

    return {
        "labels": labels,
        "total": total,
        "blocked": blocked,
        "secrets": secrets,
        "risk_score_avg": risk_avg,
    }


def dashboard_recent(
    *,
    tenant_id: str = "default",
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Latest analyses (no original prompt)."""
    limit = max(1, min(limit, 50))
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        try:
            oid = uuid.UUID(str(tenant_id))
            rows = uow.analyses.list(organization_id=oid, limit=limit, offset=0)
        except (ValueError, TypeError):
            rows = uow.analyses.list(tenant_id=tenant_id, limit=limit, offset=0)
    return [
        {
            "id": str(r.id),
            "timestamp": r.timestamp.isoformat(),
            "risk_level": r.risk_level,
            "risk_score": r.risk_score,
            "policy_action": r.policy_action,
            "finding_count": len(r.findings) if r.findings is not None else 0,
            "classification_label": r.classification_label,
            "request_id": r.request_id,
        }
        for r in rows
    ]


def dashboard_compliance(*, tenant_id: str = "default") -> dict[str, Any]:
    """Per-framework compliance scores based on historical findings.

    If 100 analyses and 18 have at least one finding tagged with a framework
    (via category → compliance mapping), score = 82.
    Empty DB → 100% for all frameworks.
    """
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        session = uow.session
        q = select(Analysis).options(selectinload(Analysis.findings))
        analyses = list(session.scalars(_filter_org(q, tenant_id)).all())

    total = len(analyses)
    result: dict[str, Any] = {}
    if total == 0:
        for fw in _FRAMEWORKS:
            result[fw.replace("-", "_") if fw == "PCI-DSS" else fw] = {
                "score": 100,
                "total_findings": 0,
                "analyses_with_issues": 0,
                "total_analyses": 0,
                "compliant": 100,
            }
        # Keep both PCI_DSS and PCI-DSS friendly keys
        result["PCI_DSS"] = result.get(
            "PCI-DSS",
            result.get(
                "PCI_DSS",
                {
                    "score": 100,
                    "total_findings": 0,
                    "analyses_with_issues": 0,
                    "total_analyses": 0,
                    "compliant": 100,
                },
            ),
        )
        if "PCI-DSS" not in result:
            result["PCI-DSS"] = result["PCI_DSS"]
        return result

    # Map framework → set of analysis ids that have a related finding
    fw_analyses: dict[str, set[str]] = {fw: set() for fw in _FRAMEWORKS}
    fw_finding_counts: dict[str, int] = {fw: 0 for fw in _FRAMEWORKS}

    def _norm(name: str) -> str:
        return name.replace("-", "").replace("_", "").upper()

    for analysis in analyses:
        aid = str(analysis.id)
        for finding in analysis.findings:
            frameworks = finding.compliance_frameworks or frameworks_for_category_list(
                finding.category
            )
            norms = {_norm(str(f)) for f in frameworks}
            for fw in _FRAMEWORKS:
                if _norm(fw) in norms:
                    fw_analyses[fw].add(aid)
                    fw_finding_counts[fw] += 1

    for fw in _FRAMEWORKS:
        issues = len(fw_analyses[fw])
        score = int(round((1 - (issues / total)) * 100)) if total else 100
        score = max(0, min(100, score))
        entry = {
            "score": score,
            "total_findings": fw_finding_counts[fw],
            "analyses_with_issues": issues,
            "total_analyses": total,
            "compliant": score,
        }
        if fw == "PCI-DSS":
            result["PCI_DSS"] = entry
            result["PCI-DSS"] = entry
        else:
            result[fw] = entry
    return result


def frameworks_for_category_list(category: str) -> list[str]:
    return list(CATEGORY_FRAMEWORKS.get(category or "", []))


def dashboard_audit_timeline(
    *,
    tenant_id: str = "default",
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Latest audit events for the dashboard feed."""
    limit = max(1, min(limit, 100))
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        try:
            oid = uuid.UUID(str(tenant_id))
            rows = uow.events.list(organization_id=oid, limit=limit, offset=0)
        except (ValueError, TypeError):
            rows = uow.events.list(tenant_id=tenant_id, limit=limit, offset=0)
    return [
        {
            "id": str(e.id),
            "event_type": e.event_type,
            "timestamp": e.timestamp.isoformat(),
            "analysis_id": str(e.analysis_id) if e.analysis_id else None,
            "metadata": _safe_metadata(dict(e.event_metadata or {})),
        }
        for e in rows
    ]


def _safe_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    """Drop any accidental secret-like values from metadata for display."""
    safe: dict[str, Any] = {}
    for k, v in meta.items():
        if isinstance(v, str) and any(
            x in v for x in ("AKIA", "ghp_", "eyJ", "BEGIN PRIVATE")
        ):
            safe[k] = "[redacted]"
        else:
            safe[k] = v
    return safe


def dashboard_report(*, tenant_id: str = "default") -> dict[str, Any]:
    """Monthly report payload for HTML export."""
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    summary = dashboard_summary(tenant_id=tenant_id)
    trend = dashboard_trend(tenant_id=tenant_id, days=30)
    compliance = dashboard_compliance(tenant_id=tenant_id)
    recent = dashboard_recent(tenant_id=tenant_id, limit=15)

    # Recommendations from top categories / detectors
    recommendations: list[str] = []
    for item in summary.get("top_categories", [])[:3]:
        cat = item["category"]
        count = item["count"]
        if cat == "secret":
            recommendations.append(
                f"Increase in secret findings ({count} in the last 30 days): "
                "review developer training and secret scanning in CI."
            )
        elif cat == "pii":
            recommendations.append(
                f"PII detected frequently ({count}): review data-minimization "
                "and masking policies before sending prompts to LLMs."
            )
        elif cat == "context":
            recommendations.append(
                f"Sensitive context ({count}): limit production/financial "
                "mentions in prompts to external providers."
            )
        else:
            recommendations.append(
                f"Category '{cat}' among top risks ({count} findings): "
                "consider dedicated block policies."
            )
    if summary["today"]["blocked"] > 0:
        recommendations.append(
            f"Today {summary['today']['blocked']} prompts blocked by policy — "
            "monitor false positives and update rules.yaml if needed."
        )
    if not recommendations:
        recommendations.append(
            "No dominant risk in the period: keep continuous monitoring."
        )

    return {
        "generated_at": now.isoformat(),
        "period": {
            "month": month_start.strftime("%Y-%m"),
            "label": month_start.strftime("%B %Y"),
        },
        "summary": summary,
        "trend": trend,
        "compliance": compliance,
        "recent": recent,
        "recommendations": recommendations,
        "tenant_id": tenant_id,
    }
