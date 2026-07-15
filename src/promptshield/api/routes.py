"""HTTP routes for PromptShield Enterprise API (``/api/v1``)."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from promptshield.api.auth import (
    require_analysis_create,
    require_analysis_read,
    require_api_key,
)
from promptshield.api.dependencies import AuthDep, ServiceDep, TenantDep
from promptshield.api.schemas import (
    AnalysisDetailResponse,
    AnalysisListResponse,
    AnalysisSummary,
    AnalyzeRequest,
    CleanupResponse,
    EventListResponse,
    EventOut,
    FindingOut,
    HealthResponse,
    SanitizeRequest,
    StatsResponse,
)
from promptshield.persistence.cleanup import (
    enforce_retention_policy,
    get_retention_days,
)
from promptshield.persistence.database import get_session_factory
from promptshield.persistence.unit_of_work import SqlAlchemyUnitOfWork

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["promptshield"])


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "") or ""


def _client_meta(request: Request) -> dict[str, Any]:
    api_key = request.headers.get("X-API-Key")
    forwarded = request.headers.get("X-Forwarded-For")
    client_ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else None)
    )
    return {
        "api_key": api_key,
        "client_ip": client_ip,
        "user_agent": request.headers.get("User-Agent"),
    }


@router.get("/health", response_model=HealthResponse, dependencies=[])
async def health(request: Request, service: ServiceDep) -> HealthResponse:
    """Liveness/readiness probe (no API key required)."""
    payload = service.health()
    return HealthResponse(
        status=payload["status"],
        version=payload["version"],
        detectors=payload["detectors"],
        policies=payload.get("policies", 0),
        request_id=_request_id(request) or None,
    )


@router.post("/analyze", dependencies=[Depends(require_analysis_create)])
async def analyze(
    body: AnalyzeRequest,
    request: Request,
    service: ServiceDep,
    tenant_id: TenantDep,
    auth: AuthDep,
) -> dict[str, Any]:
    """Analyze a prompt; optional sanitize and explain flags."""
    rid = _request_id(request)
    meta = _client_meta(request)
    t0 = time.perf_counter()
    outcome = service.analyze(
        body.prompt,
        {
            "sanitize": body.sanitize,
            "explain": body.explain,
            "request_id": rid,
            "tenant_id": tenant_id,
            "organization_id": (
                str(auth.organization_id) if auth.organization_id else None
            ),
            **meta,
        },
    )
    report = outcome.to_report_dict(request_id=rid or None)
    if outcome.options.get("analysis_id"):
        report["analysis_id"] = outcome.options["analysis_id"]
    duration_ms = (time.perf_counter() - t0) * 1000.0
    logger.info(
        "analysis_completed request_id=%s risk_score=%s duration_ms=%.1f "
        "finding_count=%s policy=%s",
        rid,
        outcome.risk_score,
        duration_ms,
        len(outcome.findings),
        outcome.decision.action.value,
        extra={
            "request_id": rid,
            "risk_score": outcome.risk_score,
            "duration_ms": duration_ms,
            "finding_count": len(outcome.findings),
        },
    )
    return report


@router.post("/sanitize", dependencies=[Depends(require_analysis_create)])
async def sanitize(
    body: SanitizeRequest,
    request: Request,
    service: ServiceDep,
    tenant_id: TenantDep,
    auth: AuthDep,
) -> dict[str, Any]:
    """Analyze and force-sanitize the prompt."""
    rid = _request_id(request)
    meta = _client_meta(request)
    t0 = time.perf_counter()
    # Use analyze with force_sanitize so audit context is applied once
    outcome = service.analyze(
        body.prompt,
        {
            "force_sanitize": True,
            "sanitize": True,
            "request_id": rid,
            "tenant_id": tenant_id,
            "organization_id": (
                str(auth.organization_id) if auth.organization_id else None
            ),
            **meta,
        },
    )
    san = outcome.sanitization
    if san is None:
        san = service.sanitizer.sanitize(body.prompt, outcome.findings)
    payload = {
        "tool": "PromptShield",
        "version": service.health()["version"],
        "timestamp": report_timestamp(),
        "request_id": rid or None,
        "original_prompt_redacted": outcome.to_report_dict()["analysis"]["prompt"],
        "sanitized_prompt": san.sanitized_prompt,
        "replacements": san.replacements,
        "skipped": san.skipped,
        "sanitization": san.to_dict(redact=True),
        "risk_score": outcome.risk_score,
        "risk_level": outcome.to_report_dict()["analysis"]["risk_level"],
        "policy_decision": outcome.decision.to_dict(),
        "exit_code": outcome.exit_code,
        "duration_ms": round(outcome.duration_ms, 2),
        "analysis_id": outcome.options.get("analysis_id"),
    }
    duration_ms = (time.perf_counter() - t0) * 1000.0
    logger.info(
        "sanitization_completed request_id=%s replacements=%s duration_ms=%.1f",
        rid,
        payload.get("replacements"),
        duration_ms,
        extra={
            "request_id": rid,
            "duration_ms": duration_ms,
            "replacements": payload.get("replacements"),
        },
    )
    return payload


def report_timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail=f"Invalid datetime: {value}"
        ) from exc


@router.get(
    "/analyses",
    response_model=AnalysisListResponse,
    dependencies=[Depends(require_analysis_read)],
)
async def list_analyses(
    request: Request,
    tenant_id: TenantDep,
    auth: AuthDep,
    risk_level: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    category: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AnalysisListResponse:
    """Paginated analysis history (scoped to caller's organization)."""
    org_id = auth.organization_id
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        rows = uow.analyses.list(
            tenant_id=tenant_id if org_id is None else None,
            organization_id=org_id,
            risk_level=risk_level,
            date_from=_parse_dt(date_from),
            date_to=_parse_dt(date_to),
            category=category,
            limit=limit,
            offset=offset,
        )
        total = uow.analyses.count(
            tenant_id=tenant_id if org_id is None else None,
            organization_id=org_id,
            risk_level=risk_level,
            date_from=_parse_dt(date_from),
            date_to=_parse_dt(date_to),
        )
    items = [
        AnalysisSummary(
            id=str(r.id),
            tenant_id=r.tenant_id,
            timestamp=r.timestamp.isoformat(),
            request_id=r.request_id,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            policy_action=r.policy_action,
            recommended_action=r.recommended_action,
            classification_label=r.classification_label,
            prompt_length=r.prompt_length,
            finding_count=len(r.findings) if r.findings is not None else 0,
        )
        for r in rows
    ]
    return AnalysisListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        request_id=_request_id(request) or None,
    )


@router.get(
    "/analyses/{analysis_id}",
    response_model=AnalysisDetailResponse,
    dependencies=[Depends(require_analysis_read)],
)
async def get_analysis(
    analysis_id: str,
    request: Request,
    auth: AuthDep,
) -> AnalysisDetailResponse:
    """Analysis detail with redacted findings (never full prompt plaintext)."""
    try:
        aid = uuid.UUID(analysis_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid analysis id") from exc
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        row = uow.analyses.get(aid)
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    if (
        auth.organization_id is not None
        and row.organization_id is not None
        and row.organization_id != auth.organization_id
    ):
        raise HTTPException(status_code=404, detail="Analysis not found")
    findings = [
        FindingOut(
            id=str(f.id),
            detector_name=f.detector_name,
            category=f.category,
            severity=f.severity,
            weight=f.weight,
            matched_text_preview=f.matched_text_preview,
            redacted_text=f.redacted_text,
            explanation=f.explanation,
            remediation=f.remediation,
            compliance_frameworks=list(f.compliance_frameworks or []),
        )
        for f in row.findings
    ]
    return AnalysisDetailResponse(
        id=str(row.id),
        tenant_id=row.tenant_id,
        organization_id=str(row.organization_id) if row.organization_id else None,
        timestamp=row.timestamp.isoformat(),
        request_id=row.request_id,
        prompt_hash=row.prompt_hash,
        prompt_length=row.prompt_length,
        risk_score=row.risk_score,
        risk_level=row.risk_level,
        policy_action=row.policy_action,
        recommended_action=row.recommended_action,
        classification_label=row.classification_label,
        safe_after_sanitization=row.safe_after_sanitization,
        duration_ms=row.duration_ms,
        has_encrypted_prompt=row.encrypted_prompt is not None,
        findings=findings,
        request_id_header=_request_id(request) or None,
    )


@router.get(
    "/stats",
    response_model=StatsResponse,
    dependencies=[Depends(require_analysis_read)],
)
async def stats(
    request: Request,
    tenant_id: TenantDep,
    auth: AuthDep,
    days: int = Query(default=30, ge=1, le=365),
) -> StatsResponse:
    """Aggregate statistics for dashboards."""
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        data = uow.analyses.stats(
            tenant_id=tenant_id,
            organization_id=auth.organization_id,
            days=days,
        )
    data["request_id"] = _request_id(request) or None
    return StatsResponse(**data)


@router.get(
    "/events",
    response_model=EventListResponse,
    dependencies=[Depends(require_analysis_read)],
)
async def list_events(
    request: Request,
    tenant_id: TenantDep,
    auth: AuthDep,
    event_type: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> EventListResponse:
    """Paginated audit events."""
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        rows = uow.events.list(
            tenant_id=tenant_id if auth.organization_id is None else None,
            organization_id=auth.organization_id,
            event_type=event_type,
            date_from=_parse_dt(date_from),
            date_to=_parse_dt(date_to),
            limit=limit,
            offset=offset,
        )
    items = [
        EventOut(
            id=str(e.id),
            tenant_id=e.tenant_id,
            analysis_id=str(e.analysis_id) if e.analysis_id else None,
            event_type=e.event_type,
            timestamp=e.timestamp.isoformat(),
            metadata=dict(e.event_metadata or {}),
        )
        for e in rows
    ]
    return EventListResponse(
        items=items,
        limit=limit,
        offset=offset,
        request_id=_request_id(request) or None,
    )


@router.post(
    "/maintenance/cleanup",
    response_model=CleanupResponse,
    dependencies=[Depends(require_api_key)],
)
async def maintenance_cleanup(
    request: Request,
    retention_days: int | None = Query(default=None, ge=1),
) -> CleanupResponse:
    """Force retention policy cleanup."""
    result = enforce_retention_policy(
        retention_days if retention_days is not None else get_retention_days()
    )
    return CleanupResponse(
        retention_days=result["retention_days"],
        cutoff=result["cutoff"],
        deleted_analyses=result["deleted_analyses"],
        deleted_events=result["deleted_events"],
        request_id=_request_id(request) or None,
    )
