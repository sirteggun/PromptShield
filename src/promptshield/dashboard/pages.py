"""HTML dashboard pages (Jinja2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from promptshield.api.dependencies import TenantDep
from promptshield.dashboard.auth import dashboard_key, require_dashboard_access
from promptshield.dashboard.metrics import (
    dashboard_audit_timeline,
    dashboard_compliance,
    dashboard_recent,
    dashboard_summary,
    dashboard_trend,
)
from promptshield.persistence.database import get_session_factory
from promptshield.persistence.unit_of_work import SqlAlchemyUnitOfWork
from promptshield.service import _package_version

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["dashboard-pages"])


def _ctx(
    request: Request,
    **extra: Any,
) -> dict[str, Any]:
    key = dashboard_key()
    # Pass key to templates for fetch() headers when set via query on first load
    qkey = request.query_params.get("key", "")
    return {
        "request": request,
        "version": _package_version(),
        "dashboard_key": qkey if key else "",
        "auth_required": bool(key),
        **extra,
    }


@router.get("/", include_in_schema=False)
async def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/dashboard", status_code=302)


@router.get("/dashboard", response_class=HTMLResponse)
@router.get("/dashboard/", response_class=HTMLResponse)
async def dashboard_home(
    request: Request,
    tenant_id: TenantDep,
    _: None = Depends(require_dashboard_access),
) -> HTMLResponse:
    summary = dashboard_summary(tenant_id=tenant_id)
    trend = dashboard_trend(tenant_id=tenant_id, days=30)
    recent = dashboard_recent(tenant_id=tenant_id, limit=10)
    events = dashboard_audit_timeline(tenant_id=tenant_id, limit=15)
    return templates.TemplateResponse(
        request,
        "index.html",
        _ctx(
            request,
            summary=summary,
            trend=trend,
            recent=recent,
            events=events,
            page="home",
        ),
    )


@router.get("/dashboard/compliance", response_class=HTMLResponse)
async def dashboard_compliance_page(
    request: Request,
    tenant_id: TenantDep,
    _: None = Depends(require_dashboard_access),
) -> HTMLResponse:
    data = dashboard_compliance(tenant_id=tenant_id)
    return templates.TemplateResponse(
        request,
        "compliance.html",
        _ctx(request, compliance=data, page="compliance"),
    )


@router.get("/dashboard/analyses", response_class=HTMLResponse)
async def dashboard_analyses_page(
    request: Request,
    tenant_id: TenantDep,
    page: int = Query(default=1, ge=1),
    _: None = Depends(require_dashboard_access),
) -> HTMLResponse:
    limit = 25
    offset = (page - 1) * limit
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        rows = uow.analyses.list(tenant_id=tenant_id, limit=limit, offset=offset)
        total = uow.analyses.count(tenant_id=tenant_id)
    items = [
        {
            "id": str(r.id),
            "timestamp": r.timestamp.isoformat(),
            "risk_level": r.risk_level,
            "risk_score": r.risk_score,
            "policy_action": r.policy_action,
            "finding_count": len(r.findings) if r.findings is not None else 0,
            "classification_label": r.classification_label or "—",
            "request_id": r.request_id,
        }
        for r in rows
    ]
    total_pages = max(1, (total + limit - 1) // limit)
    return templates.TemplateResponse(
        request,
        "analyses.html",
        _ctx(
            request,
            items=items,
            page_num=page,
            total=total,
            total_pages=total_pages,
            page="analyses",
        ),
    )


@router.get("/dashboard/analyses/{analysis_id}", response_class=HTMLResponse)
async def dashboard_analysis_detail(
    request: Request,
    analysis_id: str,
    _: None = Depends(require_dashboard_access),
) -> HTMLResponse:
    try:
        aid = UUID(analysis_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid id") from exc
    with SqlAlchemyUnitOfWork(get_session_factory()) as uow:
        row = uow.analyses.get(aid)
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    findings = [
        {
            "detector_name": f.detector_name,
            "category": f.category,
            "severity": f.severity,
            "weight": f.weight,
            "matched_text_preview": f.matched_text_preview,
            "redacted_text": f.redacted_text,
            "explanation": f.explanation,
            "remediation": f.remediation,
            "compliance_frameworks": list(f.compliance_frameworks or []),
        }
        for f in row.findings
    ]
    analysis = {
        "id": str(row.id),
        "timestamp": row.timestamp.isoformat(),
        "risk_level": row.risk_level,
        "risk_score": row.risk_score,
        "policy_action": row.policy_action,
        "recommended_action": row.recommended_action,
        "classification_label": row.classification_label,
        "prompt_hash": row.prompt_hash,
        "prompt_length": row.prompt_length,
        "duration_ms": row.duration_ms,
        "has_encrypted_prompt": row.encrypted_prompt is not None,
        "request_id": row.request_id,
        "findings": findings,
    }
    return templates.TemplateResponse(
        request,
        "analysis_detail.html",
        _ctx(request, analysis=analysis, page="analyses"),
    )


@router.get("/dashboard/audit", response_class=HTMLResponse)
async def dashboard_audit_page(
    request: Request,
    tenant_id: TenantDep,
    _: None = Depends(require_dashboard_access),
) -> HTMLResponse:
    events = dashboard_audit_timeline(tenant_id=tenant_id, limit=50)
    return templates.TemplateResponse(
        request,
        "audit.html",
        _ctx(request, events=events, page="audit"),
    )
