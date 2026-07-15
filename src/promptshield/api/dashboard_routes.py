"""JSON API endpoints consumed by the admin dashboard."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from promptshield.api.dependencies import TenantDep
from promptshield.dashboard.auth import require_dashboard_access
from promptshield.dashboard.metrics import (
    dashboard_audit_timeline,
    dashboard_compliance,
    dashboard_recent,
    dashboard_report,
    dashboard_summary,
    dashboard_trend,
)

router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_dashboard_access)],
)


def _rid(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


@router.get("/summary")
async def summary(
    request: Request,
    tenant_id: TenantDep,
) -> dict[str, Any]:
    data = dashboard_summary(tenant_id=tenant_id)
    data["request_id"] = _rid(request)
    return data


@router.get("/trend")
async def trend(
    request: Request,
    tenant_id: TenantDep,
    days: int = Query(default=30, ge=1, le=90),
) -> dict[str, Any]:
    data = dashboard_trend(tenant_id=tenant_id, days=days)
    data["request_id"] = _rid(request)
    return data


@router.get("/recent")
async def recent(
    request: Request,
    tenant_id: TenantDep,
    limit: int = Query(default=10, ge=1, le=50),
) -> dict[str, Any]:
    return {
        "items": dashboard_recent(tenant_id=tenant_id, limit=limit),
        "request_id": _rid(request),
    }


@router.get("/compliance")
async def compliance(request: Request, tenant_id: TenantDep) -> dict[str, Any]:
    data = dashboard_compliance(tenant_id=tenant_id)
    return {"frameworks": data, "request_id": _rid(request)}


@router.get("/audit-timeline")
async def audit_timeline(
    request: Request,
    tenant_id: TenantDep,
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    return {
        "items": dashboard_audit_timeline(tenant_id=tenant_id, limit=limit),
        "request_id": _rid(request),
    }


@router.get("/report")
async def report(
    request: Request,
    tenant_id: TenantDep,
    format: str = Query(default="html", pattern="^(html|pdf)$"),
) -> HTMLResponse:
    """Export monthly report as HTML (PDF falls back to HTML with notice)."""
    from pathlib import Path

    from fastapi.templating import Jinja2Templates

    payload = dashboard_report(tenant_id=tenant_id)
    templates_dir = Path(__file__).resolve().parents[1] / "dashboard" / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))
    pdf_note = format == "pdf"
    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "report": payload,
            "pdf_requested": pdf_note,
            "pdf_available": False,
        },
    )
