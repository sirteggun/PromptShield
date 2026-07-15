"""Admin multi-tenancy endpoints (organizations & API keys)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from promptshield.api.auth import require_admin_create_org, require_admin_manage_keys
from promptshield.api.dependencies import AuthDep
from promptshield.persistence.database import get_session_factory
from promptshield.persistence.models import (
    PERM_ANALYSIS_CREATE,
    PERM_ANALYSIS_READ,
    PERM_DASHBOARD_READ,
    ApiKey,
    Organization,
)
from promptshield.persistence.tenancy import (
    create_api_key_for_org,
    create_organization,
    revoke_api_key,
)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class CreateOrgRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)


class CreateOrgResponse(BaseModel):
    organization_id: str
    name: str
    api_key: str  # shown once
    api_key_prefix: str
    permissions: list[str]
    message: str = "Store the api_key now; it will not be shown again."


class CreateKeyRequest(BaseModel):
    name: str = Field(default="API key", max_length=128)
    permissions: list[str] | None = None


class CreateKeyResponse(BaseModel):
    id: str
    name: str
    api_key: str
    key_prefix: str
    permissions: list[str]
    message: str = "Store the api_key now; it will not be shown again."


class KeyInfo(BaseModel):
    id: str
    name: str
    key_prefix: str
    permissions: list[str]
    is_active: bool
    created_at: str


@router.post(
    "/organizations",
    response_model=CreateOrgResponse,
    dependencies=[Depends(require_admin_create_org)],
)
async def create_org(
    body: CreateOrgRequest,
    auth: AuthDep,
) -> CreateOrgResponse:
    """Create a new organization and return a full-permission API key (once)."""
    factory = get_session_factory()
    session = factory()
    try:
        existing = session.scalars(
            select(Organization).where(Organization.name == body.name.strip())
        ).first()
        if existing:
            raise HTTPException(
                status_code=409, detail="Organization name already exists"
            )
        org, key_row, raw = create_organization(
            session, body.name.strip(), key_name="Owner key"
        )
        session.commit()
        return CreateOrgResponse(
            organization_id=str(org.id),
            name=org.name,
            api_key=raw,
            api_key_prefix=key_row.key_prefix,
            permissions=list(key_row.permissions or []),
        )
    except HTTPException:
        session.rollback()
        raise
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        session.close()


@router.post(
    "/api-keys",
    response_model=CreateKeyResponse,
    dependencies=[Depends(require_admin_manage_keys)],
)
async def create_key(
    body: CreateKeyRequest,
    auth: AuthDep,
) -> CreateKeyResponse:
    """Create an API key for the caller's organization."""
    if auth.organization_id is None:
        raise HTTPException(
            status_code=400,
            detail="No organization context on this API key",
        )
    perms = body.permissions or [
        PERM_ANALYSIS_CREATE,
        PERM_ANALYSIS_READ,
        PERM_DASHBOARD_READ,
    ]
    # Caller cannot grant permissions they do not have
    if not set(perms).issubset(set(auth.permissions)):
        raise HTTPException(
            status_code=403,
            detail="Cannot grant permissions you do not hold",
        )
    factory = get_session_factory()
    session = factory()
    try:
        row, raw = create_api_key_for_org(
            session,
            auth.organization_id,
            name=body.name,
            permissions=perms,
        )
        session.commit()
        return CreateKeyResponse(
            id=str(row.id),
            name=row.name,
            api_key=raw,
            key_prefix=row.key_prefix,
            permissions=list(row.permissions or []),
        )
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        session.close()


@router.get(
    "/api-keys",
    response_model=list[KeyInfo],
    dependencies=[Depends(require_admin_manage_keys)],
)
async def list_keys(auth: AuthDep) -> list[KeyInfo]:
    """List API keys for the caller's organization (no secrets)."""
    if auth.organization_id is None:
        return []
    factory = get_session_factory()
    session = factory()
    try:
        rows = list(
            session.scalars(
                select(ApiKey).where(ApiKey.organization_id == auth.organization_id)
            ).all()
        )
        return [
            KeyInfo(
                id=str(r.id),
                name=r.name,
                key_prefix=r.key_prefix,
                permissions=list(r.permissions or []),
                is_active=r.is_active,
                created_at=r.created_at.isoformat(),
            )
            for r in rows
        ]
    finally:
        session.close()


@router.delete(
    "/api-keys/{key_id}",
    dependencies=[Depends(require_admin_manage_keys)],
)
async def delete_key(key_id: str, auth: AuthDep) -> dict[str, Any]:
    """Revoke (deactivate) an API key belonging to the caller's organization."""
    if auth.organization_id is None:
        raise HTTPException(status_code=400, detail="No organization context")
    try:
        kid = uuid.UUID(key_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid key id") from exc
    factory = get_session_factory()
    session = factory()
    try:
        row = session.get(ApiKey, kid)
        if row is None or row.organization_id != auth.organization_id:
            raise HTTPException(status_code=404, detail="API key not found")
        revoke_api_key(session, kid)
        session.commit()
        return {"id": key_id, "is_active": False, "revoked": True}
    except HTTPException:
        session.rollback()
        raise
    finally:
        session.close()
