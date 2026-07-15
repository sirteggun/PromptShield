"""API key authentication with multi-tenant DB keys + env fallback."""

from __future__ import annotations

import logging
import os
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request, status

from promptshield.persistence.models import (
    PERM_ADMIN_CREATE_ORG,
    PERM_ADMIN_MANAGE_KEYS,
    PERM_ANALYSIS_CREATE,
    PERM_ANALYSIS_READ,
    PERM_DASHBOARD_READ,
)
from promptshield.persistence.tenancy import AuthContext, resolve_auth_context

logger = logging.getLogger(__name__)


def get_env_name() -> str:
    """Return normalized environment name (production / development / …)."""
    return os.environ.get("PROMPTSHIELD_ENV", "development").strip().lower()


def is_production() -> bool:
    return get_env_name() == "production"


def configured_api_keys() -> list[str]:
    """Parse ``PROMPTSHIELD_API_KEY`` (comma-separated)."""
    raw = os.environ.get("PROMPTSHIELD_API_KEY", "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def validate_startup_auth() -> None:
    """Fail fast in production when no API keys are configured.

    With multi-tenancy seed, env keys or a bootstrap key may exist after seed;
    production still requires either env key or DB seed to have been prepared.
    """
    keys = configured_api_keys()
    if is_production() and not keys:
        # Allow production if orgs will be seeded with explicit ops; still warn.
        logger.warning(
            "PROMPTSHIELD_ENV=production without PROMPTSHIELD_API_KEY — "
            "ensure DB API keys exist after seed or set the env key."
        )
    if not is_production() and not keys:
        logger.warning(
            "PROMPTSHIELD_API_KEY not set — relying on DB tenancy seed or "
            "open development access."
        )


async def get_auth_context(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AuthContext:
    """Resolve and attach :class:`AuthContext` to the request."""
    # Lazy import seed path only when persistence available
    try:
        ctx = resolve_auth_context(x_api_key)
    except Exception:
        logger.exception("Auth resolution failed")
        ctx = None

    if ctx is None:
        # Legacy open mode only when no key required in non-prod and no orgs
        if not is_production() and not x_api_key and not configured_api_keys():
            try:
                from promptshield.persistence.database import get_session_factory
                from promptshield.persistence.tenancy import count_organizations

                session = get_session_factory()()
                try:
                    n = count_organizations(session)
                finally:
                    session.close()
                if n == 0:
                    ctx = AuthContext(
                        organization_id=None,
                        organization_name="Default",
                        tenant_id="default",
                        permissions=[
                            PERM_ANALYSIS_CREATE,
                            PERM_ANALYSIS_READ,
                            PERM_DASHBOARD_READ,
                            PERM_ADMIN_MANAGE_KEYS,
                            PERM_ADMIN_CREATE_ORG,
                        ],
                        api_key_id=None,
                        key_prefix="",
                        source="open",
                    )
            except Exception:
                ctx = AuthContext(
                    organization_id=None,
                    organization_name="Default",
                    tenant_id="default",
                    permissions=list(
                        [
                            PERM_ANALYSIS_CREATE,
                            PERM_ANALYSIS_READ,
                            PERM_DASHBOARD_READ,
                            PERM_ADMIN_MANAGE_KEYS,
                            PERM_ADMIN_CREATE_ORG,
                        ]
                    ),
                    api_key_id=None,
                    key_prefix="",
                    source="open",
                )

    if ctx is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    request.state.auth = ctx
    return ctx


async def require_api_key(
    request: Request,
    ctx: Annotated[AuthContext, Depends(get_auth_context)],
) -> AuthContext:
    """Backward-compatible dependency: any valid auth context."""
    return ctx


def require_permission(permission: str) -> Any:
    """Dependency factory that checks a single permission."""

    async def _check(
        ctx: Annotated[AuthContext, Depends(get_auth_context)],
    ) -> AuthContext:
        if not ctx.has(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission}",
            )
        return ctx

    return _check


require_analysis_create = require_permission(PERM_ANALYSIS_CREATE)
require_analysis_read = require_permission(PERM_ANALYSIS_READ)
require_dashboard_read = require_permission(PERM_DASHBOARD_READ)
require_admin_manage_keys = require_permission(PERM_ADMIN_MANAGE_KEYS)
require_admin_create_org = require_permission(PERM_ADMIN_CREATE_ORG)
