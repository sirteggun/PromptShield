"""FastAPI dependency injection for PromptShieldService and auth context."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request

from promptshield.api.auth import get_auth_context
from promptshield.container import build_service
from promptshield.persistence.tenancy import AuthContext
from promptshield.service import PromptShieldService


def persistence_enabled() -> bool:
    """Whether API should persist analyses (default True, opt-out via env)."""
    raw = os.environ.get("PROMPTSHIELD_PERSISTENCE", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


@lru_cache(maxsize=1)
def get_service_singleton() -> PromptShieldService:
    """Process-wide singleton service (pipeline + policies + optional DB)."""
    return build_service(enable_persistence=persistence_enabled())


def get_service() -> PromptShieldService:
    """FastAPI dependency returning the shared service instance."""
    return get_service_singleton()


ServiceDep = Annotated[PromptShieldService, Depends(get_service)]
AuthDep = Annotated[AuthContext, Depends(get_auth_context)]


def get_tenant_id(
    request: Request,
    ctx: AuthDep,
) -> str:
    """Tenant id derived from authenticated organization (or default)."""
    if ctx.organization_id is not None:
        return str(ctx.organization_id)
    return os.environ.get("PROMPTSHIELD_DEFAULT_TENANT", "default")


def get_organization_id(ctx: AuthDep) -> UUID | None:
    return ctx.organization_id


TenantDep = Annotated[str, Depends(get_tenant_id)]
OrgDep = Annotated[UUID | None, Depends(get_organization_id)]


def reset_service_cache() -> None:
    """Clear singleton (for tests)."""
    get_service_singleton.cache_clear()
