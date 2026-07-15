"""Organization / API key management and bootstrap seed."""

from __future__ import annotations

import logging
import os
import secrets
import uuid
from dataclasses import dataclass
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from promptshield.persistence.crypto import hash_api_key
from promptshield.persistence.database import get_session_factory, init_db
from promptshield.persistence.models import (
    ALL_PERMISSIONS,
    PERM_ADMIN_MANAGE_KEYS,
    PERM_ANALYSIS_CREATE,
    PERM_ANALYSIS_READ,
    PERM_DASHBOARD_READ,
    ApiKey,
    Organization,
)


def _env_api_keys() -> list[str]:
    raw = os.environ.get("PROMPTSHIELD_API_KEY", "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


logger = logging.getLogger(__name__)

DEFAULT_ORG_NAME = "Default"


@dataclass
class AuthContext:
    """Resolved identity for the current request."""

    organization_id: uuid.UUID | None
    organization_name: str
    tenant_id: str
    permissions: list[str]
    api_key_id: uuid.UUID | None
    key_prefix: str
    source: str  # "db" | "env" | "open"

    def has(self, permission: str) -> bool:
        return permission in self.permissions


def generate_raw_api_key() -> str:
    """Generate a new API key string (``ps_`` + 32 hex chars)."""
    return "ps_" + secrets.token_hex(16)


def create_organization(
    session: Session,
    name: str,
    *,
    full_permissions: bool = True,
    key_name: str = "Owner key",
) -> tuple[Organization, ApiKey, str]:
    """Create org + first API key. Returns (org, key_row, raw_key once)."""
    org = Organization(id=uuid.uuid4(), name=name, is_active=True)
    session.add(org)
    raw = generate_raw_api_key()
    perms = (
        list(ALL_PERMISSIONS)
        if full_permissions
        else [
            PERM_ANALYSIS_CREATE,
            PERM_ANALYSIS_READ,
            PERM_DASHBOARD_READ,
            PERM_ADMIN_MANAGE_KEYS,
        ]
    )
    key_row = ApiKey(
        id=uuid.uuid4(),
        organization_id=org.id,
        key_hash=hash_api_key(raw) or "",
        key_prefix=raw[:12],
        name=key_name,
        permissions=perms,
        is_active=True,
    )
    session.add(key_row)
    return org, key_row, raw


def create_api_key_for_org(
    session: Session,
    organization_id: uuid.UUID,
    *,
    name: str = "API key",
    permissions: Sequence[str] | None = None,
) -> tuple[ApiKey, str]:
    """Create an additional API key; returns (row, raw_key once)."""
    raw = generate_raw_api_key()
    perms = (
        list(permissions)
        if permissions is not None
        else [
            PERM_ANALYSIS_CREATE,
            PERM_ANALYSIS_READ,
            PERM_DASHBOARD_READ,
        ]
    )
    row = ApiKey(
        id=uuid.uuid4(),
        organization_id=organization_id,
        key_hash=hash_api_key(raw) or "",
        key_prefix=raw[:12],
        name=name,
        permissions=perms,
        is_active=True,
    )
    session.add(row)
    return row, raw


def revoke_api_key(session: Session, key_id: uuid.UUID) -> ApiKey | None:
    """Deactivate an API key (soft revoke)."""
    row = session.get(ApiKey, key_id)
    if row is None:
        return None
    row.is_active = False
    return row


def lookup_api_key(session: Session, raw_key: str) -> ApiKey | None:
    """Find active API key by raw secret."""
    digest = hash_api_key(raw_key)
    if not digest:
        return None
    return session.scalars(
        select(ApiKey)
        .where(ApiKey.key_hash == digest, ApiKey.is_active.is_(True))
        .options(selectinload(ApiKey.organization))
    ).first()


def count_organizations(session: Session) -> int:
    return len(list(session.scalars(select(Organization)).all()))


def get_org_by_name(session: Session, name: str) -> Organization | None:
    return session.scalars(
        select(Organization).where(Organization.name == name)
    ).first()


def seed_default_tenancy() -> None:
    """Bootstrap Default organization and optional env API key.

    Called at API startup when persistence is enabled.
    """
    init_db()
    factory = get_session_factory()
    session = factory()
    try:
        n = count_organizations(session)
        if n > 0:
            logger.info("Tenancy seed skipped (%s organization(s) exist)", n)
            return

        org = Organization(id=uuid.uuid4(), name=DEFAULT_ORG_NAME, is_active=True)
        session.add(org)
        env_keys = _env_api_keys()
        if env_keys:
            for i, env_key in enumerate(env_keys):
                session.add(
                    ApiKey(
                        id=uuid.uuid4(),
                        organization_id=org.id,
                        key_hash=hash_api_key(env_key) or "",
                        key_prefix=env_key[:12] if len(env_key) >= 12 else env_key,
                        name=f"Env key {i + 1}",
                        permissions=list(ALL_PERMISSIONS),
                        is_active=True,
                    )
                )
            session.commit()
            logger.info(
                "Seeded organization %r with %s env API key(s)",
                DEFAULT_ORG_NAME,
                len(env_keys),
            )
        else:
            # No keys: open access in non-production; production should set env key.
            session.commit()
            logger.warning(
                "Seeded organization %r without API keys "
                "(set PROMPTSHIELD_API_KEY or create keys via admin API).",
                DEFAULT_ORG_NAME,
            )
    except Exception:
        session.rollback()
        logger.exception("Tenancy seed failed")
        raise
    finally:
        session.close()


def count_active_api_keys(session: Session) -> int:
    return len(
        list(session.scalars(select(ApiKey).where(ApiKey.is_active.is_(True))).all())
    )


def resolve_auth_context(raw_key: str | None) -> AuthContext | None:
    """Resolve API key to :class:`AuthContext`.

    Priority:
    1. Active DB ApiKey match
    2. Env PROMPTSHIELD_API_KEY (binds to Default org when present)
    3. Open access when no active keys exist (non-production / empty keystore)
    """
    factory = get_session_factory()
    session = factory()
    try:
        active_keys = count_active_api_keys(session)
        org_default = get_org_by_name(session, DEFAULT_ORG_NAME)

        if raw_key:
            row = lookup_api_key(session, raw_key)
            if row is not None and row.organization and row.organization.is_active:
                return AuthContext(
                    organization_id=row.organization_id,
                    organization_name=row.organization.name,
                    tenant_id=str(row.organization_id),
                    permissions=list(row.permissions or []),
                    api_key_id=row.id,
                    key_prefix=row.key_prefix,
                    source="db",
                )
            env_keys = _env_api_keys()
            if raw_key in env_keys:
                return AuthContext(
                    organization_id=org_default.id if org_default else None,
                    organization_name=org_default.name
                    if org_default
                    else DEFAULT_ORG_NAME,
                    tenant_id=str(org_default.id) if org_default else "default",
                    permissions=list(ALL_PERMISSIONS),
                    api_key_id=None,
                    key_prefix=raw_key[:12],
                    source="env",
                )
            # Key provided but unknown and keystore is active → reject
            if active_keys > 0 or env_keys:
                return None

        # No key provided
        env_keys = _env_api_keys()
        is_prod = (
            os.environ.get("PROMPTSHIELD_ENV", "development").lower() == "production"
        )
        if active_keys == 0 and not env_keys and not is_prod:
            return AuthContext(
                organization_id=org_default.id if org_default else None,
                organization_name=org_default.name if org_default else DEFAULT_ORG_NAME,
                tenant_id=str(org_default.id) if org_default else "default",
                permissions=list(ALL_PERMISSIONS),
                api_key_id=None,
                key_prefix="",
                source="open",
            )
        return None
    finally:
        session.close()
