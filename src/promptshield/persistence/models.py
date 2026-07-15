"""SQLAlchemy 2.0 ORM models for analyses, findings, audit, and multi-tenancy."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for PromptShield persistence."""


class Organization(Base):
    """Tenant / customer organization (SaaS multi-tenancy).

    Future: add a ``User`` model with ``organization_id`` FK and a
    ``users`` relationship here for interactive login / SSO.
    """

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    api_keys: Mapped[list[ApiKey]] = relationship(
        "ApiKey",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    usage_records: Mapped[list[UsageRecord]] = relationship(
        "UsageRecord",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    # Future: users: Mapped[list["User"]] = relationship(...)


class ApiKey(Base):
    """Hashed API key with granular permissions scoped to an organization."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
    )
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(32), default="")
    name: Mapped[str] = mapped_column(String(128), default="default")
    permissions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    organization: Mapped[Organization] = relationship(
        "Organization", back_populates="api_keys"
    )


class UsageRecord(Base):
    """Monthly usage counters per organization."""

    __tablename__ = "usage_records"
    __table_args__ = (
        UniqueConstraint("organization_id", "year", "month", name="uq_usage_org_month"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        index=True,
    )
    year: Mapped[int] = mapped_column(Integer, index=True)
    month: Mapped[int] = mapped_column(Integer, index=True)
    analysis_count: Mapped[int] = mapped_column(Integer, default=0)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0)
    secret_count: Mapped[int] = mapped_column(Integer, default=0)

    organization: Mapped[Organization] = relationship(
        "Organization", back_populates="usage_records"
    )


class Analysis(Base):
    """Persisted analysis run (multi-tenant ready)."""

    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(128), default="default", index=True)
    # Nullable FK: NULL means legacy / default tenant behaviour.
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, index=True
    )
    request_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    prompt_hash: Mapped[str] = mapped_column(String(64), index=True)
    prompt_length: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(32), default="GREEN", index=True)
    policy_action: Mapped[str] = mapped_column(String(32), default="allow")
    recommended_action: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    classification_label: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    safe_after_sanitization: Mapped[bool] = mapped_column(Boolean, default=False)
    api_key_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    encrypted_prompt: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary, nullable=True
    )

    findings: Mapped[list[FindingRecord]] = relationship(
        "FindingRecord",
        back_populates="analysis",
        cascade="all, delete-orphan",
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        "AuditEvent",
        back_populates="analysis",
        cascade="all, delete-orphan",
    )


class FindingRecord(Base):
    """Persisted finding (always redacted previews, never full secrets)."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("analyses.id", ondelete="CASCADE"),
        index=True,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    detector_name: Mapped[str] = mapped_column(String(128), default="")
    category: Mapped[str] = mapped_column(String(64), default="", index=True)
    severity: Mapped[str] = mapped_column(String(32), default="info")
    weight: Mapped[int] = mapped_column(Integer, default=0)
    matched_text_preview: Mapped[str] = mapped_column(String(512), default="")
    redacted_text: Mapped[str] = mapped_column(String(128), default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    compliance_frameworks: Mapped[list[Any]] = mapped_column(JSON, default=list)

    analysis: Mapped[Analysis] = relationship("Analysis", back_populates="findings")


class AuditEvent(Base):
    """Append-only audit / event-sourcing style record."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[str] = mapped_column(String(128), default="default", index=True)
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    analysis_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("analyses.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, index=True
    )
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON, default=dict
    )

    analysis: Mapped[Optional[Analysis]] = relationship(
        "Analysis", back_populates="audit_events"
    )


# Permission constants (documented contract for ApiKey.permissions)
PERM_ANALYSIS_CREATE = "analysis:create"
PERM_ANALYSIS_READ = "analysis:read"
PERM_DASHBOARD_READ = "dashboard:read"
PERM_ADMIN_MANAGE_KEYS = "admin:manage_keys"
PERM_ADMIN_CREATE_ORG = "admin:create_organization"

ALL_PERMISSIONS: list[str] = [
    PERM_ANALYSIS_CREATE,
    PERM_ANALYSIS_READ,
    PERM_DASHBOARD_READ,
    PERM_ADMIN_MANAGE_KEYS,
    PERM_ADMIN_CREATE_ORG,
]
