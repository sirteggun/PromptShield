"""Pydantic request/response models for the Enterprise API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """Body for ``POST /api/v1/analyze``."""

    prompt: str = Field(..., min_length=1, description="Prompt text to analyze.")
    sanitize: bool = Field(
        default=False,
        description="If true, sanitize when policy allows send.",
    )
    explain: bool = Field(
        default=False,
        description="If true, include classification + risk explanation.",
    )


class SanitizeRequest(BaseModel):
    """Body for ``POST /api/v1/sanitize``."""

    prompt: str = Field(..., min_length=1, description="Prompt text to sanitize.")


class HealthResponse(BaseModel):
    """Response for ``GET /api/v1/health``."""

    status: str
    version: str
    detectors: int
    policies: int = 0
    request_id: str | None = None


class AnalyzeResponse(BaseModel):
    """Loose wrapper; analysis body mirrors CLI JSON report."""

    model_config = {"extra": "allow"}

    tool: str = "PromptShield"
    version: str
    timestamp: str
    request_id: str | None = None
    analysis: dict[str, Any]


class SanitizeResponse(BaseModel):
    """Sanitize endpoint response."""

    model_config = {"extra": "allow"}

    tool: str = "PromptShield"
    version: str
    timestamp: str
    request_id: str | None = None
    sanitized_prompt: str
    replacements: int
    skipped: int


class AnalysisSummary(BaseModel):
    """List item for ``GET /analyses``."""

    id: str
    tenant_id: str
    timestamp: str
    request_id: str
    risk_score: int
    risk_level: str
    policy_action: str
    recommended_action: str | None = None
    classification_label: str | None = None
    prompt_length: int
    finding_count: int = 0


class AnalysisListResponse(BaseModel):
    """Paginated analyses list."""

    items: list[AnalysisSummary]
    total: int
    limit: int
    offset: int
    request_id: str | None = None


class FindingOut(BaseModel):
    """Finding detail (redacted)."""

    id: str
    detector_name: str
    category: str
    severity: str
    weight: int
    matched_text_preview: str
    redacted_text: str
    explanation: str
    remediation: str
    compliance_frameworks: list[str] = Field(default_factory=list)


class AnalysisDetailResponse(BaseModel):
    """Full analysis with findings."""

    id: str
    tenant_id: str
    organization_id: str | None = None
    timestamp: str
    request_id: str
    prompt_hash: str
    prompt_length: int
    risk_score: int
    risk_level: str
    policy_action: str
    recommended_action: str | None = None
    classification_label: str | None = None
    safe_after_sanitization: bool
    duration_ms: int
    has_encrypted_prompt: bool
    findings: list[FindingOut]
    request_id_header: str | None = None


class StatsResponse(BaseModel):
    """Aggregate statistics."""

    model_config = {"extra": "allow"}

    tenant_id: str
    period_days: int
    total_analyses: int
    by_risk_level: dict[str, int]
    by_policy_action: dict[str, int]
    blocks: int
    warns: int
    average_risk_score: float
    top_categories: list[dict[str, object]]
    trend: list[dict[str, object]]
    request_id: str | None = None


class EventOut(BaseModel):
    """Audit event list item."""

    id: str
    tenant_id: str
    analysis_id: str | None
    event_type: str
    timestamp: str
    metadata: dict[str, object] = Field(default_factory=dict)


class EventListResponse(BaseModel):
    """Paginated audit events."""

    items: list[EventOut]
    limit: int
    offset: int
    request_id: str | None = None


class CleanupResponse(BaseModel):
    """Retention cleanup result."""

    retention_days: int
    cutoff: str
    deleted_analyses: int
    deleted_events: int
    request_id: str | None = None
