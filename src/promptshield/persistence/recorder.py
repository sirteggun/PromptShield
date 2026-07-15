"""Map ServiceAnalysisResult → ORM records and audit events."""

from __future__ import annotations

import uuid
from typing import Any

from promptshield.compliance import frameworks_for_category
from promptshield.persistence.crypto import encrypt_prompt, hash_api_key, hash_prompt
from promptshield.persistence.models import Analysis, AuditEvent, FindingRecord
from promptshield.persistence.unit_of_work import UnitOfWork
from promptshield.service import ServiceAnalysisResult
from promptshield.scoring import RiskBand

_BAND = {
    RiskBand.GREEN: "GREEN",
    RiskBand.YELLOW: "YELLOW",
    RiskBand.RED: "RED",
}


def persist_analysis(
    uow: UnitOfWork,
    outcome: ServiceAnalysisResult,
    *,
    tenant_id: str = "default",
    organization_id: str | None = None,
    request_id: str = "",
    api_key: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> Analysis:
    """Persist analysis + findings + audit events in the current UoW.

    Does not commit; caller must ``uow.commit()``.
    """
    prompt = outcome.analysis.prompt
    org_uuid: uuid.UUID | None = None
    if organization_id:
        try:
            org_uuid = (
                organization_id
                if isinstance(organization_id, uuid.UUID)
                else uuid.UUID(str(organization_id))
            )
        except (ValueError, TypeError):
            org_uuid = None

    analysis = Analysis(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        organization_id=org_uuid,
        request_id=request_id or "",
        prompt_hash=hash_prompt(prompt),
        prompt_length=len(prompt),
        risk_score=outcome.risk_score,
        risk_level=_BAND[outcome.analysis.risk.band],
        policy_action=outcome.decision.action.value,
        recommended_action=(
            outcome.explanation.recommended_action if outcome.explanation else None
        ),
        classification_label=(outcome.labels[0].label if outcome.labels else None),
        safe_after_sanitization=(
            outcome.explanation.safe_after_sanitization
            if outcome.explanation
            else False
        ),
        api_key_hash=hash_api_key(api_key),
        client_ip=client_ip,
        user_agent=user_agent,
        duration_ms=int(round(outcome.duration_ms)),
        encrypted_prompt=encrypt_prompt(prompt),
    )
    uow.analyses.add(analysis)

    for finding in outcome.findings:
        rec = FindingRecord(
            id=uuid.uuid4(),
            analysis_id=analysis.id,
            organization_id=org_uuid,
            detector_name=finding.detector_name,
            category=finding.category,
            severity=finding.severity.value,
            weight=int(finding.weight),
            matched_text_preview=finding.matched_text_preview(),
            redacted_text=finding.replacement_token or "<REDACTED>",
            explanation=finding.explanation or "",
            remediation=finding.remediation or "",
            compliance_frameworks=frameworks_for_category(finding.category),
        )
        analysis.findings.append(rec)

    events: list[tuple[str, dict[str, Any]]] = [
        (
            "analysis.created",
            {
                "risk_score": outcome.risk_score,
                "risk_level": analysis.risk_level,
                "finding_count": len(outcome.findings),
            },
        )
    ]
    if any(f.category == "secret" for f in outcome.findings):
        events.append(
            (
                "secret.detected",
                {"count": sum(1 for f in outcome.findings if f.category == "secret")},
            )
        )
    if outcome.decision.blocked:
        events.append(
            (
                "policy.blocked",
                {
                    "policy_id": (
                        outcome.decision.winning_policy.id
                        if outcome.decision.winning_policy
                        else None
                    ),
                    "messages": list(outcome.decision.messages),
                },
            )
        )
    elif outcome.decision.action.value == "warn":
        events.append(
            (
                "policy.warned",
                {
                    "policy_id": (
                        outcome.decision.winning_policy.id
                        if outcome.decision.winning_policy
                        else None
                    )
                },
            )
        )
    if outcome.sanitization is not None:
        events.append(
            (
                "sanitization.completed",
                {
                    "replacements": outcome.sanitization.replacements,
                    "skipped": outcome.sanitization.skipped,
                },
            )
        )

    for event_type, meta in events:
        uow.events.add(
            AuditEvent(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                organization_id=org_uuid,
                analysis_id=analysis.id,
                event_type=event_type,
                event_metadata=meta,
            )
        )

    return analysis
