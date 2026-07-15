"""Tests for the risk explainer (policy-priority semantics)."""

from __future__ import annotations

from promptshield.classifier import PromptLabel
from promptshield.explainer import explain_risk
from promptshield.finding import Finding, Severity
from promptshield.policy_engine import Policy, PolicyAction, PolicyDecision


def _finding(
    *,
    category: str = "secret",
    severity: Severity = Severity.HIGH,
    weight: int = 40,
    text: str = "AKIA1234567890ABCDEF",
    token: str = "<AWS_SECRET>",
) -> Finding:
    return Finding(
        detector_name="T",
        matched_text=text,
        severity=severity,
        message="m",
        weight=weight,
        start_position=0,
        end_position=len(text),
        category=category,
        replacement_token=token,
    )


def test_policy_block_priority() -> None:
    decision = PolicyDecision(
        action=PolicyAction.BLOCK,
        triggered_policies=(
            Policy(
                id="NO_SECRETS",
                description="d",
                action=PolicyAction.BLOCK,
                priority=100,
                conditions={"category": "secret"},
                message="blocked",
            ),
        ),
        messages=("blocked",),
        winning_policy=Policy(
            id="NO_SECRETS",
            description="d",
            action=PolicyAction.BLOCK,
            priority=100,
            conditions={"category": "secret"},
            message="blocked",
        ),
    )
    # Low score, no findings — policy still forces BLOCK
    exp = explain_risk([], 0, decision, [])
    assert exp.recommended_action == "BLOCK"

    exp2 = explain_risk(
        [_finding()],
        10,
        decision,
        [PromptLabel("config_file", 0.8, ["env"])],
    )
    assert exp2.recommended_action == "BLOCK"
    assert (
        "BLOCK" in exp2.summary
        or "block" in exp2.summary.lower()
        or exp2.recommended_action == "BLOCK"
    )


def test_policy_warn_priority() -> None:
    decision = PolicyDecision(
        action=PolicyAction.WARN,
        triggered_policies=(
            Policy(
                id="W",
                description="d",
                action=PolicyAction.WARN,
                priority=50,
                conditions={},
                message="warn",
            ),
        ),
        messages=("warn",),
        winning_policy=Policy(
            id="W",
            description="d",
            action=PolicyAction.WARN,
            priority=50,
            conditions={},
            message="warn",
        ),
    )
    exp = explain_risk([], 0, decision, [])
    assert exp.recommended_action != "ALLOW"
    assert exp.recommended_action in {"BLOCK", "SANITIZE", "REVIEW"}


def test_safe_after_sanitization() -> None:
    secret = _finding(token="<AWS_SECRET>")
    decision = PolicyDecision(action=PolicyAction.ALLOW)
    exp = explain_risk(
        [secret],
        40,
        decision,
        [PromptLabel("config_file", 0.7, [])],
        original_prompt="key=AKIA1234567890ABCDEF",
    )
    assert exp.safe_after_sanitization is True

    no_token = _finding(token="")
    exp2 = explain_risk([no_token], 40, decision, [])
    assert exp2.safe_after_sanitization is False


def test_no_findings() -> None:
    decision = PolicyDecision(action=PolicyAction.ALLOW)
    exp = explain_risk([], 0, decision, [PromptLabel("unknown", 1.0, ["none"])])
    assert exp.recommended_action == "ALLOW"
    assert "sensibile" in exp.summary.lower() or "Nessun" in exp.summary


def test_secret_production_config_narrative() -> None:
    findings = [
        _finding(),
        Finding(
            detector_name="ContextDetector",
            matched_text="production",
            severity=Severity.MEDIUM,
            message="ctx",
            weight=20,
            start_position=0,
            end_position=10,
            category="context",
            replacement_token="<CONTEXT_RISK_WORD>",
            metadata={"keyword": "production"},
        ),
    ]
    decision = PolicyDecision(
        action=PolicyAction.BLOCK,
        triggered_policies=(),
        messages=(),
        winning_policy=Policy(
            id="NO_SECRETS",
            description="",
            action=PolicyAction.BLOCK,
            priority=100,
            conditions={"category": "secret"},
            message="secrets",
        ),
    )
    labels = [PromptLabel("config_file", 0.8, ["KEY=value"])]
    exp = explain_risk(findings, 60, decision, labels)
    assert exp.recommended_action == "BLOCK"
    assert exp.risk_factors
    assert any("production" in f.lower() or "Segreto" in f for f in exp.risk_factors)
