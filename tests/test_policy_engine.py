"""Unit tests for the Policy Engine."""

from __future__ import annotations

from pathlib import Path


from promptshield.finding import Finding, Severity
from promptshield.policy_engine import PolicyAction, PolicyEngine

ROOT = Path(__file__).resolve().parents[1]


def _f(
    *,
    category: str,
    weight: int = 10,
    severity: Severity = Severity.MEDIUM,
    text: str = "x",
    keyword: str | None = None,
) -> Finding:
    meta: dict = {}
    if keyword is not None:
        meta["keyword"] = keyword
    return Finding(
        detector_name="T",
        matched_text=text,
        severity=severity,
        message="m",
        weight=weight,
        start_position=0,
        end_position=len(text),
        category=category,
        replacement_token="<T>",
        metadata=meta,
    )


def test_load_default_policies_file() -> None:
    engine = PolicyEngine.load(ROOT / "config" / "policies.yaml")
    ids = {p.id for p in engine.policies}
    assert "NO_SECRETS" in ids
    assert "PRODUCTION_WARNING" in ids
    assert "PCI_COMPLIANCE" in ids
    assert "INTERNAL_KEYWORDS" in ids


def test_from_dict_empty() -> None:
    engine = PolicyEngine.from_dict({"policies": []})
    decision = engine.evaluate([], 0)
    assert decision.action is PolicyAction.ALLOW
    assert decision.triggered_policies == ()


def test_no_secrets_blocks_secret_category() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "NO_SECRETS",
                    "action": "block",
                    "priority": 100,
                    "conditions": {"category": "secret"},
                    "message": "no secrets",
                }
            ]
        }
    )
    findings = [_f(category="secret", weight=40, severity=Severity.HIGH, text="AKIA")]
    decision = engine.evaluate(findings, risk_score=40)
    assert decision.action is PolicyAction.BLOCK
    assert decision.blocked
    assert decision.winning_policy is not None
    assert decision.winning_policy.id == "NO_SECRETS"
    assert "no secrets" in decision.messages


def test_production_warning_does_not_block() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "PRODUCTION_WARNING",
                    "action": "warn",
                    "priority": 50,
                    "conditions": {"context": "production"},
                    "message": "prod warn",
                }
            ]
        }
    )
    findings = [
        _f(
            category="context",
            weight=20,
            text="production",
            keyword="production",
        )
    ]
    decision = engine.evaluate(findings, risk_score=20)
    assert decision.action is PolicyAction.WARN
    assert decision.allows_send
    assert decision.winning_policy is not None
    assert decision.winning_policy.id == "PRODUCTION_WARNING"


def test_pci_requires_pii_and_financial_context() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "PCI_COMPLIANCE",
                    "action": "block",
                    "priority": 90,
                    "conditions": {
                        "category": "pii",
                        "context": "financial",
                    },
                    "message": "pci block",
                }
            ]
        }
    )
    only_pii = [_f(category="pii", weight=15, text="a@b.co")]
    assert engine.evaluate(only_pii, 15).action is PolicyAction.ALLOW

    only_fin = [
        _f(
            category="context",
            weight=20,
            text="financial",
            keyword="financial",
        )
    ]
    assert engine.evaluate(only_fin, 20).action is PolicyAction.ALLOW

    both = only_pii + only_fin
    decision = engine.evaluate(both, 35)
    assert decision.action is PolicyAction.BLOCK
    assert decision.winning_policy is not None
    assert decision.winning_policy.id == "PCI_COMPLIANCE"


def test_priority_block_beats_warn() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "WARN_SECRET",
                    "action": "warn",
                    "priority": 50,
                    "conditions": {"category": "secret"},
                    "message": "warn",
                },
                {
                    "id": "BLOCK_SECRET",
                    "action": "block",
                    "priority": 100,
                    "conditions": {"category": "secret"},
                    "message": "block",
                },
            ]
        }
    )
    findings = [_f(category="secret", weight=40)]
    decision = engine.evaluate(findings, 40)
    assert decision.action is PolicyAction.BLOCK
    assert decision.winning_policy is not None
    assert decision.winning_policy.id == "BLOCK_SECRET"
    assert len(decision.triggered_policies) == 2


def test_same_priority_block_wins_over_allow() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "A",
                    "action": "allow",
                    "priority": 10,
                    "conditions": {"category": "secret"},
                    "message": "allow",
                },
                {
                    "id": "B",
                    "action": "block",
                    "priority": 10,
                    "conditions": {"category": "secret"},
                    "message": "block",
                },
            ]
        }
    )
    decision = engine.evaluate([_f(category="secret")], 40)
    assert decision.action is PolicyAction.BLOCK


def test_allow_can_override_lower_priority_block() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "BLOCK_LOW",
                    "action": "block",
                    "priority": 10,
                    "conditions": {"category": "secret"},
                    "message": "block",
                },
                {
                    "id": "ALLOW_HIGH",
                    "action": "allow",
                    "priority": 200,
                    "conditions": {"category": "secret"},
                    "message": "allow override",
                },
            ]
        }
    )
    decision = engine.evaluate([_f(category="secret")], 40)
    assert decision.action is PolicyAction.ALLOW
    assert decision.winning_policy is not None
    assert decision.winning_policy.id == "ALLOW_HIGH"


def test_max_risk_score_condition() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "HIGH_SCORE",
                    "action": "block",
                    "priority": 80,
                    "conditions": {"max_risk_score": 50},
                    "message": "score too high",
                }
            ]
        }
    )
    assert engine.evaluate([], 50).action is PolicyAction.ALLOW
    assert engine.evaluate([], 51).action is PolicyAction.BLOCK


def test_min_weight_condition() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "HEAVY",
                    "action": "warn",
                    "priority": 10,
                    "conditions": {
                        "category": "secret",
                        "min_weight": 50,
                    },
                    "message": "heavy",
                }
            ]
        }
    )
    light = [_f(category="secret", weight=40)]
    assert engine.evaluate(light, 40).action is PolicyAction.ALLOW
    heavy = [
        _f(category="secret", weight=40),
        _f(category="secret", weight=20, text="yy"),
    ]
    assert engine.evaluate(heavy, 60).action is PolicyAction.WARN


def test_severity_floor_warning() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "SEV",
                    "action": "warn",
                    "priority": 5,
                    "conditions": {"severity": "WARNING"},
                    "message": "sev",
                }
            ]
        }
    )
    info_only = [_f(category="infrastructure", severity=Severity.INFO, weight=10)]
    assert engine.evaluate(info_only, 10).action is PolicyAction.ALLOW
    medium = [_f(category="pii", severity=Severity.MEDIUM, weight=15)]
    assert engine.evaluate(medium, 15).action is PolicyAction.WARN


def test_keyword_condition() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "KW",
                    "action": "warn",
                    "priority": 40,
                    "conditions": {"keyword": "payroll"},
                    "message": "kw",
                }
            ]
        }
    )
    findings = [_f(category="keyword", text="Payroll", keyword="payroll", weight=20)]
    assert engine.evaluate(findings, 20).action is PolicyAction.WARN
    assert engine.evaluate([], 0).action is PolicyAction.ALLOW


def test_decision_to_dict() -> None:
    engine = PolicyEngine.from_dict(
        {
            "policies": [
                {
                    "id": "X",
                    "action": "block",
                    "priority": 1,
                    "conditions": {"category": "secret"},
                    "message": "m",
                }
            ]
        }
    )
    d = engine.evaluate([_f(category="secret")], 40).to_dict()
    assert d["action"] == "block"
    assert d["blocked"] is True
    assert d["winning_policy"]["id"] == "X"
