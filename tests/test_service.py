"""Tests for PromptShieldService application layer."""

from __future__ import annotations

from promptshield.container import build_service


def test_service_analyze_clean_prompt() -> None:
    service = build_service()
    outcome = service.analyze("hello world, nothing sensitive")
    assert outcome.risk_score == 0
    assert outcome.exit_code == 0
    assert not outcome.blocked
    report = outcome.to_report_dict()
    assert report["tool"] == "PromptShield"
    assert report["analysis"]["risk_level"] == "GREEN"


def test_service_analyze_secret_blocked() -> None:
    service = build_service()
    outcome = service.analyze("key AKIA1234567890ABCDEF")
    assert outcome.blocked
    assert outcome.exit_code == 2
    assert any(f.category == "secret" for f in outcome.findings)
    report = outcome.to_report_dict()
    assert report["analysis"]["policy_decision"]["action"] == "block"
    secret = next(
        f for f in report["analysis"]["findings"] if f["category"] == "secret"
    )
    assert "matched_text" not in secret


def test_service_explain_option() -> None:
    service = build_service()
    outcome = service.analyze(
        "AKIA1234567890ABCDEF production",
        {"explain": True},
    )
    assert outcome.explanation is not None
    assert outcome.explanation.recommended_action == "BLOCK"
    report = outcome.to_report_dict()
    assert "intelligence" in report["analysis"]


def test_service_sanitize() -> None:
    service = build_service()
    payload = service.sanitize("token AKIA1234567890ABCDEF end")
    assert "sanitized_prompt" in payload
    assert "<AWS_SECRET>" in payload["sanitized_prompt"]
    assert payload["replacements"] >= 1
    assert "AKIA1234567890ABCDEF" not in payload["sanitized_prompt"]


def test_service_health() -> None:
    service = build_service()
    h = service.health()
    assert h["status"] == "ok"
    assert h["detectors"] >= 1
    assert "version" in h


def test_service_matches_cli_json_shape() -> None:
    """Service report includes the same top-level keys as historical CLI JSON."""
    service = build_service()
    report = service.analyze_dict("safe text only")
    assert set(report.keys()) >= {"tool", "version", "timestamp", "analysis"}
    assert set(report["analysis"].keys()) >= {
        "prompt",
        "findings",
        "risk_score",
        "risk_level",
        "breakdown",
        "policy_decision",
        "exit_code",
    }
