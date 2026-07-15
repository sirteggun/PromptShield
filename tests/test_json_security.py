"""Tests for JSON metadata and secret redaction in reports."""

from __future__ import annotations

import json
import re
from datetime import datetime

from promptshield.breakdown import generate_risk_breakdown
from promptshield.cli import build_json_report, get_package_version
from promptshield.finding import Finding, Severity, build_matched_text_preview
from promptshield.pipeline import AnalysisResult
from promptshield.policy_engine import PolicyAction, PolicyDecision
from promptshield.scoring import RiskBand, RiskScore


def _result(
    prompt: str, findings: list[Finding], score: int, band: RiskBand
) -> AnalysisResult:
    return AnalysisResult(
        prompt=prompt,
        findings=tuple(findings),
        risk=RiskScore(score=score, band=band, findings=tuple(findings)),
    )


def test_secret_finding_omits_matched_text_in_to_dict() -> None:
    secret = "AKIA1234567890ABCDEF"
    f = Finding(
        detector_name="SecretDetector",
        matched_text=secret,
        severity=Severity.HIGH,
        message="aws",
        weight=40,
        start_position=0,
        end_position=len(secret),
        category="secret",
        replacement_token="<AWS_SECRET>",
    )
    d = f.to_dict(redact=True)
    assert "matched_text" not in d
    assert d["matched_text_preview"] == "AKIA****CDEF"
    assert d["redacted_text"] == "<AWS_SECRET>"
    assert secret not in json.dumps(d)


def test_email_keeps_matched_text_with_preview() -> None:
    email = "alice@acme.com"
    f = Finding(
        detector_name="EmailDetector",
        matched_text=email,
        severity=Severity.MEDIUM,
        message="email",
        weight=15,
        start_position=0,
        end_position=len(email),
        category="pii",
        replacement_token="<EMAIL_ADDRESS>",
    )
    d = f.to_dict(redact=True)
    assert d["matched_text"] == email
    assert d["matched_text_preview"] == build_matched_text_preview(email, "pii")
    assert d["redacted_text"] == "<EMAIL_ADDRESS>"


def test_keyword_preview_is_full_word() -> None:
    assert build_matched_text_preview("payroll", "keyword") == "payroll"
    assert build_matched_text_preview("production", "context") == "production"


def test_json_report_metadata_and_redaction() -> None:
    secret = "AKIA1234567890ABCDEF"
    email = "user@example.com"
    prompt = f"key {secret} mail {email}"
    findings = [
        Finding(
            detector_name="SecretDetector",
            matched_text=secret,
            severity=Severity.HIGH,
            message="aws",
            weight=40,
            start_position=prompt.index(secret),
            end_position=prompt.index(secret) + len(secret),
            category="secret",
            replacement_token="<AWS_SECRET>",
        ),
        Finding(
            detector_name="EmailDetector",
            matched_text=email,
            severity=Severity.MEDIUM,
            message="email",
            weight=15,
            start_position=prompt.index(email),
            end_position=prompt.index(email) + len(email),
            category="pii",
            replacement_token="<EMAIL_ADDRESS>",
        ),
    ]
    result = _result(prompt, findings, score=55, band=RiskBand.RED)
    breakdown = generate_risk_breakdown(findings, max_score=100)
    decision = PolicyDecision(action=PolicyAction.ALLOW)
    report = build_json_report(result, breakdown=breakdown, decision=decision)

    assert report["tool"] == "PromptShield"
    assert report["version"] == get_package_version()
    # ISO 8601 UTC-ish
    datetime.strptime(report["timestamp"], "%Y-%m-%dT%H:%M:%SZ")

    analysis = report["analysis"]
    assert analysis["risk_score"] == 55
    assert analysis["risk_level"] == "RED"
    assert analysis["exit_code"] == 2
    assert "policy_decision" in analysis
    assert analysis["policy_decision"]["action"] == "allow"
    assert secret not in analysis["prompt"]
    assert "<AWS_SECRET>" in analysis["prompt"]

    secret_json = next(f for f in analysis["findings"] if f["category"] == "secret")
    assert "matched_text" not in secret_json
    assert secret_json["matched_text_preview"] == "AKIA****CDEF"
    assert secret_json["redacted_text"] == "<AWS_SECRET>"

    email_json = next(f for f in analysis["findings"] if f["category"] == "pii")
    assert email_json["matched_text"] == email

    # Breakdown percentages vs max_score
    cats = {c["category"]: c["percentage"] for c in analysis["breakdown"]["categories"]}
    assert cats["secret"] == 40.0
    assert cats["pii"] == 15.0

    # Round-trip JSON
    dumped = json.dumps(report)
    assert secret not in dumped
    json.loads(dumped)


def test_preview_pattern_for_aws_key() -> None:
    preview = build_matched_text_preview("AKIA1234567890ABCDEF", "secret")
    assert re.fullmatch(r"AKIA\*{4}CDEF", preview)
