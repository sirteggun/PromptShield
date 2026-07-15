"""Tests for SecretDetector."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from plugins.secret_detector import SecretDetector  # noqa: E402
from promptshield.finding import Severity  # noqa: E402


@pytest.fixture
def detector() -> SecretDetector:
    return SecretDetector()


def test_detects_aws_access_key_id(detector: SecretDetector) -> None:
    prompt = "La nostra API key è AKIA1234567890ABCDEF e il resto è innocuo."
    findings = detector.analyze(prompt)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_name == "SecretDetector"
    assert finding.matched_text == "AKIA1234567890ABCDEF"
    assert finding.weight == 40
    assert finding.severity == Severity.HIGH
    assert finding.category == "secret"
    assert finding.replacement_token == "<AWS_SECRET>"
    assert finding.explanation
    assert finding.remediation
    assert finding.start_position == prompt.index("AKIA1234567890ABCDEF")
    assert finding.end_position == finding.start_position + len("AKIA1234567890ABCDEF")
    # v0.1 aliases still work
    assert finding.start == finding.start_position
    assert finding.end == finding.end_position
    assert "AWS" in finding.message


def test_no_false_positive_on_clean_text(detector: SecretDetector) -> None:
    findings = detector.analyze("Hello world, no secrets here.")
    assert findings == []


def test_detects_multiple_keys(detector: SecretDetector) -> None:
    prompt = "keys: AKIA1111111111111111 and AKIA2222222222222222"
    findings = detector.analyze(prompt)
    assert len(findings) == 2
    texts = {f.matched_text for f in findings}
    assert texts == {"AKIA1111111111111111", "AKIA2222222222222222"}


def test_rejects_short_or_invalid_prefix(detector: SecretDetector) -> None:
    assert detector.analyze("AKIA1234") == []
    assert detector.analyze("BKIA1234567890ABCDEF") == []
