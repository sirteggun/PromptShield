"""Tests for EmailDetector."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from plugins.email_detector import EmailDetector  # noqa: E402
from promptshield.finding import Severity  # noqa: E402


@pytest.fixture
def detector() -> EmailDetector:
    return EmailDetector()


def test_detects_email(detector: EmailDetector) -> None:
    prompt = "Contatta alice.smith+tag@example.com per dettagli."
    findings = detector.analyze(prompt)
    assert len(findings) == 1
    f = findings[0]
    assert f.matched_text == "alice.smith+tag@example.com"
    assert f.weight == 15
    assert f.severity == Severity.MEDIUM
    assert f.category == "pii"
    assert f.replacement_token == "<EMAIL_ADDRESS>"
    assert f.explanation
    assert f.remediation


def test_no_match_without_email(detector: EmailDetector) -> None:
    assert detector.analyze("scrivi a me dopo pranzo") == []
    assert detector.analyze("user@localhost") == []  # no TLD


def test_multiple_emails(detector: EmailDetector) -> None:
    prompt = "a@b.co and c.d@sub.domain.org"
    findings = detector.analyze(prompt)
    assert len(findings) == 2
    texts = {f.matched_text for f in findings}
    assert "a@b.co" in texts
    assert "c.d@sub.domain.org" in texts
