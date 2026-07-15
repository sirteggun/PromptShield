"""Tests for InternalURLDetector."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from plugins.internal_url_detector import InternalURLDetector  # noqa: E402
from promptshield.finding import Severity  # noqa: E402


@pytest.fixture
def detector() -> InternalURLDetector:
    return InternalURLDetector()


def test_detects_internal_urls(detector: InternalURLDetector) -> None:
    prompt = (
        "see https://admin.corp.internal/dashboard and http://localhost:8080/health"
    )
    findings = detector.analyze(prompt)
    assert len(findings) >= 2
    texts = " ".join(f.matched_text for f in findings)
    assert "admin.corp.internal" in texts
    assert "localhost" in texts
    assert all(f.weight == 20 for f in findings)
    assert all(f.severity == Severity.MEDIUM for f in findings)
    assert all(f.category == "infrastructure" for f in findings)
    assert all(f.replacement_token == "<INTERNAL_URL>" for f in findings)
    assert all(f.explanation and f.remediation for f in findings)


def test_ignores_public_url(detector: InternalURLDetector) -> None:
    assert detector.analyze("docs at https://example.com/guide") == []


def test_staging_and_local_tld(detector: InternalURLDetector) -> None:
    findings = detector.analyze(
        "https://api.staging.example.com/v1 http://app.myapp.local/x"
    )
    assert len(findings) == 2
    assert any("staging" in f.matched_text for f in findings)
    assert any(".local" in f.matched_text for f in findings)
