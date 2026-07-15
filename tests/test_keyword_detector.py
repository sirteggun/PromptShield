"""Tests for KeywordDetector."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from plugins.keyword_detector import KeywordDetector  # noqa: E402
from promptshield.finding import Severity  # noqa: E402


@pytest.fixture
def detector(sample_rules: dict[str, Any]) -> KeywordDetector:
    det = KeywordDetector()
    det.configure(sample_rules)
    return det


def test_detects_keyword_case_insensitive(detector: KeywordDetector) -> None:
    prompt = "Discussione sul Payroll del Q3"
    findings = detector.analyze(prompt)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_name == "KeywordDetector"
    assert finding.matched_text.lower() == "payroll"
    assert finding.weight == 20
    assert finding.severity == Severity.MEDIUM
    assert finding.category == "keyword"
    assert finding.replacement_token == "<BLOCKED_KEYWORD>"
    assert finding.explanation
    assert finding.remediation
    assert finding.metadata.get("keyword") == "payroll"


def test_detects_multiple_keywords(detector: KeywordDetector) -> None:
    prompt = "payroll data and the acquisition plan for customer_db"
    findings = detector.analyze(prompt)
    keywords = {f.metadata["keyword"] for f in findings}
    assert keywords == {"payroll", "acquisition", "customer_db"}
    assert all(f.weight == 20 for f in findings)


def test_no_match_when_empty_config() -> None:
    det = KeywordDetector()
    det.configure({"blocked_keywords": []})
    assert det.analyze("payroll acquisition") == []


def test_clean_prompt(detector: KeywordDetector) -> None:
    assert detector.analyze("Talk about the weather and coffee.") == []


def test_word_boundary_avoids_partial_match(detector: KeywordDetector) -> None:
    findings = detector.analyze("We reviewed the payrolls summary.")
    assert findings == []


def test_ignores_context_risk_keywords_section() -> None:
    """context_risk_keywords must not be used by KeywordDetector yet."""
    det = KeywordDetector()
    det.configure(
        {
            "blocked_keywords": [],
            "context_risk_keywords": ["production", "confidential"],
        }
    )
    assert det.analyze("this is production and confidential") == []
