"""Tests for JWTDetector."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from plugins.jwt_detector import JWTDetector  # noqa: E402
from promptshield.finding import Severity  # noqa: E402

# Well-formed three-segment JWT (header starts with eyJ).
SAMPLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)


@pytest.fixture
def detector() -> JWTDetector:
    return JWTDetector()


def test_detects_jwt(detector: JWTDetector) -> None:
    prompt = f"Authorization: Bearer {SAMPLE_JWT}"
    findings = detector.analyze(prompt)
    assert len(findings) == 1
    f = findings[0]
    assert f.matched_text == SAMPLE_JWT
    assert f.weight == 50
    assert f.severity == Severity.CRITICAL
    assert f.category == "secret"
    assert f.replacement_token == "<JWT_TOKEN>"
    assert f.explanation
    assert f.remediation
    assert f.start_position == prompt.index(SAMPLE_JWT)


def test_no_match_on_clean_text(detector: JWTDetector) -> None:
    assert detector.analyze("no tokens here, just text") == []


def test_rejects_two_segment_or_non_eyj(detector: JWTDetector) -> None:
    # Only two segments
    assert detector.analyze("aaa.bbb") == []
    # Three segments but header does not start with eyJ
    assert detector.analyze("abc.def.ghi") == []
    # Missing signature
    assert detector.analyze("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0") == []
