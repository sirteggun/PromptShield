"""Tests for GitHubTokenDetector."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from plugins.github_token_detector import GitHubTokenDetector  # noqa: E402
from promptshield.finding import Severity  # noqa: E402

# ghp_ + 36 chars body → well above min length 36 total
SAMPLE_GHP = "ghp_" + ("A" * 36)
SAMPLE_GHO = "gho_" + ("B" * 36)


@pytest.fixture
def detector() -> GitHubTokenDetector:
    return GitHubTokenDetector()


def test_detects_ghp_token(detector: GitHubTokenDetector) -> None:
    prompt = f"export GITHUB_TOKEN={SAMPLE_GHP}"
    findings = detector.analyze(prompt)
    assert len(findings) == 1
    f = findings[0]
    assert f.matched_text == SAMPLE_GHP
    assert f.weight == 50
    assert f.severity == Severity.CRITICAL
    assert f.category == "secret"
    assert f.replacement_token == "<GITHUB_TOKEN>"
    assert f.explanation
    assert f.remediation


def test_detects_multiple_prefixes(detector: GitHubTokenDetector) -> None:
    prompt = f"{SAMPLE_GHP} and {SAMPLE_GHO}"
    findings = detector.analyze(prompt)
    assert len(findings) == 2
    prefixes = {f.metadata["prefix"] for f in findings}
    assert prefixes == {"ghp_", "gho_"}


def test_no_match_clean_or_too_short(detector: GitHubTokenDetector) -> None:
    assert detector.analyze("clone the repo with ssh") == []
    # Too short: ghp_ + 10 chars
    assert detector.analyze("ghp_SHORTTOKEN") == []
    # Wrong prefix
    assert detector.analyze("ghr_" + ("C" * 36)) == []
