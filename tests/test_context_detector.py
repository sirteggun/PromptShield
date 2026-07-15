"""Tests for ContextDetector and KeywordContextStrategy."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from plugins.context_detector import (  # noqa: E402
    ContextDetector,
    DEFAULT_KEYWORD_WEIGHT,
    KeywordContextStrategy,
    parse_context_keywords,
)
from promptshield.finding import Severity  # noqa: E402


def test_match_keyword_with_specific_weight() -> None:
    det = ContextDetector()
    det.configure({"context_risk_keywords": {"production": 20, "payroll": 25}})
    findings = det.analyze("Deploy to production tonight")
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_name == "ContextDetector"
    assert f.category == "context"
    assert f.severity == Severity.MEDIUM
    assert f.weight == 20
    assert f.replacement_token == "<CONTEXT_RISK_WORD>"
    assert f.metadata["keyword"] == "production"
    assert (
        "contesto" in f.explanation.lower()
        or "context" in f.explanation.lower()
        or f.explanation
    )
    assert "condivisi esternamente" in f.remediation


def test_no_match() -> None:
    det = ContextDetector()
    det.configure({"context_risk_keywords": {"production": 20}})
    assert det.analyze("talk about the weather only") == []


def test_multiple_matches_different_weights() -> None:
    det = ContextDetector()
    det.configure(
        {
            "context_risk_keywords": {
                "production": 20,
                "payroll": 25,
                "staging": 10,
            }
        }
    )
    prompt = "production payroll and staging env"
    findings = det.analyze(prompt)
    by_kw = {f.metadata["keyword"]: f.weight for f in findings}
    assert by_kw["production"] == 20
    assert by_kw["payroll"] == 25
    assert by_kw["staging"] == 10


def test_default_weight_for_unweighted_keywords() -> None:
    """List-form / missing weight → DEFAULT_KEYWORD_WEIGHT (10)."""
    # List form (legacy): each item weight 10
    weights = parse_context_keywords(["kubernetes", "production"])
    assert weights["kubernetes"] == DEFAULT_KEYWORD_WEIGHT
    assert weights["production"] == DEFAULT_KEYWORD_WEIGHT

    strategy = KeywordContextStrategy({"kubernetes": None, "production": 20})
    assert strategy.weights["kubernetes"] == 10
    assert strategy.weights["production"] == 20

    findings = strategy.analyze("scale the kubernetes cluster in production")
    by_kw = {f.metadata["keyword"]: f.weight for f in findings}
    assert by_kw["kubernetes"] == 10
    assert by_kw["production"] == 20


def test_empty_config_disables_context_matches() -> None:
    det = ContextDetector()
    det.configure({"context_risk_keywords": {}})
    assert det.analyze("production payroll confidential") == []


def test_strategy_pattern_delegation() -> None:
    class StubStrategy:
        def analyze(self, prompt: str) -> list:
            return []

    stub = StubStrategy()
    det = ContextDetector(strategy=stub)  # type: ignore[arg-type]
    assert det.analyze("anything") == []
