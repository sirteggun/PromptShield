"""Tests for risk breakdown (percentages vs max_score)."""

from __future__ import annotations

from promptshield.breakdown import generate_risk_breakdown
from promptshield.finding import Finding, Severity


def _f(
    category: str,
    weight: int,
    *,
    text: str = "x",
    severity: Severity = Severity.HIGH,
) -> Finding:
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
    )


def test_percentages_relative_to_max_score_not_weight_sum() -> None:
    """40 + 20 with max_score=100 → 40% and 20%, not 66%/33%."""
    findings = [
        _f("secret", 40, text="AKIA1234567890ABCDEF"),
        _f("keyword", 20, text="payroll"),
    ]
    bd = generate_risk_breakdown(findings, max_score=100)
    assert bd.total_score == 60
    assert bd.max_score == 100
    by_cat = {c.category: c for c in bd.categories}
    assert by_cat["secret"].percentage == 40.0
    assert by_cat["keyword"].percentage == 20.0
    assert abs(by_cat["secret"].percentage + by_cat["keyword"].percentage - 60.0) < 1e-6


def test_sum_of_percentages_never_exceeds_100() -> None:
    findings = [
        _f("secret", 60),
        _f("pii", 50),
        _f("context", 40),
    ]
    bd = generate_risk_breakdown(findings, max_score=100)
    assert bd.total_score == 100
    total_pct = sum(c.percentage for c in bd.categories)
    assert total_pct <= 100.0 + 1e-6


def test_empty_findings() -> None:
    bd = generate_risk_breakdown([], max_score=100)
    assert bd.total_score == 0
    assert bd.categories == []
    d = bd.to_dict()
    assert d["total_score"] == 0
    assert d["categories"] == []


def test_bar_reflects_percentage() -> None:
    findings = [_f("secret", 50)]
    bd = generate_risk_breakdown(findings, max_score=100)
    cat = bd.categories[0]
    assert cat.percentage == 50.0
    assert cat.bar.startswith("[")
    assert cat.bar.endswith("]")
    # ~half filled for 50%
    assert cat.bar.count("#") == 10


def test_to_dict_structure() -> None:
    findings = [_f("pii", 15, text="a@b.co")]
    bd = generate_risk_breakdown(findings, max_score=100)
    d = bd.to_dict()
    assert d["max_score"] == 100
    assert d["categories"][0]["category"] == "pii"
    assert d["categories"][0]["percentage"] == 15.0
    assert "frameworks" in d["categories"][0]


def test_format_text_contains_categories() -> None:
    findings = [_f("secret", 40)]
    text = generate_risk_breakdown(findings).format_text()
    assert "secret" in text
    assert "40.0%" in text or "40%" in text
