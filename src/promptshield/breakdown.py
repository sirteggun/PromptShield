"""Risk breakdown by finding category.

Percentages are computed against the scoring ceiling (``max_score``, default
100), not against the sum of category weights. Example: weights 40 + 20 with
``max_score=100`` → 40% and 20% (not 66% / 33%).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from promptshield.compliance import frameworks_for_category
from promptshield.finding import Finding

_BAR_WIDTH = 20


@dataclass(frozen=True, slots=True)
class CategoryBreakdown:
    """Contribution of a single category to overall risk.

    Attributes:
        category: Finding category name.
        weight: Sum of finding weights in this category (uncapped raw sum).
        percentage: Share of ``max_score`` (0–100 scale), after optional
            global scaling so the sum of percentages never exceeds 100.
        bar: ASCII bar reflecting ``percentage``.
        findings_count: Number of findings in this category.
        frameworks: Compliance frameworks mapped to this category.
    """

    category: str
    weight: int
    percentage: float
    bar: str
    findings_count: int
    frameworks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialize for JSON output."""
        return {
            "category": self.category,
            "weight": self.weight,
            "percentage": round(self.percentage, 2),
            "bar": self.bar,
            "findings_count": self.findings_count,
            "frameworks": list(self.frameworks),
        }


@dataclass(frozen=True, slots=True)
class RiskBreakdown:
    """Aggregate risk breakdown across categories.

    Attributes:
        total_score: Capped risk score (``min(sum(weights), max_score)``).
        max_score: Scoring ceiling used for percentages.
        categories: Per-category breakdown rows, highest weight first.
    """

    total_score: int
    max_score: int
    categories: list[CategoryBreakdown] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialize for JSON output."""
        return {
            "total_score": self.total_score,
            "max_score": self.max_score,
            "categories": [c.to_dict() for c in self.categories],
        }

    def format_text(self) -> str:
        """Human-readable multi-line breakdown for the CLI."""
        lines: list[str] = [
            f"Risk breakdown (score {self.total_score}/{self.max_score}):",
        ]
        if not self.categories:
            lines.append("  (nessuna categoria)")
            return "\n".join(lines)

        for cat in self.categories:
            fw = ", ".join(cat.frameworks) if cat.frameworks else "—"
            lines.append(
                f"  {cat.category:<16} "
                f"{cat.bar} "
                f"{cat.percentage:5.1f}%  "
                f"(weight={cat.weight}, n={cat.findings_count})  "
                f"[{fw}]"
            )
        return "\n".join(lines)


def generate_risk_breakdown(
    findings: list[Finding] | tuple[Finding, ...],
    *,
    max_score: int = 100,
) -> RiskBreakdown:
    """Build a :class:`RiskBreakdown` from findings.

    Percentages use ``weight / max_score * 100``. If the sum of raw
    percentages would exceed 100 (weights sum above ``max_score``), all
    percentages are scaled proportionally so their sum is at most 100.

    Args:
        findings: Analysis findings.
        max_score: Scoring ceiling (must be > 0).

    Returns:
        Structured breakdown with bars and compliance framework tags.
    """
    if max_score <= 0:
        msg = f"max_score must be positive, got {max_score}"
        raise ValueError(msg)

    weight_by_cat: dict[str, int] = defaultdict(int)
    count_by_cat: dict[str, int] = defaultdict(int)
    for finding in findings:
        cat = finding.category.strip() if finding.category else "unknown"
        weight_by_cat[cat] += int(finding.weight)
        count_by_cat[cat] += 1

    total_raw = sum(weight_by_cat.values())
    total_score = int(min(total_raw, max_score))

    # Raw percentages vs max_score.
    raw_pct: dict[str, float] = {
        cat: (weight / max_score) * 100.0 for cat, weight in weight_by_cat.items()
    }
    sum_pct = sum(raw_pct.values())
    scale = 100.0 / sum_pct if sum_pct > 100.0 else 1.0

    categories: list[CategoryBreakdown] = []
    for cat in sorted(weight_by_cat.keys(), key=lambda c: (-weight_by_cat[c], c)):
        percentage = raw_pct[cat] * scale
        categories.append(
            CategoryBreakdown(
                category=cat,
                weight=weight_by_cat[cat],
                percentage=percentage,
                bar=_render_bar(percentage),
                findings_count=count_by_cat[cat],
                frameworks=frameworks_for_category(cat),
            )
        )

    return RiskBreakdown(
        total_score=total_score,
        max_score=max_score,
        categories=categories,
    )


def _render_bar(percentage: float, width: int = _BAR_WIDTH) -> str:
    """Render an ASCII progress bar for ``percentage`` (0–100)."""
    clamped = max(0.0, min(100.0, percentage))
    filled = int(round((clamped / 100.0) * width))
    filled = max(0, min(width, filled))
    return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"
