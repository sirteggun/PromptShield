"""Risk scoring engine.

Converts a collection of :class:`~promptshield.finding.Finding` objects into
a bounded numeric score and a traffic-light risk band.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from promptshield.finding import Finding


class RiskBand(str, Enum):
    """Traffic-light classification of overall prompt risk.

    Attributes:
        GREEN: Low risk (score 0–20). Safe to proceed with low concern.
        YELLOW: Medium risk (score 21–50). Review recommended.
        RED: High risk (score 51–100). Strongly advise blocking or scrubbing.
    """

    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


@dataclass(frozen=True, slots=True)
class RiskScore:
    """Computed risk assessment for a prompt.

    Attributes:
        score: Integer risk score in the closed range ``[0, 100]``.
        band: Traffic-light band derived from ``score``.
        findings: Findings that contributed to the score (may be empty).
    """

    score: int
    band: RiskBand
    findings: tuple[Finding, ...]


class RiskScoringEngine:
    """Compute a capped sum of finding weights and map it to a risk band.

    The foundational heuristic is intentionally simple and transparent:

    * ``score = min(sum(finding.weight for finding in findings), max_score)``
    * bands: green ``[0, green_max]``, yellow ``(green_max, yellow_max]``,
      red ``(yellow_max, max_score]``

    Args:
        max_score: Upper bound for the score (default 100).
        green_max: Inclusive upper bound of the green band (default 20).
        yellow_max: Inclusive upper bound of the yellow band (default 50).
    """

    def __init__(
        self,
        *,
        max_score: int = 100,
        green_max: int = 20,
        yellow_max: int = 50,
    ) -> None:
        if not 0 <= green_max < yellow_max <= max_score:
            msg = (
                f"Invalid band thresholds: green_max={green_max}, "
                f"yellow_max={yellow_max}, max_score={max_score}"
            )
            raise ValueError(msg)
        self._max_score = max_score
        self._green_max = green_max
        self._yellow_max = yellow_max

    @property
    def max_score(self) -> int:
        """Maximum possible risk score."""
        return self._max_score

    def score(self, findings: list[Finding]) -> RiskScore:
        """Compute a :class:`RiskScore` from findings.

        Args:
            findings: Findings collected by the analysis pipeline.

        Returns:
            Immutable risk score with band classification.
        """
        raw = sum(f.weight for f in findings)
        capped = int(min(raw, self._max_score))
        band = self._band_for(capped)
        return RiskScore(
            score=capped,
            band=band,
            findings=tuple(findings),
        )

    def _band_for(self, score: int) -> RiskBand:
        if score <= self._green_max:
            return RiskBand.GREEN
        if score <= self._yellow_max:
            return RiskBand.YELLOW
        return RiskBand.RED
