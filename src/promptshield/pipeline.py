"""Analysis pipeline orchestrator.

Runs all loaded detector plugins against a prompt, aggregates findings, and
delegates scoring to :class:`~promptshield.scoring.RiskScoringEngine`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding
from promptshield.scoring import RiskScore, RiskScoringEngine

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Complete result of a pipeline run.

    Attributes:
        prompt: Original prompt text that was analyzed.
        findings: All findings from all detectors (order preserved).
        risk: Computed risk score and band.
    """

    prompt: str
    findings: tuple[Finding, ...]
    risk: RiskScore


class AnalysisPipeline:
    """Orchestrate detectors and scoring for a single prompt.

    Args:
        detectors: Ordered list of configured detector instances.
        scoring_engine: Engine used to convert findings into a risk score.
    """

    def __init__(
        self,
        detectors: list[BaseDetector],
        scoring_engine: RiskScoringEngine | None = None,
    ) -> None:
        self._detectors = list(detectors)
        self._scoring_engine = scoring_engine or RiskScoringEngine()

    @property
    def detectors(self) -> list[BaseDetector]:
        """Detectors currently registered in the pipeline."""
        return list(self._detectors)

    def analyze(self, prompt: str) -> AnalysisResult:
        """Run every detector on ``prompt`` and score the combined findings.

        Args:
            prompt: User prompt to inspect.

        Returns:
            Aggregated findings and risk assessment.
        """
        logger.info(
            "Starting analysis with %d detector(s) (prompt length=%d)",
            len(self._detectors),
            len(prompt),
        )
        findings: list[Finding] = []
        for detector in self._detectors:
            logger.debug("Running detector: %s", detector.name)
            try:
                batch = detector.analyze(prompt)
            except Exception:
                logger.exception(
                    "Detector %s failed; continuing with remaining plugins",
                    detector.name,
                )
                continue
            logger.debug(
                "Detector %s produced %d finding(s)",
                detector.name,
                len(batch),
            )
            findings.extend(batch)

        risk = self._scoring_engine.score(findings)
        logger.info(
            "Analysis complete: %d finding(s), score=%d band=%s",
            len(findings),
            risk.score,
            risk.band.value,
        )
        return AnalysisResult(
            prompt=prompt,
            findings=tuple(findings),
            risk=risk,
        )
