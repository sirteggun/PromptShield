"""Tests for AnalysisPipeline and risk scoring integration."""

from __future__ import annotations

from promptshield.finding import Finding, Severity
from promptshield.pipeline import AnalysisPipeline
from promptshield.scoring import RiskBand, RiskScoringEngine


def test_pipeline_detects_secret_and_keyword(pipeline: AnalysisPipeline) -> None:
    prompt = "La nostra API key è AKIA1234567890ABCDEF e il database dei payroll"
    result = pipeline.analyze(prompt)

    assert len(result.findings) >= 2
    detectors = {f.detector_name for f in result.findings}
    assert "SecretDetector" in detectors
    assert "KeywordDetector" in detectors

    # secret 40 + keyword 20 = 60 -> red
    assert result.risk.score == 60
    assert result.risk.band == RiskBand.RED


def test_pipeline_clean_prompt_is_green(pipeline: AnalysisPipeline) -> None:
    result = pipeline.analyze("Come si prepara un buon caffè espresso?")
    assert result.findings == ()
    assert result.risk.score == 0
    assert result.risk.band == RiskBand.GREEN


def test_scoring_caps_at_100() -> None:
    engine = RiskScoringEngine()
    heavy = [
        Finding(
            detector_name="t",
            matched_text="x",
            start=0,
            end=1,
            severity=Severity.CRITICAL,
            message="m",
            weight=60,
        )
        for _ in range(3)
    ]
    risk = engine.score(heavy)
    assert risk.score == 100
    assert risk.band == RiskBand.RED


def test_scoring_bands() -> None:
    engine = RiskScoringEngine()

    def make(weight: float) -> list[Finding]:
        return [
            Finding(
                detector_name="t",
                matched_text="x",
                start=0,
                end=1,
                severity=Severity.LOW,
                message="m",
                weight=weight,
            )
        ]

    assert engine.score([]).band == RiskBand.GREEN
    assert engine.score(make(20)).band == RiskBand.GREEN
    assert engine.score(make(21)).band == RiskBand.YELLOW
    assert engine.score(make(50)).band == RiskBand.YELLOW
    assert engine.score(make(51)).band == RiskBand.RED


def test_pipeline_isolates_failing_detector() -> None:
    """A crashing detector must not abort the rest of the pipeline."""

    class Boom:
        name = "Boom"

        def analyze(self, prompt: str) -> list[Finding]:
            raise RuntimeError("boom")

    class Ok:
        name = "Ok"

        def analyze(self, prompt: str) -> list[Finding]:
            return [
                Finding(
                    detector_name="Ok",
                    matched_text="ok",
                    start=0,
                    end=2,
                    severity=Severity.LOW,
                    message="fine",
                    weight=5,
                )
            ]

    # duck-typed detectors satisfy the interface used by the pipeline
    pipeline = AnalysisPipeline(detectors=[Boom(), Ok()])  # type: ignore[list-item]
    result = pipeline.analyze("ok")
    assert len(result.findings) == 1
    assert result.findings[0].detector_name == "Ok"
