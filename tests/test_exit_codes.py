"""Tests for CI/CD exit codes (subprocess + pure function)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


from promptshield.cli import compute_exit_code
from promptshield.finding import Finding, Severity
from promptshield.pipeline import AnalysisResult
from promptshield.scoring import RiskBand, RiskScore

ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str, prompt: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "promptshield", *args],
        input=prompt,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        check=False,
    )


def _analysis(
    findings: list[Finding],
    score: int,
    band: RiskBand,
) -> AnalysisResult:
    return AnalysisResult(
        prompt="x",
        findings=tuple(findings),
        risk=RiskScore(score=score, band=band, findings=tuple(findings)),
    )


def test_compute_exit_code_green_empty() -> None:
    assert compute_exit_code(_analysis([], 0, RiskBand.GREEN)) == 0


def test_compute_exit_code_yellow() -> None:
    f = Finding(
        detector_name="T",
        matched_text="x",
        severity=Severity.MEDIUM,
        message="m",
        weight=30,
        category="keyword",
    )
    assert compute_exit_code(_analysis([f], 30, RiskBand.YELLOW)) == 1


def test_compute_exit_code_red() -> None:
    f = Finding(
        detector_name="T",
        matched_text="x",
        severity=Severity.HIGH,
        message="m",
        weight=60,
        category="secret",
        replacement_token="<X>",
    )
    assert compute_exit_code(_analysis([f], 60, RiskBand.RED)) == 2


def test_compute_exit_code_critical_even_if_low_score() -> None:
    """CRITICAL severity forces exit 2 regardless of band."""
    f = Finding(
        detector_name="JWTDetector",
        matched_text="eyJ.x.y",
        severity=Severity.CRITICAL,
        message="jwt",
        weight=10,
        category="secret",
        replacement_token="<JWT_TOKEN>",
    )
    # Band would be green for score 10, but CRITICAL → 2
    assert compute_exit_code(_analysis([f], 10, RiskBand.GREEN)) == 2


def test_subprocess_json_clean_prompt_exit_0() -> None:
    proc = _run_cli("--json", "-y", prompt="hello world nothing sensitive")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["analysis"]["risk_level"] == "GREEN"
    assert data["analysis"]["exit_code"] == 0


def test_subprocess_json_aws_key_redacted_and_policy_block_exit_2() -> None:
    """Single AWS key: risk YELLOW but default NO_SECRETS policy → block exit 2."""
    proc = _run_cli("--json", "-y", prompt="AKIA1234567890ABCDEF")
    assert proc.returncode == 2, proc.stderr
    data = json.loads(proc.stdout)
    assert data["analysis"]["risk_level"] == "YELLOW"
    assert data["analysis"]["policy_decision"]["action"] == "block"
    secret = next(f for f in data["analysis"]["findings"] if f["category"] == "secret")
    assert "matched_text" not in secret
    assert secret["matched_text_preview"] == "AKIA****CDEF"
    assert "AKIA1234567890ABCDEF" not in proc.stdout


def test_subprocess_json_red_score_exit_2() -> None:
    """AWS (40) + production context (20) → score 60 RED → exit 2."""
    proc = _run_cli(
        "--json",
        "-y",
        prompt="Key AKIA1234567890ABCDEF for production",
    )
    assert proc.returncode == 2, proc.stderr
    data = json.loads(proc.stdout)
    assert data["analysis"]["risk_level"] == "RED"
    assert data["analysis"]["risk_score"] >= 51


def test_subprocess_json_email_only_may_be_green_or_yellow() -> None:
    """Single email weight 15 → GREEN (exit 0)."""
    proc = _run_cli("--json", "-y", prompt="contact me at alice@example.com please")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["analysis"]["risk_score"] == 15
    assert data["analysis"]["risk_level"] == "GREEN"
