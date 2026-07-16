"""CLI integration tests for the Policy Engine."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, prompt: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "promptshield", *args],
        input=prompt,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        check=False,
    )


def test_no_secrets_blocks_even_with_yes() -> None:
    proc = _run("--json", "-y", prompt="token AKIA1234567890ABCDEF here")
    assert proc.returncode == 2, proc.stderr
    data = json.loads(proc.stdout)
    pd = data["analysis"]["policy_decision"]
    assert pd["action"] == "block"
    assert pd["blocked"] is True
    assert any(p["id"] == "NO_SECRETS" for p in pd["triggered_policies"])
    assert "matched_text" not in next(
        f for f in data["analysis"]["findings"] if f["category"] == "secret"
    )


def test_production_warning_warns_not_block_on_green() -> None:
    """Context-only production: score 20 GREEN → warn, exit at least 1."""
    # Disable NO_SECRETS noise with a minimal policy file
    policies = ROOT / "tests" / "_tmp_prod_only.yaml"
    policies.write_text(
        textwrap.dedent(
            """
            policies:
              - id: PRODUCTION_WARNING
                description: prod
                action: warn
                priority: 50
                conditions:
                  context: production
                message: "The prompt contains production references."
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    try:
        proc = _run(
            "--json",
            "-y",
            "--policy-file",
            str(policies),
            prompt="please review the production rollout plan",
        )
        data = json.loads(proc.stdout)
        assert data["analysis"]["risk_level"] == "GREEN"
        pd = data["analysis"]["policy_decision"]
        assert pd["action"] == "warn"
        assert pd["blocked"] is False
        assert proc.returncode == 1
    finally:
        policies.unlink(missing_ok=True)


def test_pci_blocks_pii_with_financial_context() -> None:
    policies = ROOT / "tests" / "_tmp_pci.yaml"
    policies.write_text(
        textwrap.dedent(
            """
            policies:
              - id: PCI_COMPLIANCE
                action: block
                priority: 90
                conditions:
                  category: pii
                  context: financial
                message: "PCI block"
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    try:
        proc = _run(
            "--json",
            "-y",
            "--policy-file",
            str(policies),
            prompt="email alice@bank.com about financial statements",
        )
        assert proc.returncode == 2, proc.stderr
        data = json.loads(proc.stdout)
        assert data["analysis"]["policy_decision"]["action"] == "block"
        ids = {
            p["id"] for p in data["analysis"]["policy_decision"]["triggered_policies"]
        }
        assert "PCI_COMPLIANCE" in ids
    finally:
        policies.unlink(missing_ok=True)


def test_empty_policies_allow_and_json_section_present() -> None:
    policies = ROOT / "tests" / "_tmp_empty.yaml"
    policies.write_text("policies: []\n", encoding="utf-8")
    try:
        proc = _run(
            "--json",
            "-y",
            "--policy-file",
            str(policies),
            prompt="hello world",
        )
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert "policy_decision" in data["analysis"]
        assert data["analysis"]["policy_decision"]["action"] == "allow"
        assert data["analysis"]["policy_decision"]["triggered_policies"] == []
    finally:
        policies.unlink(missing_ok=True)


def test_human_cli_block_message_on_secret() -> None:
    proc = _run("-y", "--no-color", prompt="AKIA1234567890ABCDEF")
    out = proc.stdout + proc.stderr
    assert "BLOCKED" in out or "block" in out.lower() or "NO_SECRETS" in out
    assert proc.returncode == 2
