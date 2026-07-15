"""Tests for PrivateKeyDetector."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from plugins.private_key_detector import PrivateKeyDetector  # noqa: E402
from promptshield.finding import Severity  # noqa: E402

RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZFBtQ+EXAMPLEONLYNOTREAL
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/==
-----END RSA PRIVATE KEY-----"""

OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----"""


@pytest.fixture
def detector() -> PrivateKeyDetector:
    return PrivateKeyDetector()


def test_detects_rsa_private_key(detector: PrivateKeyDetector) -> None:
    prompt = f"here is a key:\n{RSA_KEY}\nend"
    findings = detector.analyze(prompt)
    assert len(findings) == 1
    f = findings[0]
    assert f.matched_text.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert f.matched_text.endswith("-----END RSA PRIVATE KEY-----")
    assert f.start_position == prompt.index("-----BEGIN RSA PRIVATE KEY-----")
    assert f.end_position == f.start_position + len(f.matched_text)
    assert f.weight == 50
    assert f.severity == Severity.CRITICAL
    assert f.category == "secret"
    assert f.replacement_token == "<PRIVATE_KEY>"
    assert f.explanation
    assert f.remediation


def test_detects_openssh_and_no_false_positive(
    detector: PrivateKeyDetector,
) -> None:
    findings = detector.analyze(OPENSSH_KEY)
    assert len(findings) == 1
    assert "OPENSSH" in findings[0].matched_text

    assert detector.analyze("no keys, only public docs") == []
    # Public key should not match PRIVATE KEY pattern
    pub = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq\n-----END PUBLIC KEY-----"
    assert detector.analyze(pub) == []


def test_logs_do_not_contain_key_material(
    detector: PrivateKeyDetector,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="plugins.private_key_detector"):
        detector.analyze(RSA_KEY)

    assert caplog.records, "expected at least one log record"
    for record in caplog.records:
        # Log may mention position but must not dump PEM body
        assert "MIIEowIBAAKCAQEA" not in record.getMessage()
        assert "Private key detected at position" in record.getMessage()
