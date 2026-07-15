"""Tests for IPAddressDetector."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from plugins.ip_address_detector import IPAddressDetector  # noqa: E402
from promptshield.finding import Severity  # noqa: E402


@pytest.fixture
def detector() -> IPAddressDetector:
    return IPAddressDetector()


def test_detects_private_ranges(detector: IPAddressDetector) -> None:
    prompt = "hosts: 10.0.0.5, 172.16.1.1, 192.168.1.10, 127.0.0.1"
    findings = detector.analyze(prompt)
    ips = {f.matched_text for f in findings}
    assert ips == {"10.0.0.5", "172.16.1.1", "192.168.1.10", "127.0.0.1"}
    assert all(f.weight == 10 for f in findings)
    assert all(f.severity == Severity.INFO for f in findings)
    assert all(f.category == "infrastructure" for f in findings)
    assert all(f.replacement_token == "<PRIVATE_IP>" for f in findings)
    assert all(f.explanation and f.remediation for f in findings)


def test_ignores_public_ip(detector: IPAddressDetector) -> None:
    assert detector.analyze("Reach 8.8.8.8 or 1.1.1.1") == []
    # 172.15 and 172.32 are outside 172.16–31
    assert detector.analyze("172.15.0.1 and 172.32.0.1") == []


def test_rejects_invalid_octets(detector: IPAddressDetector) -> None:
    assert detector.analyze("10.300.1.1") == []
    assert detector.analyze("192.168.1") == []
