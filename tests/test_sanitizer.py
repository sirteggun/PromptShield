"""Tests for PromptSanitizer and SanitizationResult."""

from __future__ import annotations

from promptshield.finding import Finding, Severity
from promptshield.sanitizer import PromptSanitizer


def _finding(
    *,
    text: str,
    start: int,
    end: int,
    token: str,
    severity: Severity = Severity.HIGH,
    weight: int = 40,
    detector: str = "TestDetector",
) -> Finding:
    return Finding(
        detector_name=detector,
        matched_text=text,
        start_position=start,
        end_position=end,
        severity=severity,
        message="test",
        weight=weight,
        replacement_token=token,
        category="secret",
    )


def test_no_findings_returns_identical_prompt() -> None:
    sanitizer = PromptSanitizer()
    prompt = "hello world"
    result = sanitizer.sanitize(prompt, [])
    assert result.original_prompt == prompt
    assert result.sanitized_prompt == prompt
    assert result.replacements == 0
    assert result.skipped == 0
    assert result.replaced_findings == []


def test_single_finding_simple_replacement() -> None:
    sanitizer = PromptSanitizer()
    prompt = "key=AKIA1234567890ABCDEF ok"
    # positions of AKIA1234567890ABCDEF
    start = prompt.index("AKIA1234567890ABCDEF")
    end = start + len("AKIA1234567890ABCDEF")
    f = _finding(
        text="AKIA1234567890ABCDEF",
        start=start,
        end=end,
        token="<AWS_SECRET>",
    )
    result = sanitizer.sanitize(prompt, [f])
    assert result.replacements == 1
    assert result.skipped == 0
    assert result.sanitized_prompt == "key=<AWS_SECRET> ok"
    assert result.replaced_findings == [f]


def test_multiple_non_overlapping_findings() -> None:
    sanitizer = PromptSanitizer()
    prompt = "mail a@b.co and ip 10.0.0.1"
    email = "a@b.co"
    ip = "10.0.0.1"
    f1 = _finding(
        text=email,
        start=prompt.index(email),
        end=prompt.index(email) + len(email),
        token="<EMAIL_ADDRESS>",
        severity=Severity.MEDIUM,
        weight=15,
        detector="EmailDetector",
    )
    f2 = _finding(
        text=ip,
        start=prompt.index(ip),
        end=prompt.index(ip) + len(ip),
        token="<PRIVATE_IP>",
        severity=Severity.INFO,
        weight=10,
        detector="IPAddressDetector",
    )
    result = sanitizer.sanitize(prompt, [f1, f2])
    assert result.replacements == 2
    assert result.skipped == 0
    assert result.sanitized_prompt == "mail <EMAIL_ADDRESS> and ip <PRIVATE_IP>"
    assert len(result.replaced_findings) == 2


def test_overlapping_findings_prefers_higher_severity() -> None:
    sanitizer = PromptSanitizer()
    prompt = "TOKENVALUE12345"
    # Two overlapping spans on the same region
    low = _finding(
        text="TOKENVALUE12345",
        start=0,
        end=15,
        token="<LOW_TOKEN>",
        severity=Severity.INFO,
        weight=10,
        detector="Low",
    )
    high = _finding(
        text="TOKENVALUE",
        start=0,
        end=10,
        token="<HIGH_TOKEN>",
        severity=Severity.CRITICAL,
        weight=50,
        detector="High",
    )
    result = sanitizer.sanitize(prompt, [low, high])
    assert result.replacements == 1
    assert result.skipped == 1
    assert result.replaced_findings[0].replacement_token == "<HIGH_TOKEN>"
    assert result.sanitized_prompt == "<HIGH_TOKEN>12345"


def test_overlap_tie_break_by_weight() -> None:
    sanitizer = PromptSanitizer()
    prompt = "ABCDEFGH"
    a = _finding(
        text="ABCD",
        start=0,
        end=4,
        token="<A>",
        severity=Severity.HIGH,
        weight=20,
        detector="A",
    )
    b = _finding(
        text="ABCDEF",
        start=0,
        end=6,
        token="<B>",
        severity=Severity.HIGH,
        weight=40,
        detector="B",
    )
    result = sanitizer.sanitize(prompt, [a, b])
    assert result.replacements == 1
    assert result.skipped == 1
    assert result.replaced_findings[0].replacement_token == "<B>"
    assert result.sanitized_prompt == "<B>GH"


def test_finding_at_start_and_end_of_string() -> None:
    sanitizer = PromptSanitizer()
    prompt = "SECRETmiddleENDX"
    start_f = _finding(
        text="SECRET",
        start=0,
        end=6,
        token="<S>",
        severity=Severity.CRITICAL,
        weight=50,
    )
    end_f = _finding(
        text="ENDX",
        start=12,
        end=16,
        token="<E>",
        severity=Severity.HIGH,
        weight=40,
    )
    result = sanitizer.sanitize(prompt, [start_f, end_f])
    assert result.replacements == 2
    assert result.sanitized_prompt == "<S>middle<E>"
