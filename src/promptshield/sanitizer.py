"""Prompt sanitizer — replace sensitive spans with placeholder tokens.

Operates exclusively on :class:`~promptshield.finding.Finding` position spans
and ``replacement_token`` values. Never re-runs detection logic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from promptshield.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Higher rank wins on overlapping spans (product WARNING ≡ MEDIUM).
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

# Human-readable labels for CLI replacement summaries (token → label).
TOKEN_LABELS: dict[str, str] = {
    "<AWS_SECRET>": "AWS Secret",
    "<JWT_TOKEN>": "JWT Token",
    "<GITHUB_TOKEN>": "GitHub Token",
    "<PRIVATE_KEY>": "Private Key",
    "<EMAIL_ADDRESS>": "Email",
    "<PRIVATE_IP>": "Private IP",
    "<INTERNAL_URL>": "Internal URL",
    "<BLOCKED_KEYWORD>": "Blocked keyword",
    "<CONTEXT_RISK_WORD>": "Context keyword",
}


@dataclass(frozen=True, slots=True)
class SanitizationResult:
    """Structured outcome of a sanitization pass.

    Attributes:
        original_prompt: Prompt text before any replacement.
        sanitized_prompt: Prompt after placeholder substitution.
        replacements: Number of substitutions actually applied.
        skipped: Findings not applied (overlap losers, empty token, …).
        replaced_findings: Findings that produced a substitution, in the
            order they appear in the original prompt (ascending start).
    """

    original_prompt: str
    sanitized_prompt: str
    replacements: int
    skipped: int
    replaced_findings: list[Finding] = field(default_factory=list)

    def to_dict(self, *, redact: bool = True) -> dict[str, object]:
        """Serialize for JSON output.

        Does **not** include ``original_prompt`` (may contain secrets).
        Replaced findings use :meth:`Finding.to_dict` redaction rules.

        Args:
            redact: Forwarded to finding serialization (default True).
        """
        return {
            "replacements": self.replacements,
            "skipped": self.skipped,
            "sanitized_prompt": self.sanitized_prompt,
            "replaced_findings": [
                f.to_dict(redact=redact) for f in self.replaced_findings
            ],
        }


class PromptSanitizer:
    """Replace finding spans with their ``replacement_token`` placeholders.

    Overlapping findings are resolved by severity (CRITICAL > HIGH > MEDIUM >
    LOW > INFO), then by descending weight, then by earlier start position.
    """

    def sanitize(self, prompt: str, findings: list[Finding]) -> SanitizationResult:
        """Sanitize ``prompt`` using finding spans and tokens.

        Args:
            prompt: Original prompt text.
            findings: Findings from the analysis pipeline (positions refer
                to ``prompt``).

        Returns:
            A :class:`SanitizationResult` with counts and the sanitized text.
        """
        if not findings:
            logger.debug("Sanitizer: no findings; prompt unchanged")
            return SanitizationResult(
                original_prompt=prompt,
                sanitized_prompt=prompt,
                replacements=0,
                skipped=0,
                replaced_findings=[],
            )

        selected, skipped = self._resolve_overlaps(findings)
        # Apply from the end so earlier indices stay valid.
        ordered = sorted(selected, key=lambda f: f.start_position, reverse=True)
        text = prompt
        applied: list[Finding] = []
        for finding in ordered:
            token = finding.replacement_token
            start = finding.start_position
            end = finding.end_position
            if start < 0 or end > len(prompt) or start > end:
                skipped += 1
                logger.debug(
                    "Sanitizer: skipping out-of-range span [%s, %s)",
                    start,
                    end,
                )
                continue
            # Never log the original secret material — only token and span.
            logger.debug(
                "Sanitizer: replace span [%d, %d) with %s",
                start,
                end,
                token,
            )
            text = text[:start] + token + text[end:]
            applied.append(finding)

        # Report findings in document order.
        applied_asc = sorted(applied, key=lambda f: f.start_position)
        return SanitizationResult(
            original_prompt=prompt,
            sanitized_prompt=text,
            replacements=len(applied_asc),
            skipped=skipped,
            replaced_findings=list(applied_asc),
        )

    def _resolve_overlaps(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        """Pick non-overlapping findings by severity, then weight.

        Returns:
            Tuple of (selected findings, skipped count).
        """
        ranked = sorted(
            findings,
            key=lambda f: (
                -_SEVERITY_RANK.get(f.severity, 0),
                -f.weight,
                f.start_position,
            ),
        )
        selected: list[Finding] = []
        skipped = 0
        for finding in ranked:
            if not finding.replacement_token:
                skipped += 1
                continue
            if any(self._overlaps(finding, kept) for kept in selected):
                skipped += 1
                continue
            selected.append(finding)
        return selected, skipped

    @staticmethod
    def _overlaps(a: Finding, b: Finding) -> bool:
        """Return True if half-open spans ``[start, end)`` intersect."""
        return a.start_position < b.end_position and b.start_position < a.end_position


def label_for_token(token: str, finding: Finding | None = None) -> str:
    """Return a short human label for a replacement token.

    Args:
        token: Placeholder string (e.g. ``<AWS_SECRET>``).
        finding: Optional finding used as fallback for labeling.
    """
    if token in TOKEN_LABELS:
        return TOKEN_LABELS[token]
    if finding is not None and finding.detector_name:
        return finding.detector_name
    return token.strip("<>") or "Replacement"
