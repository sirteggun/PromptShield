"""Domain models for detector findings.

A :class:`Finding` is the atomic result produced by a detector plugin when it
identifies potentially sensitive or policy-violating content in a prompt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Qualitative severity of a finding.

    The public contract of this enum is stable since v0.1. New detectors map
    product-level levels as follows:

    * INFO → :attr:`INFO`
    * WARNING (product docs) → :attr:`MEDIUM` or :attr:`HIGH` as appropriate
    * CRITICAL → :attr:`CRITICAL`

    Attributes:
        INFO: Informational only; low impact.
        LOW: Minor policy concern.
        MEDIUM: Notable risk (e.g. blocked keywords, PII, internal URLs).
        HIGH: Significant risk (e.g. cloud access key IDs).
        CRITICAL: Severe exposure requiring immediate attention (tokens, keys).
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Finding:
    """A single detection result from a plugin.

    Position fields: prefer ``start_position`` / ``end_position``. For
    backward compatibility with v0.1 call sites, keyword arguments ``start``
    and ``end`` are also accepted and mapped to the position fields.

    Attributes:
        detector_name: Name of the producing detector.
        matched_text: Substring of the prompt that triggered the finding.
        severity: Qualitative severity level.
        message: Short message for CLI / compact UIs.
        weight: Numeric contribution to the risk score (0–100 scale).
        start_position: Inclusive start index in the original prompt.
        end_position: Exclusive end index in the original prompt.
        category: Logical group (``secret``, ``pii``, ``infrastructure``,
            ``keyword``, ``context``, …).
        explanation: Human-readable risk explanation for reports/UI.
        remediation: Concrete steps to fix or avoid the issue.
        replacement_token: Placeholder for a future sanitizer
            (e.g. ``<AWS_SECRET>``).
        metadata: Optional extra structured data.
    """

    detector_name: str
    matched_text: str
    severity: Severity
    message: str
    weight: int
    start_position: int = 0
    end_position: int = 0
    category: str = ""
    explanation: str = ""
    remediation: str = ""
    replacement_token: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        detector_name: str,
        matched_text: str,
        severity: Severity,
        message: str,
        weight: int | float,
        start_position: int | None = None,
        end_position: int | None = None,
        *,
        start: int | None = None,
        end: int | None = None,
        category: str = "",
        explanation: str = "",
        remediation: str = "",
        replacement_token: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Construct a finding with v0.1-compatible position aliases.

        Args:
            detector_name: Detector that produced this finding.
            matched_text: Matched substring.
            severity: Severity level.
            message: Short CLI message.
            weight: Score contribution (stored as ``int``).
            start_position: Inclusive start (preferred).
            end_position: Exclusive end (preferred).
            start: Deprecated alias for ``start_position``.
            end: Deprecated alias for ``end_position``.
            category: Finding category string.
            explanation: Long-form risk explanation.
            remediation: Fix guidance.
            replacement_token: Sanitizer placeholder.
            metadata: Extra structured data.
        """
        if start_position is None:
            start_position = start if start is not None else 0
        if end_position is None:
            end_position = end if end is not None else 0

        object.__setattr__(self, "detector_name", detector_name)
        object.__setattr__(self, "matched_text", matched_text)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "weight", int(weight))
        object.__setattr__(self, "start_position", start_position)
        object.__setattr__(self, "end_position", end_position)
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "explanation", explanation)
        object.__setattr__(self, "remediation", remediation)
        object.__setattr__(self, "replacement_token", replacement_token)
        object.__setattr__(self, "metadata", metadata if metadata is not None else {})
        self.__post_init__()

    def __post_init__(self) -> None:
        """Validate basic invariants after construction."""
        if self.start_position < 0 or self.end_position < self.start_position:
            msg = (
                f"Invalid span: start_position={self.start_position}, "
                f"end_position={self.end_position}"
            )
            raise ValueError(msg)
        if self.weight < 0:
            msg = f"weight must be non-negative, got {self.weight}"
            raise ValueError(msg)

    # ------------------------------------------------------------------
    # Backward-compatible aliases (v0.1 public attribute names)
    # ------------------------------------------------------------------

    @property
    def start(self) -> int:
        """Inclusive start index (alias of :attr:`start_position`)."""
        return self.start_position

    @property
    def end(self) -> int:
        """Exclusive end index (alias of :attr:`end_position`)."""
        return self.end_position

    def matched_text_preview(self) -> str:
        """Return a redacted preview of :attr:`matched_text` for reports.

        * ``secret`` — first 4 + ``****`` + last 4 characters.
        * ``keyword`` / ``context`` — full token (not a credential).
        * other categories — same 4+****+4 scheme for consistency (e.g. email).
        """
        return build_matched_text_preview(self.matched_text, self.category)

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        """Serialize this finding for JSON / reports.

        When ``redact`` is True (default, required for CI-safe JSON):

        * ``category == \"secret\"``: omits ``matched_text``; exposes
          ``matched_text_preview`` and ``redacted_text`` only.
        * other categories: keeps ``matched_text``, plus preview and
          ``redacted_text`` (replacement token).

        Args:
            redact: Apply secret-safe field rules (default True).
        """
        base: dict[str, Any] = {
            "detector_name": self.detector_name,
            "category": self.category,
            "severity": self.severity.value,
            "weight": self.weight,
            "start_position": self.start_position,
            "end_position": self.end_position,
            "message": self.message,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "replacement_token": self.replacement_token,
            "metadata": dict(self.metadata),
        }
        preview = self.matched_text_preview()
        redacted = self.replacement_token or "<REDACTED>"

        if not redact:
            base["matched_text"] = self.matched_text
            base["matched_text_preview"] = preview
            base["redacted_text"] = redacted
            return base

        if self.category == "secret":
            # Never emit full secret material in JSON.
            base["matched_text_preview"] = preview
            base["redacted_text"] = redacted
        else:
            base["matched_text"] = self.matched_text
            base["matched_text_preview"] = preview
            base["redacted_text"] = redacted
        return base


def build_matched_text_preview(text: str, category: str) -> str:
    """Build a human-safe preview of matched content.

    Args:
        text: Original matched substring.
        category: Finding category.

    Returns:
        Preview string suitable for logs and JSON reports.
    """
    if not text:
        return ""
    cat = (category or "").lower()
    if cat in {"keyword", "context"}:
        return text
    if len(text) <= 8:
        if len(text) <= 2:
            return "****"
        return f"{text[:1]}****{text[-1:]}"
    return f"{text[:4]}****{text[-4:]}"
