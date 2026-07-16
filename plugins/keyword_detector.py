"""KeywordDetector — flag blocked keywords from rules.yaml.

Keywords are matched case-insensitively as whole-word-ish substrings
(using word-boundary aware search when the keyword is alphanumeric).
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding, Severity


class KeywordDetector(BaseDetector):
    """Detect policy-blocked keywords defined in configuration.

    Configuration key:
        blocked_keywords: list of strings (from ``rules.yaml``).

    Note:
        ``context_risk_keywords`` in rules.yaml is reserved for a future
        ContextAnalyzer and is intentionally ignored here.
    """

    DEFAULT_WEIGHT: ClassVar[int] = 20
    CATEGORY: ClassVar[str] = "keyword"
    REPLACEMENT_TOKEN: ClassVar[str] = "<BLOCKED_KEYWORD>"

    def __init__(self) -> None:
        self._keywords: list[str] = []
        self._patterns: list[tuple[str, re.Pattern[str]]] = []

    @property
    def name(self) -> str:
        """Stable plugin name."""
        return "KeywordDetector"

    def configure(self, config: dict[str, Any]) -> None:
        """Load ``blocked_keywords`` and compile case-insensitive patterns.

        Args:
            config: Shared application configuration mapping.
        """
        raw = config.get("blocked_keywords", [])
        if not isinstance(raw, list):
            self._keywords = []
            self._patterns = []
            return

        self._keywords = [str(k) for k in raw if str(k).strip()]
        self._patterns = []
        for keyword in self._keywords:
            escaped = re.escape(keyword)
            if re.fullmatch(r"\w+", keyword, flags=re.UNICODE):
                pattern = re.compile(rf"\b{escaped}\b", re.IGNORECASE)
            else:
                pattern = re.compile(escaped, re.IGNORECASE)
            self._patterns.append((keyword, pattern))

    def analyze(self, prompt: str) -> list[Finding]:
        """Find all configured keyword occurrences in ``prompt``.

        Args:
            prompt: Full prompt text.

        Returns:
            One finding per match.
        """
        findings: list[Finding] = []
        for original, pattern in self._patterns:
            for match in pattern.finditer(prompt):
                findings.append(
                    Finding(
                        detector_name=self.name,
                        matched_text=match.group(0),
                        start_position=match.start(),
                        end_position=match.end(),
                        severity=Severity.MEDIUM,
                        message=(
                            f"Blocked keyword detected: '{original}'. "
                            "The term is listed in rules.yaml."
                        ),
                        weight=self.DEFAULT_WEIGHT,
                        category=self.CATEGORY,
                        explanation=(
                            f"The term '{original}' is classified as a blocked "
                            "policy keyword. It may indicate sensitive topics "
                            "(HR data, M&A, customer databases) that should not "
                            "be discussed with external LLMs without authorization."
                        ),
                        remediation=(
                            "Remove or generalize references to internal data "
                            "before sending the prompt. Use anonymized descriptions "
                            "or placeholders instead of reserved system and process "
                            "names."
                        ),
                        replacement_token=self.REPLACEMENT_TOKEN,
                        metadata={"keyword": original},
                    )
                )
        return findings
