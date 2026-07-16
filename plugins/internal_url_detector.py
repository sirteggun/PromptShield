"""InternalURLDetector — detect URLs pointing to internal/non-prod hosts."""

from __future__ import annotations

import re
from typing import ClassVar

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding, Severity


class InternalURLDetector(BaseDetector):
    """Detect http(s) URLs that look internal, staging, or admin-facing.

    Flags URLs whose host/path contain markers such as ``internal``,
    ``admin``, ``staging``, ``dev``, ``test``, ``localhost``, ``.local``,
    or ``.internal``.
    """

    URL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"https?://[^\s<>\"']+",
        re.IGNORECASE,
    )
    INTERNAL_MARKERS: ClassVar[tuple[str, ...]] = (
        "internal",
        "admin",
        "staging",
        "dev",
        "test",
        "localhost",
        ".local",
        ".internal",
    )
    DEFAULT_WEIGHT: ClassVar[int] = 20
    CATEGORY: ClassVar[str] = "infrastructure"
    REPLACEMENT_TOKEN: ClassVar[str] = "<INTERNAL_URL>"

    @property
    def name(self) -> str:
        return "InternalURLDetector"

    def analyze(self, prompt: str) -> list[Finding]:
        """Find internal-looking URLs in ``prompt``."""
        findings: list[Finding] = []
        for match in self.URL_PATTERN.finditer(prompt):
            url = match.group(0)
            # Trim common trailing punctuation.
            url_clean = url.rstrip(").,;]>\"'")
            end = match.start() + len(url_clean)
            if not self._is_internal(url_clean):
                continue
            findings.append(
                Finding(
                    detector_name=self.name,
                    matched_text=url_clean,
                    start_position=match.start(),
                    end_position=end,
                    severity=Severity.MEDIUM,  # product WARNING → MEDIUM
                    message=f"Internal/non-prod URL detected: {url_clean}",
                    weight=self.DEFAULT_WEIGHT,
                    category=self.CATEGORY,
                    explanation=(
                        "URLs for internal/admin/staging environments or .local "
                        "hosts expose non-public endpoints. Sharing them with an LLM "
                        "can reveal naming conventions, ports, and attack surface "
                        "of the corporate network."
                    ),
                    remediation=(
                        "Replace the URL with "
                        f"{self.REPLACEMENT_TOKEN} or a fictional hostname. "
                        "Describe the issue without linking to admin consoles or "
                        "non-public environments."
                    ),
                    replacement_token=self.REPLACEMENT_TOKEN,
                    metadata={"pattern": "internal_url"},
                )
            )
        return findings

    def _is_internal(self, url: str) -> bool:
        lowered = url.lower()
        return any(marker in lowered for marker in self.INTERNAL_MARKERS)
