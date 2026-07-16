"""EmailDetector — detect email addresses (PII) in prompts."""

from __future__ import annotations

import re
from typing import ClassVar

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding, Severity


class EmailDetector(BaseDetector):
    """Detect email addresses with a practical, high-precision regex."""

    # Practical email pattern: local@domain.tld (supports + and dots in local).
    EMAIL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )
    DEFAULT_WEIGHT: ClassVar[int] = 15
    CATEGORY: ClassVar[str] = "pii"
    REPLACEMENT_TOKEN: ClassVar[str] = "<EMAIL_ADDRESS>"

    @property
    def name(self) -> str:
        return "EmailDetector"

    def analyze(self, prompt: str) -> list[Finding]:
        """Find email addresses in ``prompt``."""
        findings: list[Finding] = []
        for match in self.EMAIL_PATTERN.finditer(prompt):
            findings.append(
                Finding(
                    detector_name=self.name,
                    matched_text=match.group(0),
                    start_position=match.start(),
                    end_position=match.end(),
                    severity=Severity.MEDIUM,  # product WARNING → MEDIUM
                    message=f"Email address detected: {match.group(0)}",
                    weight=self.DEFAULT_WEIGHT,
                    category=self.CATEGORY,
                    explanation=(
                        "Email addresses are personal data (PII). Sending them "
                        "to an LLM may violate privacy/GDPR policy if the provider "
                        "retains prompts, and can enable phishing or targeting."
                    ),
                    remediation=(
                        "Anonymize contacts: use "
                        f"{self.REPLACEMENT_TOKEN} or a test alias. "
                        "Avoid customer or colleague lists in prompts to cloud "
                        "services not covered by a DPA."
                    ),
                    replacement_token=self.REPLACEMENT_TOKEN,
                    metadata={"pattern": "email"},
                )
            )
        return findings
