"""SecretDetector — find common cloud credential patterns in prompts.

Currently recognizes AWS Access Key IDs matching ``AKIA[0-9A-Z]{16}``.
Specialized secret types (JWT, GitHub, private keys) live in dedicated plugins.
"""

from __future__ import annotations

import re
from typing import ClassVar

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding, Severity


class SecretDetector(BaseDetector):
    """Detect hardcoded cloud credential identifiers (AWS Access Key IDs)."""

    AWS_ACCESS_KEY_ID: ClassVar[re.Pattern[str]] = re.compile(r"AKIA[0-9A-Z]{16}")
    DEFAULT_WEIGHT: ClassVar[int] = 40
    CATEGORY: ClassVar[str] = "secret"
    REPLACEMENT_TOKEN: ClassVar[str] = "<AWS_SECRET>"

    @property
    def name(self) -> str:
        """Stable plugin name."""
        return "SecretDetector"

    def analyze(self, prompt: str) -> list[Finding]:
        """Scan ``prompt`` for AWS Access Key ID patterns.

        Args:
            prompt: Full prompt text.

        Returns:
            One finding per match (weight 40, HIGH severity).
        """
        findings: list[Finding] = []
        for match in self.AWS_ACCESS_KEY_ID.finditer(prompt):
            findings.append(
                Finding(
                    detector_name=self.name,
                    matched_text=match.group(0),
                    start_position=match.start(),
                    end_position=match.end(),
                    severity=Severity.HIGH,
                    message=(
                        "Possibile AWS Access Key ID rilevata. "
                        "Non includere credenziali cloud nei prompt inviati a LLM."
                    ),
                    weight=self.DEFAULT_WEIGHT,
                    category=self.CATEGORY,
                    explanation=(
                        "AWS Access Key ID può essere usata per accedere alle "
                        "risorse cloud. Se inviata a un LLM, potrebbe essere "
                        "registrata nei log del provider e potenzialmente esposta."
                    ),
                    remediation=(
                        "Sostituisci la chiave con una variabile d'ambiente o un "
                        "placeholder prima di condividere il codice. Non committare "
                        "mai chiavi in chiaro. Ruota immediatamente le credenziali "
                        "se sono state esposte."
                    ),
                    replacement_token=self.REPLACEMENT_TOKEN,
                    metadata={"pattern": "aws_access_key_id"},
                )
            )
        return findings
