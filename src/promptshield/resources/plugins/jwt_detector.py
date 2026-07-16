"""JWTDetector — detect JSON Web Tokens in prompts."""

from __future__ import annotations

import re
from typing import ClassVar

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding, Severity


class JWTDetector(BaseDetector):
    """Detect JWT strings (header.payload.signature, base64url segments).

    Requires a typical JWT header prefix (``eyJ``) to reduce false positives
    from arbitrary dotted identifiers.
    """

    # Three base64url segments; header usually encodes {"alg":...} → eyJ...
    JWT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
    )
    DEFAULT_WEIGHT: ClassVar[int] = 50
    CATEGORY: ClassVar[str] = "secret"
    REPLACEMENT_TOKEN: ClassVar[str] = "<JWT_TOKEN>"

    @property
    def name(self) -> str:
        return "JWTDetector"

    def analyze(self, prompt: str) -> list[Finding]:
        """Find JWT-like tokens in ``prompt``."""
        findings: list[Finding] = []
        for match in self.JWT_PATTERN.finditer(prompt):
            findings.append(
                Finding(
                    detector_name=self.name,
                    matched_text=match.group(0),
                    start_position=match.start(),
                    end_position=match.end(),
                    severity=Severity.CRITICAL,
                    message="Possible JWT detected in the prompt.",
                    weight=self.DEFAULT_WEIGHT,
                    category=self.CATEGORY,
                    explanation=(
                        "A JWT (JSON Web Token) often carries identity, "
                        "authorization claims, and a digital signature. If sent "
                        "to an LLM it may be stored in provider logs and used to "
                        "impersonate users or call protected APIs until expiry."
                    ),
                    remediation=(
                        "Do not paste session or service tokens into prompts. "
                        "Use test accounts with short-lived tokens, redact the JWT "
                        f"with {self.REPLACEMENT_TOKEN}, and revoke/rotate the "
                        "token if it was already exposed."
                    ),
                    replacement_token=self.REPLACEMENT_TOKEN,
                    metadata={"pattern": "jwt"},
                )
            )
        return findings
