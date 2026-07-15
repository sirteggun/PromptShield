"""GitHubTokenDetector — detect GitHub personal/OAuth/server tokens."""

from __future__ import annotations

import re
from typing import ClassVar

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding, Severity


class GitHubTokenDetector(BaseDetector):
    """Detect GitHub tokens with known prefixes and minimum length.

    Recognizes classic prefixes ``ghp_``, ``gho_``, ``ghu_``, ``ghs_``.
    The full match must be at least 36 characters to avoid short false hits.
    """

    # Prefix (4 chars) + body; total length >= 36 → body at least 32.
    TOKEN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{32,}\b"
    )
    DEFAULT_WEIGHT: ClassVar[int] = 50
    CATEGORY: ClassVar[str] = "secret"
    REPLACEMENT_TOKEN: ClassVar[str] = "<GITHUB_TOKEN>"
    MIN_LENGTH: ClassVar[int] = 36

    @property
    def name(self) -> str:
        return "GitHubTokenDetector"

    def analyze(self, prompt: str) -> list[Finding]:
        """Find GitHub API tokens in ``prompt``."""
        findings: list[Finding] = []
        for match in self.TOKEN_PATTERN.finditer(prompt):
            token = match.group(0)
            if len(token) < self.MIN_LENGTH:
                continue
            findings.append(
                Finding(
                    detector_name=self.name,
                    matched_text=token,
                    start_position=match.start(),
                    end_position=match.end(),
                    severity=Severity.CRITICAL,
                    message="Possibile token GitHub rilevato nel prompt.",
                    weight=self.DEFAULT_WEIGHT,
                    category=self.CATEGORY,
                    explanation=(
                        "I token GitHub (PAT, OAuth, server-to-server) concedono "
                        "accesso a repository, organizzazioni e API. Un LLM o i "
                        "suoi log potrebbero conservare il valore, consentendo "
                        "clonazioni, push o esfiltrazione del codice."
                    ),
                    remediation=(
                        "Revoca immediatamente il token su GitHub → Settings → "
                        "Developer settings. Non condividere PAT nei prompt; usa "
                        f"{self.REPLACEMENT_TOKEN} o secret store / CI secrets. "
                        "Preferisci fine-grained PAT con scope minimi."
                    ),
                    replacement_token=self.REPLACEMENT_TOKEN,
                    metadata={
                        "pattern": "github_token",
                        "prefix": token[:4],
                    },
                )
            )
        return findings
