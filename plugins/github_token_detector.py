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
                    message="Possible GitHub token detected in the prompt.",
                    weight=self.DEFAULT_WEIGHT,
                    category=self.CATEGORY,
                    explanation=(
                        "GitHub tokens (PAT, OAuth, server-to-server) grant "
                        "access to repositories, organizations, and APIs. An LLM "
                        "or its logs may retain the value, enabling clones, "
                        "pushes, or code exfiltration."
                    ),
                    remediation=(
                        "Revoke the token immediately in GitHub -> Settings -> "
                        "Developer settings. Do not share PATs in prompts; use "
                        f"{self.REPLACEMENT_TOKEN} or a secret store / CI secrets. "
                        "Prefer fine-grained PATs with minimal scopes."
                    ),
                    replacement_token=self.REPLACEMENT_TOKEN,
                    metadata={
                        "pattern": "github_token",
                        "prefix": token[:4],
                    },
                )
            )
        return findings
