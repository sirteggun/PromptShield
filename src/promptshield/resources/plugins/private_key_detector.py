"""PrivateKeyDetector — detect PEM / OpenSSH private key blocks."""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding, Severity

logger = logging.getLogger(__name__)


class PrivateKeyDetector(BaseDetector):
    """Detect multi-line private key PEM/OpenSSH blocks.

    Matches from ``-----BEGIN … PRIVATE KEY-----`` through the corresponding
    ``-----END … PRIVATE KEY-----`` line. Logs only positions, never key body.
    """

    # RSA, OpenSSH, EC, and generic PKCS#8 PRIVATE KEY headers.
    KEY_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?"
        r"PRIVATE KEY-----"
        r"[\s\S]*?"
        r"-----END (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?"
        r"PRIVATE KEY-----",
        re.MULTILINE,
    )
    DEFAULT_WEIGHT: ClassVar[int] = 50
    CATEGORY: ClassVar[str] = "secret"
    REPLACEMENT_TOKEN: ClassVar[str] = "<PRIVATE_KEY>"

    @property
    def name(self) -> str:
        return "PrivateKeyDetector"

    def analyze(self, prompt: str) -> list[Finding]:
        """Find private key blocks in ``prompt``.

        Args:
            prompt: Full prompt text (may be multi-line).

        Returns:
            Findings covering each full BEGIN…END block.
        """
        findings: list[Finding] = []
        for match in self.KEY_PATTERN.finditer(prompt):
            start = match.start()
            end = match.end()
            # Never log the key material — only location metadata.
            logger.info(
                "Private key detected at position %d–%d (length=%d)",
                start,
                end,
                end - start,
            )
            header_line = match.group(0).splitlines()[0] if match.group(0) else ""
            findings.append(
                Finding(
                    detector_name=self.name,
                    matched_text=match.group(0),
                    start_position=start,
                    end_position=end,
                    severity=Severity.CRITICAL,
                    message=(f"Private key block detected (pos. {start})."),
                    weight=self.DEFAULT_WEIGHT,
                    category=self.CATEGORY,
                    explanation=(
                        "A private key can sign or decrypt data and authenticate "
                        "to servers and services. If included in an LLM prompt it "
                        "may end up in logs, training caches, or support tickets, "
                        "compromising the infrastructure protected by that key."
                    ),
                    remediation=(
                        "Remove the PEM block from the prompt immediately. "
                        f"Replace it with {self.REPLACEMENT_TOKEN}. "
                        "If the key was exposed, generate a new key pair, "
                        "distribute the public key, and revoke the old one. Never "
                        "share private keys with AI tools."
                    ),
                    replacement_token=self.REPLACEMENT_TOKEN,
                    metadata={
                        "pattern": "private_key",
                        "header": header_line,
                    },
                )
            )
        return findings
