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
                    message=(f"Blocco di chiave privata rilevato (pos. {start})."),
                    weight=self.DEFAULT_WEIGHT,
                    category=self.CATEGORY,
                    explanation=(
                        "Una chiave privata consente di firmare o decifrare dati "
                        "e autenticarsi a server/servizi. Se inclusa in un prompt "
                        "LLM può finire in log, training cache o ticket di supporto, "
                        "compromettendo l'intera infrastruttura protetta da quella chiave."
                    ),
                    remediation=(
                        "Rimuovi immediatamente il blocco PEM dal prompt. "
                        f"Sostituiscilo con {self.REPLACEMENT_TOKEN}. "
                        "Se la chiave è stata esposta, genera una nuova coppia, "
                        "distribuisci la pubblica e revoca la vecchia. Non "
                        "condividere mai chiavi private con strumenti AI."
                    ),
                    replacement_token=self.REPLACEMENT_TOKEN,
                    metadata={
                        "pattern": "private_key",
                        "header": header_line,
                    },
                )
            )
        return findings
