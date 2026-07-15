"""IPAddressDetector — detect private and loopback IPv4 addresses."""

from __future__ import annotations

import re
from typing import ClassVar

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding, Severity


class IPAddressDetector(BaseDetector):
    """Detect private RFC1918 and loopback IPv4 addresses.

    Ranges:
        * 10.0.0.0/8
        * 172.16.0.0/12 (172.16–31.x.x)
        * 192.168.0.0/16
        * 127.0.0.0/8 (loopback)
    """

    # Capture four octets; validate privately in code for precise 172.16–31.
    IPV4_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b("
        r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"|(?:172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})"
        r"|(?:192\.168\.\d{1,3}\.\d{1,3})"
        r"|(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r")\b"
    )
    DEFAULT_WEIGHT: ClassVar[int] = 10
    CATEGORY: ClassVar[str] = "infrastructure"
    REPLACEMENT_TOKEN: ClassVar[str] = "<PRIVATE_IP>"

    @property
    def name(self) -> str:
        return "IPAddressDetector"

    def analyze(self, prompt: str) -> list[Finding]:
        """Find private/loopback IPv4 addresses in ``prompt``."""
        findings: list[Finding] = []
        for match in self.IPV4_PATTERN.finditer(prompt):
            ip = match.group(0)
            if not self._octets_in_range(ip):
                continue
            findings.append(
                Finding(
                    detector_name=self.name,
                    matched_text=ip,
                    start_position=match.start(),
                    end_position=match.end(),
                    severity=Severity.INFO,
                    message=f"Indirizzo IP privato/loopback rilevato: {ip}",
                    weight=self.DEFAULT_WEIGHT,
                    category=self.CATEGORY,
                    explanation=(
                        "Gli IP privati e di loopback rivelano topologia di rete "
                        "interna. In un prompt LLM possono aiutare un attaccante "
                        "a mappare segmenti non pubblici o a preparare pivot laterali."
                    ),
                    remediation=(
                        "Sostituisci gli indirizzi con "
                        f"{self.REPLACEMENT_TOKEN} o descrizioni generiche "
                        "(es. 'host interno A'). Non condividere mappe di rete "
                        "complete con servizi esterni."
                    ),
                    replacement_token=self.REPLACEMENT_TOKEN,
                    metadata={"pattern": "private_ip"},
                )
            )
        return findings

    @staticmethod
    def _octets_in_range(ip: str) -> bool:
        """Reject octet values outside 0–255 (regex alone is permissive)."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
