"""ContextDetector — strategy-based contextual risk analysis.

Uses weighted keywords from ``rules.yaml`` (``context_risk_keywords``).
Future strategies (NLP, local LLM) can implement
:class:`ContextDetectionStrategy` without changing the detector façade.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from promptshield.base_detector import BaseDetector
from promptshield.finding import Finding, Severity

# Product defaults used when no strategy/config is supplied.
DEFAULT_CONTEXT_KEYWORDS: dict[str, int] = {
    "production": 20,
    "payroll": 25,
    "salaries": 10,
    "internal": 15,
    "confidential": 25,
    "staging": 10,
    "live": 15,
    "customer data": 20,
    "financial": 20,
    "m&a": 25,
    "soc2": 15,
    "gdpr": 15,
    "hipaa": 20,
}

DEFAULT_KEYWORD_WEIGHT: int = 10


class ContextDetectionStrategy(ABC):
    """Strategy interface for contextual risk detection."""

    @abstractmethod
    def analyze(self, prompt: str) -> list[Finding]:
        """Analyze ``prompt`` and return context-related findings."""
        raise NotImplementedError


class KeywordContextStrategy(ContextDetectionStrategy):
    """Keyword-based context strategy with per-term weights.

    Args:
        keywords_config: Mapping of keyword → weight. Missing/None weights
            default to :data:`DEFAULT_KEYWORD_WEIGHT` (10).
    """

    REPLACEMENT_TOKEN: ClassVar[str] = "<CONTEXT_RISK_WORD>"
    CATEGORY: ClassVar[str] = "context"
    DETECTOR_NAME: ClassVar[str] = "ContextDetector"

    def __init__(self, keywords_config: dict[str, Any] | None = None) -> None:
        raw = keywords_config if keywords_config is not None else {}
        self._weights: dict[str, int] = {}
        for key, value in raw.items():
            keyword = str(key).strip()
            if not keyword:
                continue
            if value is None or value == "":
                weight = DEFAULT_KEYWORD_WEIGHT
            else:
                try:
                    weight = int(value)
                except (TypeError, ValueError):
                    weight = DEFAULT_KEYWORD_WEIGHT
            self._weights[keyword] = weight

        self._patterns: list[tuple[str, int, re.Pattern[str]]] = []
        # Longer keywords first so multi-word phrases match before fragments.
        for keyword, weight in sorted(
            self._weights.items(), key=lambda kv: len(kv[0]), reverse=True
        ):
            escaped = re.escape(keyword)
            if re.search(r"\s", keyword):
                pattern = re.compile(escaped, re.IGNORECASE)
            elif re.fullmatch(r"[\w&+-]+", keyword, flags=re.UNICODE):
                pattern = re.compile(rf"\b{escaped}\b", re.IGNORECASE)
            else:
                pattern = re.compile(escaped, re.IGNORECASE)
            self._patterns.append((keyword, weight, pattern))

    @property
    def weights(self) -> dict[str, int]:
        """Copy of keyword → weight mapping."""
        return dict(self._weights)

    def analyze(self, prompt: str) -> list[Finding]:
        """Find weighted context keywords in ``prompt``."""
        findings: list[Finding] = []
        for keyword, weight, pattern in self._patterns:
            for match in pattern.finditer(prompt):
                findings.append(
                    Finding(
                        detector_name=self.DETECTOR_NAME,
                        matched_text=match.group(0),
                        start_position=match.start(),
                        end_position=match.end(),
                        severity=Severity.MEDIUM,  # product WARNING
                        message=(
                            f"Parola di contesto a rischio: '{keyword}' "
                            f"(peso {weight})."
                        ),
                        weight=weight,
                        category=self.CATEGORY,
                        explanation=(
                            f"Il termine '{keyword}' suggerisce un contesto "
                            "operativo o di compliance sensibile. Combinato con "
                            "altri dati nel prompt può rivelare processi interni, "
                            "dati HR/finanziari o obblighi normativi che non "
                            "dovrebbero essere esposti a LLM esterni."
                        ),
                        remediation=(
                            "Valuta se il prompt contiene dettagli operativi "
                            "che non dovrebbero essere condivisi esternamente."
                        ),
                        replacement_token=self.REPLACEMENT_TOKEN,
                        metadata={
                            "keyword": keyword,
                            "context_weight": weight,
                        },
                    )
                )
        return findings


def parse_context_keywords(raw: Any) -> dict[str, int]:
    """Normalize YAML ``context_risk_keywords`` to a weight mapping.

    Accepts:
        * ``dict`` — keyword → weight (missing weight → 10)
        * ``list`` — each item weight 10 (legacy / unweighted form)

    Args:
        raw: Value from configuration.

    Returns:
        Mapping of keyword to integer weight.
    """
    if raw is None:
        return {}
    if isinstance(raw, dict):
        result: dict[str, int] = {}
        for key, value in raw.items():
            keyword = str(key).strip()
            if not keyword:
                continue
            if value is None or value == "":
                result[keyword] = DEFAULT_KEYWORD_WEIGHT
            else:
                try:
                    result[keyword] = int(value)
                except (TypeError, ValueError):
                    result[keyword] = DEFAULT_KEYWORD_WEIGHT
        return result
    if isinstance(raw, list):
        return {
            str(item).strip(): DEFAULT_KEYWORD_WEIGHT
            for item in raw
            if str(item).strip()
        }
    return {}


class ContextDetector(BaseDetector):
    """Façade for context analysis; delegates to a :class:`ContextDetectionStrategy`."""

    def __init__(self, strategy: ContextDetectionStrategy | None = None) -> None:
        self.strategy: ContextDetectionStrategy = strategy or KeywordContextStrategy(
            DEFAULT_CONTEXT_KEYWORDS
        )

    @property
    def name(self) -> str:
        return "ContextDetector"

    def configure(self, config: dict[str, Any]) -> None:
        """Rebuild the keyword strategy from ``context_risk_keywords``.

        If the key is absent, keeps product default weights. If present but
        empty, disables keyword matching (empty strategy map).

        Args:
            config: Shared application configuration.
        """
        if "context_risk_keywords" not in config:
            self.strategy = KeywordContextStrategy(DEFAULT_CONTEXT_KEYWORDS)
            return
        weights = parse_context_keywords(config.get("context_risk_keywords"))
        self.strategy = KeywordContextStrategy(weights)

    def analyze(self, prompt: str) -> list[Finding]:
        """Delegate analysis to the active strategy."""
        return self.strategy.analyze(prompt)
