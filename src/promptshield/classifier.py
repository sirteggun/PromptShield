"""Prompt content classifier — deterministic, strategy-based heuristics.

This module is **read-only** with respect to the detection pipeline: it only
inspects the raw prompt string and never mutates findings, scores, or policies.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Sequence

# Minimum confidence for a strategy label to be retained (unless unknown).
_MIN_REPORTED_CONFIDENCE = 0.0
# Below this max confidence across strategies → emit "unknown".
_UNKNOWN_THRESHOLD = 0.3


@dataclass(frozen=True, slots=True)
class PromptLabel:
    """A single content-type classification label.

    Attributes:
        label: Stable identifier (e.g. ``source_code``, ``config_file``).
        confidence: Deterministic score in ``[0.0, 1.0]``.
        evidence: Human-readable reasons that contributed to the score.
    """

    label: str
    confidence: float
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialize for JSON intelligence output."""
        return {
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "evidence": list(self.evidence),
        }


class ClassificationStrategy(ABC):
    """Strategy interface for a single content-type heuristic."""

    name: str

    @abstractmethod
    def evaluate(self, prompt: str) -> PromptLabel | None:
        """Return a label if this strategy applies, otherwise ``None``."""
        raise NotImplementedError


def _saturate(score: float) -> float:
    return min(1.0, max(0.0, score))


def _lines(prompt: str) -> list[str]:
    return prompt.splitlines() if prompt else []


class SourceCodeStrategy(ClassificationStrategy):
    """Detect source-code-like prompts.

    Scoring (documented increments, saturated at 1.0):

    * +0.3 — keywords: import, def, class, function, var, let, const
    * +0.2 — comments: ``//``, ``#``, ``/*``
    * +0.2 — balanced curly braces
    * +0.2 — ≥3 lines with leading indentation (spaces/tabs)
    * +0.1 — common language keywords (return, public, private, …)
    """

    name = "source_code"

    _CODE_CORE = re.compile(
        r"\b(import|def|class|function|var|let|const)\b",
        re.IGNORECASE,
    )
    _COMMENT = re.compile(r"(//|#|/\*)")
    _LANG_KW = re.compile(
        r"\b(return|public|private|protected|static|async|await|package|"
        r"namespace|interface|implements|extends|yield|lambda)\b",
        re.IGNORECASE,
    )

    def evaluate(self, prompt: str) -> PromptLabel | None:
        if not prompt or not prompt.strip():
            return None
        score = 0.0
        evidence: list[str] = []

        if self._CODE_CORE.search(prompt):
            score += 0.3
            evidence.append("code keywords (import/def/class/function/var/let/const)")
        if self._COMMENT.search(prompt):
            score += 0.2
            evidence.append("comments (//, #, /*)")
        opens = prompt.count("{")
        closes = prompt.count("}")
        if opens > 0 and opens == closes:
            score += 0.2
            evidence.append("balanced curly braces")
        indented = sum(1 for line in _lines(prompt) if re.match(r"^[ \t]+\S", line))
        if indented >= 3:
            score += 0.2
            evidence.append("multi-line indentation (>=3 lines)")
        if self._LANG_KW.search(prompt):
            score += 0.1
            evidence.append("common language keywords")

        score = _saturate(score)
        if score <= 0.0:
            return None
        return PromptLabel(label=self.name, confidence=score, evidence=evidence)


class ConfigFileStrategy(ClassificationStrategy):
    """Detect configuration file fragments (.env, YAML, TOML, INI, JSON-ish).

    Scoring:

    * +0.3 — ``KEY=value`` / ``KEY: value`` assignment lines
    * +0.2 — INI/TOML section headers ``[name]``
    * +0.2 — YAML-like ``key:`` nested structure (≥2 lines)
    * +0.2 — JSON object/array braces with quoted keys
    * +0.1 — .env / config file markers (export, dotenv, .yaml, .toml)
    """

    name = "config_file"

    _ASSIGN = re.compile(
        r"(?m)^[A-Za-z_][A-Za-z0-9_.-]*\s*[=:]\s*\S+",
    )
    _SECTION = re.compile(r"(?m)^\[[^\]]+\]\s*$")
    _YAML_KEY = re.compile(r"(?m)^[ \t]*[A-Za-z_][\w.-]*:\s")
    _JSON_KEY = re.compile(r'"[^"]+"\s*:')
    _MARKERS = re.compile(
        r"(\.env|dotenv|\.ya?ml|\.toml|\.ini|\.cfg|export\s+[A-Z_]+)",
        re.IGNORECASE,
    )

    def evaluate(self, prompt: str) -> PromptLabel | None:
        if not prompt or not prompt.strip():
            return None
        score = 0.0
        evidence: list[str] = []

        assigns = self._ASSIGN.findall(prompt)
        if len(assigns) >= 2:
            # 0.35 so two KEY=value lines clear the >0.3 report threshold
            score += 0.35
            evidence.append("key=value / key: value assignments")
        elif len(assigns) == 1:
            score += 0.2
            evidence.append("key=value assignment")

        if re.search(r"(?m)^\s*#\s*\S+", prompt):
            score += 0.1
            evidence.append("config-style comments (#)")

        if self._SECTION.search(prompt):
            score += 0.2
            evidence.append("[name] sections (INI/TOML)")

        yaml_keys = self._YAML_KEY.findall(prompt)
        if len(yaml_keys) >= 2:
            score += 0.2
            evidence.append("YAML structure (keys:)")

        if self._JSON_KEY.search(prompt) and ("{" in prompt or "[" in prompt):
            score += 0.2
            evidence.append("JSON with quoted keys")

        if self._MARKERS.search(prompt):
            score += 0.1
            evidence.append("configuration file markers")

        score = _saturate(score)
        if score <= 0.0:
            return None
        return PromptLabel(label=self.name, confidence=score, evidence=evidence)


class LogOutputStrategy(ClassificationStrategy):
    """Detect log dumps and stack traces.

    Scoring:

    * +0.3 — ISO / common timestamps
    * +0.3 — log levels (INFO, DEBUG, ERROR, WARN, TRACE, FATAL)
    * +0.2 — stack-trace markers (Traceback, at com., Exception, Caused by)
    * +0.2 — multiple level-prefixed lines
    """

    name = "log_output"

    _TS = re.compile(
        r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
        r"|\b\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}"
    )
    _LEVEL = re.compile(r"\b(INFO|DEBUG|ERROR|WARN(?:ING)?|TRACE|FATAL|CRITICAL)\b")
    _STACK = re.compile(
        r"(Traceback \(most recent call last\)|"
        r"\bat\s+[\w.$]+\(|"
        r"\bException\b|"
        r"Caused by:|"
        r"\bpanic:)",
        re.IGNORECASE,
    )

    def evaluate(self, prompt: str) -> PromptLabel | None:
        if not prompt or not prompt.strip():
            return None
        score = 0.0
        evidence: list[str] = []

        if self._TS.search(prompt):
            score += 0.3
            evidence.append("log timestamps")
        levels = self._LEVEL.findall(prompt)
        if levels:
            score += 0.3
            evidence.append("log levels (INFO/DEBUG/ERROR/...)")
        if self._STACK.search(prompt):
            score += 0.2
            evidence.append("stack trace / exception")
        level_lines = sum(1 for line in _lines(prompt) if self._LEVEL.search(line))
        if level_lines >= 2:
            score += 0.2
            evidence.append("multiple lines with log levels")

        score = _saturate(score)
        if score <= 0.0:
            return None
        return PromptLabel(label=self.name, confidence=score, evidence=evidence)


class DatabaseDumpStrategy(ClassificationStrategy):
    """Detect SQL dumps / tabular data exports.

    Scoring:

    * +0.3 — SQL keywords (INSERT INTO, CREATE TABLE, SELECT … FROM)
    * +0.2 — pipe-separated columns ``a|b|c``
    * +0.2 — CSV-like rows with ≥3 commas repeated
    * +0.2 — repetitive similar-length lines (≥4 lines)
    * +0.1 — SQL data types / VALUES (
    """

    name = "database_dump"

    _SQL = re.compile(
        r"\b(INSERT\s+INTO|CREATE\s+TABLE|SELECT\s+.+\s+FROM|DROP\s+TABLE|"
        r"UPDATE\s+\w+\s+SET)\b",
        re.IGNORECASE | re.DOTALL,
    )
    _PIPE = re.compile(r"(?m)^[^\n|]+\|[^\n|]+\|[^\n|]+")
    _VALUES = re.compile(r"\bVALUES\s*\(", re.IGNORECASE)
    _SQL_TYPE = re.compile(
        r"\b(VARCHAR|INTEGER|PRIMARY\s+KEY|NOT\s+NULL|AUTO_INCREMENT)\b",
        re.IGNORECASE,
    )

    def evaluate(self, prompt: str) -> PromptLabel | None:
        if not prompt or not prompt.strip():
            return None
        score = 0.0
        evidence: list[str] = []

        if self._SQL.search(prompt):
            score += 0.3
            evidence.append("SQL statements (INSERT/SELECT/CREATE...)")
        if self._PIPE.search(prompt):
            score += 0.2
            evidence.append("pipe-separated columns")
        csv_lines = [
            line
            for line in _lines(prompt)
            if line.count(",") >= 2 and len(line.split(",")) >= 3
        ]
        if len(csv_lines) >= 2:
            score += 0.2
            evidence.append("repetitive CSV rows")
        lengths = [len(line) for line in _lines(prompt) if line.strip()]
        if len(lengths) >= 4:
            avg = sum(lengths) / len(lengths)
            similar = sum(1 for n in lengths if abs(n - avg) <= max(5, avg * 0.2))
            if similar >= 4:
                score += 0.2
                evidence.append("similar-length lines (tabular dump)")
        if self._VALUES.search(prompt) or self._SQL_TYPE.search(prompt):
            score += 0.1
            evidence.append("SQL VALUES pattern / column types")

        score = _saturate(score)
        if score <= 0.0:
            return None
        return PromptLabel(label=self.name, confidence=score, evidence=evidence)


class EmailConversationStrategy(ClassificationStrategy):
    """Detect email / mail-thread style text.

    Scoring:

    * +0.3 — headers From: / To: / Subject:
    * +0.2 — Cc: / Bcc: / Date: / Reply-To:
    * +0.2 — quoting with ``>`` on multiple lines
    * +0.2 — ``On … wrote:`` / ``-----Original Message-----``
    * +0.1 — email address present
    """

    name = "email_conversation"

    _HEADERS = re.compile(
        r"(?mi)^(From|To|Subject)\s*:",
    )
    _EXTRA = re.compile(
        r"(?mi)^(Cc|Bcc|Date|Reply-To|Sent)\s*:",
    )
    _QUOTE = re.compile(r"(?m)^>")
    _THREAD = re.compile(
        r"(On .+ wrote:|-----Original Message-----|Begin forwarded message)",
        re.IGNORECASE,
    )
    _EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.\w{2,}\b")

    def evaluate(self, prompt: str) -> PromptLabel | None:
        if not prompt or not prompt.strip():
            return None
        score = 0.0
        evidence: list[str] = []

        headers = self._HEADERS.findall(prompt)
        if headers:
            score += 0.3
            evidence.append("email headers (From/To/Subject)")
        if self._EXTRA.search(prompt):
            score += 0.2
            evidence.append("additional headers (Cc/Date/...)")
        quote_lines = len(self._QUOTE.findall(prompt))
        if quote_lines >= 2:
            score += 0.2
            evidence.append("quoting with >")
        if self._THREAD.search(prompt):
            score += 0.2
            evidence.append("thread / original message")
        if self._EMAIL.search(prompt):
            score += 0.1
            evidence.append("email address present")

        score = _saturate(score)
        if score <= 0.0:
            return None
        return PromptLabel(label=self.name, confidence=score, evidence=evidence)


class GenericDocumentStrategy(ClassificationStrategy):
    """Fallback for prose documents (low confidence when others are weak).

    Scoring:

    * +0.3 — ≥2 sentences ending with ``.!?``
    * +0.2 — average word length / presence of articles (the, a, il, la, …)
    * +0.2 — absence of strong technical tokens ({}, ``=``, ``;`` density low)
    * +0.1 — long continuous paragraphs

    This strategy is intended as a soft signal; the classifier may still emit
    ``unknown`` when no strategy exceeds the 0.3 threshold.
    """

    name = "generic_document"

    _SENTENCE = re.compile(r"[.!?]\s+[A-ZÀ-ÖØ-Þ]")
    _ARTICLE = re.compile(
        r"\b(the|a|an|il|lo|la|i|gli|le|un|una|and|e|di|da|per)\b",
        re.IGNORECASE,
    )

    def evaluate(self, prompt: str) -> PromptLabel | None:
        if not prompt or not prompt.strip():
            return None
        score = 0.0
        evidence: list[str] = []
        text = prompt.strip()

        sentences = self._SENTENCE.findall(text)
        # Also count terminal punctuation
        ends = len(re.findall(r"[.!?]", text))
        if ends >= 2 or len(sentences) >= 1:
            score += 0.3
            evidence.append("complete sentences with punctuation")

        if len(self._ARTICLE.findall(text)) >= 3:
            score += 0.2
            evidence.append("prose articles / connectives")

        tech = sum(text.count(c) for c in "{}[];=")
        words = max(1, len(text.split()))
        if tech / words < 0.05:
            score += 0.2
            evidence.append("low density of technical tokens")

        if len(text) >= 120 and "\n\n" in text:
            score += 0.1
            evidence.append("long paragraphs")

        score = _saturate(score)
        # Soft fallback: only report if some prose signal exists
        if score < 0.3:
            return None
        # Cap generic document so it rarely dominates technical labels
        score = min(score, 0.55)
        return PromptLabel(label=self.name, confidence=score, evidence=evidence)


def default_strategies() -> list[ClassificationStrategy]:
    """Return the built-in strategy set in evaluation order."""
    return [
        SourceCodeStrategy(),
        ConfigFileStrategy(),
        LogOutputStrategy(),
        DatabaseDumpStrategy(),
        EmailConversationStrategy(),
        GenericDocumentStrategy(),
    ]


class PromptClassifier:
    """Run all classification strategies and aggregate labels.

    Args:
        strategies: Optional list of strategies (defaults to built-ins).
    """

    def __init__(
        self,
        strategies: Sequence[ClassificationStrategy] | None = None,
    ) -> None:
        self._strategies = (
            list(strategies) if strategies is not None else default_strategies()
        )

    @property
    def strategies(self) -> list[ClassificationStrategy]:
        """Copy of registered strategies."""
        return list(self._strategies)

    def classify(self, prompt: str) -> list[PromptLabel]:
        """Classify ``prompt``; deterministic and exception-safe.

        Returns labels with confidence > 0, sorted by confidence descending.
        If no strategy reaches confidence > 0.3, returns a single
        ``unknown`` label with confidence 1.0.
        """
        try:
            text = prompt if isinstance(prompt, str) else str(prompt)
        except Exception:
            text = ""

        labels: list[PromptLabel] = []
        try:
            for strategy in self._strategies:
                try:
                    result = strategy.evaluate(text)
                except Exception:
                    continue
                if result is None:
                    continue
                if result.confidence > _MIN_REPORTED_CONFIDENCE:
                    labels.append(
                        PromptLabel(
                            label=result.label,
                            confidence=_saturate(float(result.confidence)),
                            evidence=list(result.evidence),
                        )
                    )
        except Exception:
            return [
                PromptLabel(
                    label="unknown",
                    confidence=1.0,
                    evidence=["Internal classification error"],
                )
            ]

        labels.sort(key=lambda lab: (-lab.confidence, lab.label))
        if not labels or labels[0].confidence <= _UNKNOWN_THRESHOLD:
            return [
                PromptLabel(
                    label="unknown",
                    confidence=1.0,
                    evidence=["No recognized pattern"],
                )
            ]
        return labels
