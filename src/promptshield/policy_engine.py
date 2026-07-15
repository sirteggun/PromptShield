"""Policy Engine — YAML-driven decision rules over findings and risk score.

Policies do **not** change the numeric risk score produced by
:class:`~promptshield.scoring.RiskScoringEngine`. They produce a send
decision (``block`` / ``warn`` / ``allow``) that the CLI and CI exit codes
honour.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

from promptshield.config import project_root
from promptshield.finding import Finding, Severity

logger = logging.getLogger(__name__)

_DEFAULT_POLICY_CANDIDATES: tuple[Path, ...] = (
    Path("config/policies.yaml"),
    Path(__file__).resolve().parents[2] / "config" / "policies.yaml",
    Path.cwd() / "config" / "policies.yaml",
    # Bundled with the installed wheel/sdist
    Path(__file__).resolve().parent / "resources" / "config" / "policies.yaml",
)

# Product severity labels used in YAML → minimum internal Severity rank.
_SEVERITY_FLOOR: dict[str, int] = {
    "info": 1,
    "low": 2,
    "warning": 3,  # product WARNING ≡ medium+
    "medium": 3,
    "high": 4,
    "critical": 5,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

_ACTION_RANK: dict[str, int] = {
    "allow": 1,
    "warn": 2,
    "block": 3,
}


class PolicyAction(str, Enum):
    """Final send decision produced by the policy engine."""

    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"


@dataclass(frozen=True, slots=True)
class Policy:
    """A single decision rule loaded from YAML.

    Attributes:
        id: Unique policy identifier.
        description: Human-readable purpose.
        action: ``block``, ``warn``, or ``allow``.
        priority: Higher value wins conflicts.
        conditions: Raw conditions mapping (AND semantics).
        message: User-facing message when the policy triggers.
    """

    id: str
    description: str
    action: PolicyAction
    priority: int
    conditions: dict[str, Any] = field(default_factory=dict)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON reports."""
        return {
            "id": self.id,
            "description": self.description,
            "action": self.action.value,
            "priority": self.priority,
            "conditions": dict(self.conditions),
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Outcome of evaluating all policies against findings + score.

    Attributes:
        action: Winning action after priority / tie-break resolution.
        triggered_policies: Policies whose conditions matched (all of them).
        messages: Messages from triggered policies (stable order).
        winning_policy: Policy that determined ``action``, if any.
    """

    action: PolicyAction
    triggered_policies: tuple[Policy, ...] = ()
    messages: tuple[str, ...] = ()
    winning_policy: Policy | None = None

    @property
    def blocked(self) -> bool:
        """True when the winning action is ``block``."""
        return self.action is PolicyAction.BLOCK

    @property
    def allows_send(self) -> bool:
        """True when send is not hard-blocked by policy."""
        return self.action is not PolicyAction.BLOCK

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON ``policy_decision`` section."""
        return {
            "action": self.action.value,
            "blocked": self.blocked,
            "messages": list(self.messages),
            "winning_policy": (
                self.winning_policy.to_dict() if self.winning_policy else None
            ),
            "triggered_policies": [p.to_dict() for p in self.triggered_policies],
        }


class PolicyEngine:
    """Load and evaluate YAML policies against analysis results.

    Args:
        policies: Ordered list of :class:`Policy` instances.
    """

    def __init__(self, policies: Sequence[Policy] | None = None) -> None:
        self._policies: list[Policy] = list(policies or [])

    @property
    def policies(self) -> list[Policy]:
        """Copy of loaded policies."""
        return list(self._policies)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | list[Any] | None) -> PolicyEngine:
        """Build an engine from a parsed YAML/dict structure.

        Accepts either ``{\"policies\": [...]}`` or a bare list of policy maps.
        """
        if data is None:
            return cls([])
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            raw_list = data.get("policies", [])
        else:
            msg = f"Invalid policies root type: {type(data).__name__}"
            raise ValueError(msg)
        if raw_list is None:
            raw_list = []
        if not isinstance(raw_list, list):
            msg = "policies must be a list"
            raise ValueError(msg)
        policies = [_parse_policy(item) for item in raw_list]
        return cls(policies)

    @classmethod
    def from_yaml_file(cls, path: Path | str) -> PolicyEngine:
        """Load policies from an explicit YAML file path."""
        resolved = Path(path).expanduser().resolve()
        logger.info("Loading policies from %s", resolved)
        with resolved.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return cls.from_dict(data)

    @classmethod
    def load(cls, path: Path | str | None = None) -> PolicyEngine:
        """Load policies from ``path`` or default ``config/policies.yaml``.

        If no file is found and ``path`` is None, returns an empty engine
        (all decisions default to ``allow``).
        """
        if path is not None:
            return cls.from_yaml_file(path)

        for candidate in _DEFAULT_POLICY_CANDIDATES:
            try:
                resolved = candidate.expanduser().resolve()
            except OSError:
                continue
            if resolved.is_file():
                return cls.from_yaml_file(resolved)

        # Also try project root relative path
        root_candidate = project_root() / "config" / "policies.yaml"
        if root_candidate.is_file():
            return cls.from_yaml_file(root_candidate)

        logger.warning("No policies.yaml found; PolicyEngine has zero rules")
        return cls([])

    def evaluate(
        self,
        findings: Sequence[Finding],
        risk_score: int,
    ) -> PolicyDecision:
        """Evaluate all policies; resolve conflicts by priority then action rank.

        Args:
            findings: Findings from the analysis pipeline.
            risk_score: Numeric score from :class:`RiskScoringEngine`.

        Returns:
            A :class:`PolicyDecision`. When nothing triggers, ``action`` is
            :attr:`PolicyAction.ALLOW` with empty triggered lists.
        """
        findings_list = list(findings)
        triggered: list[Policy] = []
        for policy in self._policies:
            if self._matches(policy, findings_list, risk_score):
                logger.info(
                    "Policy triggered: id=%s action=%s priority=%d",
                    policy.id,
                    policy.action.value,
                    policy.priority,
                )
                triggered.append(policy)

        if not triggered:
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                triggered_policies=(),
                messages=(),
                winning_policy=None,
            )

        winning = max(
            triggered,
            key=lambda p: (p.priority, _ACTION_RANK[p.action.value]),
        )
        messages = tuple(p.message for p in triggered if p.message.strip())
        return PolicyDecision(
            action=winning.action,
            triggered_policies=tuple(triggered),
            messages=messages,
            winning_policy=winning,
        )

    def _matches(
        self,
        policy: Policy,
        findings: list[Finding],
        risk_score: int,
    ) -> bool:
        """Return True if all conditions of ``policy`` are satisfied (AND)."""
        conditions = policy.conditions or {}
        if not conditions:
            # Empty conditions never auto-fire (avoid accidental global block).
            return False

        finding_filters_present = any(
            key in conditions for key in ("category", "context", "keyword", "severity")
        )
        matched_findings = (
            _filter_findings(findings, conditions)
            if finding_filters_present
            else list(findings)
        )

        # Each finding-level key must be satisfied (AND).
        if "category" in conditions:
            wanted = _as_str_list(conditions["category"])
            if not any(f.category in wanted for f in findings):
                return False

        if "context" in conditions:
            context_wanted = {w.lower() for w in _as_str_list(conditions["context"])}
            if not _has_context_keywords(findings, context_wanted):
                return False

        if "keyword" in conditions:
            keyword_wanted = {w.lower() for w in _as_str_list(conditions["keyword"])}
            if not _has_blocked_keywords(findings, keyword_wanted):
                return False

        if "severity" in conditions:
            floor = _severity_floor(conditions["severity"])
            if not any(_SEVERITY_RANK.get(f.severity, 0) >= floor for f in findings):
                return False

        if "min_weight" in conditions:
            try:
                min_weight = int(conditions["min_weight"])
            except (TypeError, ValueError):
                min_weight = 0
            total = sum(f.weight for f in matched_findings)
            if total < min_weight:
                return False

        if "max_risk_score" in conditions:
            try:
                threshold = int(conditions["max_risk_score"])
            except (TypeError, ValueError):
                threshold = 100
            # Triggers when score *exceeds* the threshold.
            if risk_score <= threshold:
                return False

        return True


def _parse_policy(raw: Any) -> Policy:
    if not isinstance(raw, dict):
        msg = f"Policy entry must be a mapping, got {type(raw).__name__}"
        raise ValueError(msg)
    pid = str(raw.get("id", "")).strip()
    if not pid:
        msg = "Policy entry requires a non-empty 'id'"
        raise ValueError(msg)

    action_raw = str(raw.get("action", "warn")).strip().lower()
    if action_raw not in _ACTION_RANK:
        msg = f"Policy {pid}: invalid action {action_raw!r}"
        raise ValueError(msg)

    try:
        priority = int(raw.get("priority", 0))
    except (TypeError, ValueError):
        priority = 0

    conditions = raw.get("conditions") or {}
    if not isinstance(conditions, dict):
        msg = f"Policy {pid}: conditions must be a mapping"
        raise ValueError(msg)

    return Policy(
        id=pid,
        description=str(raw.get("description", "")),
        action=PolicyAction(action_raw),
        priority=priority,
        conditions=dict(conditions),
        message=str(raw.get("message", "")),
    )


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    return [text] if text else []


def _severity_floor(value: Any) -> int:
    key = str(value).strip().lower()
    return _SEVERITY_FLOOR.get(key, 1)


def _context_terms(finding: Finding) -> set[str]:
    terms: set[str] = set()
    if finding.category == "context":
        kw = finding.metadata.get("keyword")
        if kw:
            terms.add(str(kw).lower())
        terms.add(finding.matched_text.lower())
    return terms


def _keyword_terms(finding: Finding) -> set[str]:
    terms: set[str] = set()
    if finding.category == "keyword":
        kw = finding.metadata.get("keyword")
        if kw:
            terms.add(str(kw).lower())
        terms.add(finding.matched_text.lower())
    return terms


def _has_context_keywords(findings: Iterable[Finding], wanted: set[str]) -> bool:
    found: set[str] = set()
    for finding in findings:
        found |= _context_terms(finding)
    return bool(found & wanted)


def _has_blocked_keywords(findings: Iterable[Finding], wanted: set[str]) -> bool:
    found: set[str] = set()
    for finding in findings:
        found |= _keyword_terms(finding)
    return bool(found & wanted)


def _filter_findings(
    findings: list[Finding],
    conditions: dict[str, Any],
) -> list[Finding]:
    """Findings that satisfy category/context/keyword/severity filters (AND)."""
    result = list(findings)

    if "category" in conditions:
        wanted = set(_as_str_list(conditions["category"]))
        result = [f for f in result if f.category in wanted]

    if "context" in conditions:
        wanted = {w.lower() for w in _as_str_list(conditions["context"])}
        result = [
            f
            for f in result
            if f.category == "context" and (_context_terms(f) & wanted)
        ]

    if "keyword" in conditions:
        wanted = {w.lower() for w in _as_str_list(conditions["keyword"])}
        result = [
            f
            for f in result
            if f.category == "keyword" and (_keyword_terms(f) & wanted)
        ]

    if "severity" in conditions:
        floor = _severity_floor(conditions["severity"])
        result = [f for f in result if _SEVERITY_RANK.get(f.severity, 0) >= floor]

    return result
