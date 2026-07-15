"""Application service layer — shared business logic for CLI and API.

:class:`PromptShieldService` orchestrates pipeline, policy, sanitizer,
classifier, and explainer without coupling to a specific transport (CLI/HTTP).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from promptshield._version import __version__ as _MODULE_VERSION
from promptshield.breakdown import RiskBreakdown, generate_risk_breakdown
from promptshield.classifier import PromptClassifier, PromptLabel
from promptshield.explainer import RiskExplanation, explain_risk
from promptshield.finding import Finding
from promptshield.pipeline import AnalysisPipeline, AnalysisResult
from promptshield.policy_engine import PolicyAction, PolicyDecision, PolicyEngine
from promptshield.sanitizer import PromptSanitizer, SanitizationResult
from promptshield.scoring import RiskBand

logger = logging.getLogger(__name__)

_BAND_JSON: dict[RiskBand, str] = {
    RiskBand.GREEN: "GREEN",
    RiskBand.YELLOW: "YELLOW",
    RiskBand.RED: "RED",
}


def _package_version() -> str:
    """Single source of truth: ``promptshield._version.__version__``."""
    return _MODULE_VERSION


def compute_risk_exit_code(result: AnalysisResult) -> int:
    """Risk-only exit code (0 green / 1 yellow / 2 red or critical)."""
    from promptshield.finding import Severity

    if any(f.severity == Severity.CRITICAL for f in result.findings):
        return 2
    if result.risk.band == RiskBand.RED:
        return 2
    if result.risk.band == RiskBand.YELLOW:
        return 1
    return 0


def compute_final_exit_code(
    result: AnalysisResult,
    decision: PolicyDecision,
) -> int:
    """Combine risk exit code with policy decision."""
    if decision.action is PolicyAction.BLOCK:
        return 2
    risk_exit = compute_risk_exit_code(result)
    if decision.action is PolicyAction.WARN and decision.triggered_policies:
        return max(risk_exit, 1)
    return risk_exit


def _redact_prompt_for_report(prompt: str, findings: list[Finding]) -> str:
    secret_findings = [f for f in findings if f.category == "secret"]
    if not secret_findings:
        return prompt
    return PromptSanitizer().sanitize(prompt, secret_findings).sanitized_prompt


@dataclass
class ServiceAnalysisResult:
    """Full analysis outcome for CLI / API consumers."""

    analysis: AnalysisResult
    decision: PolicyDecision
    breakdown: RiskBreakdown
    exit_code: int
    duration_ms: float = 0.0
    sanitization: SanitizationResult | None = None
    labels: list[PromptLabel] = field(default_factory=list)
    explanation: RiskExplanation | None = None
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        return list(self.analysis.findings)

    @property
    def risk_score(self) -> int:
        return self.analysis.risk.score

    @property
    def blocked(self) -> bool:
        return self.decision.blocked

    def to_report_dict(self, *, request_id: str | None = None) -> dict[str, Any]:
        """Build the standard JSON report (same shape as CLI ``--json``)."""
        findings_list = self.findings
        safe_prompt = _redact_prompt_for_report(self.analysis.prompt, findings_list)

        analysis_body: dict[str, Any] = {
            "prompt": safe_prompt,
            "findings": [f.to_dict(redact=True) for f in findings_list],
            "risk_score": self.analysis.risk.score,
            "risk_level": _BAND_JSON[self.analysis.risk.band],
            "breakdown": self.breakdown.to_dict(),
            "policy_decision": self.decision.to_dict(),
            "exit_code": self.exit_code,
        }

        if self.sanitization is not None:
            analysis_body["sanitized_prompt"] = self.sanitization.sanitized_prompt
            analysis_body["sanitization"] = self.sanitization.to_dict(redact=True)
        elif self.options.get("sanitize"):
            analysis_body["sanitized_prompt"] = None
            analysis_body["sanitization"] = None

        if self.explanation is not None:
            analysis_body["intelligence"] = {
                "classification": [lab.to_dict() for lab in self.labels],
                "explanation": self.explanation.to_dict(),
            }

        report: dict[str, Any] = {
            "tool": "PromptShield",
            "version": _package_version(),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "analysis": analysis_body,
        }
        if request_id is not None:
            report["request_id"] = request_id
        return report


class PromptShieldService:
    """Facade over pipeline, policy, sanitizer, and intelligence modules.

    Args:
        pipeline: Configured analysis pipeline.
        policy_engine: Policy evaluation engine.
        sanitizer: Prompt sanitizer instance.
        classifier: Optional classifier (created lazily if omitted).
        uow_factory: Optional callable returning a :class:`UnitOfWork`
            context manager. When set, each ``analyze``/``sanitize`` is
            persisted with audit events. CLI leaves this ``None``.
    """

    def __init__(
        self,
        pipeline: AnalysisPipeline,
        policy_engine: PolicyEngine,
        sanitizer: PromptSanitizer | None = None,
        classifier: PromptClassifier | None = None,
        uow_factory: Any | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._policy_engine = policy_engine
        self._sanitizer = sanitizer or PromptSanitizer()
        self._classifier = classifier or PromptClassifier()
        self._uow_factory = uow_factory

    @property
    def pipeline(self) -> AnalysisPipeline:
        return self._pipeline

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    @property
    def sanitizer(self) -> PromptSanitizer:
        return self._sanitizer

    @property
    def detector_count(self) -> int:
        return len(self._pipeline.detectors)

    def analyze(
        self,
        prompt: str,
        options: dict[str, Any] | None = None,
    ) -> ServiceAnalysisResult:
        """Run full analysis (detect → score → policy → optional sanitize/explain).

        Options keys:
            * ``sanitize`` (bool): run sanitizer when policy allows send
            * ``explain`` (bool): run classifier + explainer
            * ``force_sanitize`` (bool): sanitize even if policy blocks
              (API sanitize endpoint uses True)
            * ``request_id``, ``tenant_id``, ``organization_id``
            * ``api_key``, ``client_ip``, ``user_agent`` (audit metadata)
            * ``persist`` (bool): force/disable persistence for this call

        Returns:
            :class:`ServiceAnalysisResult` with all artifacts.
        """
        opts = dict(options or {})
        t0 = time.perf_counter()

        analysis = self._pipeline.analyze(prompt)
        findings = list(analysis.findings)
        breakdown = generate_risk_breakdown(findings, max_score=100)
        decision = self._policy_engine.evaluate(findings, analysis.risk.score)
        exit_code = compute_final_exit_code(analysis, decision)

        sanitization: SanitizationResult | None = None
        want_sanitize = bool(opts.get("sanitize") or opts.get("force_sanitize"))
        if want_sanitize:
            if decision.allows_send or opts.get("force_sanitize"):
                sanitization = self._sanitizer.sanitize(prompt, findings)

        labels: list[PromptLabel] = []
        explanation: RiskExplanation | None = None
        if opts.get("explain"):
            labels = self._classifier.classify(prompt)
            explanation = explain_risk(
                findings,
                analysis.risk.score,
                decision,
                labels,
                original_prompt=prompt,
            )

        duration_ms = (time.perf_counter() - t0) * 1000.0
        logger.info(
            "analysis_completed risk_score=%s finding_count=%s duration_ms=%.1f "
            "policy=%s",
            analysis.risk.score,
            len(findings),
            duration_ms,
            decision.action.value,
        )

        outcome = ServiceAnalysisResult(
            analysis=analysis,
            decision=decision,
            breakdown=breakdown,
            exit_code=exit_code,
            duration_ms=duration_ms,
            sanitization=sanitization,
            labels=labels,
            explanation=explanation,
            options=opts,
        )
        self._maybe_persist(outcome, opts)
        return outcome

    def _maybe_persist(
        self,
        outcome: ServiceAnalysisResult,
        opts: dict[str, Any],
    ) -> None:
        """Persist analysis when a unit-of-work factory is configured."""
        if self._uow_factory is None:
            return
        if opts.get("persist") is False:
            return
        try:
            from promptshield.persistence.recorder import persist_analysis
            from promptshield.persistence.usage import track_usage

            org_id = opts.get("organization_id")
            tenant = str(opts.get("tenant_id") or org_id or "default")
            with self._uow_factory() as uow:
                analysis_row = persist_analysis(
                    uow,
                    outcome,
                    tenant_id=tenant,
                    organization_id=org_id,
                    request_id=str(opts.get("request_id") or ""),
                    api_key=opts.get("api_key"),
                    client_ip=opts.get("client_ip"),
                    user_agent=opts.get("user_agent"),
                )
                track_usage(uow, org_id, outcome)
                uow.commit()
                # Attach id for API consumers without breaking public shape
                outcome.options["analysis_id"] = str(analysis_row.id)
        except Exception:
            logger.exception("Failed to persist analysis (non-fatal for caller)")

    def analyze_dict(
        self,
        prompt: str,
        options: dict[str, Any] | None = None,
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Convenience wrapper returning the JSON report dictionary."""
        return self.analyze(prompt, options).to_report_dict(request_id=request_id)

    def sanitize(
        self,
        prompt: str,
        *,
        policy_file: str | Path | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Analyze then sanitize (forced), returning a sanitization-focused dict.

        ``policy_file`` is accepted for API symmetry; reloading policies mid-request
        is only applied when a new engine is injected via factory.
        """
        del policy_file  # engine is fixed at construction; reserved for future
        opts: dict[str, Any] = {"force_sanitize": True, "sanitize": True}
        if request_id is not None:
            opts["request_id"] = request_id
        # Allow callers to pass audit context via kwargs-like options later
        outcome = self.analyze(prompt, opts)
        san = outcome.sanitization
        if san is None:
            san = self._sanitizer.sanitize(prompt, outcome.findings)

        payload: dict[str, Any] = {
            "tool": "PromptShield",
            "version": _package_version(),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "original_prompt_redacted": _redact_prompt_for_report(
                prompt, outcome.findings
            ),
            "sanitized_prompt": san.sanitized_prompt,
            "replacements": san.replacements,
            "skipped": san.skipped,
            "sanitization": san.to_dict(redact=True),
            "risk_score": outcome.risk_score,
            "risk_level": _BAND_JSON[outcome.analysis.risk.band],
            "policy_decision": outcome.decision.to_dict(),
            "exit_code": outcome.exit_code,
            "duration_ms": round(outcome.duration_ms, 2),
        }
        if request_id is not None:
            payload["request_id"] = request_id
        if outcome.options.get("analysis_id"):
            payload["analysis_id"] = outcome.options["analysis_id"]
        logger.info(
            "sanitization_completed replacements=%s skipped=%s duration_ms=%.1f",
            san.replacements,
            san.skipped,
            outcome.duration_ms,
        )
        return payload

    def explain(
        self,
        findings: list[Finding],
        risk_score: int,
        policy_decision: PolicyDecision,
        prompt_labels: list[PromptLabel] | None = None,
        *,
        original_prompt: str | None = None,
    ) -> dict[str, Any]:
        """Generate a risk explanation dictionary (read-only)."""
        labels = prompt_labels if prompt_labels is not None else []
        explanation = explain_risk(
            findings,
            risk_score,
            policy_decision,
            labels,
            original_prompt=original_prompt,
        )
        return explanation.to_dict()

    def health(self) -> dict[str, Any]:
        """Health payload for API/CLI checks."""
        return {
            "status": "ok",
            "version": _package_version(),
            "detectors": self.detector_count,
            "policies": len(self._policy_engine.policies),
        }
