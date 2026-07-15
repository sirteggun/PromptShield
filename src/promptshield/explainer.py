"""Risk explainer — natural-language summary over detection + policy results.

Read-only: consumes findings, risk score, policy decision, and prompt labels.
Never mutates findings, scores, or policy decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from promptshield.classifier import PromptLabel
from promptshield.finding import Finding, Severity
from promptshield.policy_engine import PolicyAction, PolicyDecision
from promptshield.sanitizer import PromptSanitizer


@dataclass(frozen=True, slots=True)
class RiskExplanation:
    """Human-readable risk narrative and recommended next step.

    Attributes:
        summary: Short natural-language explanation.
        risk_factors: Bullet reasons contributing to risk.
        safe_after_sanitization: True if sanitizing would remove all
            high/critical findings (and no residual secrets).
        recommended_action: One of BLOCK, SANITIZE, REVIEW, ALLOW.
    """

    summary: str
    risk_factors: list[str] = field(default_factory=list)
    safe_after_sanitization: bool = False
    recommended_action: str = "ALLOW"

    def to_dict(self) -> dict[str, object]:
        """Serialize for JSON intelligence output."""
        return {
            "summary": self.summary,
            "risk_factors": list(self.risk_factors),
            "safe_after_sanitization": self.safe_after_sanitization,
            "recommended_action": self.recommended_action,
        }


_CRITICAL_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})


def _categories(findings: Sequence[Finding]) -> set[str]:
    return {f.category for f in findings if f.category}


def _has_context(findings: Sequence[Finding], term: str) -> bool:
    term_l = term.lower()
    for finding in findings:
        if finding.category != "context":
            continue
        kw = str(finding.metadata.get("keyword", "")).lower()
        preview = finding.matched_text_preview().lower()
        if term_l in kw or term_l in preview:
            return True
    return False


def _primary_label(labels: Sequence[PromptLabel]) -> str:
    if not labels:
        return "unknown"
    return labels[0].label


def _collect_risk_factors(
    findings: Sequence[Finding],
    policy_decision: PolicyDecision,
    prompt_labels: Sequence[PromptLabel],
) -> list[str]:
    factors: list[str] = []
    for finding in findings:
        if finding.category == "secret":
            factors.append(
                f"Segreto rilevato da {finding.detector_name} "
                f"({finding.matched_text_preview()})"
            )
        elif finding.category == "pii":
            preview = finding.matched_text_preview()
            token = finding.replacement_token or "<REDACTED>"
            factors.append(f"Dato personale (PII): {preview or token}")
        elif finding.category == "context":
            kw = finding.metadata.get("keyword") or finding.matched_text_preview()
            factors.append(f"Contesto a rischio: '{kw}'")
        elif finding.category == "keyword":
            kw = finding.metadata.get("keyword") or finding.matched_text_preview()
            factors.append(f"Parola chiave bloccata: '{kw}'")
        elif finding.category == "infrastructure":
            factors.append(
                f"Infrastruttura: {finding.detector_name} "
                f"({finding.matched_text_preview()})"
            )
        else:
            factors.append(finding.message)

    for policy in policy_decision.triggered_policies:
        factors.append(f"Policy '{policy.id}': {policy.message or policy.action.value}")

    top = _primary_label(prompt_labels)
    if top and top != "unknown":
        factors.append(f"Classificazione contenuto: {top}")

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for item in factors:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def compute_safe_after_sanitization(
    findings: Sequence[Finding],
    *,
    original_prompt: str | None = None,
) -> bool:
    """Return True if sanitization would neutralize high/critical findings.

    Heuristic (no re-detection): every finding with severity HIGH/CRITICAL
    must have a non-empty ``replacement_token``. Remaining findings may be
    lower severity (info/medium keyword noise).
    """
    critical = [f for f in findings if f.severity in _CRITICAL_SEVERITIES]
    if not critical:
        # Also treat category secret as critical for sanitization safety
        critical = [f for f in findings if f.category == "secret"]
    if not critical:
        return True
    return all(bool(f.replacement_token) for f in critical)


def _recommended_action(
    findings: Sequence[Finding],
    risk_score: int,
    policy_decision: PolicyDecision,
    safe_after: bool,
) -> str:
    """Select recommended action with absolute policy priority."""
    # 1) Policy BLOCK → always BLOCK
    if policy_decision.action is PolicyAction.BLOCK:
        return "BLOCK"

    cats = _categories(findings)
    has_secret = "secret" in cats
    has_pii = "pii" in cats

    # 2) Policy WARN → never ALLOW
    if policy_decision.action is PolicyAction.WARN:
        if has_secret and safe_after:
            return "SANITIZE"
        if risk_score >= 51 or has_secret:
            return "SANITIZE" if safe_after else "REVIEW"
        return "REVIEW"

    # 3) No blocking/warn policy (or explicit allow): use score + severity
    if not findings:
        return "ALLOW"

    if has_secret:
        return "SANITIZE" if safe_after else "BLOCK"

    if risk_score >= 51:
        return "SANITIZE" if safe_after else "REVIEW"

    if has_pii or risk_score >= 21:
        return "REVIEW"

    return "ALLOW"


def _build_summary(
    findings: Sequence[Finding],
    risk_score: int,
    policy_decision: PolicyDecision,
    prompt_labels: Sequence[PromptLabel],
    action: str,
) -> str:
    cats = _categories(findings)
    label = _primary_label(prompt_labels)
    parts: list[str] = []

    if "secret" in cats:
        parts.append("Il prompt contiene credenziali o segreti")
    if "pii" in cats:
        parts.append("contiene dati personali (PII)")
    if _has_context(findings, "production"):
        parts.append("menziona l'ambiente di produzione")
    if _has_context(findings, "financial"):
        parts.append("si colloca in un contesto finanziario")
    if "keyword" in cats:
        parts.append("include parole chiave di policy interna")

    if not parts and findings:
        parts.append(
            f"Il prompt ha generato {len(findings)} finding "
            f"(risk score {risk_score}/100)"
        )
    elif not parts:
        parts.append("Nessun contenuto sensibile rilevato nel prompt")

    # Classification flavour
    label_hints = {
        "source_code": "Sembra codice sorgente.",
        "config_file": "Sembra un file di configurazione.",
        "log_output": "Sembra un estratto di log.",
        "database_dump": "Sembra un dump o export di database.",
        "email_conversation": "Sembra una conversazione email.",
        "generic_document": "Sembra un documento di testo generico.",
        "unknown": "",
    }
    flavour = label_hints.get(label, "")
    if flavour:
        parts.append(flavour.rstrip("."))

    if policy_decision.winning_policy is not None:
        parts.append(
            f"Policy '{policy_decision.winning_policy.id}' → "
            f"{policy_decision.action.value}"
        )

    core = ". ".join(p[0].upper() + p[1:] if p else p for p in parts if p)
    if not core.endswith("."):
        core += "."
    return f"{core} Azione consigliata: {action}."


def explain_risk(
    findings: list[Finding] | Sequence[Finding],
    risk_score: int,
    policy_decision: PolicyDecision,
    prompt_labels: list[PromptLabel] | Sequence[PromptLabel],
    *,
    original_prompt: str | None = None,
) -> RiskExplanation:
    """Build a :class:`RiskExplanation` from analysis artifacts.

    Policy decision has absolute priority over score-based recommendations.

    Args:
        findings: Detection findings (not modified).
        risk_score: Score from RiskScoringEngine.
        policy_decision: Decision from PolicyEngine.
        prompt_labels: Labels from PromptClassifier.
        original_prompt: Optional; reserved for future sanitizer dry-runs.

    Returns:
        Immutable risk explanation.
    """
    findings_list = list(findings)
    labels_list = list(prompt_labels)

    safe_after = compute_safe_after_sanitization(
        findings_list, original_prompt=original_prompt
    )
    # Optional: if prompt given, verify sanitizer leaves no secret spans
    # structurally (tokens present). Does not re-run detectors.
    if original_prompt is not None and findings_list:
        try:
            san = PromptSanitizer().sanitize(original_prompt, findings_list)
            # Safe if all high/critical findings were applied as replacements
            critical = [
                f
                for f in findings_list
                if f.severity in _CRITICAL_SEVERITIES or f.category == "secret"
            ]
            if critical:
                # Fallback: compare by span
                applied_spans = {
                    (f.start_position, f.end_position) for f in san.replaced_findings
                }
                safe_after = all(
                    (f.start_position, f.end_position) in applied_spans
                    for f in critical
                    if f.replacement_token
                ) and all(bool(f.replacement_token) for f in critical)
            else:
                safe_after = True
        except Exception:
            pass

    action = _recommended_action(findings_list, risk_score, policy_decision, safe_after)
    # Enforce policy constraints (defence in depth)
    if policy_decision.action is PolicyAction.BLOCK:
        action = "BLOCK"
    elif policy_decision.action is PolicyAction.WARN and action == "ALLOW":
        action = "REVIEW"

    factors = _collect_risk_factors(findings_list, policy_decision, labels_list)
    summary = _build_summary(
        findings_list, risk_score, policy_decision, labels_list, action
    )

    return RiskExplanation(
        summary=summary,
        risk_factors=factors,
        safe_after_sanitization=safe_after,
        recommended_action=action,
    )
