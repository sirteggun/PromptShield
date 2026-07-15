"""PromptShield — firewall for prompts sent to Large Language Models.

This package provides a modular analysis pipeline: detectors (plugins) inspect
user prompts, produce :class:`~promptshield.finding.Finding` objects, and a
risk-scoring engine maps them to a 0–100 score and traffic-light band.
"""

from promptshield._version import __version__
from promptshield.breakdown import (
    CategoryBreakdown,
    RiskBreakdown,
    generate_risk_breakdown,
)
from promptshield.classifier import PromptClassifier, PromptLabel
from promptshield.client import PromptShieldClient
from promptshield.explainer import RiskExplanation, explain_risk
from promptshield.finding import Finding, Severity
from promptshield.pipeline import AnalysisPipeline, AnalysisResult
from promptshield.policy_engine import (
    Policy,
    PolicyAction,
    PolicyDecision,
    PolicyEngine,
)
from promptshield.sanitizer import PromptSanitizer, SanitizationResult
from promptshield.scoring import RiskBand, RiskScore, RiskScoringEngine
from promptshield.service import PromptShieldService

__all__ = [
    "AnalysisPipeline",
    "AnalysisResult",
    "CategoryBreakdown",
    "Finding",
    "Policy",
    "PolicyAction",
    "PolicyDecision",
    "PolicyEngine",
    "PromptClassifier",
    "PromptLabel",
    "PromptShieldClient",
    "PromptShieldService",
    "PromptSanitizer",
    "RiskBand",
    "RiskBreakdown",
    "RiskExplanation",
    "RiskScore",
    "RiskScoringEngine",
    "SanitizationResult",
    "Severity",
    "explain_risk",
    "generate_risk_breakdown",
    "__version__",
]
