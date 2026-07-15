"""Shared pytest fixtures for PromptShield tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from promptshield.pipeline import AnalysisPipeline
from promptshield.plugin_loader import PluginLoader
from promptshield.scoring import RiskScoringEngine


@pytest.fixture
def project_root() -> Path:
    """Repository root (parent of tests/)."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def plugins_dir(project_root: Path) -> Path:
    """Path to the demo plugins directory."""
    return project_root / "plugins"


@pytest.fixture
def rules_path(project_root: Path) -> Path:
    """Path to the default rules.yaml."""
    return project_root / "config" / "rules.yaml"


@pytest.fixture
def sample_rules() -> dict[str, Any]:
    """Minimal in-memory rules configuration for unit tests.

    Empty ``context_risk_keywords`` disables ContextDetector matches so
    legacy pipeline score assertions stay stable.
    """
    return {
        "blocked_keywords": ["payroll", "acquisition", "customer_db"],
        "context_risk_keywords": {},
    }


@pytest.fixture
def scoring_engine() -> RiskScoringEngine:
    """Default risk scoring engine."""
    return RiskScoringEngine()


@pytest.fixture
def pipeline(
    plugins_dir: Path,
    sample_rules: dict[str, Any],
    scoring_engine: RiskScoringEngine,
) -> AnalysisPipeline:
    """Fully wired pipeline with demo plugins and sample rules."""
    loader = PluginLoader(plugins_dir, config=sample_rules)
    detectors = loader.load()
    return AnalysisPipeline(detectors=detectors, scoring_engine=scoring_engine)
