"""Simple composition root (manual dependency injection).

Builds a fully wired :class:`~promptshield.pipeline.AnalysisPipeline` from
filesystem paths and configuration, without a heavy DI framework.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from collections.abc import Callable

from promptshield.config import load_rules, packaged_plugins_dir, project_root
from promptshield.pipeline import AnalysisPipeline
from promptshield.plugin_loader import PluginLoader
from promptshield.policy_engine import PolicyEngine
from promptshield.sanitizer import PromptSanitizer
from promptshield.scoring import RiskScoringEngine
from promptshield.service import PromptShieldService

logger = logging.getLogger(__name__)


def build_pipeline(
    *,
    rules_path: Path | str | None = None,
    plugins_dir: Path | str | None = None,
    scoring_engine: RiskScoringEngine | None = None,
    extra_config: dict[str, Any] | None = None,
) -> AnalysisPipeline:
    """Compose rules, plugins, scoring engine, and pipeline.

    Args:
        rules_path: Optional path to ``rules.yaml``.
        plugins_dir: Optional plugins directory. Defaults to ``<root>/plugins``.
        scoring_engine: Optional custom scoring engine.
        extra_config: Extra keys merged into the config passed to plugins.

    Returns:
        A ready-to-use :class:`AnalysisPipeline`.
    """
    root = project_root()
    config = load_rules(rules_path)
    if extra_config:
        config = {**config, **extra_config}

    if plugins_dir is not None:
        resolved_plugins = Path(plugins_dir).expanduser().resolve()
    else:
        checkout_plugins = (root / "plugins").resolve()
        resolved_plugins = (
            checkout_plugins
            if checkout_plugins.is_dir()
            else packaged_plugins_dir().resolve()
        )
    logger.debug("Using plugins directory: %s", resolved_plugins)

    loader = PluginLoader(resolved_plugins, config=config)
    detectors = loader.load()
    engine = scoring_engine or RiskScoringEngine()
    return AnalysisPipeline(detectors=detectors, scoring_engine=engine)


def build_sanitizer() -> PromptSanitizer:
    """Return a :class:`PromptSanitizer` instance (composition helper)."""
    return PromptSanitizer()


def build_policy_engine(
    policy_file: Path | str | None = None,
) -> PolicyEngine:
    """Load a :class:`PolicyEngine` from YAML (default ``config/policies.yaml``).

    Args:
        policy_file: Optional explicit path to ``policies.yaml``.
    """
    return PolicyEngine.load(policy_file)


def build_service(
    *,
    rules_path: Path | str | None = None,
    plugins_dir: Path | str | None = None,
    policy_file: Path | str | None = None,
    scoring_engine: RiskScoringEngine | None = None,
    extra_config: dict[str, Any] | None = None,
    enable_persistence: bool = False,
    database_url: str | None = None,
) -> PromptShieldService:
    """Compose a fully wired :class:`PromptShieldService`.

    Args:
        rules_path: Optional path to ``rules.yaml``.
        plugins_dir: Optional plugins directory.
        policy_file: Optional path to ``policies.yaml``.
        scoring_engine: Optional custom scoring engine.
        extra_config: Extra config keys for detectors.
        enable_persistence: When True, attach a SQLAlchemy UnitOfWork factory
            (API default). CLI leaves this False.
        database_url: Optional override for ``DATABASE_URL``.
    """
    pipeline = build_pipeline(
        rules_path=rules_path,
        plugins_dir=plugins_dir,
        scoring_engine=scoring_engine,
        extra_config=extra_config,
    )
    policy_engine = build_policy_engine(policy_file)
    uow_factory: Callable[[], Any] | None = None
    if enable_persistence:
        from promptshield.persistence.database import get_session_factory, init_db
        from promptshield.persistence.unit_of_work import SqlAlchemyUnitOfWork

        init_db(database_url)
        factory = get_session_factory(database_url)

        def _make_uow() -> SqlAlchemyUnitOfWork:
            return SqlAlchemyUnitOfWork(factory)

        uow_factory = _make_uow

    return PromptShieldService(
        pipeline=pipeline,
        policy_engine=policy_engine,
        sanitizer=build_sanitizer(),
        uow_factory=uow_factory,
    )
