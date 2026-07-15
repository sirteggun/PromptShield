"""Configuration loading for PromptShield.

Loads YAML rule files (e.g. ``blocked_keywords``) and exposes them as plain
dictionaries suitable for injection into detector plugins.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def _packaged_config_dir() -> Path:
    """Config shipped inside the installed package (wheel/sdist)."""
    return Path(__file__).resolve().parent / "resources" / "config"


# Default search order for rules.yaml when no explicit path is given.
_DEFAULT_RULE_CANDIDATES: tuple[Path, ...] = (
    Path("config/rules.yaml"),
    Path(__file__).resolve().parents[2] / "config" / "rules.yaml",
    Path.cwd() / "config" / "rules.yaml",
    _packaged_config_dir() / "rules.yaml",
)


def load_rules(path: Path | str | None = None) -> dict[str, Any]:
    """Load detector rules from a YAML file.

    Args:
        path: Explicit path to ``rules.yaml``. If ``None``, common project
            locations are tried. If no file is found, an empty configuration
            with an empty ``blocked_keywords`` list is returned.

    Returns:
        Parsed YAML mapping. Always includes at least
        ``blocked_keywords: list[str]`` (possibly empty).

    Raises:
        ValueError: If the YAML root is not a mapping.
        OSError: If an explicit path is given but cannot be read.
    """
    rules_path = _resolve_rules_path(path)
    if rules_path is None:
        logger.warning("No rules.yaml found; using empty configuration")
        return {"blocked_keywords": []}

    logger.info("Loading rules from %s", rules_path)
    with rules_path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if data is None:
        data = {}
    if not isinstance(data, dict):
        msg = f"rules.yaml root must be a mapping, got {type(data).__name__}"
        raise ValueError(msg)

    keywords = data.get("blocked_keywords", [])
    if keywords is None:
        keywords = []
    if not isinstance(keywords, list):
        msg = "blocked_keywords must be a list of strings"
        raise ValueError(msg)
    data["blocked_keywords"] = [str(item) for item in keywords]

    # Normalize context_risk_keywords to dict[str, int] (list form → weight 10).
    data["context_risk_keywords"] = _normalize_context_keywords(
        data.get("context_risk_keywords")
    )
    return data


def _normalize_context_keywords(raw: Any) -> dict[str, int]:
    """Convert list or mapping YAML forms to keyword → weight."""
    default_weight = 10
    if raw is None:
        return {}
    if isinstance(raw, dict):
        result: dict[str, int] = {}
        for key, value in raw.items():
            keyword = str(key).strip()
            if not keyword:
                continue
            if value is None or value == "":
                result[keyword] = default_weight
            else:
                try:
                    result[keyword] = int(value)
                except (TypeError, ValueError):
                    result[keyword] = default_weight
        return result
    if isinstance(raw, list):
        return {str(item).strip(): default_weight for item in raw if str(item).strip()}
    return {}


def _resolve_rules_path(path: Path | str | None) -> Path | None:
    if path is not None:
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            msg = f"Rules file not found: {resolved}"
            raise FileNotFoundError(msg)
        return resolved

    for candidate in _DEFAULT_RULE_CANDIDATES:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    return None


def project_root() -> Path:
    """Return the repository root when running from a source checkout.

    Falls back to the current working directory when the package is installed
    without the adjacent ``config/`` and ``plugins/`` trees.
    """
    # src/promptshield/config.py -> parents[2] == project root
    candidate = Path(__file__).resolve().parents[2]
    if (candidate / "plugins").is_dir() or (candidate / "config").is_dir():
        return candidate
    return Path.cwd()


def packaged_plugins_dir() -> Path:
    """Detector plugins shipped inside the installed package."""
    return Path(__file__).resolve().parent / "resources" / "plugins"


def packaged_config_dir() -> Path:
    """YAML config shipped inside the installed package."""
    return _packaged_config_dir()
