"""Automatic discovery and loading of detector plugins.

Plugins are Python modules living under a ``plugins/`` directory. Any class
that subclasses :class:`~promptshield.base_detector.BaseDetector` (and is not
abstract) is instantiated, configured, and returned.

This approach keeps the foundation free of entry-point boilerplate while
remaining compatible with future setuptools entry-point registration.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from promptshield.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class PluginLoader:
    """Discover, import, and configure detector plugins from a directory.

    Args:
        plugins_dir: Directory containing detector modules (``*.py``).
        config: Shared configuration dict passed to each detector's
            :meth:`~promptshield.base_detector.BaseDetector.configure`.
    """

    def __init__(
        self,
        plugins_dir: Path | str,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._plugins_dir = Path(plugins_dir).expanduser().resolve()
        self._config: dict[str, Any] = config if config is not None else {}

    @property
    def plugins_dir(self) -> Path:
        """Absolute path to the plugins directory."""
        return self._plugins_dir

    def load(self) -> list[BaseDetector]:
        """Load all concrete :class:`BaseDetector` subclasses found.

        Returns:
            Instantiated and configured detectors, sorted by ``name`` for
            deterministic pipeline order.

        Raises:
            FileNotFoundError: If ``plugins_dir`` does not exist.
        """
        if not self._plugins_dir.is_dir():
            msg = f"Plugins directory not found: {self._plugins_dir}"
            raise FileNotFoundError(msg)

        detectors: list[BaseDetector] = []
        module_paths = sorted(self._plugins_dir.glob("*.py"))
        for module_path in module_paths:
            if module_path.name.startswith("_"):
                continue
            module = self._import_module(module_path)
            for cls in self._iter_detector_classes(module):
                instance = cls()
                instance.configure(self._config)
                logger.info("Loaded detector plugin: %s", instance.name)
                detectors.append(instance)

        detectors.sort(key=lambda d: d.name)
        if not detectors:
            logger.warning("No detector plugins discovered in %s", self._plugins_dir)
        return detectors

    def _import_module(self, module_path: Path) -> ModuleType:
        """Import a plugin file as a uniquely named module."""
        module_name = f"promptshield_plugins.{module_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            msg = f"Cannot create import spec for {module_path}"
            raise ImportError(msg)

        module = importlib.util.module_from_spec(spec)
        # Register before exec so relative patterns / pickling work if needed.
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _iter_detector_classes(module: ModuleType) -> list[type[BaseDetector]]:
        """Yield concrete BaseDetector subclasses defined in ``module``."""
        found: list[type[BaseDetector]] = []
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj is BaseDetector:
                continue
            if not issubclass(obj, BaseDetector):
                continue
            if inspect.isabstract(obj):
                continue
            # Only classes defined in this module (skip re-exports).
            if obj.__module__ != module.__name__:
                continue
            found.append(obj)
        return found
