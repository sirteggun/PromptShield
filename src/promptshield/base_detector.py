"""Abstract base for detector plugins.

Every detector must subclass :class:`BaseDetector` and implement
:meth:`BaseDetector.analyze`. Optional lifecycle hooks
(:meth:`configure`, :meth:`name`) support dependency injection of
configuration without hard-coding paths inside plugins.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from promptshield.finding import Finding


class BaseDetector(ABC):
    """Common interface for PromptShield detector plugins.

    Implementations should be side-effect free during :meth:`analyze` so that
    the pipeline can safely run detectors in sequence (or later in parallel).

    Example:
        >>> class MyDetector(BaseDetector):
        ...     @property
        ...     def name(self) -> str:
        ...         return "my_detector"
        ...
        ...     def analyze(self, prompt: str) -> list[Finding]:
        ...         return []
    """

    @property
    def name(self) -> str:
        """Stable short identifier for this detector.

        Defaults to the class name. Override for a stable public name that
        does not change if the class is renamed for refactoring.
        """
        return type(self).__name__

    def configure(self, config: dict[str, Any]) -> None:
        """Inject runtime configuration after construction.

        The plugin loader calls this with a shared configuration dictionary
        (e.g. contents derived from ``rules.yaml``). Detectors that do not
        need configuration can ignore this hook.

        Args:
            config: Arbitrary configuration mapping. Structure is defined by
                the application and individual detectors.
        """
        return None

    @abstractmethod
    def analyze(self, prompt: str) -> list[Finding]:
        """Analyze a prompt and return zero or more findings.

        Args:
            prompt: Raw user prompt text (may be multi-line).

        Returns:
            A list of :class:`~promptshield.finding.Finding` instances. An
            empty list means no issues were detected by this plugin.
        """
        raise NotImplementedError
