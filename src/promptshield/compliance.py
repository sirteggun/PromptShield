"""Compliance framework mapping — independent of detectors and analysis.

Maps finding categories to high-level regulatory / control frameworks for
reporting. Intentionally static for now; designed so a future YAML loader can
replace :data:`CATEGORY_FRAMEWORKS` without touching the analysis pipeline.
"""

from __future__ import annotations

from typing import Final

# Central static mapping. Keys are Finding.category values used by plugins.
CATEGORY_FRAMEWORKS: Final[dict[str, list[str]]] = {
    "secret": ["PCI-DSS", "SOC2", "ISO27001", "NIST"],
    "pii": ["GDPR", "CCPA", "HIPAA", "SOC2"],
    "infrastructure": ["SOC2", "ISO27001", "NIST"],
    "keyword": ["Internal Policy", "SOC2"],
    "context": ["Internal Policy", "SOC2", "ISO27001"],
}

# Known categories with an explicit mapping entry.
KNOWN_CATEGORIES: Final[frozenset[str]] = frozenset(CATEGORY_FRAMEWORKS.keys())


def frameworks_for_category(category: str) -> list[str]:
    """Return compliance frameworks associated with a finding category.

    Args:
        category: Finding category string (e.g. ``\"secret\"``).

    Returns:
        A new list of framework identifiers. Unknown categories yield an
        empty list (never ``None``).
    """
    if not category:
        return []
    frameworks = CATEGORY_FRAMEWORKS.get(category)
    if frameworks is None:
        return []
    return list(frameworks)


def all_mapped_categories() -> frozenset[str]:
    """Return the set of categories that have a compliance mapping."""
    return KNOWN_CATEGORIES
