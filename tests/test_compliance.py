"""Tests for the independent compliance mapping module."""

from __future__ import annotations

from promptshield.compliance import (
    CATEGORY_FRAMEWORKS,
    KNOWN_CATEGORIES,
    all_mapped_categories,
    frameworks_for_category,
)


def test_every_known_category_has_non_empty_mapping() -> None:
    assert KNOWN_CATEGORIES == all_mapped_categories()
    for category in KNOWN_CATEGORIES:
        frameworks = frameworks_for_category(category)
        assert frameworks, f"expected mapping for {category}"
        assert frameworks == CATEGORY_FRAMEWORKS[category]


def test_unknown_category_returns_empty_list() -> None:
    assert frameworks_for_category("not_a_real_category") == []
    assert frameworks_for_category("") == []


def test_mapping_is_copy_not_shared_mutable() -> None:
    a = frameworks_for_category("secret")
    b = frameworks_for_category("secret")
    a.append("MUTATED")
    assert "MUTATED" not in b
    assert "MUTATED" not in CATEGORY_FRAMEWORKS["secret"]


def test_core_categories_present() -> None:
    for cat in ("secret", "pii", "infrastructure", "keyword", "context"):
        assert cat in KNOWN_CATEGORIES
