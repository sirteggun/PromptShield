"""API audit / stats / cleanup endpoint tests."""

from __future__ import annotations

import os
from typing import Generator
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from promptshield.api.app import create_app
from promptshield.api.dependencies import reset_service_cache
from promptshield.persistence.database import reset_engine_cache

MEMORY_URL = "sqlite:///:memory:"


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    reset_engine_cache()
    reset_service_cache()
    env = {
        "PROMPTSHIELD_ENV": "development",
        "DATABASE_URL": MEMORY_URL,
        "PROMPTSHIELD_PERSISTENCE": "1",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        os.environ.pop("PROMPTSHIELD_API_KEY", None)
        reset_engine_cache()
        reset_service_cache()
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client
    reset_service_cache()
    reset_engine_cache()


def test_analyze_then_list_analyses(client: TestClient) -> None:
    r = client.post(
        "/api/v1/analyze",
        json={"prompt": "AKIA1234567890ABCDEF"},
    )
    assert r.status_code == 200
    analysis_id = r.json().get("analysis_id")
    assert analysis_id

    listing = client.get("/api/v1/analyses")
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] >= 1
    assert any(item["id"] == analysis_id for item in body["items"])
    # No raw secret in list payload
    assert "AKIA1234567890ABCDEF" not in listing.text


def test_get_analysis_detail(client: TestClient) -> None:
    r = client.post(
        "/api/v1/analyze",
        json={"prompt": "hello AKIA1234567890ABCDEF"},
    )
    aid = r.json()["analysis_id"]
    detail = client.get(f"/api/v1/analyses/{aid}")
    assert detail.status_code == 200
    data = detail.json()
    assert data["id"] == aid
    assert data["has_encrypted_prompt"] in {True, False}
    assert "findings" in data
    assert "AKIA1234567890ABCDEF" not in detail.text


def test_stats_endpoint(client: TestClient) -> None:
    client.post("/api/v1/analyze", json={"prompt": "safe text"})
    client.post(
        "/api/v1/analyze",
        json={"prompt": "AKIA1234567890ABCDEF"},
    )
    stats = client.get("/api/v1/stats?days=30")
    assert stats.status_code == 200
    data = stats.json()
    assert data["total_analyses"] >= 2
    assert "by_risk_level" in data
    assert "trend" in data


def test_events_endpoint(client: TestClient) -> None:
    client.post(
        "/api/v1/analyze",
        json={"prompt": "AKIA1234567890ABCDEF"},
    )
    events = client.get("/api/v1/events")
    assert events.status_code == 200
    types = {e["event_type"] for e in events.json()["items"]}
    assert "analysis.created" in types


def test_cleanup_endpoint(client: TestClient) -> None:
    resp = client.post("/api/v1/maintenance/cleanup?retention_days=90")
    assert resp.status_code == 200
    data = resp.json()
    assert "deleted_analyses" in data
    assert data["retention_days"] == 90
