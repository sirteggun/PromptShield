"""Tests for dashboard JSON API endpoints."""

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
        os.environ.pop("PROMPTSHIELD_DASHBOARD_KEY", None)
        reset_engine_cache()
        reset_service_cache()
        app = create_app()
        with TestClient(app) as tc:
            # seed one analysis
            tc.post("/api/v1/analyze", json={"prompt": "AKIA1234567890ABCDEF"})
            yield tc
    reset_service_cache()
    reset_engine_cache()


def test_summary(client: TestClient) -> None:
    r = client.get("/api/v1/dashboard/summary")
    assert r.status_code == 200
    data = r.json()
    assert "today" in data
    assert "risk_distribution" in data
    assert "top_detectors" in data
    assert "top_categories" in data
    assert data["today"]["total_analyses"] >= 1


def test_trend(client: TestClient) -> None:
    r = client.get("/api/v1/dashboard/trend?days=7")
    assert r.status_code == 200
    data = r.json()
    assert len(data["labels"]) == 7
    assert len(data["total"]) == 7
    assert "blocked" in data and "secrets" in data


def test_recent(client: TestClient) -> None:
    r = client.get("/api/v1/dashboard/recent?limit=5")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 1
    assert "risk_level" in items[0]
    assert "AKIA1234567890ABCDEF" not in r.text


def test_compliance(client: TestClient) -> None:
    r = client.get("/api/v1/dashboard/compliance")
    assert r.status_code == 200
    fw = r.json()["frameworks"]
    assert "GDPR" in fw or "SOC2" in fw
    for key in ("GDPR", "SOC2", "ISO27001"):
        if key in fw:
            assert 0 <= fw[key]["score"] <= 100


def test_audit_timeline(client: TestClient) -> None:
    r = client.get("/api/v1/dashboard/audit-timeline?limit=10")
    assert r.status_code == 200
    assert "items" in r.json()


def test_report_html(client: TestClient) -> None:
    r = client.get("/api/v1/dashboard/report?format=html")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "PromptShield" in r.text
    assert (
        "Recommendations" in r.text
        or "raccomand" in r.text.lower()
        or "Recommendations" in r.text
    )
    assert "AKIA1234567890ABCDEF" not in r.text
