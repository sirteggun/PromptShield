"""HTML dashboard page smoke tests."""

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
            tc.post("/api/v1/analyze", json={"prompt": "AKIA1234567890ABCDEF"})
            yield tc
    reset_service_cache()
    reset_engine_cache()


def test_dashboard_home(client: TestClient) -> None:
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "Security Overview" in r.text
    assert "Analyses today" in r.text
    assert "Chart" in r.text or "chart" in r.text
    assert "AKIA1234567890ABCDEF" not in r.text


def test_compliance_page(client: TestClient) -> None:
    r = client.get("/dashboard/compliance")
    assert r.status_code == 200
    assert "Compliance" in r.text
    assert "GDPR" in r.text or "progress" in r.text


def test_analyses_page(client: TestClient) -> None:
    r = client.get("/dashboard/analyses")
    assert r.status_code == 200
    assert "Analyses" in r.text
    assert "AKIA1234567890ABCDEF" not in r.text


def test_audit_page(client: TestClient) -> None:
    r = client.get("/dashboard/audit")
    assert r.status_code == 200
    assert "Audit" in r.text


def test_analysis_detail_page(client: TestClient) -> None:
    listed = client.get("/api/v1/dashboard/recent?limit=1").json()["items"]
    assert listed
    aid = listed[0]["id"]
    r = client.get(f"/dashboard/analyses/{aid}")
    assert r.status_code == 200
    assert "Findings" in r.text
    assert "AKIA1234567890ABCDEF" not in r.text
