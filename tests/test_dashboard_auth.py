"""Dashboard authentication tests."""

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
def locked_client() -> Generator[TestClient, None, None]:
    reset_engine_cache()
    reset_service_cache()
    env = {
        "PROMPTSHIELD_ENV": "development",
        "DATABASE_URL": MEMORY_URL,
        "PROMPTSHIELD_PERSISTENCE": "1",
        "PROMPTSHIELD_DASHBOARD_KEY": "dash-secret",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        os.environ.pop("PROMPTSHIELD_API_KEY", None)
        reset_engine_cache()
        reset_service_cache()
        app = create_app()
        with TestClient(app) as tc:
            yield tc
    reset_service_cache()
    reset_engine_cache()


def test_dashboard_requires_key(locked_client: TestClient) -> None:
    assert locked_client.get("/dashboard").status_code == 401
    assert locked_client.get("/api/v1/dashboard/summary").status_code == 401


def test_dashboard_accepts_header(locked_client: TestClient) -> None:
    r = locked_client.get(
        "/dashboard",
        headers={"X-Dashboard-Key": "dash-secret"},
    )
    assert r.status_code == 200
    r2 = locked_client.get(
        "/api/v1/dashboard/summary",
        headers={"X-Dashboard-Key": "dash-secret"},
    )
    assert r2.status_code == 200


def test_dashboard_accepts_query_param(locked_client: TestClient) -> None:
    r = locked_client.get("/dashboard?key=dash-secret")
    assert r.status_code == 200
    r2 = locked_client.get("/api/v1/dashboard/summary?key=dash-secret")
    assert r2.status_code == 200


def test_wrong_key_rejected(locked_client: TestClient) -> None:
    r = locked_client.get("/dashboard?key=wrong")
    assert r.status_code == 401
