"""Admin permission enforcement tests."""

from __future__ import annotations

import os
from typing import Generator
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from promptshield.api.app import create_app
from promptshield.api.dependencies import reset_service_cache
from promptshield.persistence.database import reset_engine_cache

MEMORY = "sqlite:///:memory:"


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    reset_engine_cache()
    reset_service_cache()
    env = {
        "PROMPTSHIELD_ENV": "development",
        "DATABASE_URL": MEMORY,
        "PROMPTSHIELD_PERSISTENCE": "1",
        "PROMPTSHIELD_API_KEY": "super-admin-key",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        reset_engine_cache()
        reset_service_cache()
        app = create_app()
        with TestClient(app) as tc:
            yield tc
    reset_service_cache()
    reset_engine_cache()


def test_create_org_requires_permission(client: TestClient) -> None:
    # Create org with master
    org = client.post(
        "/api/v1/admin/organizations",
        json={"name": "LimitedCo"},
        headers={"X-API-Key": "super-admin-key"},
    ).json()
    limited_key = client.post(
        "/api/v1/admin/api-keys",
        json={
            "name": "analyst",
            "permissions": ["analysis:create", "analysis:read"],
        },
        headers={"X-API-Key": org["api_key"]},
    ).json()["api_key"]

    denied = client.post(
        "/api/v1/admin/organizations",
        json={"name": "ShouldFail"},
        headers={"X-API-Key": limited_key},
    )
    assert denied.status_code == 403

    denied_keys = client.post(
        "/api/v1/admin/api-keys",
        json={"name": "x"},
        headers={"X-API-Key": limited_key},
    )
    assert denied_keys.status_code == 403


def test_manage_keys_scoped_to_org(client: TestClient) -> None:
    master = {"X-API-Key": "super-admin-key"}
    a = client.post(
        "/api/v1/admin/organizations", json={"name": "A1"}, headers=master
    ).json()
    b = client.post(
        "/api/v1/admin/organizations", json={"name": "B1"}, headers=master
    ).json()
    # Org B cannot revoke Org A keys
    keys_a = client.get(
        "/api/v1/admin/api-keys", headers={"X-API-Key": a["api_key"]}
    ).json()
    assert keys_a
    foreign = client.delete(
        f"/api/v1/admin/api-keys/{keys_a[0]['id']}",
        headers={"X-API-Key": b["api_key"]},
    )
    assert foreign.status_code == 404
