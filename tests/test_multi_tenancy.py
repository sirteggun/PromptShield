"""Multi-tenancy isolation and organization bootstrap tests."""

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
def tenant_client() -> Generator[TestClient, None, None]:
    reset_engine_cache()
    reset_service_cache()
    env = {
        "PROMPTSHIELD_ENV": "development",
        "DATABASE_URL": MEMORY,
        "PROMPTSHIELD_PERSISTENCE": "1",
        "PROMPTSHIELD_API_KEY": "master-key-with-admin",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        reset_engine_cache()
        reset_service_cache()
        app = create_app()
        with TestClient(app) as client:
            yield client
    reset_service_cache()
    reset_engine_cache()


def test_create_organization_returns_full_key_once(tenant_client: TestClient) -> None:
    r = tenant_client.post(
        "/api/v1/admin/organizations",
        json={"name": "Acme Corp"},
        headers={"X-API-Key": "master-key-with-admin"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["name"] == "Acme Corp"
    assert data["api_key"].startswith("ps_")
    assert "admin:manage_keys" in data["permissions"]
    assert "admin:create_organization" in data["permissions"]
    # Key works for analysis
    r2 = tenant_client.post(
        "/api/v1/analyze",
        json={"prompt": "hello from acme"},
        headers={"X-API-Key": data["api_key"]},
    )
    assert r2.status_code == 200


def test_data_isolation_between_orgs(tenant_client: TestClient) -> None:
    master = {"X-API-Key": "master-key-with-admin"}
    a = tenant_client.post(
        "/api/v1/admin/organizations",
        json={"name": "OrgA"},
        headers=master,
    ).json()
    b = tenant_client.post(
        "/api/v1/admin/organizations",
        json={"name": "OrgB"},
        headers=master,
    ).json()
    key_a, key_b = a["api_key"], b["api_key"]

    tenant_client.post(
        "/api/v1/analyze",
        json={"prompt": "AKIA1234567890ABCDEF orgA secret"},
        headers={"X-API-Key": key_a},
    )
    tenant_client.post(
        "/api/v1/analyze",
        json={"prompt": "safe prompt for orgB only"},
        headers={"X-API-Key": key_b},
    )

    list_a = tenant_client.get("/api/v1/analyses", headers={"X-API-Key": key_a}).json()
    list_b = tenant_client.get("/api/v1/analyses", headers={"X-API-Key": key_b}).json()
    assert list_a["total"] >= 1
    assert list_b["total"] >= 1
    # OrgA should only see its own (blocked secret) — not orgB's clean prompt alone as only
    ids_a = {i["id"] for i in list_a["items"]}
    ids_b = {i["id"] for i in list_b["items"]}
    assert ids_a.isdisjoint(ids_b)

    # Cross-tenant detail access denied
    if list_a["items"]:
        foreign = tenant_client.get(
            f"/api/v1/analyses/{list_a['items'][0]['id']}",
            headers={"X-API-Key": key_b},
        )
        assert foreign.status_code == 404


def test_revoke_api_key(tenant_client: TestClient) -> None:
    master = {"X-API-Key": "master-key-with-admin"}
    org = tenant_client.post(
        "/api/v1/admin/organizations",
        json={"name": "RevokeCo"},
        headers=master,
    ).json()
    owner_key = org["api_key"]
    created = tenant_client.post(
        "/api/v1/admin/api-keys",
        json={"name": "CI", "permissions": ["analysis:create", "analysis:read"]},
        headers={"X-API-Key": owner_key},
    )
    assert created.status_code == 200
    kid = created.json()["id"]
    ci_key = created.json()["api_key"]
    assert (
        tenant_client.post(
            "/api/v1/analyze",
            json={"prompt": "hi"},
            headers={"X-API-Key": ci_key},
        ).status_code
        == 200
    )

    rev = tenant_client.delete(
        f"/api/v1/admin/api-keys/{kid}",
        headers={"X-API-Key": owner_key},
    )
    assert rev.status_code == 200
    assert rev.json()["revoked"] is True
    assert (
        tenant_client.post(
            "/api/v1/analyze",
            json={"prompt": "hi"},
            headers={"X-API-Key": ci_key},
        ).status_code
        == 401
    )
