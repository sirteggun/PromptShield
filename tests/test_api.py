"""FastAPI integration tests for PromptShield Enterprise API."""

from __future__ import annotations

import os
from typing import Generator
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from promptshield.api.app import create_app
from promptshield.api.dependencies import reset_service_cache


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    """Test client in development mode without API key requirement."""
    env = {
        "PROMPTSHIELD_ENV": "development",
        "PROMPTSHIELD_API_KEY": "",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        # Ensure empty key is treated as unset
        os.environ.pop("PROMPTSHIELD_API_KEY", None)
        reset_service_cache()
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client
    reset_service_cache()


@pytest.fixture()
def client_with_key() -> Generator[TestClient, None, None]:
    env = {
        "PROMPTSHIELD_ENV": "development",
        "PROMPTSHIELD_API_KEY": "test-key,other-key",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        reset_service_cache()
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client
    reset_service_cache()


def test_health(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["detectors"] >= 1
    assert "version" in data
    assert "X-Request-ID" in resp.headers


def test_request_id_echo(client: TestClient) -> None:
    rid = "custom-req-123"
    resp = client.get("/api/v1/health", headers={"X-Request-ID": rid})
    assert resp.headers["X-Request-ID"] == rid


def test_analyze_clean(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/analyze",
        json={"prompt": "hello clean world"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["analysis"]["risk_level"] == "GREEN"
    assert data["analysis"]["exit_code"] == 0
    assert "request_id" in data or "X-Request-ID" in resp.headers


def test_analyze_secret(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/analyze",
        json={"prompt": "AKIA1234567890ABCDEF"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["analysis"]["policy_decision"]["action"] == "block"
    assert data["analysis"]["exit_code"] == 2
    secret = next(f for f in data["analysis"]["findings"] if f["category"] == "secret")
    assert "matched_text" not in secret


def test_analyze_with_explain(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/analyze",
        json={
            "prompt": "AKIA1234567890ABCDEF production",
            "explain": True,
        },
    )
    assert resp.status_code == 200
    intel = resp.json()["analysis"]["intelligence"]
    assert "classification" in intel
    assert intel["explanation"]["recommended_action"] == "BLOCK"


def test_analyze_with_sanitize_when_blocked(client: TestClient) -> None:
    """sanitize flag does not force sanitize when policy blocks."""
    resp = client.post(
        "/api/v1/analyze",
        json={"prompt": "AKIA1234567890ABCDEF", "sanitize": True},
    )
    assert resp.status_code == 200
    analysis = resp.json()["analysis"]
    # Policy block → no automatic sanitization on analyze
    assert analysis.get("sanitized_prompt") in (None, ...) or (
        analysis.get("sanitization") is None or analysis.get("sanitized_prompt") is None
    )


def test_sanitize_endpoint(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/sanitize",
        json={"prompt": "secret AKIA1234567890ABCDEF here"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "<AWS_SECRET>" in data["sanitized_prompt"]
    assert data["replacements"] >= 1


def test_api_key_required_when_configured(client_with_key: TestClient) -> None:
    resp = client_with_key.post(
        "/api/v1/analyze",
        json={"prompt": "hello"},
    )
    assert resp.status_code == 401

    resp_ok = client_with_key.post(
        "/api/v1/analyze",
        json={"prompt": "hello"},
        headers={"X-API-Key": "test-key"},
    )
    assert resp_ok.status_code == 200

    # health remains open
    assert client_with_key.get("/api/v1/health").status_code == 200


def test_production_without_env_key_starts_but_rejects_requests() -> None:
    """Production may start (seeded tenancy) but unauthenticated analyze fails."""
    env = {
        "PROMPTSHIELD_ENV": "production",
        "DATABASE_URL": "sqlite:///:memory:",
        "PROMPTSHIELD_PERSISTENCE": "1",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        os.environ.pop("PROMPTSHIELD_API_KEY", None)
        from promptshield.persistence.database import reset_engine_cache

        reset_engine_cache()
        reset_service_cache()
        app = create_app()
        with TestClient(app) as client:
            denied = client.post("/api/v1/analyze", json={"prompt": "hi"})
            # No open keys in production seed without env → 401
            assert denied.status_code in {401, 403}
    reset_service_cache()


def test_production_with_api_key() -> None:
    env = {
        "PROMPTSHIELD_ENV": "production",
        "PROMPTSHIELD_API_KEY": "prod-secret",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        reset_service_cache()
        app = create_app()
        with TestClient(app) as client:
            denied = client.post(
                "/api/v1/analyze",
                json={"prompt": "hi"},
            )
            assert denied.status_code == 401
            ok = client.post(
                "/api/v1/analyze",
                json={"prompt": "hi"},
                headers={"X-API-Key": "prod-secret"},
            )
            assert ok.status_code == 200
    reset_service_cache()


def test_docs_available(client: TestClient) -> None:
    resp = client.get("/docs")
    assert resp.status_code == 200
