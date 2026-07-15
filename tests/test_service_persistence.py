"""Service-layer persistence and audit events."""

from __future__ import annotations

import os

import pytest

from promptshield.container import build_service
from promptshield.persistence.crypto import decrypt_prompt
from promptshield.persistence.database import (
    get_session_factory,
    init_db,
    reset_engine_cache,
)
from promptshield.persistence.unit_of_work import SqlAlchemyUnitOfWork

MEMORY_URL = "sqlite:///:memory:"


@pytest.fixture()
def persisted_service(monkeypatch: pytest.MonkeyPatch):
    reset_engine_cache()
    monkeypatch.setenv("DATABASE_URL", MEMORY_URL)
    key = os.urandom(32).hex()
    monkeypatch.setenv("PROMPTSHIELD_ENCRYPTION_KEY", key)
    init_db(MEMORY_URL)
    service = build_service(enable_persistence=True, database_url=MEMORY_URL)
    yield service, key
    reset_engine_cache()


def test_analyze_persists_analysis_findings_events(persisted_service) -> None:
    service, key = persisted_service
    outcome = service.analyze(
        "token AKIA1234567890ABCDEF",
        {
            "request_id": "req-1",
            "tenant_id": "default",
            "api_key": "my-api-key",
            "client_ip": "127.0.0.1",
            "user_agent": "pytest",
        },
    )
    assert outcome.blocked
    analysis_id = outcome.options.get("analysis_id")
    assert analysis_id

    factory = get_session_factory(MEMORY_URL)
    with SqlAlchemyUnitOfWork(factory) as uow:
        from uuid import UUID

        row = uow.analyses.get(UUID(analysis_id))
        assert row is not None
        assert row.risk_score >= 40
        assert row.api_key_hash is not None
        assert "my-api-key" not in (row.api_key_hash or "")
        assert row.client_ip == "127.0.0.1"
        assert row.encrypted_prompt is not None
        # Ciphertext must not contain plaintext secret
        assert b"AKIA1234567890ABCDEF" not in row.encrypted_prompt
        plain = decrypt_prompt(row.encrypted_prompt, bytes.fromhex(key))
        assert "AKIA1234567890ABCDEF" in plain
        assert any(f.category == "secret" for f in row.findings)
        for f in row.findings:
            if f.category == "secret":
                assert "AKIA1234567890ABCDEF" not in f.matched_text_preview
        events = uow.events.list(tenant_id="default")
        types = {e.event_type for e in events}
        assert "analysis.created" in types
        assert "secret.detected" in types
        assert "policy.blocked" in types


def test_cli_service_without_persistence_does_not_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_engine_cache()
    monkeypatch.setenv("DATABASE_URL", MEMORY_URL)
    init_db(MEMORY_URL)
    service = build_service(enable_persistence=False, database_url=MEMORY_URL)
    service.analyze("AKIA1234567890ABCDEF")
    factory = get_session_factory(MEMORY_URL)
    with SqlAlchemyUnitOfWork(factory) as uow:
        assert uow.analyses.count() == 0
