"""Unit tests for ORM models, repositories, crypto, and UnitOfWork."""

from __future__ import annotations

import os
import uuid

import pytest

from promptshield.persistence.crypto import (
    decrypt_prompt,
    encrypt_prompt,
    hash_api_key,
    hash_prompt,
)
from promptshield.persistence.database import init_db, reset_engine_cache
from promptshield.persistence.models import Analysis, AuditEvent, FindingRecord
from promptshield.persistence.unit_of_work import SqlAlchemyUnitOfWork

MEMORY_URL = "sqlite:///:memory:"


@pytest.fixture()
def db_url(monkeypatch: pytest.MonkeyPatch) -> str:
    reset_engine_cache()
    monkeypatch.setenv("DATABASE_URL", MEMORY_URL)
    init_db(MEMORY_URL)
    yield MEMORY_URL
    reset_engine_cache()


def test_hash_api_key_never_plaintext() -> None:
    key = "super-secret-key"
    digest = hash_api_key(key)
    assert digest is not None
    assert key not in digest
    assert len(digest) == 64


def test_encrypt_decrypt_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    key = os.urandom(32).hex()
    monkeypatch.setenv("PROMPTSHIELD_ENCRYPTION_KEY", key)
    blob = encrypt_prompt("AKIA1234567890ABCDEF secret")
    assert blob is not None
    assert b"AKIA" not in blob
    plain = decrypt_prompt(blob)
    assert plain == "AKIA1234567890ABCDEF secret"


def test_encrypt_without_key_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PROMPTSHIELD_ENCRYPTION_KEY", raising=False)
    assert encrypt_prompt("hello") is None


def test_unit_of_work_crud(db_url: str) -> None:
    from promptshield.persistence.database import get_session_factory

    factory = get_session_factory(db_url)
    with SqlAlchemyUnitOfWork(factory) as uow:
        analysis = Analysis(
            id=uuid.uuid4(),
            tenant_id="default",
            request_id="r1",
            prompt_hash=hash_prompt("hello"),
            prompt_length=5,
            risk_score=0,
            risk_level="GREEN",
            policy_action="allow",
            encrypted_prompt=None,
        )
        analysis.findings.append(
            FindingRecord(
                id=uuid.uuid4(),
                detector_name="T",
                category="keyword",
                severity="medium",
                weight=20,
                matched_text_preview="x",
                redacted_text="<X>",
                explanation="e",
                remediation="r",
                compliance_frameworks=["SOC2"],
            )
        )
        uow.analyses.add(analysis)
        uow.events.add(
            AuditEvent(
                id=uuid.uuid4(),
                tenant_id="default",
                analysis_id=analysis.id,
                event_type="analysis.created",
                event_metadata={"ok": True},
            )
        )
        uow.commit()
        aid = analysis.id

    with SqlAlchemyUnitOfWork(factory) as uow:
        loaded = uow.analyses.get(aid)
        assert loaded is not None
        assert loaded.risk_level == "GREEN"
        assert len(loaded.findings) == 1
        assert loaded.findings[0].category == "keyword"
        events = uow.events.list(tenant_id="default")
        assert any(e.event_type == "analysis.created" for e in events)


def test_list_filter_risk_level(db_url: str) -> None:
    from promptshield.persistence.database import get_session_factory

    factory = get_session_factory(db_url)
    with SqlAlchemyUnitOfWork(factory) as uow:
        for level, score in [("GREEN", 0), ("RED", 80)]:
            uow.analyses.add(
                Analysis(
                    id=uuid.uuid4(),
                    tenant_id="default",
                    request_id=level,
                    prompt_hash=hash_prompt(level),
                    prompt_length=1,
                    risk_score=score,
                    risk_level=level,
                    policy_action="allow",
                )
            )
        uow.commit()

    with SqlAlchemyUnitOfWork(factory) as uow:
        reds = uow.analyses.list(tenant_id="default", risk_level="RED")
        assert len(reds) == 1
        assert reds[0].risk_level == "RED"
