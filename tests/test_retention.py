"""Retention policy tests."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from promptshield.persistence.cleanup import enforce_retention_policy
from promptshield.persistence.crypto import hash_prompt
from promptshield.persistence.database import (
    get_session_factory,
    init_db,
    reset_engine_cache,
)
from promptshield.persistence.models import Analysis, AuditEvent
from promptshield.persistence.unit_of_work import SqlAlchemyUnitOfWork

MEMORY_URL = "sqlite:///:memory:"


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> str:
    reset_engine_cache()
    monkeypatch.setenv("DATABASE_URL", MEMORY_URL)
    init_db(MEMORY_URL)
    yield MEMORY_URL
    reset_engine_cache()


def test_retention_deletes_old_records(db: str) -> None:
    factory = get_session_factory(db)
    old_ts = datetime.now(timezone.utc) - timedelta(days=120)
    new_ts = datetime.now(timezone.utc)

    with SqlAlchemyUnitOfWork(factory) as uow:
        old = Analysis(
            id=uuid.uuid4(),
            tenant_id="default",
            request_id="old",
            prompt_hash=hash_prompt("old"),
            prompt_length=3,
            risk_score=0,
            risk_level="GREEN",
            policy_action="allow",
            timestamp=old_ts,
        )
        new = Analysis(
            id=uuid.uuid4(),
            tenant_id="default",
            request_id="new",
            prompt_hash=hash_prompt("new"),
            prompt_length=3,
            risk_score=0,
            risk_level="GREEN",
            policy_action="allow",
            timestamp=new_ts,
        )
        uow.analyses.add(old)
        uow.analyses.add(new)
        uow.events.add(
            AuditEvent(
                id=uuid.uuid4(),
                tenant_id="default",
                analysis_id=old.id,
                event_type="analysis.created",
                timestamp=old_ts,
                event_metadata={},
            )
        )
        uow.commit()

    result = enforce_retention_policy(90, database_url=db)
    assert result["deleted_analyses"] >= 1

    with SqlAlchemyUnitOfWork(factory) as uow:
        remaining = uow.analyses.list(tenant_id="default", limit=100)
        ids = {r.request_id for r in remaining}
        assert "new" in ids
        assert "old" not in ids
