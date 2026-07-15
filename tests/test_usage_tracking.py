"""Usage tracking unit tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from promptshield.container import build_service
from promptshield.persistence.database import (
    get_session_factory,
    init_db,
    reset_engine_cache,
)
from promptshield.persistence.models import UsageRecord
from promptshield.persistence.tenancy import create_organization
from promptshield.persistence.unit_of_work import SqlAlchemyUnitOfWork
from sqlalchemy import select

MEMORY = "sqlite:///:memory:"


@pytest.fixture()
def setup_db(monkeypatch: pytest.MonkeyPatch):
    reset_engine_cache()
    monkeypatch.setenv("DATABASE_URL", MEMORY)
    monkeypatch.setenv("PROMPTSHIELD_PERSISTENCE", "1")
    init_db(MEMORY)
    factory = get_session_factory(MEMORY)
    session = factory()
    org, key_row, raw = create_organization(session, "UsageCo")
    session.commit()
    org_id = org.id
    session.close()
    service = build_service(enable_persistence=True, database_url=MEMORY)
    yield service, org_id, raw
    reset_engine_cache()


def test_usage_increments(setup_db) -> None:
    service, org_id, _raw = setup_db
    service.analyze(
        "hello clean",
        {"organization_id": str(org_id), "tenant_id": str(org_id)},
    )
    service.analyze(
        "AKIA1234567890ABCDEF",
        {"organization_id": str(org_id), "tenant_id": str(org_id)},
    )
    now = datetime.now(timezone.utc)
    factory = get_session_factory(MEMORY)
    with SqlAlchemyUnitOfWork(factory) as uow:
        row = uow.session.scalars(
            select(UsageRecord).where(
                UsageRecord.organization_id == org_id,
                UsageRecord.year == now.year,
                UsageRecord.month == now.month,
            )
        ).first()
        assert row is not None
        assert row.analysis_count == 2
        assert row.blocked_count >= 1
        assert row.secret_count >= 1
