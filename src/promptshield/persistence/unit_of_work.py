"""Unit of Work pattern for transactional persistence."""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Self

from sqlalchemy.orm import Session, sessionmaker

from promptshield.persistence.database import get_session_factory
from promptshield.persistence.repository import AnalysisRepository, AuditEventRepository


class UnitOfWork(ABC):
    """Abstract unit of work exposing repositories."""

    analyses: AnalysisRepository
    events: AuditEventRepository

    @abstractmethod
    def __enter__(self) -> Self: ...

    @abstractmethod
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    @abstractmethod
    def commit(self) -> None: ...

    @abstractmethod
    def rollback(self) -> None: ...


class SqlAlchemyUnitOfWork(UnitOfWork):
    """SQLAlchemy-backed unit of work."""

    def __init__(self, session_factory: sessionmaker[Session] | None = None) -> None:
        self._session_factory = session_factory or get_session_factory()
        self._session: Session | None = None

    def __enter__(self) -> Self:
        self._session = self._session_factory()
        self.analyses = AnalysisRepository(self._session)
        self.events = AuditEventRepository(self._session)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            self.rollback()
        if self._session is not None:
            self._session.close()
            self._session = None

    def commit(self) -> None:
        if self._session is None:
            raise RuntimeError("UnitOfWork not started")
        self._session.commit()

    def rollback(self) -> None:
        if self._session is not None:
            self._session.rollback()

    @property
    def session(self) -> Session:
        if self._session is None:
            raise RuntimeError("UnitOfWork not started")
        return self._session
