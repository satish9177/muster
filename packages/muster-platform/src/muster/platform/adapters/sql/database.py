"""Transactions, and the tenant scope that is the only way into a repository.

Two entry points, and the difference between them is the whole transaction
design:

* ``writing`` is read-committed and read-write.  It is TX A -- admit octets,
  add membership -- and TX B -- cache the derived artifacts, swap the head.
  Read-committed is not a compromise: the compare-and-swap is a single-row
  conditional update, which PostgreSQL re-evaluates against the updated row
  after waiting for a concurrent writer, so exactly one of two contending
  swaps succeeds and the other is told it matched nothing.
* ``reading`` is read-only and repeatable-read.  A revision is derived from a
  head *and* a membership set, and those have to be the same instant or the
  derivation is describing a state that never existed.  A read-only
  repeatable-read transaction in PostgreSQL cannot fail with a serialization
  error, so this costs a snapshot and nothing else.

Nothing analytical happens inside either.  The rebuild, the solver and the
planner run between them, with no transaction open, because a transaction held
across a solver call is a lock held for as long as the hardest query takes.

A connection per transaction, and no pool.  A pool is a property of a process
that serves requests, and this milestone has no such process; adding one now
would be tuning something nobody runs.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import psycopg

from muster.platform.adapters.sql.content import SqlContentStore
from muster.platform.adapters.sql.head import SqlCaseHeadRepository
from muster.platform.adapters.sql.requests import SqlEvidenceRequestRepository
from muster.platform.adapters.sql.transcript import SqlTranscriptRepository
from muster.platform.casework.ports import CaseHeadRepository as CaseHeadRepositoryPort
from muster.platform.casework.ports import (
    ContentStore,
    EvidenceRequestRepository,
    TenantScope,
    TranscriptRepository,
)


@dataclass(frozen=True, slots=True)
class SqlTenantScope:
    """Four repositories, one connection, one tenant, and no way to change it."""

    connection: psycopg.Connection[tuple[object, ...]]
    _tenant_id: str

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def content(self) -> ContentStore:
        return SqlContentStore(self.connection, self._tenant_id)

    @property
    def transcript(self) -> TranscriptRepository:
        return SqlTranscriptRepository(self.connection, self._tenant_id)

    @property
    def heads(self) -> CaseHeadRepositoryPort:
        return SqlCaseHeadRepository(self.connection, self._tenant_id)

    @property
    def requests(self) -> EvidenceRequestRepository:
        return SqlEvidenceRequestRepository(self.connection, self._tenant_id)


@dataclass(frozen=True, slots=True)
class SqlDatabase:
    """Durable custody over PostgreSQL."""

    dsn: str

    @contextmanager
    def writing(self, tenant_id: str) -> Iterator[TenantScope]:
        with psycopg.connect(self.dsn) as connection:
            connection.isolation_level = psycopg.IsolationLevel.READ_COMMITTED
            with connection.transaction():
                yield SqlTenantScope(connection, tenant_id)

    @contextmanager
    def reading(self, tenant_id: str) -> Iterator[TenantScope]:
        with psycopg.connect(self.dsn) as connection:
            connection.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
            connection.read_only = True
            with connection.transaction():
                yield SqlTenantScope(connection, tenant_id)
