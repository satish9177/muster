"""Durable execution-state port, already bound to one tenant."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from muster.core.results import Result
from muster.core.values.times import Instant
from muster.platform.gate.model import (
    ActionIntent,
    ExecutionKey,
    ExecutionRecord,
    ExecutionState,
)


class ExecutionStoreFailure(Enum):
    ABSENT = "ABSENT"
    CASE_IDENTITY_CONFLICT = "CASE_IDENTITY_CONFLICT"
    EXECUTION_KEY_COLLISION = "EXECUTION_KEY_COLLISION"
    ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
    INSTANT_NOT_DURABLE = "INSTANT_NOT_DURABLE"


@dataclass(frozen=True, slots=True)
class ExecutionStoreError:
    failure: ExecutionStoreFailure
    detail: str


@dataclass(frozen=True, slots=True)
class Reservation:
    record: ExecutionRecord
    acquired: bool


@dataclass(frozen=True, slots=True)
class DispatchClaim:
    """Result of the durable RESERVED -> DISPATCHED compare-and-swap."""

    record: ExecutionRecord
    acquired: bool


@dataclass(frozen=True, slots=True)
class ReconciliationClaim:
    """Result of the durable reconciliation compare-and-swap."""

    record: ExecutionRecord
    applied: bool


class ExecutionRepository(Protocol):
    def reserve(
        self, intent: ActionIntent, *, requested_by: str, now: Instant
    ) -> Result[Reservation, ExecutionStoreError]: ...

    def read(self, execution_key: ExecutionKey) -> Result[ExecutionRecord, ExecutionStoreError]:
        """The one lifecycle stored under this key for this tenant.

        A read, and only a read: it reserves nothing, transitions nothing and
        cannot create a row.  ``ABSENT`` when the key names no row -- and never
        some other row that looked close enough.  This is also the whole of the
        idempotency read's store access, which is why that path can be exact
        without consulting the case at all: the key *is* the durable primary
        key, so there is one answer or none.
        """
        ...

    def read_for_case(self, case_id: str) -> Result[ExecutionRecord, ExecutionStoreError]: ...

    def begin_dispatch(
        self, execution_key: ExecutionKey, *, now: Instant
    ) -> Result[DispatchClaim, ExecutionStoreError]: ...

    def finalize(
        self,
        execution_key: ExecutionKey,
        *,
        state: ExecutionState,
        outcome_code: str,
        external_reference: str | None,
        detail: str | None,
        now: Instant,
    ) -> Result[ExecutionRecord, ExecutionStoreError]: ...

    def reconcile(
        self,
        execution_key: ExecutionKey,
        *,
        source_state: ExecutionState,
        state: ExecutionState,
        outcome_code: str,
        external_reference: str | None,
        detail: str | None,
        now: Instant,
    ) -> Result[ReconciliationClaim, ExecutionStoreError]:
        """Observationally refine DISPATCHED/UNCERTAIN through one durable CAS."""
        ...
