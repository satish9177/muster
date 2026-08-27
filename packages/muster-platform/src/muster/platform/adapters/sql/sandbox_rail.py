"""Durable simulated external-world effects for the sandbox executor.

This module is a SIMULATED EXTERNAL SYSTEM, not MUSTER custody and not a
payment rail.  It has no payment credentials and moves no real funds.  Its
separate PostgreSQL transaction exists only to prove that a synthetic external
acceptance can survive the death of the process that called it.

Only :class:`DurableSandboxPaymentExecutor` reads the external-world record.
The Gate receives an executor protocol and never imports this module, its SQL,
or its schema.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from muster.core.results import InvariantViolation
from muster.core.values.times import Instant
from muster.platform.gate.executor import (
    Confirmed,
    DefiniteFailure,
    ExecutedAs,
    ExecutorDispatch,
    ExecutorInquiry,
    ExecutorOutcome,
    NotExecuted,
    ReconciliationAnswer,
    StillUnknown,
    validate_sandbox_payment,
)

_INSERT_ATTEMPT = """
INSERT INTO sandbox_rail.attempt (
    idempotency_key, outcome, failure_code, failure_detail
)
VALUES (%s, 'ATTEMPTED', NULL, NULL)
ON CONFLICT (idempotency_key) DO NOTHING
RETURNING idempotency_key, outcome, failure_code, failure_detail
"""

_SEAL_NOT_EXECUTED = """
INSERT INTO sandbox_rail.attempt (
    idempotency_key, outcome, failure_code, failure_detail
)
VALUES (%s, 'DEFINITIVELY_NOT_EXECUTED', %s, %s)
ON CONFLICT (idempotency_key) DO NOTHING
RETURNING idempotency_key, outcome, failure_code, failure_detail
"""

_MARK_NOT_EXECUTED = """
UPDATE sandbox_rail.attempt
SET outcome = 'DEFINITIVELY_NOT_EXECUTED',
    failure_code = %s,
    failure_detail = %s
WHERE idempotency_key = %s AND outcome = 'ATTEMPTED'
RETURNING idempotency_key, outcome, failure_code, failure_detail
"""

_SELECT_ATTEMPT = """
SELECT idempotency_key, outcome, failure_code, failure_detail
FROM sandbox_rail.attempt
WHERE idempotency_key = %s
"""

_INSERT_TRANSFER = """
INSERT INTO sandbox_rail.transfer (idempotency_key, external_reference, accepted_at)
VALUES (%s, %s, %s)
ON CONFLICT (idempotency_key) DO NOTHING
RETURNING idempotency_key, external_reference, accepted_at
"""

_SELECT_TRANSFER = """
SELECT idempotency_key, external_reference, accepted_at
FROM sandbox_rail.transfer
WHERE idempotency_key = %s
"""

_COUNT = "SELECT count(*) FROM sandbox_rail.transfer WHERE idempotency_key = %s"


@dataclass(frozen=True, slots=True)
class SandboxRailTransfer:
    """One synthetic acceptance in the simulated external system."""

    idempotency_key: str
    external_reference: str
    accepted_at: Instant


@dataclass(frozen=True, slots=True)
class SandboxRailAttempt:
    """Durable external evidence that precedes or excludes an effect."""

    idempotency_key: str
    outcome: str
    failure_code: str | None
    failure_detail: str | None


class DurableSandboxPaymentExecutor:
    """A durable simulated external system; no payment rail and no real funds.

    Dispatch first commits an ATTEMPTED marker in a transaction independent of
    MUSTER, then starts the transfer transaction.  Inspection can therefore
    distinguish an in-progress attempt from a completed transfer.  If no
    marker exists, inspection atomically writes durable negative evidence;
    the same primary key then prevents a later dispatch from starting.
    """

    def __init__(
        self,
        dsn: str,
        *,
        accepted_at: Instant,
        executor_id: str = "sandbox-payment/v1",
        trusted_gate_id: str = "local-action-gate/v1",
        definite_failure: DefiniteFailure | None = None,
    ) -> None:
        self._dsn = dsn
        self._accepted_at = accepted_at
        self._executor_id = executor_id
        self._trusted_gate_id = trusted_gate_id
        self._definite_failure = definite_failure
        self._dispatch_count = 0
        self._inspection_count = 0

    @property
    def executor_id(self) -> str:
        return self._executor_id

    @property
    def trusted_gate_id(self) -> str:
        return self._trusted_gate_id

    @property
    def transfers_real_funds(self) -> bool:
        """Always false: this simulation has no payment rail or credentials."""
        return False

    @property
    def dispatch_count(self) -> int:
        return self._dispatch_count

    @property
    def inspection_count(self) -> int:
        return self._inspection_count

    def transfer_count(self, idempotency_key: str) -> int:
        """Count this exact synthetic record, never MUSTER execution rows."""
        with psycopg.connect(self._dsn) as connection:
            connection.read_only = True
            row = connection.execute(_COUNT, (idempotency_key,)).fetchone()
        if row is None or not isinstance(row[0], int):
            raise InvariantViolation("the simulated external transfer count is absent")
        return row[0]

    def dispatch(self, request: ExecutorDispatch) -> ExecutorOutcome:
        self._dispatch_count += 1
        refused = validate_sandbox_payment(
            request,
            executor_id=self.executor_id,
            trusted_gate_id=self.trusted_gate_id,
        )
        if refused is not None:
            return refused

        attempt = self._establish_attempt(request.idempotency_key)
        if attempt.outcome == "DEFINITIVELY_NOT_EXECUTED":
            return _definite_failure(attempt)
        if attempt.outcome != "ATTEMPTED":
            raise InvariantViolation("the simulated external attempt has an invalid outcome")

        if self._definite_failure is not None:
            return self._record_definite_failure(
                request.idempotency_key, self._definite_failure
            )

        self._before_external_effect(request)
        reference = f"sandbox-pay-{request.idempotency_key}"
        with psycopg.connect(self._dsn) as connection:
            inserted = connection.execute(
                _INSERT_TRANSFER,
                (request.idempotency_key, reference, self._accepted_at),
            ).fetchone()
            row = inserted or connection.execute(
                _SELECT_TRANSFER, (request.idempotency_key,)
            ).fetchone()
            self._before_transfer_commit(request)
        transfer = _transfer(row)
        if transfer.external_reference != reference:
            raise InvariantViolation(
                "the simulated external record disagrees with its deterministic reference"
            )
        return Confirmed(transfer.external_reference, duplicate=inserted is None)

    def _establish_attempt(self, idempotency_key: str) -> SandboxRailAttempt:
        with psycopg.connect(self._dsn) as connection:
            inserted = connection.execute(_INSERT_ATTEMPT, (idempotency_key,)).fetchone()
            row = inserted or connection.execute(
                _SELECT_ATTEMPT, (idempotency_key,)
            ).fetchone()
        return _attempt(row)

    def _record_definite_failure(
        self, idempotency_key: str, failure: DefiniteFailure
    ) -> DefiniteFailure:
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                _MARK_NOT_EXECUTED,
                (failure.code, failure.detail, idempotency_key),
            ).fetchone()
            if row is None:
                row = connection.execute(
                    _SELECT_ATTEMPT, (idempotency_key,)
                ).fetchone()
        evidence = _attempt(row)
        if evidence.outcome != "DEFINITIVELY_NOT_EXECUTED":
            raise InvariantViolation(
                "the simulated external failure was not durably recorded"
            )
        return _definite_failure(evidence)

    def _before_external_effect(self, request: ExecutorDispatch) -> None:
        """Test rendezvous after ATTEMPTED commits and before the effect begins."""

    def _before_transfer_commit(self, request: ExecutorDispatch) -> None:
        """Test rendezvous after transfer insertion and before it becomes visible."""

    def inspect(self, inquiry: ExecutorInquiry) -> ReconciliationAnswer:
        self._inspection_count += 1
        invalid = _invalid_inquiry(
            inquiry,
            executor_id=self.executor_id,
            trusted_gate_id=self.trusted_gate_id,
        )
        if invalid is not None:
            return invalid

        negative_code = "SANDBOX_DEFINITIVELY_NOT_EXECUTED"
        negative_detail = (
            "the simulated external system sealed this key before any attempt"
        )
        with psycopg.connect(self._dsn) as connection:
            inserted = connection.execute(
                _SEAL_NOT_EXECUTED,
                (inquiry.idempotency_key, negative_code, negative_detail),
            ).fetchone()
            attempt_row = inserted or connection.execute(
                _SELECT_ATTEMPT, (inquiry.idempotency_key,)
            ).fetchone()
            transfer_row = connection.execute(
                _SELECT_TRANSFER, (inquiry.idempotency_key,)
            ).fetchone()

        attempt = _attempt(attempt_row)
        if transfer_row is not None:
            if attempt.outcome != "ATTEMPTED":
                raise InvariantViolation(
                    "a completed simulated transfer has negative attempt evidence"
                )
            return ExecutedAs(_transfer(transfer_row).external_reference)
        if attempt.outcome == "ATTEMPTED":
            return StillUnknown(
                "SANDBOX_ATTEMPT_IN_PROGRESS",
                "the simulated external attempt exists but no outcome is yet visible",
            )
        return NotExecuted(*_negative_evidence(attempt))


def _invalid_inquiry(
    inquiry: ExecutorInquiry, *, executor_id: str, trusted_gate_id: str
) -> StillUnknown | None:
    if inquiry.gate_id != trusted_gate_id or inquiry.intent.gate_id != trusted_gate_id:
        return StillUnknown("UNTRUSTED_GATE", "the inquiry names another Gate")
    if inquiry.intent.executor_id != executor_id:
        return StillUnknown("WRONG_EXECUTOR", "the inquiry names another executor")
    if inquiry.idempotency_key != inquiry.intent.execution_key().hex:
        return StillUnknown(
            "IDEMPOTENCY_MISMATCH",
            "the inquiry key is not the key of the exact authorized intent",
        )
    return None


def _transfer(row: tuple[object, ...] | None) -> SandboxRailTransfer:
    if row is None:
        raise InvariantViolation("the simulated external acceptance disappeared")
    key, reference, accepted_at = row
    if not isinstance(key, str) or not isinstance(reference, str) or not isinstance(
        accepted_at, int
    ):
        raise InvariantViolation("the simulated external acceptance has an invalid shape")
    return SandboxRailTransfer(key, reference, accepted_at)


def _attempt(row: tuple[object, ...] | None) -> SandboxRailAttempt:
    if row is None:
        raise InvariantViolation("the simulated external attempt disappeared")
    key, outcome, failure_code, failure_detail = row
    if not isinstance(key, str) or not isinstance(outcome, str):
        raise InvariantViolation("the simulated external attempt has an invalid shape")
    if failure_code is not None and not isinstance(failure_code, str):
        raise InvariantViolation("the simulated external failure code is not text")
    if failure_detail is not None and not isinstance(failure_detail, str):
        raise InvariantViolation("the simulated external failure detail is not text")
    return SandboxRailAttempt(key, outcome, failure_code, failure_detail)


def _negative_evidence(attempt: SandboxRailAttempt) -> tuple[str, str]:
    if (
        attempt.outcome != "DEFINITIVELY_NOT_EXECUTED"
        or attempt.failure_code is None
        or attempt.failure_detail is None
    ):
        raise InvariantViolation("the simulated external negative evidence is incomplete")
    return attempt.failure_code, attempt.failure_detail


def _definite_failure(attempt: SandboxRailAttempt) -> DefiniteFailure:
    code, detail = _negative_evidence(attempt)
    return DefiniteFailure(code, detail)
