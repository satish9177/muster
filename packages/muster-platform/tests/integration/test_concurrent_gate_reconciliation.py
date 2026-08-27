"""The reconciliation race proof, resting on PostgreSQL and on nothing else.

Every contender has its own ``SqlDatabase``, ``ActionGate`` and durable sandbox
executor.  They share only the DSN and durable identifiers: no Python lock,
counter or executor can decide the winner or make the losers agree.  PostgreSQL
must serialize the reconciliation compare-and-swap and return the one durable
answer to all eight independently constructed deployments.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import Event

import psycopg
import pytest

from muster.core.results import Err, Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.sandbox_rail import DurableSandboxPaymentExecutor
from muster.platform.casework.commands import case_status
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import Confirmed, ExecutorDispatch
from muster.platform.gate.model import (
    ExecuteProposal,
    ExecutionKey,
    ExecutionLookup,
    ExecutionRecord,
    ExecutionState,
)
from muster.platform.gate.service import ActionGate
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

pytestmark = pytest.mark.postgres

_CONTENDER_COUNT = 8
_PRINCIPAL_ID = "postgres-reconciliation-operator"


@dataclass(frozen=True, slots=True)
class _Deployment:
    """One contender's private database handle, gate, caller and executor."""

    gate: ActionGate
    caller: GateCaller
    executor: DurableSandboxPaymentExecutor


class _PausingTransferExecutor(DurableSandboxPaymentExecutor):
    """Pause after transfer insertion while its transaction is uncommitted."""

    def __init__(self, dsn: str) -> None:
        super().__init__(dsn, accepted_at=ravi.NOW)
        self.transfer_inserted = Event()
        self.allow_transfer_commit = Event()

    def _before_transfer_commit(self, request: ExecutorDispatch) -> None:
        assert request.idempotency_key
        self.transfer_inserted.set()
        self.allow_transfer_commit.wait()


def _deployment(dsn: str, tenant_id: str) -> _Deployment:
    executor = DurableSandboxPaymentExecutor(dsn, accepted_at=ravi.NOW + 1)
    return _deployment_with_executor(dsn, tenant_id, executor)


def _deployment_with_executor(
    dsn: str,
    tenant_id: str,
    executor: DurableSandboxPaymentExecutor,
) -> _Deployment:
    caller = GateCaller(_PRINCIPAL_ID)
    database = SqlDatabase(dsn)
    authority = LocalExecutionAuthority(
        (
            ExecutionGrant(
                principal_id=caller.principal_id,
                tenant_id=tenant_id,
                action_kind="PAY",
                gate_id=executor.trusted_gate_id,
                executor_id=executor.executor_id,
            ),
        )
    )
    return _Deployment(
        gate=ActionGate(
            casework=ravi.casework(database),
            executor=executor,
            authority=authority,
        ),
        caller=caller,
        executor=executor,
    )


def _manually_dispatched(
    deployment: _Deployment,
    tenant_id: str,
    request: ExecuteProposal,
) -> ExecutionRecord:
    reported = case_status(
        deployment.gate.casework,
        tenant_id=tenant_id,
        case_id=request.case_id,
        now=ravi.NOW,
    )
    assert isinstance(reported, Ok), reported
    eligible = current_action_intent(
        reported.value,
        request,
        tenant_id=tenant_id,
        gate_id=deployment.gate.gate_id,
        executor_id=deployment.executor.executor_id,
    )
    assert isinstance(eligible, Ok), eligible
    intent = eligible.value

    with deployment.gate.casework.database.writing(tenant_id) as scope:
        reserved = scope.executions.reserve(
            intent,
            requested_by=deployment.caller.principal_id,
            now=ravi.NOW,
        )
    assert isinstance(reserved, Ok) and reserved.value.acquired, reserved

    with deployment.gate.casework.database.writing(tenant_id) as scope:
        dispatched = scope.executions.begin_dispatch(intent.execution_key(), now=ravi.NOW)
    assert isinstance(dispatched, Ok) and dispatched.value.acquired, dispatched
    return dispatched.value.record


def _execution_rows(
    dsn: str, tenant_id: str, case_id: str
) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT execution_id, state, external_reference, outcome_code, "
            "reconciled_from, reconciled_at "
            "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchall()


def _transfer_rows(dsn: str, idempotency_key: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT idempotency_key, external_reference, accepted_at "
            "FROM sandbox_rail.transfer WHERE idempotency_key = %s",
            (idempotency_key,),
        ).fetchall()


def _attempt_rows(dsn: str, idempotency_key: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT idempotency_key, outcome, failure_code, failure_detail "
            "FROM sandbox_rail.attempt WHERE idempotency_key = %s",
            (idempotency_key,),
        ).fetchall()


def test_reconcile_while_transfer_uncommitted_stays_unknown_then_confirms(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    """ATTEMPTED is visible before the paused transfer can become visible."""
    dispatch_executor = _PausingTransferExecutor(migrated_dsn)
    dispatcher = _deployment_with_executor(
        migrated_dsn, tenant_id, dispatch_executor
    )
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(dispatcher.gate.casework, case)
    append_all(dispatcher.gate.casework, case, now=ravi.NOW)
    _report, request = proposal(dispatcher.gate.casework, case)

    with ThreadPoolExecutor(max_workers=1) as pool:
        dispatched = pool.submit(
            dispatcher.gate.execute,
            caller=dispatcher.caller,
            tenant_id=tenant_id,
            request=request,
            now=ravi.NOW,
        )
        dispatch_executor.transfer_inserted.wait()
        try:
            rows = _execution_rows(migrated_dsn, tenant_id, case_id)
            assert len(rows) == 1
            execution_key = rows[0][0]
            assert isinstance(execution_key, bytes)
            execution_key_hex = execution_key.hex()
            assert rows[0][1] == "DISPATCHED"
            assert _attempt_rows(migrated_dsn, execution_key_hex) == [
                (execution_key_hex, "ATTEMPTED", None, None)
            ]
            assert _transfer_rows(migrated_dsn, execution_key_hex) == []

            observer = _deployment(migrated_dsn, tenant_id)
            uncertain = observer.gate.reconcile_execution(
                caller=observer.caller,
                tenant_id=tenant_id,
                lookup=ExecutionLookup(
                    execution_key=ExecutionKey(execution_key),
                    expected_case_id=case_id,
                ),
                now=ravi.NOW + 1,
            )
        finally:
            dispatch_executor.allow_transfer_commit.set()
        dispatch_result = dispatched.result()

    assert isinstance(uncertain, Ok), uncertain
    assert uncertain.value.state is ExecutionState.UNCERTAIN
    assert uncertain.value.outcome_code == "SANDBOX_ATTEMPT_IN_PROGRESS"
    assert uncertain.value.reconciled_from is ExecutionState.DISPATCHED
    assert uncertain.value.reconciled_at == ravi.NOW + 1
    original_finalized_at = uncertain.value.finalized_at
    assert original_finalized_at == ravi.NOW + 1
    assert isinstance(dispatch_result, Err), dispatch_result
    assert observer.executor.dispatch_count == 0
    assert observer.executor.inspection_count == 1

    later = _deployment(migrated_dsn, tenant_id)
    confirmed = later.gate.reconcile_execution(
        caller=later.caller,
        tenant_id=tenant_id,
        lookup=ExecutionLookup(
            uncertain.value.execution_key,
            expected_case_id=case_id,
        ),
        now=ravi.NOW + 2,
    )

    assert isinstance(confirmed, Ok), confirmed
    assert confirmed.value.state is ExecutionState.CONFIRMED
    assert confirmed.value.external_reference == f"sandbox-pay-{execution_key_hex}"
    assert confirmed.value.finalized_at == original_finalized_at
    assert confirmed.value.reconciled_from is ExecutionState.UNCERTAIN
    assert confirmed.value.reconciled_at == ravi.NOW + 2
    assert dispatch_executor.dispatch_count == 1
    assert later.executor.dispatch_count == 0
    assert later.executor.inspection_count == 1
    assert _transfer_rows(migrated_dsn, execution_key_hex) == [
        (execution_key_hex, confirmed.value.external_reference, ravi.NOW)
    ]


def test_eight_independent_reconcilers_return_one_durable_confirmation(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    """Eight observers race; PostgreSQL makes every answer the winner's answer."""
    seeder = _deployment(migrated_dsn, tenant_id)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(seeder.gate.casework, case)
    append_all(seeder.gate.casework, case, now=ravi.NOW)
    _report, request = proposal(seeder.gate.casework, case)
    dispatched = _manually_dispatched(seeder, tenant_id, request)
    execution_key = dispatched.execution_key

    accepted = seeder.executor.dispatch(
        ExecutorDispatch(
            intent=dispatched.intent,
            idempotency_key=execution_key.hex,
            gate_id=seeder.gate.gate_id,
        )
    )
    assert isinstance(accepted, Confirmed), accepted
    external_reference = accepted.external_reference
    transfer_before = _transfer_rows(migrated_dsn, execution_key.hex)
    assert transfer_before == [(execution_key.hex, external_reference, ravi.NOW + 1)]

    contenders = [
        _deployment(migrated_dsn, tenant_id) for _ in range(_CONTENDER_COUNT)
    ]
    with ThreadPoolExecutor(max_workers=_CONTENDER_COUNT) as pool:
        results = [
            future.result()
            for future in [
                pool.submit(
                    contender.gate.reconcile_execution,
                    caller=contender.caller,
                    tenant_id=tenant_id,
                    lookup=ExecutionLookup(
                        execution_key=execution_key,
                        expected_case_id=case_id,
                    ),
                    now=ravi.NOW + 2,
                )
                for contender in contenders
            ]
        ]

    assert all(isinstance(result, Ok) for result in results), results
    records = [result.value for result in results if isinstance(result, Ok)]
    assert len(records) == _CONTENDER_COUNT
    assert {record.execution_key for record in records} == {execution_key}
    assert {record.state for record in records} == {ExecutionState.CONFIRMED}
    assert {record.external_reference for record in records} == {external_reference}

    rows = _execution_rows(migrated_dsn, tenant_id, case_id)
    assert len(rows) == 1
    row = rows[0]
    assert row[0] == execution_key.octets
    assert row[1] == "CONFIRMED"
    assert row[2] == external_reference
    assert row[3] == "CONFIRMED"
    assert row[4] == "DISPATCHED"
    assert row[5] is not None

    assert sum(contender.executor.dispatch_count for contender in contenders) == 0
    assert sum(contender.executor.inspection_count for contender in contenders) >= 1
    assert _transfer_rows(migrated_dsn, execution_key.hex) == transfer_before
