"""Exact-repeat idempotency rests on PostgreSQL and the existing execute path."""

from __future__ import annotations

from dataclasses import dataclass

import psycopg
import pytest

from muster.core.results import Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import case_status
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import SandboxMode, SandboxPaymentExecutor
from muster.platform.gate.model import ExecuteProposal, ExecutionState, Finality
from muster.platform.gate.service import ActionGate
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

pytestmark = pytest.mark.postgres

CALLER = GateCaller("postgres-exact-repeat-operator")


@dataclass(frozen=True, slots=True)
class _Deployment:
    gate: ActionGate
    executor: SandboxPaymentExecutor


def _deployment(
    dsn: str, tenant_id: str, *, mode: SandboxMode = SandboxMode.SUCCESS
) -> _Deployment:
    executor = SandboxPaymentExecutor(mode=mode)
    authority = LocalExecutionAuthority(
        (
            ExecutionGrant(
                principal_id=CALLER.principal_id,
                tenant_id=tenant_id,
                action_kind="PAY",
                gate_id=executor.trusted_gate_id,
                executor_id=executor.executor_id,
            ),
        )
    )
    return _Deployment(
        ActionGate(
            casework=ravi.casework(SqlDatabase(dsn)),
            executor=executor,
            authority=authority,
        ),
        executor,
    )


def _seeded(
    dsn: str, tenant_id: str, case_id: str
) -> tuple[_Deployment, ExecuteProposal]:
    deployment = _deployment(dsn, tenant_id)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(deployment.gate.casework, case)
    append_all(deployment.gate.casework, case, now=ravi.NOW)
    _report, request = proposal(deployment.gate.casework, case)
    return deployment, request


def _intent(deployment: _Deployment, tenant_id: str, request: ExecuteProposal):  # type: ignore[no-untyped-def]
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
    return eligible.value


def _execute(deployment: _Deployment, tenant_id: str, request: ExecuteProposal):  # type: ignore[no-untyped-def]
    return deployment.gate.execute(
        caller=CALLER,
        tenant_id=tenant_id,
        request=request,
        now=ravi.NOW,
    )


def _row(dsn: str, tenant_id: str, case_id: str) -> tuple[object, ...]:
    with psycopg.connect(dsn) as connection:
        rows = connection.execute(
            "SELECT tenant_id, case_id, execution_id, intent_octets, revision_number, "
            "revision_digest, certificate_digest, kernel_result_digest, "
            "bundle_manifest_digest, authorization_context_digest, action_schema_digest, "
            "action_digest, action_kind, gate_id, executor_id, requested_by, state, "
            "reserved_at, dispatched_at, finalized_at, external_reference, outcome_code, detail "
            "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchall()
    assert len(rows) == 1
    return rows[0]


def test_second_identical_execute_reuses_confirmation_without_dispatch(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    first, request = _seeded(migrated_dsn, tenant_id, case_id)
    executed = _execute(first, tenant_id, request)
    assert isinstance(executed, Ok), executed
    assert executed.value.state is ExecutionState.CONFIRMED
    assert first.executor.dispatch_count == 1

    repeat = _deployment(migrated_dsn, tenant_id)
    repeated = _execute(repeat, tenant_id, request)

    assert isinstance(repeated, Ok), repeated
    assert repeated.value.state is ExecutionState.CONFIRMED
    assert repeated.value.execution_key == executed.value.execution_key
    assert repeated.value.external_reference == executed.value.external_reference
    assert repeat.executor.dispatch_count == 0
    assert repeat.executor.execution_count == 0


def test_repeat_neither_creates_a_row_nor_moves_the_existing_row(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    first, request = _seeded(migrated_dsn, tenant_id, case_id)
    executed = _execute(first, tenant_id, request)
    assert isinstance(executed, Ok), executed
    before = _row(migrated_dsn, tenant_id, case_id)

    repeat = _deployment(migrated_dsn, tenant_id)
    repeated = _execute(repeat, tenant_id, request)
    after = _row(migrated_dsn, tenant_id, case_id)

    assert isinstance(repeated, Ok), repeated
    assert after == before
    assert repeat.executor.dispatch_count == 0


def test_five_exact_repeats_all_dispatch_zero_times(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    first, request = _seeded(migrated_dsn, tenant_id, case_id)
    executed = _execute(first, tenant_id, request)
    assert isinstance(executed, Ok), executed

    repeats = [_deployment(migrated_dsn, tenant_id) for _ in range(5)]
    results = [_execute(repeat, tenant_id, request) for repeat in repeats]

    assert all(isinstance(result, Ok) for result in results), results
    assert all(result.value == executed.value for result in results if isinstance(result, Ok))
    assert sum(repeat.executor.dispatch_count for repeat in repeats) == 0
    assert _row(migrated_dsn, tenant_id, case_id)[16] == "CONFIRMED"


def test_repeat_over_dispatched_returns_unknown_finality_without_dispatch(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    first, request = _seeded(migrated_dsn, tenant_id, case_id)
    intent = _intent(first, tenant_id, request)
    with first.gate.casework.database.writing(tenant_id) as scope:
        reserved = scope.executions.reserve(
            intent, requested_by=CALLER.principal_id, now=ravi.NOW
        )
    assert isinstance(reserved, Ok) and reserved.value.acquired
    with first.gate.casework.database.writing(tenant_id) as scope:
        begun = scope.executions.begin_dispatch(intent.execution_key(), now=ravi.NOW)
    assert isinstance(begun, Ok) and begun.value.acquired

    repeat = _deployment(migrated_dsn, tenant_id)
    repeated = _execute(repeat, tenant_id, request)

    assert isinstance(repeated, Ok), repeated
    assert repeated.value.state is ExecutionState.DISPATCHED
    assert repeated.value.finality is Finality.OUTCOME_UNKNOWN
    assert repeat.executor.dispatch_count == 0


def test_repeat_over_reserved_dispatches_once_across_independent_executors(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    seeded, request = _seeded(migrated_dsn, tenant_id, case_id)
    intent = _intent(seeded, tenant_id, request)
    with seeded.gate.casework.database.writing(tenant_id) as scope:
        reserved = scope.executions.reserve(
            intent, requested_by=CALLER.principal_id, now=ravi.NOW
        )
    assert isinstance(reserved, Ok) and reserved.value.acquired

    first = _deployment(migrated_dsn, tenant_id)
    second = _deployment(migrated_dsn, tenant_id)
    recovered = _execute(first, tenant_id, request)
    repeated = _execute(second, tenant_id, request)

    assert isinstance(recovered, Ok), recovered
    assert isinstance(repeated, Ok), repeated
    assert recovered.value.state is ExecutionState.CONFIRMED
    assert repeated.value == recovered.value
    assert first.executor.dispatch_count + second.executor.dispatch_count == 1


def test_repeat_over_failed_returns_failure_without_dispatch(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    _first, request = _seeded(migrated_dsn, tenant_id, case_id)
    failing = _deployment(
        migrated_dsn,
        tenant_id,
        mode=SandboxMode.DEFINITE_PRE_DISPATCH_FAILURE,
    )
    failed = _execute(failing, tenant_id, request)
    assert isinstance(failed, Ok), failed
    assert failed.value.state is ExecutionState.FAILED
    assert failing.executor.dispatch_count == 1

    repeat = _deployment(migrated_dsn, tenant_id)
    repeated = _execute(repeat, tenant_id, request)

    assert isinstance(repeated, Ok), repeated
    assert repeated.value == failed.value
    assert repeated.value.finality is Finality.DEFINITELY_NOT_EXECUTED
    assert repeat.executor.dispatch_count == 0


def test_primary_key_refuses_a_second_raw_insert(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    first, request = _seeded(migrated_dsn, tenant_id, case_id)
    assert isinstance(_execute(first, tenant_id, request), Ok)

    with psycopg.connect(migrated_dsn) as connection:
        duplicate = connection.execute(
            "INSERT INTO action_gate.execution "
            "SELECT * FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s "
            "ON CONFLICT DO NOTHING",
            (tenant_id, case_id),
        )
        assert duplicate.rowcount == 0
    assert _row(migrated_dsn, tenant_id, case_id)[16] == "CONFIRMED"


def test_two_confirmed_rows_with_one_external_reference_are_unrepresentable(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    first, request = _seeded(migrated_dsn, tenant_id, case_id)
    assert isinstance(_execute(first, tenant_id, request), Ok)

    with psycopg.connect(migrated_dsn) as connection:
        with pytest.raises(psycopg.errors.UniqueViolation) as raised:
            connection.execute(
                "INSERT INTO action_gate.execution "
                "SELECT tenant_id, case_id, %s, intent_octets, revision_number + 1, "
                "revision_digest, certificate_digest, kernel_result_digest, "
                "bundle_manifest_digest, authorization_context_digest, action_schema_digest, "
                "action_digest, action_kind, gate_id, executor_id, requested_by, state, "
                "reserved_at, dispatched_at, finalized_at, external_reference, outcome_code, "
                "detail "
                "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s",
                (b"\xa6" * 32, tenant_id, case_id),
            )
        assert raised.value.diag.constraint_name == "action_gate_external_reference_unique"
