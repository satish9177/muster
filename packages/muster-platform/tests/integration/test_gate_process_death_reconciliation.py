"""Real process-death and crash-window proofs for durable reconciliation."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest

from muster.core.results import Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.sandbox_rail import DurableSandboxPaymentExecutor
from muster.platform.casework.commands import case_status
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import (
    ActionExecutor,
    Confirmed,
    DefiniteFailure,
    ExecutorDispatch,
    ExecutorInquiry,
    ExecutorOutcome,
    NotExecuted,
    ReconciliationAnswer,
    StillUnknown,
)
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

REPOSITORY = Path(__file__).resolve().parents[4]

_CHILD = r"""
import json
import os
import sys
from pathlib import Path

from muster.core.results import Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.sandbox_rail import DurableSandboxPaymentExecutor
from muster.platform.casework.commands import case_status
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import Confirmed, ExecutorDispatch
from muster.platform.gate.service import ActionGate
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

dsn, tenant_id, case_id, mode, output_name = sys.argv[1:]


class _DiesAfterAttempt(DurableSandboxPaymentExecutor):
    def _before_external_effect(self, request: ExecutorDispatch) -> None:
        Path(output_name).write_text(json.dumps({
            "execution_key": request.idempotency_key,
            "state": "DISPATCHED",
        }), encoding="utf-8")
        os._exit(74)


database = SqlDatabase(dsn)
casework = ravi.casework(database)
case = ravi.ravi(tenant_id, case_id, attested=True)
open_ravi(casework, case)
append_all(casework, case, now=ravi.NOW)
_report, request = proposal(casework, case)
caller = GateCaller("process-death-operator")
executor = (
    _DiesAfterAttempt(dsn, accepted_at=ravi.NOW)
    if mode == "after_attempt"
    else DurableSandboxPaymentExecutor(dsn, accepted_at=ravi.NOW)
)
gate = ActionGate(
    casework=casework,
    executor=executor,
    authority=LocalExecutionAuthority((ExecutionGrant(
        principal_id=caller.principal_id,
        tenant_id=tenant_id,
        action_kind="PAY",
        gate_id=executor.trusted_gate_id,
        executor_id=executor.executor_id,
    ),)),
)
reported = case_status(casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
assert isinstance(reported, Ok), reported
eligible = current_action_intent(
    reported.value,
    request,
    tenant_id=tenant_id,
    gate_id=gate.gate_id,
    executor_id=executor.executor_id,
)
assert isinstance(eligible, Ok), eligible
intent = eligible.value
assert gate.authority.may_invoke(
    caller,
    tenant_id=tenant_id,
    gate_id=gate.gate_id,
    executor_id=executor.executor_id,
)
assert gate.authority.permits(
    caller,
    tenant_id=tenant_id,
    action_kind=intent.action.kind,
    gate_id=gate.gate_id,
    executor_id=executor.executor_id,
)
with database.writing(tenant_id) as scope:
    reserved = scope.executions.reserve(
        intent, requested_by=caller.principal_id, now=ravi.NOW
    )
assert isinstance(reserved, Ok) and reserved.value.acquired, reserved
with database.writing(tenant_id) as scope:
    claimed = scope.executions.begin_dispatch(intent.execution_key(), now=ravi.NOW)
assert isinstance(claimed, Ok) and claimed.value.acquired, claimed

if mode == "before_external":
    # Rendezvous A: the DISPATCHED CAS is committed, but dispatch has not been
    # called. Closing this file makes the parent wait on an explicit event.
    Path(output_name).write_text(json.dumps({
        "execution_key": intent.execution_key().hex,
        "state": claimed.value.record.state.value,
    }), encoding="utf-8")
    os._exit(71)

outcome = executor.dispatch(ExecutorDispatch(
    intent=claimed.value.record.intent,
    idempotency_key=claimed.value.record.execution_key.hex,
    gate_id=gate.gate_id,
))
assert isinstance(outcome, Confirmed), outcome

# Rendezvous B: dispatch returned only after its independent sandbox_rail
# transaction committed. ActionGate.execute/finalize has never been called.
# The closed file is the deterministic signal; death is immediate afterwards.
Path(output_name).write_text(json.dumps({
    "execution_key": intent.execution_key().hex,
    "external_reference": outcome.external_reference,
    "state": claimed.value.record.state.value,
}), encoding="utf-8")
os._exit(72)
"""


def _run_crashing_child(
    dsn: str,
    tenant_id: str,
    case_id: str,
    mode: str,
    output: Path,
) -> dict[str, Any]:
    environment = os.environ.copy()
    pythonpath = [
        REPOSITORY,
        REPOSITORY / "packages" / "muster-kernel" / "src",
        REPOSITORY / "packages" / "muster-kernel",
        REPOSITORY / "packages" / "muster-platform" / "src",
        REPOSITORY / "packages" / "muster-platform" / "tests",
    ]
    environment["PYTHONPATH"] = os.pathsep.join(map(str, pythonpath))
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and local test program
        [
            sys.executable,
            "-c",
            _CHILD,
            dsn,
            tenant_id,
            case_id,
            mode,
            str(output),
        ],
        cwd=REPOSITORY,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    expected = {"before_external": 71, "after_attempt": 74, "after_external": 72}[mode]
    assert completed.returncode == expected, completed.stderr
    loaded: object = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, Any], loaded)


def _gate(
    dsn: str,
    tenant_id: str,
    caller: GateCaller,
    executor: ActionExecutor,
) -> ActionGate:
    return ActionGate(
        casework=ravi.casework(SqlDatabase(dsn)),
        executor=executor,
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=caller.principal_id,
                    tenant_id=tenant_id,
                    action_kind="PAY",
                    gate_id=executor.trusted_gate_id,
                    executor_id=executor.executor_id,
                ),
            )
        ),
    )


def _lookup(data: dict[str, Any], case_id: str) -> ExecutionLookup:
    raw = data["execution_key"]
    assert isinstance(raw, str)
    return ExecutionLookup(ExecutionKey(bytes.fromhex(raw)), expected_case_id=case_id)


def _external_rows(dsn: str, execution_key: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT idempotency_key, external_reference, accepted_at "
            "FROM sandbox_rail.transfer WHERE idempotency_key = %s",
            (execution_key,),
        ).fetchall()


def _attempt_rows(dsn: str, execution_key: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT idempotency_key, outcome, failure_code, failure_detail "
            "FROM sandbox_rail.attempt WHERE idempotency_key = %s",
            (execution_key,),
        ).fetchall()


def _gate_state(dsn: str, tenant_id: str, execution_key: str) -> str:
    with psycopg.connect(dsn) as connection:
        row = connection.execute(
            "SELECT state FROM action_gate.execution "
            "WHERE tenant_id = %s AND execution_id = %s",
            (tenant_id, bytes.fromhex(execution_key)),
        ).fetchone()
    assert row is not None and isinstance(row[0], str)
    return row[0]


def test_external_acceptance_survives_abrupt_process_death_and_reconciles(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    child = _run_crashing_child(
        migrated_dsn,
        tenant_id,
        case_id,
        "after_external",
        tmp_path / "accepted.json",
    )
    execution_key = cast(str, child["execution_key"])
    external_reference = cast(str, child["external_reference"])

    assert _gate_state(migrated_dsn, tenant_id, execution_key) == "DISPATCHED"
    assert _attempt_rows(migrated_dsn, execution_key) == [
        (execution_key, "ATTEMPTED", None, None)
    ]
    assert _external_rows(migrated_dsn, execution_key) == [
        (execution_key, external_reference, ravi.NOW)
    ]

    caller = GateCaller("process-death-operator")
    executor = DurableSandboxPaymentExecutor(migrated_dsn, accepted_at=ravi.NOW + 1)
    gate = _gate(migrated_dsn, tenant_id, caller, executor)
    reconciled = gate.reconcile_execution(
        caller=caller,
        tenant_id=tenant_id,
        lookup=_lookup(child, case_id),
        now=ravi.NOW + 1,
    )

    assert isinstance(reconciled, Ok), reconciled
    assert reconciled.value.state is ExecutionState.CONFIRMED
    assert reconciled.value.external_reference == external_reference
    assert executor.dispatch_count == 0
    assert executor.inspection_count == 1
    assert executor.transfer_count(execution_key) == 1
    assert _external_rows(migrated_dsn, execution_key) == [
        (execution_key, external_reference, ravi.NOW)
    ]


def test_process_dies_after_dispatched_cas_before_external_call(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    child = _run_crashing_child(
        migrated_dsn,
        tenant_id,
        case_id,
        "before_external",
        tmp_path / "before-external.json",
    )
    execution_key = cast(str, child["execution_key"])
    assert _gate_state(migrated_dsn, tenant_id, execution_key) == "DISPATCHED"
    assert _attempt_rows(migrated_dsn, execution_key) == []
    assert _external_rows(migrated_dsn, execution_key) == []

    caller = GateCaller("process-death-operator")
    executor = DurableSandboxPaymentExecutor(migrated_dsn, accepted_at=ravi.NOW + 1)
    reconciled = _gate(migrated_dsn, tenant_id, caller, executor).reconcile_execution(
        caller=caller,
        tenant_id=tenant_id,
        lookup=_lookup(child, case_id),
        now=ravi.NOW + 1,
    )

    assert isinstance(reconciled, Ok), reconciled
    assert reconciled.value.state is ExecutionState.FAILED
    assert reconciled.value.outcome_code == "SANDBOX_DEFINITIVELY_NOT_EXECUTED"
    assert executor.dispatch_count == 0
    assert executor.inspection_count == 1
    assert executor.transfer_count(execution_key) == 0
    assert _attempt_rows(migrated_dsn, execution_key) == [
        (
            execution_key,
            "DEFINITIVELY_NOT_EXECUTED",
            "SANDBOX_DEFINITIVELY_NOT_EXECUTED",
            "the simulated external system sealed this key before any attempt",
        )
    ]


def test_process_dies_after_attempt_before_external_effect_is_unknown(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    child = _run_crashing_child(
        migrated_dsn,
        tenant_id,
        case_id,
        "after_attempt",
        tmp_path / "after-attempt.json",
    )
    execution_key = cast(str, child["execution_key"])
    assert _gate_state(migrated_dsn, tenant_id, execution_key) == "DISPATCHED"
    assert _attempt_rows(migrated_dsn, execution_key) == [
        (execution_key, "ATTEMPTED", None, None)
    ]
    assert _external_rows(migrated_dsn, execution_key) == []

    caller = GateCaller("process-death-operator")
    executor = DurableSandboxPaymentExecutor(migrated_dsn, accepted_at=ravi.NOW + 1)
    reconciled = _gate(migrated_dsn, tenant_id, caller, executor).reconcile_execution(
        caller=caller,
        tenant_id=tenant_id,
        lookup=_lookup(child, case_id),
        now=ravi.NOW + 1,
    )

    assert isinstance(reconciled, Ok), reconciled
    assert reconciled.value.state is ExecutionState.UNCERTAIN
    assert reconciled.value.outcome_code == "SANDBOX_ATTEMPT_IN_PROGRESS"
    assert reconciled.value.reconciled_from is ExecutionState.DISPATCHED
    assert executor.dispatch_count == 0
    assert executor.inspection_count == 1
    assert executor.transfer_count(execution_key) == 0


class _RaisesAfterAcceptance(DurableSandboxPaymentExecutor):
    def dispatch(self, request: ExecutorDispatch) -> ExecutorOutcome:
        accepted = super().dispatch(request)
        assert isinstance(accepted, Confirmed)
        raise RuntimeError("process lost the accepted result")


class _StillUnknownExecutor:
    executor_id = "sandbox-payment/v1"
    trusted_gate_id = "local-action-gate/v1"
    transfers_real_funds = False

    def __init__(self) -> None:
        self.dispatch_count = 0
        self.inspection_count = 0

    def dispatch(self, request: ExecutorDispatch) -> ExecutorOutcome:
        self.dispatch_count += 1
        raise AssertionError(f"reconciliation dispatched {request.idempotency_key}")

    def inspect(self, inquiry: ExecutorInquiry) -> ReconciliationAnswer:
        self.inspection_count += 1
        return StillUnknown(
            "SANDBOX_EXTERNAL_QUERY_UNAVAILABLE",
            f"no durable answer for {inquiry.idempotency_key}",
        )


def _prepared_gate(
    dsn: str,
    tenant_id: str,
    case_id: str,
    executor: ActionExecutor,
    *,
    principal_id: str,
) -> tuple[ActionGate, GateCaller, ExecuteProposal]:
    casework = ravi.casework(SqlDatabase(dsn))
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    _report, request = proposal(casework, case)
    caller = GateCaller(principal_id)
    return _gate(dsn, tenant_id, caller, executor), caller, request


def _manually_dispatched(
    gate: ActionGate,
    caller: GateCaller,
    tenant_id: str,
    request: ExecuteProposal,
) -> ExecutionRecord:
    reported = case_status(
        gate.casework, tenant_id=tenant_id, case_id=request.case_id, now=ravi.NOW
    )
    assert isinstance(reported, Ok), reported
    eligible = current_action_intent(
        reported.value,
        request,
        tenant_id=tenant_id,
        gate_id=gate.gate_id,
        executor_id=gate.executor.executor_id,
    )
    assert isinstance(eligible, Ok), eligible
    intent = eligible.value
    with gate.casework.database.writing(tenant_id) as scope:
        reserved = scope.executions.reserve(
            intent, requested_by=caller.principal_id, now=ravi.NOW
        )
    assert isinstance(reserved, Ok) and reserved.value.acquired
    with gate.casework.database.writing(tenant_id) as scope:
        claimed = scope.executions.begin_dispatch(intent.execution_key(), now=ravi.NOW)
    assert isinstance(claimed, Ok) and claimed.value.acquired
    return claimed.value.record


def test_uncertain_external_result_later_proves_original_acceptance(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    uncertain_executor = _RaisesAfterAcceptance(migrated_dsn, accepted_at=ravi.NOW)
    gate, caller, request = _prepared_gate(
        migrated_dsn,
        tenant_id,
        case_id,
        uncertain_executor,
        principal_id="uncertain-result-operator",
    )
    uncertain = gate.execute(
        caller=caller, tenant_id=tenant_id, request=request, now=ravi.NOW
    )
    assert isinstance(uncertain, Ok), uncertain
    assert uncertain.value.state is ExecutionState.UNCERTAIN
    assert uncertain.value.finalized_at == ravi.NOW
    original_finalized_at = uncertain.value.finalized_at
    execution_key = uncertain.value.execution_key.hex
    original_external = _external_rows(migrated_dsn, execution_key)
    assert len(original_external) == 1

    fresh_executor = DurableSandboxPaymentExecutor(
        migrated_dsn, accepted_at=ravi.NOW + 1
    )
    fresh_gate = _gate(migrated_dsn, tenant_id, caller, fresh_executor)
    reconciled = fresh_gate.reconcile_execution(
        caller=caller,
        tenant_id=tenant_id,
        lookup=ExecutionLookup(
            uncertain.value.execution_key, expected_case_id=case_id
        ),
        now=ravi.NOW + 1,
    )

    assert isinstance(reconciled, Ok), reconciled
    assert reconciled.value.state is ExecutionState.CONFIRMED
    assert reconciled.value.external_reference == original_external[0][1]
    assert reconciled.value.finalized_at == original_finalized_at
    assert reconciled.value.reconciled_at == ravi.NOW + 1
    assert reconciled.value.reconciled_from is ExecutionState.UNCERTAIN
    assert fresh_executor.dispatch_count == 0
    assert fresh_executor.inspection_count == 1
    assert fresh_executor.transfer_count(execution_key) == 1


def test_genuine_non_execution_from_durable_negative_evidence_becomes_failed(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    failure = DefiniteFailure(
        "SANDBOX_PROVIDER_REFUSAL",
        "the simulation durably refused before creating an external effect",
    )
    executor = DurableSandboxPaymentExecutor(
        migrated_dsn,
        accepted_at=ravi.NOW,
        definite_failure=failure,
    )
    gate, caller, request = _prepared_gate(
        migrated_dsn,
        tenant_id,
        case_id,
        executor,
        principal_id="non-execution-operator",
    )
    dispatched = _manually_dispatched(gate, caller, tenant_id, request)
    assert _external_rows(migrated_dsn, dispatched.execution_key.hex) == []

    outcome = executor.dispatch(
        ExecutorDispatch(
            intent=dispatched.intent,
            idempotency_key=dispatched.execution_key.hex,
            gate_id=gate.gate_id,
        )
    )
    assert outcome == failure
    assert _attempt_rows(migrated_dsn, dispatched.execution_key.hex) == [
        (
            dispatched.execution_key.hex,
            "DEFINITIVELY_NOT_EXECUTED",
            failure.code,
            failure.detail,
        )
    ]

    fresh_executor = DurableSandboxPaymentExecutor(migrated_dsn, accepted_at=ravi.NOW + 1)
    reconciled = _gate(migrated_dsn, tenant_id, caller, fresh_executor).reconcile_execution(
        caller=caller,
        tenant_id=tenant_id,
        lookup=ExecutionLookup(dispatched.execution_key, expected_case_id=case_id),
        now=ravi.NOW + 1,
    )

    assert isinstance(reconciled, Ok), reconciled
    assert reconciled.value.state is ExecutionState.FAILED
    assert reconciled.value.outcome_code == failure.code
    assert reconciled.value.detail == failure.detail
    assert executor.dispatch_count == 1
    assert fresh_executor.dispatch_count == 0
    assert fresh_executor.inspection_count == 1
    assert executor.transfer_count(dispatched.execution_key.hex) == 0


def test_absent_attempt_is_durably_sealed_before_not_executed_is_returned(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    executor = DurableSandboxPaymentExecutor(migrated_dsn, accepted_at=ravi.NOW)
    gate, caller, request = _prepared_gate(
        migrated_dsn,
        tenant_id,
        case_id,
        executor,
        principal_id="negative-tombstone-operator",
    )
    dispatched = _manually_dispatched(gate, caller, tenant_id, request)
    inquiry = ExecutorInquiry(
        intent=dispatched.intent,
        idempotency_key=dispatched.execution_key.hex,
        gate_id=gate.gate_id,
    )

    answer = executor.inspect(inquiry)

    assert isinstance(answer, NotExecuted)
    assert _attempt_rows(migrated_dsn, dispatched.execution_key.hex) == [
        (
            dispatched.execution_key.hex,
            "DEFINITIVELY_NOT_EXECUTED",
            answer.code,
            answer.detail,
        )
    ]
    delayed = executor.dispatch(
        ExecutorDispatch(
            intent=dispatched.intent,
            idempotency_key=dispatched.execution_key.hex,
            gate_id=gate.gate_id,
        )
    )
    assert delayed == DefiniteFailure(answer.code, answer.detail)
    assert executor.transfer_count(dispatched.execution_key.hex) == 0


def test_durable_sandbox_rail_dispatch_is_idempotent(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    executor = DurableSandboxPaymentExecutor(migrated_dsn, accepted_at=ravi.NOW)
    gate, caller, request = _prepared_gate(
        migrated_dsn,
        tenant_id,
        case_id,
        executor,
        principal_id="rail-idempotency-operator",
    )
    dispatched = _manually_dispatched(gate, caller, tenant_id, request)
    dispatch = ExecutorDispatch(
        intent=dispatched.intent,
        idempotency_key=dispatched.execution_key.hex,
        gate_id=gate.gate_id,
    )

    first = executor.dispatch(dispatch)
    duplicate = executor.dispatch(dispatch)

    assert isinstance(first, Confirmed) and not first.duplicate
    assert duplicate == Confirmed(first.external_reference, duplicate=True)
    assert _attempt_rows(migrated_dsn, dispatched.execution_key.hex) == [
        (dispatched.execution_key.hex, "ATTEMPTED", None, None)
    ]
    assert _external_rows(migrated_dsn, dispatched.execution_key.hex) == [
        (dispatched.execution_key.hex, first.external_reference, ravi.NOW)
    ]
    assert executor.transfer_count(dispatched.execution_key.hex) == 1


def test_still_unknown_transitions_once_and_does_not_rewrite_uncertain(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    executor = _StillUnknownExecutor()
    gate, caller, request = _prepared_gate(
        migrated_dsn,
        tenant_id,
        case_id,
        executor,
        principal_id="still-unknown-operator",
    )
    dispatched = _manually_dispatched(gate, caller, tenant_id, request)
    lookup = ExecutionLookup(dispatched.execution_key, expected_case_id=case_id)
    uncertain = gate.reconcile_execution(
        caller=caller, tenant_id=tenant_id, lookup=lookup, now=ravi.NOW + 1
    )
    assert isinstance(uncertain, Ok), uncertain
    assert uncertain.value.state is ExecutionState.UNCERTAIN
    assert uncertain.value.reconciled_at == ravi.NOW + 1
    assert uncertain.value.reconciled_from is ExecutionState.DISPATCHED

    before = uncertain.value
    repeated = gate.reconcile_execution(
        caller=caller, tenant_id=tenant_id, lookup=lookup, now=ravi.NOW + 2
    )

    assert isinstance(repeated, Ok), repeated
    assert repeated.value == before
    assert repeated.value.reconciled_at == before.reconciled_at
    assert repeated.value.reconciled_from == before.reconciled_from
    assert executor.dispatch_count == 0
    assert executor.inspection_count == 2
