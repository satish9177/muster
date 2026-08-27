"""Reconciliation observes an existing execution and has no dispatch path."""

from __future__ import annotations

import ast
import inspect
import textwrap
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from muster.core.results import Err, Ok
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.casework.commands import case_status
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import (
    ActionExecutor,
    ExecutedAs,
    ExecutorDispatch,
    ExecutorInquiry,
    ExecutorOutcome,
    NotExecuted,
    ReconciliationAnswer,
    SandboxPaymentExecutor,
    StillUnknown,
)
from muster.platform.gate.model import (
    ExecuteProposal,
    ExecutionLookup,
    ExecutionRecord,
    ExecutionState,
)
from muster.platform.gate.service import ActionGate, GateFailure
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

TENANT = "reconciliation-tenant"
CASE = "reconciliation-case"
CALLER = GateCaller("reconciliation-operator")


@dataclass(slots=True)
class _InspectingExecutor:
    """A read-capable executor whose action method makes any dispatch fail loudly."""

    answer: ReconciliationAnswer | Exception
    executor_id: str = "sandbox-payment/v1"
    trusted_gate_id: str = "local-action-gate/v1"
    transfers_real_funds: bool = False
    inspect_hook: Callable[[ExecutorInquiry], ReconciliationAnswer] | None = None
    inquiries: list[ExecutorInquiry] = field(default_factory=list, init=False)

    def dispatch(self, request: ExecutorDispatch) -> ExecutorOutcome:
        raise AssertionError(f"reconciliation dispatched {request.idempotency_key}")

    def inspect(self, inquiry: ExecutorInquiry) -> ReconciliationAnswer:
        self.inquiries.append(inquiry)
        if self.inspect_hook is not None:
            return self.inspect_hook(inquiry)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _gate(executor: ActionExecutor) -> tuple[ActionGate, ExecuteProposal]:
    database = MemoryDatabase()
    casework = ravi.casework(database)
    case = ravi.ravi(TENANT, CASE, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    _report, request = proposal(casework, case)
    gate = ActionGate(
        casework=casework,
        executor=executor,
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=CALLER.principal_id,
                    tenant_id=TENANT,
                    action_kind="PAY",
                    gate_id=executor.trusted_gate_id,
                    executor_id=executor.executor_id,
                ),
            )
        ),
    )
    return gate, request


def _seed(
    executor: ActionExecutor, state: ExecutionState
) -> tuple[ActionGate, ExecutionLookup, ExecutionRecord]:
    gate, request = _gate(executor)
    reported = case_status(gate.casework, tenant_id=TENANT, case_id=CASE, now=ravi.NOW)
    assert isinstance(reported, Ok)
    eligible = current_action_intent(
        reported.value,
        request,
        tenant_id=TENANT,
        gate_id=gate.gate_id,
        executor_id=executor.executor_id,
    )
    assert isinstance(eligible, Ok)
    intent = eligible.value
    with gate.casework.database.writing(TENANT) as scope:
        reserved = scope.executions.reserve(
            intent, requested_by=CALLER.principal_id, now=ravi.NOW
        )
    assert isinstance(reserved, Ok)
    record = reserved.value.record
    if state is not ExecutionState.RESERVED:
        with gate.casework.database.writing(TENANT) as scope:
            begun = scope.executions.begin_dispatch(
                intent.execution_key(), now=ravi.NOW + 1
            )
        assert isinstance(begun, Ok)
        record = begun.value.record
    if state in {ExecutionState.CONFIRMED, ExecutionState.FAILED, ExecutionState.UNCERTAIN}:
        with gate.casework.database.writing(TENANT) as scope:
            finalized = scope.executions.finalize(
                intent.execution_key(),
                state=state,
                outcome_code="ORIGINAL",
                external_reference="original-reference"
                if state is ExecutionState.CONFIRMED
                else None,
                detail=None,
                now=ravi.NOW + 2,
            )
        assert isinstance(finalized, Ok)
        record = finalized.value
    return (
        gate,
        ExecutionLookup(intent.execution_key(), expected_case_id=CASE),
        record,
    )


@pytest.mark.parametrize(
    ("source", "answer", "target", "external_reference"),
    (
        (
            ExecutionState.DISPATCHED,
            ExecutedAs("observed-reference"),
            ExecutionState.CONFIRMED,
            "observed-reference",
        ),
        (
            ExecutionState.DISPATCHED,
            NotExecuted("NOT_EXECUTED", "the rail has no effect"),
            ExecutionState.FAILED,
            None,
        ),
        (
            ExecutionState.DISPATCHED,
            StillUnknown("NO_ANSWER", "the rail cannot decide"),
            ExecutionState.UNCERTAIN,
            None,
        ),
        (
            ExecutionState.UNCERTAIN,
            ExecutedAs("late-reference"),
            ExecutionState.CONFIRMED,
            "late-reference",
        ),
        (
            ExecutionState.UNCERTAIN,
            NotExecuted("ABSENT", "the rail proves absence"),
            ExecutionState.FAILED,
            None,
        ),
    ),
)
def test_each_observation_maps_to_one_durable_transition_without_dispatch(
    source: ExecutionState,
    answer: ReconciliationAnswer,
    target: ExecutionState,
    external_reference: str | None,
) -> None:
    executor = _InspectingExecutor(answer)
    gate, lookup, before = _seed(executor, source)

    reconciled = gate.reconcile_execution(
        caller=CALLER,
        tenant_id=TENANT,
        lookup=lookup,
        now=ravi.NOW + 10,
    )

    assert isinstance(reconciled, Ok), reconciled
    assert reconciled.value.state is target
    assert reconciled.value.external_reference == external_reference
    assert reconciled.value.reconciled_from is source
    assert reconciled.value.reconciled_at == ravi.NOW + 10
    expected_finalized = (
        ravi.NOW + 10 if source is ExecutionState.DISPATCHED else before.finalized_at
    )
    assert reconciled.value.finalized_at == expected_finalized
    assert len(executor.inquiries) == 1
    inquiry = executor.inquiries[0]
    assert inquiry.intent == before.intent
    assert inquiry.idempotency_key == lookup.execution_key.hex
    assert inquiry.gate_id == gate.gate_id


def test_still_unknown_does_not_rewrite_an_already_uncertain_row() -> None:
    executor = _InspectingExecutor(StillUnknown("STILL_UNKNOWN", "no new evidence"))
    gate, lookup, before = _seed(executor, ExecutionState.UNCERTAIN)

    reconciled = gate.reconcile_execution(
        caller=CALLER, tenant_id=TENANT, lookup=lookup, now=ravi.NOW + 10
    )

    assert isinstance(reconciled, Ok)
    assert reconciled.value == before
    assert len(executor.inquiries) == 1


def test_an_inspection_exception_is_durable_unknown_not_a_new_failure_kind() -> None:
    executor = _InspectingExecutor(RuntimeError("connection broke during observation"))
    gate, lookup, _before = _seed(executor, ExecutionState.DISPATCHED)

    reconciled = gate.reconcile_execution(
        caller=CALLER, tenant_id=TENANT, lookup=lookup, now=ravi.NOW + 10
    )

    assert isinstance(reconciled, Ok)
    assert reconciled.value.state is ExecutionState.UNCERTAIN
    assert reconciled.value.outcome_code == "EXECUTOR_INSPECTION_EXCEPTION"
    assert reconciled.value.detail == "RuntimeError"
    assert len(executor.inquiries) == 1


@pytest.mark.parametrize(
    "state",
    (ExecutionState.RESERVED, ExecutionState.CONFIRMED, ExecutionState.FAILED),
)
def test_states_that_need_no_observation_never_reach_the_executor(
    state: ExecutionState,
) -> None:
    executor = _InspectingExecutor(ExecutedAs("must-not-be-used"))
    gate, lookup, before = _seed(executor, state)

    result = gate.reconcile_execution(
        caller=CALLER, tenant_id=TENANT, lookup=lookup, now=ravi.NOW + 10
    )

    assert executor.inquiries == []
    if state is ExecutionState.RESERVED:
        assert isinstance(result, Err)
        assert result.error.failure is GateFailure.NOTHING_TO_RECONCILE
    else:
        assert isinstance(result, Ok)
        assert result.value == before


def test_an_existing_action_executor_may_decline_reconciliation() -> None:
    executor = SandboxPaymentExecutor()
    gate, lookup, _before = _seed(executor, ExecutionState.DISPATCHED)

    refused = gate.reconcile_execution(
        caller=CALLER, tenant_id=TENANT, lookup=lookup, now=ravi.NOW + 10
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTOR_NOT_RECONCILABLE
    assert executor.dispatch_count == 0


def test_authority_is_refused_before_inspection() -> None:
    executor = _InspectingExecutor(ExecutedAs("must-not-be-used"))
    gate, lookup, _before = _seed(executor, ExecutionState.DISPATCHED)

    refused = gate.reconcile_execution(
        caller=GateCaller("intruder"),
        tenant_id=TENANT,
        lookup=lookup,
        now=ravi.NOW + 10,
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_AUTHORITY_REFUSED
    assert executor.inquiries == []


def test_a_losing_reconciler_returns_the_winners_durable_answer() -> None:
    executor = _InspectingExecutor(NotExecuted("LOSER", "must not replace winner"))
    gate, lookup, _before = _seed(executor, ExecutionState.DISPATCHED)

    def win_before_returning(_inquiry: ExecutorInquiry) -> ReconciliationAnswer:
        with gate.casework.database.writing(TENANT) as scope:
            winner = scope.executions.reconcile(
                lookup.execution_key,
                source_state=ExecutionState.DISPATCHED,
                state=ExecutionState.CONFIRMED,
                outcome_code="CONFIRMED",
                external_reference="winner-reference",
                detail=None,
                now=ravi.NOW + 9,
            )
        assert isinstance(winner, Ok) and winner.value.applied
        return NotExecuted("LOSER", "must not replace winner")

    executor.inspect_hook = win_before_returning
    reconciled = gate.reconcile_execution(
        caller=CALLER, tenant_id=TENANT, lookup=lookup, now=ravi.NOW + 10
    )

    assert isinstance(reconciled, Ok)
    assert reconciled.value.state is ExecutionState.CONFIRMED
    assert reconciled.value.external_reference == "winner-reference"
    assert len(executor.inquiries) == 1


def test_reconciliation_has_no_syntactic_dispatch_call() -> None:
    tree = ast.parse(textwrap.dedent(inspect.getsource(ActionGate.reconcile_execution)))
    dispatches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "dispatch"
    ]
    assert dispatches == []
