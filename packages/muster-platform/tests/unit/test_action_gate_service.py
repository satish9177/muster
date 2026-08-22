"""The local Gate runs the real Ravi case without a model or payment rail."""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.core.results import Err, Ok
from muster.core.wire.digests import Digest
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.casework.commands import case_status
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import ExecutorDispatch, SandboxMode, SandboxPaymentExecutor
from muster.platform.gate.model import (
    ActionIntent,
    ExecuteProposal,
    ExecutionState,
    Finality,
    GateReadState,
)
from muster.platform.gate.service import ActionGate, GateFailure
from support import authority as source_authority
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import CALLER, configured_gate, proposal


def _ready(
    *, mode: SandboxMode = SandboxMode.SUCCESS
) -> tuple[ActionGate, SandboxPaymentExecutor, ExecuteProposal]:
    database = MemoryDatabase()
    casework = ravi.casework(database)
    case = ravi.ravi("gate-tenant", "gate-case", attested=True)
    open_ravi(casework, case)
    advanced = append_all(casework, case, now=ravi.NOW)
    assert advanced.analysis.kernel.outcome.__class__.__name__ == "Invariant"
    executor = SandboxPaymentExecutor(mode=mode)
    gate = configured_gate(casework, executor)
    _report, request = proposal(casework, case)
    return gate, executor, request


def _current_intent(gate: ActionGate, request: ExecuteProposal) -> ActionIntent:
    reported = case_status(
        gate.casework,
        tenant_id="gate-tenant",
        case_id=request.case_id,
        now=ravi.NOW,
    )
    assert isinstance(reported, Ok), reported
    intent = current_action_intent(
        reported.value,
        request,
        tenant_id="gate-tenant",
        gate_id=gate.gate_id,
        executor_id=gate.executor.executor_id,
    )
    assert isinstance(intent, Ok), intent
    return intent.value


def test_ravi_executes_the_exact_sandbox_action_once_and_replay_reads_proof() -> None:
    gate, executor, request = _ready()

    first = gate.execute(
        caller=CALLER, tenant_id="gate-tenant", request=request, now=ravi.NOW
    )
    second = gate.execute(
        caller=CALLER, tenant_id="gate-tenant", request=request, now=ravi.NOW
    )

    assert isinstance(first, Ok) and isinstance(second, Ok)
    assert first.value == second.value
    assert first.value.state is ExecutionState.CONFIRMED
    assert first.value.finality is Finality.DEFINITELY_EXECUTED
    assert first.value.external_reference is not None
    assert executor.dispatch_count == 1
    assert executor.execution_count == 1

    status = gate.status(tenant_id="gate-tenant", case_id="gate-case")
    assert isinstance(status, Ok), status
    assert status.value.state is GateReadState.EXECUTED
    assert status.value.external_reference == first.value.external_reference


@pytest.mark.parametrize(
    ("mode", "state", "finality"),
    [
        (
            SandboxMode.DEFINITE_PRE_DISPATCH_FAILURE,
            ExecutionState.FAILED,
            Finality.DEFINITELY_NOT_EXECUTED,
        ),
        (
            SandboxMode.UNKNOWN_AFTER_DISPATCH,
            ExecutionState.UNCERTAIN,
            Finality.OUTCOME_UNKNOWN,
        ),
        (
            SandboxMode.CONFIRMED_DUPLICATE,
            ExecutionState.CONFIRMED,
            Finality.DEFINITELY_EXECUTED,
        ),
    ],
)
def test_external_finality_is_recorded_and_never_automatically_retried(
    mode: SandboxMode, state: ExecutionState, finality: Finality
) -> None:
    gate, executor, request = _ready(mode=mode)
    first = gate.execute(
        caller=CALLER, tenant_id="gate-tenant", request=request, now=ravi.NOW
    )
    replay = gate.execute(
        caller=CALLER, tenant_id="gate-tenant", request=request, now=ravi.NOW + 1
    )
    assert isinstance(first, Ok) and isinstance(replay, Ok)
    assert first.value == replay.value
    assert first.value.state is state
    assert first.value.finality is finality
    assert executor.dispatch_count == 1


def test_an_unauthorized_actor_cannot_reserve_or_dispatch() -> None:
    gate, executor, request = _ready()
    refused = gate.execute(
        caller=GateCaller("intruder"),
        tenant_id="gate-tenant",
        request=request,
        now=ravi.NOW,
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_AUTHORITY_REFUSED
    assert executor.dispatch_count == 0


@pytest.mark.parametrize(
    "source_identity",
    (source_authority.SITE_A, "agent-site-a"),
)
def test_source_authority_identity_alone_cannot_invoke_the_gate(
    source_identity: str,
) -> None:
    """The fully admitted Q-12 case grants no execution authority."""
    gate, executor, request = _ready()

    refused = gate.execute(
        caller=GateCaller(source_identity),
        tenant_id="gate-tenant",
        request=request,
        now=ravi.NOW,
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_AUTHORITY_REFUSED
    assert executor.dispatch_count == 0


def test_a_durable_reservation_abandoned_by_caller_a_is_recovered_by_caller_b() -> None:
    gate, executor, request = _ready()
    caller_b = GateCaller("recovery-operator")
    grant_b = ExecutionGrant(
        principal_id=caller_b.principal_id,
        tenant_id="gate-tenant",
        action_kind="PAY",
        gate_id=gate.gate_id,
        executor_id=executor.executor_id,
    )
    gate = replace(gate, authority=LocalExecutionAuthority((*gate.authority.grants, grant_b)))
    intent = _current_intent(gate, request)

    # Caller A commits RESERVED and dies before attempting the dispatch CAS.
    with gate.casework.database.writing("gate-tenant") as scope:
        reservation = scope.executions.reserve(
            intent, requested_by=CALLER.principal_id, now=ravi.NOW
        )
    assert isinstance(reservation, Ok) and reservation.value.acquired
    assert reservation.value.record.state is ExecutionState.RESERVED

    recovered = gate.execute(
        caller=caller_b,
        tenant_id="gate-tenant",
        request=request,
        now=ravi.NOW + 1,
    )

    assert isinstance(recovered, Ok), recovered
    assert recovered.value.state is ExecutionState.CONFIRMED
    assert recovered.value.requested_by == CALLER.principal_id
    assert executor.dispatch_count == 1
    assert executor.execution_count == 1


@pytest.mark.parametrize("executor_responded", (False, True))
def test_durable_dispatched_is_never_retried_when_the_result_was_not_recorded(
    executor_responded: bool,
) -> None:
    gate, executor, request = _ready()
    intent = _current_intent(gate, request)
    with gate.casework.database.writing("gate-tenant") as scope:
        reservation = scope.executions.reserve(
            intent, requested_by=CALLER.principal_id, now=ravi.NOW
        )
    assert isinstance(reservation, Ok)
    with gate.casework.database.writing("gate-tenant") as scope:
        claim = scope.executions.begin_dispatch(intent.execution_key(), now=ravi.NOW)
    assert isinstance(claim, Ok) and claim.value.acquired
    assert claim.value.record.state is ExecutionState.DISPATCHED

    # The crash can occur before invocation, or after the executor responded
    # but before that response was made durable. Both have the same safe fact.
    if executor_responded:
        executor.dispatch(
            ExecutorDispatch(
                intent=intent,
                idempotency_key=intent.execution_key().hex,
                gate_id=gate.gate_id,
            )
        )
    calls_before_retry = executor.dispatch_count

    replay = gate.execute(
        caller=CALLER,
        tenant_id="gate-tenant",
        request=request,
        now=ravi.NOW + 1,
    )

    assert isinstance(replay, Ok), replay
    assert replay.value.state is ExecutionState.DISPATCHED
    assert replay.value.finality is Finality.OUTCOME_UNKNOWN
    assert executor.dispatch_count == calls_before_retry


def test_action_and_result_identity_substitution_are_refused_before_reservation() -> None:
    gate, executor, request = _ready()
    assert hasattr(request, "action_digest")
    substitutions = (
        replace(request, revision_digest=Digest(b"\x81" * 32)),
        replace(request, certificate_digest=Digest(b"\x82" * 32)),
        replace(request, action_digest=Digest(b"\x83" * 32)),
    )
    for substituted in substitutions:
        refused = gate.execute(
            caller=CALLER,
            tenant_id="gate-tenant",
            request=substituted,
            now=ravi.NOW,
        )
        assert isinstance(refused, Err)
        assert refused.error.failure is GateFailure.PROPOSAL_REFUSED
    assert executor.dispatch_count == 0


def test_a_different_authorized_caller_replays_the_same_execution_identity() -> None:
    gate, executor, request = _ready()
    second_caller = GateCaller("backup-operator")
    grant = ExecutionGrant(
        principal_id=second_caller.principal_id,
        tenant_id="gate-tenant",
        action_kind="PAY",
        gate_id=gate.gate_id,
        executor_id=executor.executor_id,
    )
    gate = replace(
        gate,
        authority=LocalExecutionAuthority((*gate.authority.grants, grant)),
    )
    first = gate.execute(
        caller=CALLER, tenant_id="gate-tenant", request=request, now=ravi.NOW
    )
    replay = gate.execute(
        caller=second_caller,
        tenant_id="gate-tenant",
        request=request,
        now=ravi.NOW + 1,
    )
    assert isinstance(first, Ok) and isinstance(replay, Ok)
    assert replay.value.execution_key == first.value.execution_key
    assert replay.value.requested_by == CALLER.principal_id
    assert executor.dispatch_count == 1
