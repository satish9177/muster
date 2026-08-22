"""Imperative shell: validate, reserve, mark dispatch, call once, record finality."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.results import Err, Ok, Result
from muster.core.values.times import Instant
from muster.platform.casework.advance import Casework
from muster.platform.casework.commands import case_status
from muster.platform.gate.authority import GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import (
    ActionExecutor,
    Confirmed,
    DefiniteFailure,
    ExecutorDispatch,
    UnknownOutcome,
)
from muster.platform.gate.model import (
    ExecuteProposal,
    ExecutionRecord,
    ExecutionState,
    GateReadModel,
    read_model,
)
from muster.platform.gate.ports import ExecutionStoreFailure


class GateFailure(Enum):
    EXECUTION_AUTHORITY_REFUSED = "EXECUTION_AUTHORITY_REFUSED"
    CASE_REFUSED = "CASE_REFUSED"
    PROPOSAL_REFUSED = "PROPOSAL_REFUSED"
    CASE_MOVED = "CASE_MOVED"
    STORE_REFUSED = "STORE_REFUSED"


@dataclass(frozen=True, slots=True)
class GateRejection:
    failure: GateFailure
    detail: str


@dataclass(frozen=True, slots=True)
class ActionGate:
    """A deterministic Gate around one casework database and one executor."""

    casework: Casework
    authority: LocalExecutionAuthority
    executor: ActionExecutor
    gate_id: str = "local-action-gate/v1"

    def __post_init__(self) -> None:
        if not self.gate_id:
            raise ValueError("the Action Gate names its local identity")
        if self.executor.trusted_gate_id != self.gate_id:
            raise ValueError("the Action Gate and executor trust different gate identities")

    def execute(
        self,
        *,
        caller: GateCaller,
        tenant_id: str,
        request: ExecuteProposal,
        now: Instant,
    ) -> Result[ExecutionRecord, GateRejection]:
        """Execute this current proposal, or return its existing durable state."""
        if not self.authority.may_invoke(
            caller,
            tenant_id=tenant_id,
            gate_id=self.gate_id,
            executor_id=self.executor.executor_id,
        ):
            return Err(
                GateRejection(
                    GateFailure.EXECUTION_AUTHORITY_REFUSED,
                    f"{caller.principal_id!r} has no local execution grant for {tenant_id!r}",
                )
            )

        reported = case_status(
            self.casework, tenant_id=tenant_id, case_id=request.case_id, now=now
        )
        if isinstance(reported, Err):
            return Err(
                GateRejection(
                    GateFailure.CASE_REFUSED,
                    f"{reported.error.failure.value}: {reported.error.detail}",
                )
            )
        eligible = current_action_intent(
            reported.value,
            request,
            tenant_id=tenant_id,
            gate_id=self.gate_id,
            executor_id=self.executor.executor_id,
        )
        if isinstance(eligible, Err):
            return Err(
                GateRejection(
                    GateFailure.PROPOSAL_REFUSED,
                    f"{eligible.error.failure.value}: {eligible.error.detail}",
                )
            )
        intent = eligible.value
        if not self.authority.permits(
            caller,
            tenant_id=tenant_id,
            action_kind=intent.action.kind,
            gate_id=self.gate_id,
            executor_id=self.executor.executor_id,
        ):
            return Err(
                GateRejection(
                    GateFailure.EXECUTION_AUTHORITY_REFUSED,
                    f"{caller.principal_id!r} may not execute {intent.action.kind}",
                )
            )

        # The head hold closes the validation/reservation window.  A proposal
        # cannot become stale between the replay above and the durable insert.
        with self.casework.database.writing(tenant_id) as scope:
            held = scope.heads.hold(request.case_id)
            if isinstance(held, Err) or held.value != reported.value.head:
                return Err(
                    GateRejection(
                        GateFailure.CASE_MOVED,
                        "the case head moved before the action could be reserved",
                    )
                )
            reserved = scope.executions.reserve(
                intent, requested_by=caller.principal_id, now=now
            )
            if isinstance(reserved, Err):
                return Err(_store_rejection(reserved.error.failure, reserved.error.detail))
            reservation = reserved.value

        # A durable RESERVED row is recoverable work, irrespective of which
        # process inserted it. Every contender uses the next durable CAS; only
        # its winner crosses the no-automatic-redispatch boundary.
        if reservation.record.state is not ExecutionState.RESERVED:
            return Ok(reservation.record)

        with self.casework.database.writing(tenant_id) as scope:
            begun = scope.executions.begin_dispatch(intent.execution_key(), now=now)
            if isinstance(begun, Err):
                return Err(_store_rejection(begun.error.failure, begun.error.detail))
            claim = begun.value

        if not claim.acquired:
            return Ok(claim.record)

        dispatch = ExecutorDispatch(
            intent=claim.record.intent,
            idempotency_key=claim.record.execution_key.hex,
            gate_id=self.gate_id,
        )
        try:
            outcome = self.executor.dispatch(dispatch)
        except Exception as error:  # an invoked boundary may have accepted before raising
            outcome = UnknownOutcome("EXECUTOR_EXCEPTION", type(error).__name__)

        state: ExecutionState
        code: str
        external_reference: str | None
        detail: str | None
        match outcome:
            case Confirmed(reference, duplicate):
                state = ExecutionState.CONFIRMED
                code = "CONFIRMED_DUPLICATE" if duplicate else "CONFIRMED"
                external_reference = reference
                detail = None
            case DefiniteFailure(failure_code, failure_detail):
                state = ExecutionState.FAILED
                code = failure_code
                external_reference = None
                detail = failure_detail
            case UnknownOutcome(unknown_code, unknown_detail):
                state = ExecutionState.UNCERTAIN
                code = unknown_code
                external_reference = None
                detail = unknown_detail

        with self.casework.database.writing(tenant_id) as scope:
            finalized = scope.executions.finalize(
                intent.execution_key(),
                state=state,
                outcome_code=code,
                external_reference=external_reference,
                detail=detail,
                now=now,
            )
            if isinstance(finalized, Err):
                # The durable row remains DISPATCHED, whose finality is UNKNOWN;
                # a retry will read it and will never redispatch.
                return Err(_store_rejection(finalized.error.failure, finalized.error.detail))
            return finalized

    def status(
        self, *, tenant_id: str, case_id: str
    ) -> Result[GateReadModel, GateRejection]:
        """The application read model, without reconstructing payment authority."""
        with self.casework.database.reading(tenant_id) as scope:
            found = scope.executions.read_for_case(case_id)
        if isinstance(found, Err):
            return Err(_store_rejection(found.error.failure, found.error.detail))
        return Ok(read_model(found.value))


def _store_rejection(failure: ExecutionStoreFailure, detail: str) -> GateRejection:
    return GateRejection(GateFailure.STORE_REFUSED, f"{failure.value}: {detail}")
