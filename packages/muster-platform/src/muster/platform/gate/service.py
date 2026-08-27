"""Imperative shell: validate, reserve, mark dispatch, call once, record finality.

Three entry points, with action, durable read and observation kept distinct.

:meth:`ActionGate.execute` is the **only** way a proposal becomes an execution.
It authenticates the caller, replays the case, derives every imperative field
server-side, holds the head across the durable insert, and lets exactly one
contender past the reservation compare-and-swap.  Nothing in this milestone
removes, weakens or reorders any of that.

:meth:`ActionGate.read_authorized_execution` is an **idempotency read**.  It
answers "what did this exact authorized execution already durably do", and it
answers it from the stored canonical ``ActionIntent`` without replaying the
case and without reading the case head at all.  That is not a resumption and
not a re-validation: it creates nothing, transitions nothing, and has no path
to the executor.  It exists because a *second process* legitimately cannot
re-derive the semantic trust material the process that authored the case held,
while the question a retry is actually asking -- "did this already happen?" --
is a question the durable row answers on its own.

Its identity is the ``ExecutionKey``, which is the hash of the authorized
intent and the row's own primary key.  Nothing about it is derived from the
current state of the case, so a confirmed execution stays addressable after the
case head moves on.

The two are kept apart deliberately.  A single method that fell back from one
to the other would be a method where a validation failure and a durable
success are one code path, and the first bug in it would be an execution
created on evidence nobody checked.

:meth:`ActionGate.reconcile_execution` is the U5 observational path.  It loads
through the idempotency read's complete authority and binding boundary, asks
only the stored intent's executor about an execution already in DISPATCHED or
UNCERTAIN, and records the answer through a durable compare-and-swap.  It never
dispatches and cannot make RESERVED actionable.
"""

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
    ExecutedAs,
    ExecutorDispatch,
    ExecutorInquiry,
    NotExecuted,
    ReconcilableExecutor,
    StillUnknown,
    UnknownOutcome,
)
from muster.platform.gate.model import (
    ExecuteProposal,
    ExecutionLookup,
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
    #  An idempotency read found a row whose stored intent names another Gate
    #  or another executor.  Refused rather than reported: this composition did
    #  not authorize it and cannot speak for what did.
    GATE_BINDING_MISMATCH = "GATE_BINDING_MISMATCH"
    #  An idempotency read was given an execution key and an expected case, and
    #  the stored row belongs to the other one.  A refusal rather than an
    #  answer, because a caller that named a case has told the Gate which case
    #  it believes it is retrying -- and answering the wrong one confidently is
    #  the failure the optional check exists to catch.
    EXECUTION_CASE_MISMATCH = "EXECUTION_CASE_MISMATCH"
    #  An idempotency read loaded a row whose canonical octets do not hash to
    #  the key it was found by.  A store defect rather than a caller's input:
    #  the key *is* the hash, so a row where they disagree is a row whose
    #  identity nothing can be concluded from.
    EXECUTION_IDENTITY_CORRUPT = "EXECUTION_IDENTITY_CORRUPT"
    #  An idempotency read found a durable reservation that never crossed the
    #  executor boundary.  U2 does not carry a reservation forward from another
    #  process -- see ``read_authorized_execution``.
    RESERVED_WITHOUT_DISPATCH = "RESERVED_WITHOUT_DISPATCH"
    NOTHING_TO_RECONCILE = "NOTHING_TO_RECONCILE"
    EXECUTOR_NOT_RECONCILABLE = "EXECUTOR_NOT_RECONCILABLE"


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

    def read_authorized_execution(
        self,
        *,
        caller: GateCaller,
        tenant_id: str,
        lookup: ExecutionLookup,
    ) -> Result[ExecutionRecord, GateRejection]:
        """Return what this exact authorized execution already durably did.

        **This is an idempotency read, not a second way to execute.**  It calls
        no case command, runs no analysis, reads no case head, takes no head
        hold, writes nothing, and never touches ``self.executor`` -- so there is
        no input to it that can produce a dispatch, a reservation or a state
        transition.  What it can do is fail closed, and every branch below is
        one of the ways.

        **It does not consult the current case, and that is deliberate.**  The
        identity it is given is an :class:`ExecutionKey`: the hash of the exact
        canonical ``ActionIntent`` that was authorized, and the durable primary
        key of the row holding those octets.  So a CONFIRMED execution stays
        addressable for as long as its row exists, no matter how far the case
        head has since advanced -- an appended transcript entry does not make a
        payment that already happened unfindable.  A retry derived from the
        *current* head would have had exactly that defect, and "retry before the
        case moves" is not a property a duplicate-prevention story can rest on.

        The caller is still authenticated and still needs an exact grant.  A
        read that skipped authority would be a read that told anyone who could
        reach the process which payment reference a tenant's case carries.

        The stored octets stay the authority for what the row *is*.  The store
        has already proved they decode canonically, re-encode byte-identically
        and hash to the key they were stored under; this proves it again
        against the key the *caller* asked for, so "the query matched" and "the
        canonical value agrees" remain two checks rather than one.  A caller
        that also named a case is held to it: a key belonging to another case
        is refused rather than answered.

        The stored ``gate_id`` and ``executor_id`` must be this composition's
        own.  A row authorized by a different Gate is a row this Gate did not
        decide and must not report as its own execution.

        **RESERVED is refused, and that is a deliberate U2 boundary.**  A
        reservation that never reached the executor is unfinished work, and the
        only safe way to finish it is to cross the dispatch compare-and-swap --
        which is an *action*, and an action may only follow the complete
        validation in :meth:`execute`.  Treating a stored reservation as a
        capability a later process may exercise would mean trusting durable
        authorization material as a resumable grant, and U2 does not design or
        prove that.  So a second process is told the reservation exists and is
        not carried forward, rather than being handed something that looks like
        permission to pay.

        Every other durable state is returned exactly as recorded.  DISPATCHED
        and UNCERTAIN are ``OUTCOME_UNKNOWN`` and stay that way; FAILED is a
        definite non-execution; CONFIRMED carries the one external reference
        the original dispatch produced.  None of them is redispatched, here or
        anywhere else.
        """
        loaded = self._load_authorized_execution(
            caller=caller,
            tenant_id=tenant_id,
            lookup=lookup,
        )
        if isinstance(loaded, Err):
            return loaded
        record = loaded.value
        if record.state is ExecutionState.RESERVED:
            return Err(
                GateRejection(
                    GateFailure.RESERVED_WITHOUT_DISPATCH,
                    "a durable reservation has not crossed the executor boundary, and "
                    "this milestone does not carry one forward from another process",
                )
            )
        return Ok(record)

    def _load_authorized_execution(
        self,
        *,
        caller: GateCaller,
        tenant_id: str,
        lookup: ExecutionLookup,
    ) -> Result[ExecutionRecord, GateRejection]:
        """Load one exact stored execution after every read-side authority check.

        The ordering is part of the boundary: authenticate before touching the
        store, then prove the stored identity and bindings, then authorize the
        action kind read from the canonical stored intent.  Callers may impose
        narrower state-specific rules only after this loader succeeds.
        """
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

        #  One exact lookup, by the durable primary key, inside the tenant the
        #  caller was authorized for.  There is no scan, no ordering and no
        #  "closest match": either this tenant stores that key or it does not.
        with self.casework.database.reading(tenant_id) as scope:
            found = scope.executions.read(lookup.execution_key)
        if isinstance(found, Err):
            return Err(_store_rejection(found.error.failure, found.error.detail))
        record = found.value
        intent = record.intent

        #  Recomputed from the octets rather than taken from the store's key.
        #  ``mismatches`` hashes the canonical value it just read back, so a
        #  store that indexed a row under a key its own contents do not produce
        #  is caught here even if the adapter never checked.
        disagreed = lookup.mismatches(intent)
        if "execution_key" in disagreed:
            return Err(
                GateRejection(
                    GateFailure.EXECUTION_IDENTITY_CORRUPT,
                    "the stored intent does not hash to the key it was found by",
                )
            )
        if "case_id" in disagreed:
            return Err(
                GateRejection(
                    GateFailure.EXECUTION_CASE_MISMATCH,
                    "the stored execution belongs to another case",
                )
            )
        if intent.tenant_id != tenant_id:
            return Err(
                GateRejection(
                    GateFailure.STORE_REFUSED,
                    "the stored intent names another tenant",
                )
            )
        if intent.gate_id != self.gate_id or intent.executor_id != self.executor.executor_id:
            return Err(
                GateRejection(
                    GateFailure.GATE_BINDING_MISMATCH,
                    "the stored execution was authorized by another gate or executor",
                )
            )
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
                    f"{caller.principal_id!r} may not read executions of {intent.action.kind}",
                )
            )
        return Ok(record)

    def reconcile_execution(
        self,
        *,
        caller: GateCaller,
        tenant_id: str,
        lookup: ExecutionLookup,
        now: Instant,
    ) -> Result[ExecutionRecord, GateRejection]:
        """Inspect and durably refine one already-dispatched execution.

        Reconciliation is an observation, never another attempt to act.  It
        first uses the same authenticated, exact-key loader as the idempotency
        read, including every stored intent and Gate/executor binding check.
        RESERVED is therefore visible but cannot cross the dispatch boundary;
        definite durable outcomes are returned without consulting the executor.

        Only DISPATCHED and UNCERTAIN reach the executor's read-only ``inspect``
        boundary, with the stored canonical intent and its existing execution
        key.  The answer is written by one compare-and-swap whose source states
        are explicit.  If another reconciler wins, its durable answer is the
        result.  No branch in this method calls ``dispatch`` or reconstructs an
        action from current case state.
        """
        loaded = self._load_authorized_execution(
            caller=caller,
            tenant_id=tenant_id,
            lookup=lookup,
        )
        if isinstance(loaded, Err):
            return loaded
        record = loaded.value
        if record.state is ExecutionState.RESERVED:
            return Err(
                GateRejection(
                    GateFailure.NOTHING_TO_RECONCILE,
                    "the execution has not crossed the dispatch boundary",
                )
            )
        if record.state in {ExecutionState.CONFIRMED, ExecutionState.FAILED}:
            return Ok(record)
        if not isinstance(self.executor, ReconcilableExecutor):
            return Err(
                GateRejection(
                    GateFailure.EXECUTOR_NOT_RECONCILABLE,
                    f"executor {self.executor.executor_id!r} exposes no outcome inspection",
                )
            )

        inquiry = ExecutorInquiry(
            intent=record.intent,
            idempotency_key=record.execution_key.hex,
            gate_id=self.gate_id,
        )
        try:
            answer = self.executor.inspect(inquiry)
        except Exception as error:
            # An observation that failed proves neither execution nor
            # non-execution.  Persist UNKNOWN only when it refines DISPATCHED;
            # an already-UNCERTAIN row remains byte-for-byte unchanged below.
            answer = StillUnknown("EXECUTOR_INSPECTION_EXCEPTION", type(error).__name__)

        state: ExecutionState
        code: str
        external_reference: str | None
        detail: str | None
        match answer:
            case ExecutedAs(reference):
                state = ExecutionState.CONFIRMED
                code = "CONFIRMED"
                external_reference = reference
                detail = None
            case NotExecuted(failure_code, failure_detail):
                state = ExecutionState.FAILED
                code = failure_code
                external_reference = None
                detail = failure_detail
            case StillUnknown(unknown_code, unknown_detail):
                if record.state is ExecutionState.UNCERTAIN:
                    return Ok(record)
                state = ExecutionState.UNCERTAIN
                code = unknown_code
                external_reference = None
                detail = unknown_detail

        with self.casework.database.writing(tenant_id) as scope:
            reconciled = scope.executions.reconcile(
                record.execution_key,
                source_state=record.state,
                state=state,
                outcome_code=code,
                external_reference=external_reference,
                detail=detail,
                now=now,
            )
        if isinstance(reconciled, Err):
            return Err(_store_rejection(reconciled.error.failure, reconciled.error.detail))
        return Ok(reconciled.value.record)

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
