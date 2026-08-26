"""Every way the idempotency read must refuse, and the one way it must not act.

The read exists so a second process can be told what an earlier authorization
already durably did.  That is a much smaller claim than "execute", and this
file is the boundary between them: nothing here may create a row, transition a
state, or reach the executor, and the identity the read is given has to be
exact.

**That identity is the execution key**: the hash of the exact canonical
``ActionIntent`` that was authorized, and the durable primary key of the row
holding those octets.  None of it is derived from the case's current state,
and ``test_a_confirmed_execution_stays_readable_after_the_case_head_moves`` is
where that stops being a design note and becomes a fact.

The executor's own dispatch counter is asserted in almost every test, because
it is the single number that distinguishes a read from an action.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import cast

import psycopg
import pytest

from muster.core.results import Err, InvariantViolation, Ok
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.schema import SchemaNotCurrent, require_current_schema
from muster.platform.casework.commands import append_transcript_entry, case_status
from muster.platform.casework.ports import CaseworkDatabase, TenantScope
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import SandboxMode, SandboxPaymentExecutor
from muster.platform.gate.model import (
    ActionIntent,
    ExecuteProposal,
    ExecutionKey,
    ExecutionLookup,
    ExecutionState,
)
from muster.platform.gate.ports import ExecutionStoreFailure
from muster.platform.gate.service import ActionGate, GateFailure
from muster.policy.registry import BundleRegistry
from muster.solve.backend import SolverBackend
from muster.solve.reference.bounded import BoundedEnumerationBackend
from support import ravi
from support.fixtures import append_all, open_ravi, split_at_the_inert_claim
from support.gate import CALLER, configured_gate, proposal

TENANT = "gate-tenant"


def _ready(
    case_id: str, *, mode: SandboxMode = SandboxMode.SUCCESS
) -> tuple[ActionGate, SandboxPaymentExecutor, ExecuteProposal, ExecutionLookup]:
    database = MemoryDatabase()
    casework = ravi.casework(database)
    case = ravi.ravi(TENANT, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    executor = SandboxPaymentExecutor(mode=mode)
    gate = configured_gate(casework, executor)
    _report, request = proposal(casework, case)
    return gate, executor, request, _lookup(gate, request)


def _intent(gate: ActionGate, request: ExecuteProposal) -> ActionIntent:
    reported = case_status(gate.casework, tenant_id=TENANT, case_id=request.case_id, now=ravi.NOW)
    assert isinstance(reported, Ok), reported
    eligible = current_action_intent(
        reported.value,
        request,
        tenant_id=TENANT,
        gate_id=gate.gate_id,
        executor_id=gate.executor.executor_id,
    )
    assert isinstance(eligible, Ok), eligible
    return eligible.value


def _lookup(gate: ActionGate, request: ExecuteProposal) -> ExecutionLookup:
    """The durable identity a retry presents, obtained the way a retry gets it.

    In the deployment the key is a string the first execution *printed*; here
    it is recomputed from the intent that execution authorizes, which is the
    same 32 octets by construction.  Nothing consequential is carried -- a
    lookup cannot name a recipient, an amount or a currency even if a caller
    wanted it to -- and the case identifier it does carry only narrows.
    """
    return ExecutionLookup(
        execution_key=_intent(gate, request).execution_key(),
        expected_case_id=request.case_id,
    )


#  ---- the one thing it may do ---------------------------------------------


def test_a_confirmed_lifecycle_is_returned_without_a_second_dispatch() -> None:
    gate, executor, request, lookup = _ready("idempotent-confirmed")
    first = gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW)
    assert isinstance(first, Ok), first
    assert first.value.state is ExecutionState.CONFIRMED
    assert executor.dispatch_count == 1

    read = gate.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=lookup)

    assert isinstance(read, Ok), read
    assert read.value == first.value
    assert read.value.external_reference == first.value.external_reference
    assert executor.dispatch_count == 1
    assert executor.execution_count == 1


@pytest.mark.parametrize(
    ("mode", "state"),
    [
        (SandboxMode.UNKNOWN_AFTER_DISPATCH, ExecutionState.UNCERTAIN),
        (SandboxMode.DEFINITE_PRE_DISPATCH_FAILURE, ExecutionState.FAILED),
    ],
)
def test_an_unconfirmed_lifecycle_is_reported_as_recorded_and_never_redispatched(
    mode: SandboxMode, state: ExecutionState
) -> None:
    """A retry reads the durable state; it does not improve it.

    UNCERTAIN in particular: the point of the state is that nobody knows, and a
    retry that dispatched again to find out would be a retry that could pay
    twice to answer a question.
    """
    gate, executor, request, lookup = _ready(f"idempotent-{state.value.lower()}", mode=mode)
    first = gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW)
    assert isinstance(first, Ok), first
    assert first.value.state is state
    dispatched = executor.dispatch_count

    read = gate.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=lookup)

    assert isinstance(read, Ok), read
    assert read.value.state is state
    assert read.value.external_reference is None
    assert executor.dispatch_count == dispatched


def test_a_dispatched_lifecycle_is_returned_as_unknown_and_never_redispatched() -> None:
    gate, executor, request, lookup = _ready("idempotent-dispatched")
    intent = _intent(gate, request)
    with gate.casework.database.writing(TENANT) as scope:
        reserved = scope.executions.reserve(intent, requested_by=CALLER.principal_id, now=ravi.NOW)
    assert isinstance(reserved, Ok)
    with gate.casework.database.writing(TENANT) as scope:
        claim = scope.executions.begin_dispatch(intent.execution_key(), now=ravi.NOW)
    assert isinstance(claim, Ok) and claim.value.acquired

    read = gate.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=lookup)

    assert isinstance(read, Ok), read
    assert read.value.state is ExecutionState.DISPATCHED
    assert executor.dispatch_count == 0


#  ---- the reservation boundary U2 deliberately does not cross --------------


def test_a_reservation_that_never_dispatched_is_refused_rather_than_carried_forward() -> None:
    """U2 does not treat durable authorization material as a resumable capability.

    A RESERVED row is unfinished work.  Finishing it means crossing the dispatch
    compare-and-swap, which is an action, and an action may only follow the
    complete validation in ``execute``.  So a process that did not validate the
    case is told the reservation exists and is not carried forward -- rather
    than being handed something shaped like permission to pay.
    """
    gate, executor, request, lookup = _ready("idempotent-reserved")
    intent = _intent(gate, request)
    with gate.casework.database.writing(TENANT) as scope:
        reserved = scope.executions.reserve(intent, requested_by=CALLER.principal_id, now=ravi.NOW)
    assert isinstance(reserved, Ok) and reserved.value.acquired

    refused = gate.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=lookup)

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.RESERVED_WITHOUT_DISPATCH
    assert executor.dispatch_count == 0
    #  And the row is untouched: a refusal that had transitioned it would be
    #  the resumption this test exists to rule out.
    with gate.casework.database.reading(TENANT) as scope:
        still = scope.executions.read(intent.execution_key())
    assert isinstance(still, Ok)
    assert still.value.state is ExecutionState.RESERVED


#  ---- identity ------------------------------------------------------------


def test_a_wrong_execution_key_finds_nothing() -> None:
    """The key is the whole identity, so one wrong octet is an absence.

    Not a near miss and not a fallback to something similar: the store's answer
    is a primary-key lookup, and a key nobody stored has no row.  A read that
    degraded to "the newest execution on this case" when its key missed would
    be a read that answers a retry with a payment it did not ask about.
    """
    gate, executor, request, lookup = _ready("idempotent-key")
    executed = gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW)
    assert isinstance(executed, Ok)

    forged = replace(lookup, execution_key=ExecutionKey(b"\x7f" * 32))
    refused = gate.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=forged)

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.STORE_REFUSED
    assert ExecutionStoreFailure.ABSENT.value in refused.error.detail
    assert executor.dispatch_count == 1


def test_a_key_belonging_to_another_case_is_refused_when_a_case_is_named() -> None:
    """The optional narrowing, doing the one thing it exists for.

    Two cases, each with its own confirmed execution.  Asking about the first
    case using the *second* case's key is a configuration mix-up -- the shape
    an operator produces by pasting the wrong line out of the wrong job log --
    and it is refused by name rather than answered confidently about a case
    nobody asked about.
    """
    gate, executor, request, _lookup_unused = _ready("idempotent-mine")
    assert isinstance(
        gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW), Ok
    )
    #  A second case in the same store, so the key names a row that really
    #  exists.  A refusal over an absent key would prove nothing about the
    #  case check.
    other_case = ravi.ravi(TENANT, "idempotent-theirs", attested=True)
    open_ravi(gate.casework, other_case)
    append_all(gate.casework, other_case, now=ravi.NOW)
    _report, other_request = proposal(gate.casework, other_case)
    other = gate.execute(caller=CALLER, tenant_id=TENANT, request=other_request, now=ravi.NOW)
    assert isinstance(other, Ok), other

    refused = gate.read_authorized_execution(
        caller=CALLER,
        tenant_id=TENANT,
        lookup=ExecutionLookup(
            execution_key=other.value.execution_key, expected_case_id="idempotent-mine"
        ),
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_CASE_MISMATCH
    assert executor.dispatch_count == 2


def test_a_lookup_that_names_no_case_still_answers_only_for_its_own_key() -> None:
    """``expected_case_id`` narrows; it is not what makes the read exact.

    Omitting it asks "what did this execution do", which the key already
    answers on its own -- so the same key returns the same row, and it is the
    row that key names rather than anything belonging to the case the caller
    happens to be thinking about.
    """
    gate, executor, request, lookup = _ready("idempotent-unnamed")
    executed = gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW)
    assert isinstance(executed, Ok)

    read = gate.read_authorized_execution(
        caller=CALLER,
        tenant_id=TENANT,
        lookup=ExecutionLookup(execution_key=lookup.execution_key),
    )

    assert isinstance(read, Ok), read
    assert read.value == executed.value
    assert executor.dispatch_count == 1


def test_another_tenant_cannot_read_a_tenants_execution() -> None:
    """The store is already tenant-bound; this proves the Gate keeps it that way."""
    gate, executor, request, lookup = _ready("idempotent-tenant")
    assert isinstance(
        gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW), Ok
    )

    refused = gate.read_authorized_execution(caller=CALLER, tenant_id="ALPHA", lookup=lookup)

    assert isinstance(refused, Err)
    assert executor.dispatch_count == 1


#  ---- authority -----------------------------------------------------------


def test_an_unauthorized_caller_cannot_read_an_execution() -> None:
    """A read is not public.

    It answers with a payment reference, and a Gate that handed one to any
    caller that could reach the process would be leaking the outcome of a
    tenant's case to whoever asked.
    """
    gate, executor, request, lookup = _ready("idempotent-caller")
    assert isinstance(
        gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW), Ok
    )

    refused = gate.read_authorized_execution(
        caller=GateCaller("someone-else"), tenant_id=TENANT, lookup=lookup
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_AUTHORITY_REFUSED
    assert executor.dispatch_count == 1


def test_an_ungranted_caller_is_refused_before_the_database_is_opened() -> None:
    """Ordering, and it is the whole reason there are two authority checks.

    ``may_invoke`` answers "could any grant this principal holds possibly
    apply", and it answers it before a case or a row is loaded.  The second
    check needs the stored action kind and therefore needs the row.  A Gate
    with only the second one still *refuses* -- which is why asserting the
    refusal alone would not notice the first one disappearing -- but it refuses
    after letting an ungranted caller make it read a tenant's execution table.

    Stated with a database that raises on contact, so "before" is a fact rather
    than a reading of the source.
    """
    gate, executor, request, lookup = _ready("idempotent-before-the-store")
    assert isinstance(
        gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW), Ok
    )

    class _Sealed:
        def reading(self, tenant_id: str) -> object:  # noqa: ARG002
            raise AssertionError("the read opened the database for an ungranted caller")

        def writing(self, tenant_id: str) -> object:  # noqa: ARG002
            raise AssertionError("the read opened the database for an ungranted caller")

    sealed = replace(
        gate,
        casework=replace(gate.casework, database=cast(CaseworkDatabase, _Sealed())),
    )
    refused = sealed.read_authorized_execution(
        caller=GateCaller("someone-else"), tenant_id=TENANT, lookup=lookup
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_AUTHORITY_REFUSED
    assert executor.dispatch_count == 1


def test_a_caller_granted_another_action_kind_cannot_read_a_pay_execution() -> None:
    gate, executor, request, lookup = _ready("idempotent-kind")
    assert isinstance(
        gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW), Ok
    )

    narrowed = replace(
        gate,
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=CALLER.principal_id,
                    tenant_id=TENANT,
                    action_kind="REFUND",
                    gate_id=gate.gate_id,
                    executor_id=gate.executor.executor_id,
                ),
            )
        ),
    )
    refused = narrowed.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=lookup)

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_AUTHORITY_REFUSED
    assert executor.dispatch_count == 1


def test_a_gate_with_another_identity_will_not_speak_for_this_execution() -> None:
    """A row names the gate that authorized it, and only that gate reports it.

    The scenario is a second deployment pointed at the same database.  It did
    not decide this execution, it cannot say what its executor did, and
    returning the row would be it claiming both.
    """
    gate, executor, request, lookup = _ready("idempotent-gate")
    assert isinstance(
        gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW), Ok
    )

    other_executor = SandboxPaymentExecutor(
        executor_id="sandbox-payment/v1", trusted_gate_id="another-action-gate/v1"
    )
    other_gate = ActionGate(
        casework=gate.casework,
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=CALLER.principal_id,
                    tenant_id=TENANT,
                    action_kind="PAY",
                    gate_id="another-action-gate/v1",
                    executor_id=other_executor.executor_id,
                ),
            )
        ),
        executor=other_executor,
        gate_id="another-action-gate/v1",
    )

    refused = other_gate.read_authorized_execution(
        caller=CALLER, tenant_id=TENANT, lookup=lookup
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.GATE_BINDING_MISMATCH
    assert executor.dispatch_count == 1
    assert other_executor.dispatch_count == 0


def test_a_gate_whose_executor_differs_will_not_speak_for_this_execution() -> None:
    gate, _executor, request, lookup = _ready("idempotent-executor")
    assert isinstance(
        gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW), Ok
    )

    other_executor = SandboxPaymentExecutor(
        executor_id="sandbox-payment-other/v1", trusted_gate_id=gate.gate_id
    )
    other_gate = replace(
        gate,
        executor=other_executor,
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=CALLER.principal_id,
                    tenant_id=TENANT,
                    action_kind="PAY",
                    gate_id=gate.gate_id,
                    executor_id=other_executor.executor_id,
                ),
            )
        ),
    )

    refused = other_gate.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=lookup)

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.GATE_BINDING_MISMATCH
    assert other_executor.dispatch_count == 0


#  ---- absence -------------------------------------------------------------


def test_a_proposal_that_was_never_executed_is_absent_rather_than_created() -> None:
    """The read has no path that could reserve, and this is the case that proves it."""
    gate, executor, _unused, lookup = _ready("idempotent-absent")

    refused = gate.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=lookup)

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.STORE_REFUSED
    assert ExecutionStoreFailure.ABSENT.value in refused.error.detail
    assert executor.dispatch_count == 0
    absent = gate.status(tenant_id=TENANT, case_id="idempotent-absent")
    assert isinstance(absent, Err)


def test_the_read_analyses_nothing_even_when_analysis_is_impossible() -> None:
    """Stated as a behaviour rather than as a docstring.

    The Gate's casework keeps its database and loses everything an analysis
    needs: the bundle registry and the solver backend both raise on contact.
    ``execute`` cannot survive that; the read does not need either, and a read
    that had quietly grown a case command would fail here rather than in a
    review.

    This is the local twin of the cloud property the whole milestone rests on:
    a second process holds a database and not the trust material the case was
    authored under, and the read is honest precisely because it never asks.
    """
    gate, executor, request, lookup = _ready("idempotent-no-analysis")
    assert isinstance(
        gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW), Ok
    )

    class _Absent:
        def __getattr__(self, name: str) -> object:
            raise AssertionError(f"the idempotency read reached the analysis path: {name}")

        def __call__(self) -> object:
            raise AssertionError("the idempotency read built a solver")

    #  ``cast`` rather than a real stub: the point is to install something the
    #  analysis path cannot use, which is by definition not a value of either
    #  declared type.
    absent = _Absent()
    blinded = replace(
        gate,
        casework=replace(
            gate.casework,
            registry=cast(BundleRegistry, absent),
            backend=cast(Callable[[], SolverBackend], absent),
        ),
    )
    read = blinded.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=lookup)

    assert isinstance(read, Ok), read
    assert read.value.state is ExecutionState.CONFIRMED
    assert executor.dispatch_count == 1

    #  And the same Gate cannot execute, which is what makes the line above a
    #  statement about the read rather than about this fixture.
    with pytest.raises(AssertionError):
        blinded.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW)


#  ---- a stored row whose identity is not its own ---------------------------


def test_a_row_filed_under_a_key_its_octets_do_not_produce_is_refused() -> None:
    """The key must be the hash of the intent stored beside it.

    Manufactured directly in the in-memory store, because no adapter API can
    produce it: reserve files a record under intent.execution_key(), and
    PostgreSQL's own reader raises before such a row could escape.  The value
    of the refusal is precisely that it does not depend on either of those
    having been right.

    Answering anyway would be the worst available behaviour.  The key is what a
    retry names and also what the executor was handed as its idempotency key,
    so a row where the two disagree is a row from which nothing can be
    concluded about which payment happened.
    """
    gate, executor, request, _unused = _ready("idempotent-corrupt")
    executed = gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW)
    assert isinstance(executed, Ok), executed

    database = gate.casework.database
    assert isinstance(database, MemoryDatabase)
    misfiled = ExecutionKey(b"\x33" * 32)
    database.records.executions[(TENANT, misfiled)] = executed.value

    refused = gate.read_authorized_execution(
        caller=CALLER,
        tenant_id=TENANT,
        lookup=ExecutionLookup(execution_key=misfiled, expected_case_id="idempotent-corrupt"),
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_IDENTITY_CORRUPT
    assert executor.dispatch_count == 1


#  ---- independence from the case's current state ---------------------------


def test_a_confirmed_execution_stays_readable_after_the_case_head_moves() -> None:
    """The point of the whole identity, stated as a sequence.

    Execute, then legitimately advance the case, then retry.  The advance is
    real: one more transcript entry goes in through the ordinary command and
    the case publishes a new revision, so the head the execution was authorized
    against is no longer the head the case has.

    A retry identified by anything derived from that head would now be absent,
    and "the retry has to happen before the case moves" would be a caveat this
    system carried into production.  Identified by the execution key, the
    historical row is exactly as readable as it was a moment ago: same record,
    same reference, and still nothing dispatched.
    """
    database = MemoryDatabase()
    casework = ravi.casework(database)
    case = ravi.ravi(TENANT, "idempotent-advanced", attested=True)
    open_ravi(casework, case)
    analysed, held = split_at_the_inert_claim(case)
    for entry in analysed:
        appended = append_transcript_entry(
            casework, tenant_id=TENANT, case_id=case.case_id, entry=entry, now=ravi.NOW
        )
        assert isinstance(appended, Ok), appended

    executor = SandboxPaymentExecutor()
    gate = configured_gate(casework, executor)
    before, request = proposal(casework, case)
    executed = gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW)
    assert isinstance(executed, Ok), executed
    assert executed.value.state is ExecutionState.CONFIRMED
    assert executor.dispatch_count == 1
    key = executed.value.execution_key

    advanced = append_transcript_entry(
        casework, tenant_id=TENANT, case_id=case.case_id, entry=held, now=ravi.NOW
    )
    assert isinstance(advanced, Ok), advanced
    after = case_status(casework, tenant_id=TENANT, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(after, Ok), after
    #  Asserted rather than assumed: without this the test could pass against a
    #  case that never moved, which is the one thing it is about.
    assert after.value.head.revision_digest != before.head.revision_digest
    assert after.value.head.revision_number > before.head.revision_number

    #  A second process's Gate, sharing the database and nothing else.
    retrying = SandboxPaymentExecutor()
    second = configured_gate(ravi.casework(database), retrying)
    read = second.read_authorized_execution(
        caller=CALLER,
        tenant_id=TENANT,
        lookup=ExecutionLookup(execution_key=key, expected_case_id=case.case_id),
    )

    assert isinstance(read, Ok), read
    assert read.value == executed.value
    assert read.value.state is ExecutionState.CONFIRMED
    assert read.value.external_reference == executed.value.external_reference
    assert retrying.dispatch_count == 0
    assert executor.dispatch_count == 1


class _HeadlessScope:
    """A tenant scope whose case heads raise on contact.

    Everything else is delegated, so what is removed is exactly one capability
    rather than a whole database -- which is what makes the read succeeding
    below a statement about the head and not about the fixture.
    """

    def __init__(self, inner: object) -> None:
        self._inner = inner

    @property
    def heads(self) -> object:
        raise AssertionError("the idempotency read reached the case head")

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


class _HeadlessDatabase:
    """The same database, with the case heads taken away from every scope."""

    def __init__(self, inner: MemoryDatabase) -> None:
        self._inner = inner

    @contextmanager
    def reading(self, tenant_id: str) -> Iterator[TenantScope]:
        with self._inner.reading(tenant_id) as scope:
            yield cast(TenantScope, _HeadlessScope(scope))

    @contextmanager
    def writing(self, tenant_id: str) -> Iterator[TenantScope]:
        with self._inner.writing(tenant_id) as scope:
            yield cast(TenantScope, _HeadlessScope(scope))


def test_the_read_never_consults_the_case_head_at_all() -> None:
    """Stronger than "it still works": it does not look.

    The case-head repository raises on contact, so a read that grew a head
    access -- to narrow, to validate, to be helpful -- fails here rather than
    in a review.  This is the mutation the identity redesign is guarding
    against, and the advancement test above would not catch it on its own: a
    read that consulted the head and then ignored it would pass that one.
    """
    gate, executor, request, lookup = _ready("idempotent-no-head")
    assert isinstance(
        gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW), Ok
    )

    database = gate.casework.database
    assert isinstance(database, MemoryDatabase)
    blinded = replace(
        gate,
        casework=replace(
            gate.casework, database=cast(CaseworkDatabase, _HeadlessDatabase(database))
        ),
    )
    read = blinded.read_authorized_execution(caller=CALLER, tenant_id=TENANT, lookup=lookup)

    assert isinstance(read, Ok), read
    assert read.value.state is ExecutionState.CONFIRMED
    assert executor.dispatch_count == 1

    #  And the same Gate cannot execute, which is what makes the line above a
    #  statement about the read rather than about this fixture.
    with pytest.raises(AssertionError, match="case head"):
        blinded.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW)


#  ---- the complete repeat refuses every substituted binding ---------------


def _sql_gate(dsn: str, tenant_id: str) -> tuple[ActionGate, SandboxPaymentExecutor]:
    executor = SandboxPaymentExecutor()
    return (
        ActionGate(
            casework=ravi.casework(SqlDatabase(dsn)),
            authority=LocalExecutionAuthority(
                (
                    ExecutionGrant(
                        principal_id=CALLER.principal_id,
                        tenant_id=tenant_id,
                        action_kind="PAY",
                        gate_id=executor.trusted_gate_id,
                        executor_id=executor.executor_id,
                    ),
                )
            ),
            executor=executor,
        ),
        executor,
    )


def _sql_ready(
    dsn: str, tenant_id: str, case_id: str
) -> tuple[ActionGate, SandboxPaymentExecutor, ExecuteProposal]:
    gate, executor = _sql_gate(dsn, tenant_id)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(gate.casework, case)
    append_all(gate.casework, case, now=ravi.NOW)
    _report, request = proposal(gate.casework, case)
    return gate, executor, request


@pytest.mark.postgres
@pytest.mark.parametrize("substitution", ("gate_id", "executor_id"))
def test_repeat_cannot_rebind_an_authorized_proposal(
    migrated_dsn: str, tenant_id: str, case_id: str, substitution: str
) -> None:
    first, first_executor, request = _sql_ready(migrated_dsn, tenant_id, case_id)
    executed = first.execute(
        caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW
    )
    assert isinstance(executed, Ok), executed

    gate_id = first.gate_id if substitution == "executor_id" else "other-action-gate/v1"
    executor_id = (
        first_executor.executor_id
        if substitution == "gate_id"
        else "sandbox-payment-other/v1"
    )
    retry_executor = SandboxPaymentExecutor(
        executor_id=executor_id,
        trusted_gate_id=gate_id,
    )
    retry = ActionGate(
        casework=ravi.casework(SqlDatabase(migrated_dsn)),
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=CALLER.principal_id,
                    tenant_id=tenant_id,
                    action_kind="PAY",
                    gate_id=gate_id,
                    executor_id=executor_id,
                ),
            )
        ),
        executor=retry_executor,
        gate_id=gate_id,
    )

    refused = retry.execute(
        caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.STORE_REFUSED
    assert ExecutionStoreFailure.CASE_IDENTITY_CONFLICT.value in refused.error.detail
    assert retry_executor.dispatch_count == 0
    assert first_executor.dispatch_count == 1
    with psycopg.connect(migrated_dsn) as connection:
        count = connection.execute(
            "SELECT count(*) FROM action_gate.execution "
            "WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchone()
    assert count == (1,)


@pytest.mark.postgres
@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("intent_octets", "stored ActionIntent"),
        ("execution_id", "execution_id is not the key"),
        ("action_kind", "action_kind disagrees"),
    ),
)
def test_repeat_refuses_a_corrupt_execution_row_before_dispatch(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    mutation: str,
    expected: str,
) -> None:
    first, _first_executor, request = _sql_ready(migrated_dsn, tenant_id, case_id)
    assert isinstance(
        first.execute(caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW),
        Ok,
    )

    statements: dict[str, tuple[str, object]] = {
        "intent_octets": (
            "UPDATE action_gate.execution SET intent_octets = %s "
            "WHERE tenant_id = %s AND case_id = %s",
            b"not-canonical-action-intent",
        ),
        "execution_id": (
            "UPDATE action_gate.execution SET execution_id = %s "
            "WHERE tenant_id = %s AND case_id = %s",
            b"\x99" * 32,
        ),
        "action_kind": (
            "UPDATE action_gate.execution SET action_kind = %s "
            "WHERE tenant_id = %s AND case_id = %s",
            "REFUND",
        ),
    }
    statement, value = statements[mutation]
    with psycopg.connect(migrated_dsn) as connection:
        connection.execute(statement, (value, tenant_id, case_id))

    retry, retry_executor = _sql_gate(migrated_dsn, tenant_id)
    with pytest.raises(InvariantViolation, match=expected):
        retry.execute(caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW)
    assert retry_executor.dispatch_count == 0


#  ---- mutation guard for the confirmed-row early return -------------------


def test_the_confirmed_repeat_early_return_is_load_bearing(tmp_path: Path) -> None:
    """A patched copy that dispatches at the branch makes the regression visible."""
    import muster.platform.gate.service as real_service

    gate, first_executor, request, _lookup = _ready("idempotent-mutation")
    first = gate.execute(caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW)
    assert isinstance(first, Ok), first
    assert first_executor.dispatch_count == 1

    source = Path(real_service.__file__).read_text(encoding="utf-8")
    protected = (
        "        if reservation.record.state is not ExecutionState.RESERVED:\n"
        "            return Ok(reservation.record)\n"
    )
    mutated = (
        "        if reservation.record.state is not ExecutionState.RESERVED:\n"
        "            self.executor.dispatch(\n"
        "                ExecutorDispatch(\n"
        "                    intent=reservation.record.intent,\n"
        "                    idempotency_key=reservation.record.execution_key.hex,\n"
        "                    gate_id=self.gate_id,\n"
        "                )\n"
        "            )\n"
        "            return Ok(reservation.record)\n"
    )
    assert source.count(protected) == 1
    patched_path = tmp_path / "service_mutated.py"
    patched_path.write_text(source.replace(protected, mutated), encoding="utf-8")

    module_name = "_muster_test_mutated_gate_service"
    specification = importlib.util.spec_from_file_location(module_name, patched_path)
    assert specification is not None and specification.loader is not None
    patched = importlib.util.module_from_spec(specification)
    sys.modules[module_name] = patched
    try:
        specification.loader.exec_module(patched)
        retry_executor = SandboxPaymentExecutor()
        retry = patched.ActionGate(
            casework=ravi.casework(cast(MemoryDatabase, gate.casework.database)),
            authority=LocalExecutionAuthority(
                (
                    ExecutionGrant(
                        principal_id=CALLER.principal_id,
                        tenant_id=TENANT,
                        action_kind="PAY",
                        gate_id=retry_executor.trusted_gate_id,
                        executor_id=retry_executor.executor_id,
                    ),
                )
            ),
            executor=retry_executor,
        )
        repeated = retry.execute(
            caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW
        )
    finally:
        del sys.modules[module_name]

    assert isinstance(repeated, Ok), repeated
    assert repeated.value == first.value
    assert retry_executor.dispatch_count == 1


#  ---- repeat failure paths ------------------------------------------------


@pytest.mark.postgres
def test_repeat_is_refused_before_unmigrated_custody_can_be_used(
    scratch_database: str,
) -> None:
    with pytest.raises(SchemaNotCurrent, match="ledger is absent"):
        require_current_schema(scratch_database)
    with psycopg.connect(scratch_database) as connection:
        relation = connection.execute(
            "SELECT to_regclass('action_gate.execution')"
        ).fetchone()
    assert relation == (None,)


def test_another_principal_executes_nothing() -> None:
    gate, executor, request, _lookup = _ready("idempotent-other-principal")

    refused = gate.execute(
        caller=GateCaller("someone-else"),
        tenant_id=TENANT,
        request=request,
        now=ravi.NOW,
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_AUTHORITY_REFUSED
    assert executor.dispatch_count == 0
    assert isinstance(gate.status(tenant_id=TENANT, case_id=request.case_id), Err)


def test_a_certificate_that_does_not_reproduce_creates_no_lifecycle() -> None:
    gate, _executor, request, _lookup = _ready("idempotent-certificate-mismatch")
    database = cast(MemoryDatabase, gate.casework.database)
    retry_executor = SandboxPaymentExecutor()
    retry = replace(
        configured_gate(ravi.casework(database), retry_executor),
        casework=ravi.casework(
            database,
            solver=lambda: BoundedEnumerationBackend(
                ravi.configuration().enumeration_budget * 2
            ),
        ),
    )

    refused = retry.execute(
        caller=CALLER, tenant_id=TENANT, request=request, now=ravi.NOW
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.PROPOSAL_REFUSED
    assert "CERTIFICATE_NOT_REPRODUCED" in refused.error.detail
    assert retry_executor.dispatch_count == 0
    assert isinstance(retry.status(tenant_id=TENANT, case_id=request.case_id), Err)


def test_a_moved_head_derives_a_distinct_execution_lifecycle() -> None:
    database = MemoryDatabase()
    casework = ravi.casework(database)
    case = ravi.ravi(TENANT, "idempotent-distinct-head", attested=True)
    open_ravi(casework, case)
    analysed, held = split_at_the_inert_claim(case)
    for entry in analysed:
        assert isinstance(
            append_transcript_entry(
                casework,
                tenant_id=TENANT,
                case_id=case.case_id,
                entry=entry,
                now=ravi.NOW,
            ),
            Ok,
        )

    first_executor = SandboxPaymentExecutor()
    first_gate = configured_gate(casework, first_executor)
    _first_report, first_request = proposal(casework, case)
    first = first_gate.execute(
        caller=CALLER, tenant_id=TENANT, request=first_request, now=ravi.NOW
    )
    assert isinstance(first, Ok), first

    assert isinstance(
        append_transcript_entry(
            casework,
            tenant_id=TENANT,
            case_id=case.case_id,
            entry=held,
            now=ravi.NOW,
        ),
        Ok,
    )
    second_executor = SandboxPaymentExecutor()
    second_gate = configured_gate(ravi.casework(database), second_executor)
    _second_report, second_request = proposal(second_gate.casework, case)
    second = second_gate.execute(
        caller=CALLER, tenant_id=TENANT, request=second_request, now=ravi.NOW
    )

    assert isinstance(second, Ok), second
    assert second.value.execution_key != first.value.execution_key
    assert first.value.state is ExecutionState.CONFIRMED
    assert second.value.state is ExecutionState.CONFIRMED
    assert first_executor.dispatch_count == 1
    assert second_executor.dispatch_count == 1
    assert len(database.records.executions) == 2


def test_repeat_against_an_absent_case_creates_nothing() -> None:
    gate, executor, request, _lookup = _ready("idempotent-present-case")
    absent_request = replace(request, case_id="idempotent-absent-case")

    refused = gate.execute(
        caller=CALLER,
        tenant_id=TENANT,
        request=absent_request,
        now=ravi.NOW,
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.CASE_REFUSED
    assert executor.dispatch_count == 0
    database = cast(MemoryDatabase, gate.casework.database)
    assert database.records.executions == {}
