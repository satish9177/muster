"""The duplicate-prevention proof, resting on PostgreSQL and on nothing else.

Every claim in this file is a claim about a database.  In particular:

**No proof here is allowed to rest on the sandbox executor's lock.**  That lock
protects one Python dictionary inside one process, and a system whose
exactly-once property came from it would have no exactly-once property at all
the moment it ran as two Cloud Run executions.  So every contender below gets
its **own** executor instance -- separate counters, separate dictionary,
separate lock -- and the assertion is over the *sum* of what those independent
executors did.  If the reservation and the dispatch compare-and-swap were not
doing the work, these tests would count two.

The second process is simulated the way the deployment actually produces one:
a fresh ``ActionGate`` over a fresh ``SqlDatabase`` on the same DSN, with no
shared object between it and the first.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import cast

import psycopg
import pytest

from muster.core.results import Err, InvariantViolation, Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import append_transcript_entry, case_status
from muster.platform.casework.ports import CaseworkDatabase
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import SandboxMode, SandboxPaymentExecutor
from muster.platform.gate.model import (
    ExecuteProposal,
    ExecutionKey,
    ExecutionLookup,
    ExecutionState,
    Finality,
)
from muster.platform.gate.ports import ExecutionStoreFailure
from muster.platform.gate.service import ActionGate, GateFailure
from support import ravi
from support.fixtures import append_all, open_ravi, split_at_the_inert_claim
from support.gate import proposal

pytestmark = pytest.mark.postgres

CALLER = GateCaller("postgres-idempotency-operator")


@dataclass(frozen=True, slots=True)
class _Deployment:
    """One process's view: its own database handle, gate and executor."""

    gate: ActionGate
    executor: SandboxPaymentExecutor


def _grants(tenant_id: str, executor: SandboxPaymentExecutor) -> LocalExecutionAuthority:
    return LocalExecutionAuthority(
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


def _deployment(
    dsn: str, tenant_id: str, *, mode: SandboxMode = SandboxMode.SUCCESS
) -> _Deployment:
    """A process that shares a database with the others and nothing else."""
    executor = SandboxPaymentExecutor(mode=mode)
    casework = ravi.casework(SqlDatabase(dsn))
    return _Deployment(
        gate=ActionGate(
            casework=casework, executor=executor, authority=_grants(tenant_id, executor)
        ),
        executor=executor,
    )


def _seeded(
    dsn: str, tenant_id: str, case_id: str
) -> tuple[_Deployment, ExecuteProposal, ExecutionLookup]:
    first = _deployment(dsn, tenant_id)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(first.gate.casework, case)
    append_all(first.gate.casework, case, now=ravi.NOW)
    _report, request = proposal(first.gate.casework, case)
    return first, request, _lookup(first.gate, tenant_id, request)


def _lookup(gate: ActionGate, tenant_id: str, request: ExecuteProposal) -> ExecutionLookup:
    """The durable identity a retry presents: the execution key, and a case.

    Derived here from the intent the Gate would authorize, which is the same 32
    octets the first execution prints in the deployment.  The case identifier
    is a narrowing rather than part of the identity -- see ``ExecutionLookup``.
    """
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
    return ExecutionLookup(
        execution_key=eligible.value.execution_key(),
        expected_case_id=request.case_id,
    )


def _rows(dsn: str, tenant_id: str, case_id: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT execution_id, state, external_reference, outcome_code "
            "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchall()


#  ---- the central proof ----------------------------------------------------


def test_a_second_process_reads_the_confirmation_and_dispatches_nothing(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """First execution, then a retry from a process that shares only the database.

    The whole U2 claim, as one sequence of assertions:

        first    dispatch_count 1, execution_count 1, CONFIRMED, one row,
                 one external reference;
        retry    dispatch_count still 1 on the first executor and 0 on the
                 second, the same execution key, the same reference, still one
                 row, and no new row of any kind.

    The retrying deployment carries its own executor, so "no second dispatch"
    is measured on a counter the first process cannot have touched.
    """
    first, request, lookup = _seeded(migrated_dsn, tenant_id, case_id)

    executed = first.gate.execute(
        caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW
    )
    assert isinstance(executed, Ok), executed
    record = executed.value
    assert record.state is ExecutionState.CONFIRMED
    assert record.finality is Finality.DEFINITELY_EXECUTED
    assert record.external_reference is not None
    assert first.executor.dispatch_count == 1
    assert first.executor.execution_count == 1

    before = _rows(migrated_dsn, tenant_id, case_id)
    assert len(before) == 1
    assert before[0][1] == "CONFIRMED"

    second = _deployment(migrated_dsn, tenant_id)
    read = second.gate.read_authorized_execution(
        caller=CALLER, tenant_id=tenant_id, lookup=lookup
    )

    assert isinstance(read, Ok), read
    assert read.value == record
    assert read.value.execution_key == record.execution_key
    assert read.value.external_reference == record.external_reference
    assert second.executor.dispatch_count == 0
    assert second.executor.execution_count == 0
    assert first.executor.dispatch_count == 1
    assert _rows(migrated_dsn, tenant_id, case_id) == before


def test_repeated_retries_never_accumulate_rows_dispatches_or_references(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """Idempotence is a property of *every* retry, not of the second one.

    Five reads from five independent deployments.  A store that created on
    read, or a Gate that fell back to executing when a read was inconvenient,
    would show up here as a growing row count -- which is exactly the shape a
    duplicate payment takes.
    """
    first, request, lookup = _seeded(migrated_dsn, tenant_id, case_id)
    executed = first.gate.execute(
        caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW
    )
    assert isinstance(executed, Ok), executed
    reference = executed.value.external_reference

    for _ in range(5):
        deployment = _deployment(migrated_dsn, tenant_id)
        read = deployment.gate.read_authorized_execution(
            caller=CALLER, tenant_id=tenant_id, lookup=lookup
        )
        assert isinstance(read, Ok), read
        assert read.value.state is ExecutionState.CONFIRMED
        assert read.value.external_reference == reference
        assert deployment.executor.dispatch_count == 0

    rows = _rows(migrated_dsn, tenant_id, case_id)
    assert len(rows) == 1
    assert rows[0][1] == "CONFIRMED"
    assert rows[0][2] == reference
    assert first.executor.dispatch_count == 1


#  ---- concurrency, without the sandbox lock --------------------------------


def test_two_independent_processes_produce_one_reservation_and_one_dispatch(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """Two contenders, two executors, two connections. One payment.

    Deliberately *not* the existing shared-gate concurrency test: there both
    contenders reach one ``SandboxPaymentExecutor``, whose lock and dictionary
    would mask a broken reservation as a confirmed duplicate.  Here the two
    executors cannot see each other, so the only thing serialising them is
    PostgreSQL -- the insert that loses ``ON CONFLICT DO NOTHING``, and the
    conditional update that changes no row.

    ``sum(...) == 1`` rather than "the winner dispatched once": which contender
    wins is a race, and asserting on a particular one would be asserting on the
    scheduler.
    """
    first, request, lookup = _seeded(migrated_dsn, tenant_id, case_id)
    second = _deployment(migrated_dsn, tenant_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            future.result()
            for future in [
                pool.submit(
                    deployment.gate.execute,
                    caller=CALLER,
                    tenant_id=tenant_id,
                    request=request,
                    now=ravi.NOW,
                )
                for deployment in (first, second)
            ]
        ]

    assert all(isinstance(result, Ok) for result in results), results
    records = [result.value for result in results if isinstance(result, Ok)]
    assert {record.execution_key for record in records} == {records[0].execution_key}

    #  The loser is answered with whatever the shared row said when it read it,
    #  which is legitimately DISPATCHED while the winner is still inside its
    #  executor call.  That is the honest answer and not a defect: its finality
    #  is OUTCOME_UNKNOWN, it holds no reference of its own, and it did not
    #  dispatch.  What must never appear is a *second* execution key or a
    #  second reference, and neither does.
    assert {record.state for record in records} <= {
        ExecutionState.CONFIRMED,
        ExecutionState.DISPATCHED,
    }
    references = {
        record.external_reference for record in records if record.external_reference is not None
    }
    assert len(references) <= 1

    #  The proof, and it is a sum over counters that share nothing.
    assert first.executor.dispatch_count + second.executor.dispatch_count == 1
    assert first.executor.execution_count + second.executor.execution_count == 1

    rows = _rows(migrated_dsn, tenant_id, case_id)
    assert len(rows) == 1
    assert rows[0][1] == "CONFIRMED"
    assert references <= {rows[0][2]}

    #  And once it is durable, a read from either side is a read.
    for deployment in (first, second):
        read = deployment.gate.read_authorized_execution(
            caller=CALLER, tenant_id=tenant_id, lookup=lookup
        )
        assert isinstance(read, Ok), read
        assert read.value.state is ExecutionState.CONFIRMED
    assert first.executor.dispatch_count + second.executor.dispatch_count == 1


def test_eight_independent_processes_still_produce_one_payment(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The same claim, widened until a lucky interleaving is unlikely to be luck.

    Eight contenders with eight executors. One row, one reference, one dispatch.
    The external-reference uniqueness constraint is asserted directly, because
    it is the last line of defence: two confirmed rows for one case would
    violate it at the database rather than at any assertion here.
    """
    first, request, _lookup_unused = _seeded(migrated_dsn, tenant_id, case_id)
    deployments = [first, *(_deployment(migrated_dsn, tenant_id) for _ in range(7))]

    with ThreadPoolExecutor(max_workers=len(deployments)) as pool:
        results = [
            future.result()
            for future in [
                pool.submit(
                    deployment.gate.execute,
                    caller=CALLER,
                    tenant_id=tenant_id,
                    request=request,
                    now=ravi.NOW,
                )
                for deployment in deployments
            ]
        ]

    assert all(isinstance(result, Ok) for result in results), results
    assert sum(deployment.executor.dispatch_count for deployment in deployments) == 1
    assert sum(deployment.executor.execution_count for deployment in deployments) == 1

    records = [result.value for result in results if isinstance(result, Ok)]
    assert {record.execution_key for record in records} == {records[0].execution_key}

    rows = _rows(migrated_dsn, tenant_id, case_id)
    assert len(rows) == 1
    assert rows[0][1] == "CONFIRMED"
    #  One reference exists, exactly one contender ever saw it, and it is the
    #  one the durable row carries.  A second confirmed row would not reach
    #  this assertion at all: the external-reference uniqueness constraint
    #  would have refused it at the database.
    references = {
        record.external_reference for record in records if record.external_reference is not None
    }
    assert references <= {rows[0][2]}
    assert rows[0][2] is not None


def test_a_contender_that_loses_the_dispatch_swap_never_reaches_its_executor(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The compare-and-swap is what gates the executor, stated on its own.

    The row is driven to DISPATCHED out of band, so every ``execute`` that
    follows *must* lose the swap.  Its executor's counter staying at zero is
    the property: only the winner of the durable CAS crosses the
    no-automatic-redispatch boundary.
    """
    first, request, _unused = _seeded(migrated_dsn, tenant_id, case_id)
    reported = case_status(
        first.gate.casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW
    )
    assert isinstance(reported, Ok)
    eligible = current_action_intent(
        reported.value,
        request,
        tenant_id=tenant_id,
        gate_id=first.gate.gate_id,
        executor_id=first.gate.executor.executor_id,
    )
    assert isinstance(eligible, Ok)
    intent = eligible.value

    database = SqlDatabase(migrated_dsn)
    with database.writing(tenant_id) as scope:
        reserved = scope.executions.reserve(
            intent, requested_by=CALLER.principal_id, now=ravi.NOW
        )
    assert isinstance(reserved, Ok) and reserved.value.acquired
    with database.writing(tenant_id) as scope:
        claim = scope.executions.begin_dispatch(intent.execution_key(), now=ravi.NOW)
    assert isinstance(claim, Ok) and claim.value.acquired

    loser = _deployment(migrated_dsn, tenant_id)
    lost = loser.gate.execute(
        caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW + 1
    )

    assert isinstance(lost, Ok), lost
    assert lost.value.state is ExecutionState.DISPATCHED
    assert lost.value.finality is Finality.OUTCOME_UNKNOWN
    assert loser.executor.dispatch_count == 0
    assert len(_rows(migrated_dsn, tenant_id, case_id)) == 1


#  ---- the durable identity the read rests on -------------------------------


def test_a_stored_lifecycle_is_found_by_its_key_and_by_nothing_looser(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The SQL lookup is a primary-key select, and that is the whole of it.

    Run against PostgreSQL rather than the in-memory store because this is a
    claim about the query: a ``WHERE`` clause that had grown a fallback, an
    ordering or a ``LIMIT`` over the case would still pass in a store that
    fetches out of a dictionary by the same key.

    A wrong key is ABSENT, and specifically not a near match.  A wrong case is
    a named refusal rather than an absence, because the row *was* found -- the
    caller simply told the Gate which case it believed it was retrying, and it
    was not this one.
    """
    first, request, lookup = _seeded(migrated_dsn, tenant_id, case_id)
    executed = first.gate.execute(
        caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW
    )
    assert isinstance(executed, Ok)

    second = _deployment(migrated_dsn, tenant_id)
    found = second.gate.read_authorized_execution(
        caller=CALLER, tenant_id=tenant_id, lookup=lookup
    )
    assert isinstance(found, Ok)

    absent = second.gate.read_authorized_execution(
        caller=CALLER,
        tenant_id=tenant_id,
        lookup=replace(lookup, execution_key=ExecutionKey(b"\xa5" * 32)),
    )
    assert isinstance(absent, Err)
    assert absent.error.failure is GateFailure.STORE_REFUSED
    assert ExecutionStoreFailure.ABSENT.value in absent.error.detail

    other_case = second.gate.read_authorized_execution(
        caller=CALLER,
        tenant_id=tenant_id,
        lookup=replace(lookup, expected_case_id=f"{case_id}-other"),
    )
    assert isinstance(other_case, Err)
    assert other_case.error.failure is GateFailure.EXECUTION_CASE_MISMATCH
    assert second.executor.dispatch_count == 0


def test_a_confirmed_execution_stays_readable_after_the_case_head_moves(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """Durable idempotency does not depend on mutable current case state.

    The sequence, against PostgreSQL:

        execute      the proposal the analysis produced, to CONFIRMED, and
                     remember its execution key;
        advance      one more transcript entry through the ordinary command,
                     publishing a new revision -- asserted, not assumed;
        retry        a second deployment, sharing only the DSN, reading by that
                     remembered key.

    The retry must return the *same historical* CONFIRMED execution and must
    dispatch nothing.  An identity derived from the current head would report
    this row absent the moment the case moved, which would leave "retry before
    the case advances" as a caveat carried into production.
    """
    first = _deployment(migrated_dsn, tenant_id)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(first.gate.casework, case)
    analysed, held = split_at_the_inert_claim(case)
    for entry in analysed:
        appended = append_transcript_entry(
            first.gate.casework,
            tenant_id=tenant_id,
            case_id=case_id,
            entry=entry,
            now=ravi.NOW,
        )
        assert isinstance(appended, Ok), appended

    before, request = proposal(first.gate.casework, case)
    executed = first.gate.execute(
        caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW
    )
    assert isinstance(executed, Ok), executed
    assert executed.value.state is ExecutionState.CONFIRMED
    assert first.executor.dispatch_count == 1
    key = executed.value.execution_key
    rows = _rows(migrated_dsn, tenant_id, case_id)
    assert len(rows) == 1

    advanced = append_transcript_entry(
        first.gate.casework, tenant_id=tenant_id, case_id=case_id, entry=held, now=ravi.NOW
    )
    assert isinstance(advanced, Ok), advanced
    after = case_status(first.gate.casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(after, Ok), after
    assert after.value.head.revision_digest != before.head.revision_digest
    assert after.value.head.revision_number > before.head.revision_number

    second = _deployment(migrated_dsn, tenant_id)
    read = second.gate.read_authorized_execution(
        caller=CALLER,
        tenant_id=tenant_id,
        lookup=ExecutionLookup(execution_key=key, expected_case_id=case_id),
    )

    assert isinstance(read, Ok), read
    assert read.value == executed.value
    assert read.value.execution_key == key
    assert read.value.state is ExecutionState.CONFIRMED
    assert read.value.external_reference == executed.value.external_reference
    assert second.executor.dispatch_count == 0
    assert second.executor.execution_count == 0
    assert first.executor.dispatch_count == 1
    #  And no row was created, moved or added by the retry.
    assert _rows(migrated_dsn, tenant_id, case_id) == rows


def test_an_execution_key_from_another_tenant_is_refused(
    migrated_dsn: str, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    """One database, two tenants, and a key that exists in the wrong one.

    The row is really there -- so this is not the absent-key case wearing a
    different name -- and it is still ABSENT to the tenant that did not
    authorize it, because the store's lookup is bound to the tenant before the
    key is considered at all.
    """
    other_tenant = other_tenant_id  # a tenant this caller was never granted anything in
    other = _deployment(migrated_dsn, other_tenant)
    other_case = ravi.ravi(other_tenant, case_id, attested=True)
    open_ravi(other.gate.casework, other_case)
    append_all(other.gate.casework, other_case, now=ravi.NOW)
    _report, other_request = proposal(other.gate.casework, other_case)
    executed = other.gate.execute(
        caller=CALLER, tenant_id=other_tenant, request=other_request, now=ravi.NOW
    )
    assert isinstance(executed, Ok), executed

    mine = _deployment(migrated_dsn, tenant_id)
    refused = mine.gate.read_authorized_execution(
        caller=CALLER,
        tenant_id=tenant_id,
        lookup=ExecutionLookup(execution_key=executed.value.execution_key),
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.STORE_REFUSED
    assert ExecutionStoreFailure.ABSENT.value in refused.error.detail
    assert mine.executor.dispatch_count == 0


def test_an_ungranted_caller_is_refused_before_any_execution_state_is_read(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """Authority first, and "first" is asserted rather than read off the source.

    The refusal alone would pass with the ``may_invoke`` check deleted: the
    grant test that needs the stored action kind would still refuse, just after
    letting an ungranted caller make the process read a tenant's execution
    table.  So the Gate is handed a database that raises on contact, and the
    refusal has to arrive anyway.

    Run against the PostgreSQL suite because that is where "opened the
    database" means something real -- a connection, a query, and a row this
    caller has no business causing to be fetched.
    """
    first, request, lookup = _seeded(migrated_dsn, tenant_id, case_id)
    assert isinstance(
        first.gate.execute(caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW),
        Ok,
    )

    class _Sealed:
        def reading(self, tenant_id: str) -> object:  # noqa: ARG002
            raise AssertionError("the read opened the database for an ungranted caller")

        def writing(self, tenant_id: str) -> object:  # noqa: ARG002
            raise AssertionError("the read opened the database for an ungranted caller")

    second = _deployment(migrated_dsn, tenant_id)
    sealed = replace(
        second.gate,
        casework=replace(
            second.gate.casework, database=cast(CaseworkDatabase, _Sealed())
        ),
    )
    refused = sealed.read_authorized_execution(
        caller=GateCaller("nobody-granted-anything"), tenant_id=tenant_id, lookup=lookup
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.EXECUTION_AUTHORITY_REFUSED
    #  Nothing about the durable execution reached the caller: not the state,
    #  not the reference, not even its absence.
    assert "execution grant" in refused.error.detail
    assert second.executor.dispatch_count == 0


#  ---- what the store refuses to read back ----------------------------------


def _corrupt(dsn: str, tenant_id: str, case_id: str, **columns: object) -> None:
    """Write a value into a stored lifecycle that the Gate never could.

    Deliberately raw SQL against a test tenant.  Nothing in the application can
    produce these rows -- the columns are immutable after insert and every one
    of them is derived from the canonical octets -- which is exactly why they
    have to be manufactured to find out what happens when a row is wrong.
    """
    assignments = ", ".join(f"{name} = %({name})s" for name in columns)
    with psycopg.connect(dsn) as connection:
        connection.execute(
            f"UPDATE action_gate.execution SET {assignments} "  # noqa: S608 - test-owned names
            "WHERE tenant_id = %(tenant)s AND case_id = %(case)s",
            {"tenant": tenant_id, "case": case_id, **columns},
        )
        connection.commit()


def test_a_stored_intent_that_is_not_canonical_wire_data_is_refused_loudly(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """A malformed preimage is a defect, not an input, so it raises.

    Everything the Gate refuses by *value* is something an untrusted party can
    cause.  This is not: ``intent_octets`` is written once, by this application,
    from a canonical encoder.  A row whose octets no longer decode means the
    store is wrong, and continuing on a partially-read execution record is the
    one behaviour that could turn a corrupt row into a second payment.
    """
    first, request, lookup = _seeded(migrated_dsn, tenant_id, case_id)
    assert isinstance(
        first.gate.execute(caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW),
        Ok,
    )
    _corrupt(migrated_dsn, tenant_id, case_id, intent_octets=b"\x00not canonical wire data")

    second = _deployment(migrated_dsn, tenant_id)
    with pytest.raises(InvariantViolation, match="canonical wire data"):
        second.gate.read_authorized_execution(
            caller=CALLER, tenant_id=tenant_id, lookup=lookup
        )
    assert second.executor.dispatch_count == 0


def test_an_execution_id_that_is_not_the_hash_of_its_intent_is_refused_loudly(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The idempotency key must be the hash of the exact authorized intent.

    If it were not, two different intents could share a reservation and an
    executor idempotency key -- which is the precise mechanism by which "pay
    Ravi 5100" and something else become one confirmed payment.

    Asked for by the *forged* key, deliberately.  Asking by the original one
    would only prove that a row filed elsewhere is absent, which is true and is
    a different claim.  What has to be refused is the row a caller can actually
    reach: the store finds it, and then discovers that the octets beside it do
    not produce the key it was filed under.
    """
    first, request, _unused = _seeded(migrated_dsn, tenant_id, case_id)
    assert isinstance(
        first.gate.execute(caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW),
        Ok,
    )
    forged = b"\x5c" * 32
    _corrupt(migrated_dsn, tenant_id, case_id, execution_id=forged)

    second = _deployment(migrated_dsn, tenant_id)
    with pytest.raises(InvariantViolation, match="execution_id"):
        second.gate.read_authorized_execution(
            caller=CALLER,
            tenant_id=tenant_id,
            lookup=ExecutionLookup(
                execution_key=ExecutionKey(forged), expected_case_id=case_id
            ),
        )
    assert second.executor.dispatch_count == 0


def test_an_identity_column_that_disagrees_with_the_stored_intent_is_refused_loudly(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The indexed columns describe the octets, and a store must not disagree.

    The lookup matches on columns; the answer is the canonical value.  A row
    where those two things say different actions is a row where the query that
    found it and the intent that would be dispatched are about different
    payments.
    """
    first, request, lookup = _seeded(migrated_dsn, tenant_id, case_id)
    assert isinstance(
        first.gate.execute(caller=CALLER, tenant_id=tenant_id, request=request, now=ravi.NOW),
        Ok,
    )
    _corrupt(migrated_dsn, tenant_id, case_id, action_kind="REFUND")

    second = _deployment(migrated_dsn, tenant_id)
    with pytest.raises(InvariantViolation, match="action_kind"):
        second.gate.read_authorized_execution(
            caller=CALLER, tenant_id=tenant_id, lookup=lookup
        )
    assert second.executor.dispatch_count == 0
