"""Atomic Gate reservation and exactly-once dispatch against real PostgreSQL."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import psycopg
import pytest

from muster.core.evidence.relations import ExactValue
from muster.core.evidence.transcript import Attestation, Statement
from muster.core.results import Err, Ok
from muster.core.values.scalars import VScaled
from muster.core.values.times import Instant
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import case_status
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.executor import SandboxPaymentExecutor
from muster.platform.gate.model import ActionIntent, ExecuteProposal, ExecutionState, Finality
from muster.platform.gate.service import ActionGate, GateFailure
from support import authority as source_authority
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

pytestmark = pytest.mark.postgres


def _intent(
    gate: ActionGate, tenant_id: str, request: ExecuteProposal, *, now: Instant
) -> ActionIntent:
    reported = case_status(
        gate.casework, tenant_id=tenant_id, case_id=request.case_id, now=now
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
    return eligible.value


def _independently_authorized_later_intent(
    tenant_id: str,
    case_id: str,
    executor: SandboxPaymentExecutor,
) -> ActionIntent:
    """Derive B through real admission, Q-12, rebuild, certificate, and eligibility.

    The current Ravi domain exposes no repin command, so this independent
    casework instance supplies the repository seam with the future generic
    situation under test: the same case identity, a later revision number, and
    a materially different action that has passed every layer above the store.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    daily_rate = case.entries[0]
    inert_claim = case.entries[17]
    assert isinstance(daily_rate, Attestation)
    assert isinstance(inert_claim, Statement)
    relation = daily_rate.receipt.payload.relation
    assert isinstance(relation, ExactValue)
    value = relation.value
    assert isinstance(value, VScaled)
    changed_rate = source_authority.sign_entry(
        Attestation(
            replace(
                daily_rate.receipt,
                payload=replace(
                    daily_rate.receipt.payload,
                    relation=ExactValue(
                        VScaled(value.unit_tag, value.scale, value.minor + 1_000)
                    ),
                ),
            )
        )
    )
    extra_inert_claim = Statement(
        replace(inert_claim.record, statement_time=inert_claim.record.statement_time + 1)
    )
    later = replace(
        case,
        entries=(changed_rate, *case.entries[1:], extra_inert_claim),
    )
    memory = MemoryDatabase()
    casework = ravi.casework(memory)
    open_ravi(casework, later)
    append_all(casework, later, now=ravi.NOW)
    _report, request = proposal(casework, later)
    gate = ActionGate(
        casework=casework,
        executor=executor,
        authority=LocalExecutionAuthority(()),
    )
    return _intent(gate, tenant_id, request, now=ravi.NOW)


def test_two_concurrent_callers_create_one_reservation_and_one_dispatch(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(database)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    _report, request = proposal(casework, case)

    caller = GateCaller("postgres-gate-operator")
    executor = SandboxPaymentExecutor()
    gate = ActionGate(
        casework=casework,
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

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                gate.execute,
                caller=caller,
                tenant_id=tenant_id,
                request=request,
                now=ravi.NOW,
            )
            for _ in range(2)
        ]
        results = [future.result() for future in futures]

    assert all(isinstance(result, Ok) for result in results)
    records = [result.value for result in results if isinstance(result, Ok)]
    assert {record.execution_key for record in records} == {records[0].execution_key}
    assert executor.dispatch_count == 1
    assert executor.execution_count == 1

    replay = gate.execute(
        caller=caller, tenant_id=tenant_id, request=request, now=ravi.NOW + 1
    )
    assert isinstance(replay, Ok)
    assert replay.value.state is ExecutionState.CONFIRMED
    assert executor.dispatch_count == 1

    with psycopg.connect(migrated_dsn) as connection:
        row = connection.execute(
            "SELECT count(*), min(state), max(state) FROM action_gate.execution "
            "WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchone()
    assert row == (1, "CONFIRMED", "CONFIRMED")


def test_abandoned_reserved_is_claimed_by_a_retrying_authorized_caller(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(database)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    _report, request = proposal(casework, case)
    caller_a = GateCaller("postgres-reserver-a")
    caller_b = GateCaller("postgres-recovery-b")
    executor = SandboxPaymentExecutor()
    grants = tuple(
        ExecutionGrant(
            principal_id=caller.principal_id,
            tenant_id=tenant_id,
            action_kind="PAY",
            gate_id=executor.trusted_gate_id,
            executor_id=executor.executor_id,
        )
        for caller in (caller_a, caller_b)
    )
    gate = ActionGate(
        casework=casework,
        executor=executor,
        authority=LocalExecutionAuthority(grants),
    )
    intent = _intent(gate, tenant_id, request, now=ravi.NOW)

    # A commits the durable reservation, then disappears before dispatch.
    with database.writing(tenant_id) as scope:
        reserved = scope.executions.reserve(
            intent, requested_by=caller_a.principal_id, now=ravi.NOW
        )
    assert isinstance(reserved, Ok) and reserved.value.acquired
    assert reserved.value.record.state is ExecutionState.RESERVED

    recovered = gate.execute(
        caller=caller_b,
        tenant_id=tenant_id,
        request=request,
        now=ravi.NOW + 1,
    )

    assert isinstance(recovered, Ok), recovered
    assert recovered.value.state is ExecutionState.CONFIRMED
    assert recovered.value.requested_by == caller_a.principal_id
    assert executor.dispatch_count == 1
    assert executor.execution_count == 1


def test_dispatched_without_a_durable_result_is_unknown_and_never_redispatched(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(database)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    _report, request = proposal(casework, case)
    caller = GateCaller("postgres-dispatch-operator")
    executor = SandboxPaymentExecutor()
    gate = ActionGate(
        casework=casework,
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
    intent = _intent(gate, tenant_id, request, now=ravi.NOW)
    with database.writing(tenant_id) as scope:
        reserved = scope.executions.reserve(
            intent, requested_by=caller.principal_id, now=ravi.NOW
        )
    assert isinstance(reserved, Ok)
    with database.writing(tenant_id) as scope:
        claim = scope.executions.begin_dispatch(intent.execution_key(), now=ravi.NOW)
    assert isinstance(claim, Ok) and claim.value.acquired
    assert claim.value.record.state is ExecutionState.DISPATCHED

    retried = gate.execute(
        caller=caller,
        tenant_id=tenant_id,
        request=request,
        now=ravi.NOW + 1,
    )

    assert isinstance(retried, Ok), retried
    assert retried.value.state is ExecutionState.DISPATCHED
    assert retried.value.finality is Finality.OUTCOME_UNKNOWN
    assert executor.dispatch_count == 0


def test_same_case_later_authorized_action_has_a_distinct_durable_lifecycle(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """Exercise proposal-scoped SQL uniqueness and stale Gate binding together."""
    casework = ravi.casework(database)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    _report, request_a = proposal(casework, case)
    caller = GateCaller("postgres-revision-operator")
    executor = SandboxPaymentExecutor()
    gate = ActionGate(
        casework=casework,
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
    intent_a = _intent(gate, tenant_id, request_a, now=ravi.NOW)
    confirmed_a = gate.execute(
        caller=caller, tenant_id=tenant_id, request=request_a, now=ravi.NOW
    )
    assert isinstance(confirmed_a, Ok), confirmed_a
    immutable_a = confirmed_a.value

    intent_b = _independently_authorized_later_intent(
        tenant_id,
        case_id,
        executor,
    )
    action_b = intent_b.action
    assert intent_b.revision_number == intent_a.revision_number + 1
    assert intent_b.action != intent_a.action
    assert intent_b.execution_key() != intent_a.execution_key()

    with database.writing(tenant_id) as scope:
        reserved_b = scope.executions.reserve(
            intent_b, requested_by=caller.principal_id, now=ravi.NOW + 1
        )
        replayed_a = scope.executions.reserve(
            intent_a, requested_by=caller.principal_id, now=ravi.NOW + 1
        )
        reread_a = scope.executions.read(intent_a.execution_key())
    assert isinstance(reserved_b, Ok) and reserved_b.value.acquired
    assert reserved_b.value.record.execution_key == intent_b.execution_key()
    assert isinstance(replayed_a, Ok) and not replayed_a.value.acquired
    assert isinstance(reread_a, Ok) and reread_a.value == immutable_a

    gate_replay_a = gate.execute(
        caller=caller,
        tenant_id=tenant_id,
        request=request_a,
        now=ravi.NOW + 1,
    )
    assert isinstance(gate_replay_a, Ok)
    assert gate_replay_a.value == immutable_a
    assert executor.dispatch_count == 1

    stale_n_for_b = gate.execute(
        caller=caller,
        tenant_id=tenant_id,
        request=replace(request_a, action_digest=action_b.digest()),
        now=ravi.NOW + 1,
    )
    assert isinstance(stale_n_for_b, Err)
    assert stale_n_for_b.error.failure is GateFailure.PROPOSAL_REFUSED
    assert executor.dispatch_count == 1

    with psycopg.connect(migrated_dsn) as connection:
        rows = connection.execute(
            "SELECT execution_id, revision_number, action_digest, state "
            "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s "
            "ORDER BY revision_number",
            (tenant_id, case_id),
        ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] != rows[1][0]
    assert rows[0][1:] == (
        intent_a.revision_number,
        intent_a.action_digest.octets,
        "CONFIRMED",
    )
    assert rows[1][1:] == (
        intent_b.revision_number,
        intent_b.action_digest.octets,
        "RESERVED",
    )


def test_execution_uniqueness_is_proposal_scoped_not_case_scoped(
    migrated_dsn: str,
) -> None:
    with psycopg.connect(migrated_dsn) as connection:
        constraints: dict[str, str] = dict(
            connection.execute(
                "SELECT conname, pg_get_constraintdef(oid) "
                "FROM pg_constraint "
                "WHERE conrelid = 'action_gate.execution'::regclass "
                "AND contype IN ('p', 'u')"
            ).fetchall()
        )
        indexes: set[str] = {
            row[0]
            for row in connection.execute(
                "SELECT indexname FROM pg_indexes "
                "WHERE schemaname = 'action_gate' AND tablename = 'execution'"
            ).fetchall()
        }

    assert constraints == {
        "execution_pkey": "PRIMARY KEY (tenant_id, execution_id)",
        "action_gate_one_lifecycle_per_authorized_proposal": (
            "UNIQUE (tenant_id, case_id, revision_number, revision_digest, "
            "certificate_digest, kernel_result_digest, bundle_manifest_digest, "
            "authorization_context_digest, action_schema_digest, action_digest)"
        ),
        "action_gate_external_reference_unique": (
            "UNIQUE (tenant_id, external_reference)"
        ),
    }
    assert indexes == set(constraints)
    assert "action_gate_one_lifecycle_per_case" not in constraints
