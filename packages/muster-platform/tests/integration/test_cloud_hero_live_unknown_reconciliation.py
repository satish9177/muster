"""The deployed sequence a live reconciliation proof is actually made of.

Three executions against one PostgreSQL database, in the order an operator runs
them.  The first composes the deployed Gate with the demo-only simulation that
loses its answer *after* the synthetic external system has committed, and leaves
a durable UNCERTAIN row behind.  The second is the real
``demo.cloud_hero.reconcile_gate_execution`` -- not a stand-in for it -- which
observes that row through the executor's read-only boundary and refines it to
CONFIRMED without dispatching.  The third runs the ordinary first-execution
entry point again and dispatches nothing.

**What this does and does not establish.**  It establishes that a durably
unknown outcome over a committed external effect is reconciled by observation,
once, with zero redispatch, through the deployed composition root.  It does not
establish process death: nothing here is killed.  The killed-process proof is
``demo/reconcile_ravi.py``, against local PostgreSQL, and stays there.

The only substitution is the metadata server, which no test process can reach.
Everything else -- the executor selection, ``ActionGate.execute``,
``ActionGate.reconcile_execution``, ``build_casework``, ``cloud_gate`` and the
``ReconciledExecution`` projection -- is the code the deployed job runs.
"""

from __future__ import annotations

import psycopg
import pytest
from demo.cloud_hero import (
    CLOUD_ACTION_KIND,
    CLOUD_EXECUTOR_ID,
    CLOUD_GATE_ID,
    PRINCIPAL_SOURCE,
    CloudFleet,
    CloudSandboxExecutor,
    HeroMode,
    SimulatedUnknownOutcome,
    cloud_executor,
    reconcile_gate_execution,
)

from muster.core.results import Ok, Result
from muster.platform.adapters.sql.config import DatabaseDeployment
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.sandbox_rail import DurableSandboxPaymentExecutor
from muster.platform.casework.advance import Casework
from muster.platform.gate.authority import (
    ExecutionGrant,
    GateCaller,
    LocalExecutionAuthority,
)
from muster.platform.gate.cloud import CloudPrincipalError
from muster.platform.gate.executor import ExecutorDispatch, ReconcilableExecutor
from muster.platform.gate.model import ExecuteProposal, ExecutionKey, ExecutionState
from muster.platform.gate.service import ActionGate
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

pytestmark = pytest.mark.postgres

PRINCIPAL = "muster-control-plane@muster-project.iam.gserviceaccount.com"


class _MetadataServerSaysThisWorkload:
    """The one boundary a test process cannot reach, and nothing else."""

    def principal_id(self) -> Result[str, CloudPrincipalError]:
        return Ok(PRINCIPAL)


def _fleet(dsn: str, tenant_id: str, case_id: str, **overrides: object) -> CloudFleet:
    """The Gate-mode custody inputs; the inert fleet fields are never contacted."""
    settings: dict[str, object] = {
        "tenant_id": tenant_id,
        "case_id": case_id,
        "site_endpoint": "https://site.example.invalid",
        "employer_endpoint": "https://employer.example.invalid",
        "site_key_ref": "site-key/test",
        "employer_key_ref": "employer-key/test",
        "site_public_key": b"",
        "employer_public_key": b"",
        "timeout_seconds": None,
        "raw_object": None,
        "postgres": dsn,
        "deployment": DatabaseDeployment.CLOUD_SQL,
        "gate_mode": HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX,
        "gate_principal": PRINCIPAL,
    }
    settings.update(overrides)
    return CloudFleet(**settings)  # type: ignore[arg-type]


def _gate(
    casework: Casework,
    tenant_id: str,
    caller: GateCaller,
    executor: CloudSandboxExecutor,
) -> ActionGate:
    """Substitute only the unreachable metadata authority with a local grant."""
    return ActionGate(
        casework=casework,
        executor=executor,
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=caller.principal_id,
                    tenant_id=tenant_id,
                    action_kind=CLOUD_ACTION_KIND,
                    gate_id=CLOUD_GATE_ID,
                    executor_id=CLOUD_EXECUTOR_ID,
                ),
            )
        ),
        gate_id=CLOUD_GATE_ID,
    )


def _analysed_proposal(
    dsn: str, tenant_id: str, case_id: str
) -> tuple[Casework, ExecuteProposal]:
    casework = ravi.casework(SqlDatabase(dsn))
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    _report, request = proposal(casework, case)
    return casework, request


def _transfer_rows(dsn: str, execution_key: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        return connection.execute(
            "SELECT external_reference FROM sandbox_rail.transfer "
            "WHERE idempotency_key = %s",
            (execution_key,),
        ).fetchall()


def _attempt_outcome(dsn: str, execution_key: str) -> str | None:
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        row = connection.execute(
            "SELECT outcome FROM sandbox_rail.attempt WHERE idempotency_key = %s",
            (execution_key,),
        ).fetchone()
    return None if row is None else str(row[0])


def _execution_row(dsn: str, tenant_id: str, execution_key: str) -> tuple[object, ...]:
    """The lifecycle columns, read outside every projection that claims them."""
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        row = connection.execute(
            "SELECT state, outcome_code, external_reference, finalized_at, "
            "reconciled_at, reconciled_from "
            "FROM action_gate.execution WHERE tenant_id = %s AND execution_id = %s",
            (tenant_id, bytes.fromhex(execution_key)),
        ).fetchone()
    assert row is not None
    return row


def _leaves_an_unknown_outcome(
    dsn: str, tenant_id: str, case_id: str
) -> tuple[str, CloudSandboxExecutor]:
    """The setup execution, through the deployed composition and the real Gate."""
    fleet = _fleet(dsn, tenant_id, case_id, gate_simulate_unknown=True)
    casework, request = _analysed_proposal(dsn, tenant_id, case_id)
    caller = GateCaller(PRINCIPAL)
    executor = cloud_executor(fleet)

    performed = _gate(casework, tenant_id, caller, executor).execute(
        caller=caller,
        tenant_id=tenant_id,
        request=request,
        now=ravi.NOW,
    )

    assert isinstance(performed, Ok), performed
    return performed.value.execution_key.hex, executor


#  ---- the setup half: a real unknown outcome over a real external effect ---


def test_the_simulation_commits_the_transfer_and_then_loses_the_answer(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The exception follows the acceptance; it does not replace it.

    Asserted against ``sandbox_rail`` directly, because the ordering *is* the
    proof: an exception raised before the commit would leave no external effect
    to reconcile and would make the whole sequence below vacuous.
    """
    fleet = _fleet(migrated_dsn, tenant_id, case_id, gate_simulate_unknown=True)
    casework, request = _analysed_proposal(migrated_dsn, tenant_id, case_id)
    executor = cloud_executor(fleet)
    assert isinstance(executor, DurableSandboxPaymentExecutor)
    #  The exact intent the Gate would hand it, derived the way the Gate derives
    #  it, so the idempotency key is the one the durable row is keyed by.
    caller = GateCaller(PRINCIPAL)
    reserved = _gate(casework, tenant_id, caller, executor).execute(
        caller=caller, tenant_id=tenant_id, request=request, now=ravi.NOW
    )
    assert isinstance(reserved, Ok), reserved
    key = reserved.value.execution_key.hex

    assert _attempt_outcome(migrated_dsn, key) == "ATTEMPTED"
    assert len(_transfer_rows(migrated_dsn, key)) == 1
    assert executor.dispatch_count == 1

    #  And the raise itself, named rather than anonymous, over the same key: a
    #  second dispatch finds the committed transfer, still accepts, still loses.
    with pytest.raises(SimulatedUnknownOutcome, match="lost the answer"):
        executor.dispatch(
            ExecutorDispatch(
                intent=reserved.value.intent,
                idempotency_key=key,
                gate_id=CLOUD_GATE_ID,
            )
        )
    assert len(_transfer_rows(migrated_dsn, key)) == 1


def test_the_deployed_gate_records_uncertain_over_a_committed_transfer(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """``ActionGate.execute`` converts the lost answer into a durable UNCERTAIN."""
    key, executor = _leaves_an_unknown_outcome(migrated_dsn, tenant_id, case_id)

    state, outcome_code, reference, finalized_at, reconciled_at, reconciled_from = (
        _execution_row(migrated_dsn, tenant_id, key)
    )

    assert state == "UNCERTAIN"
    #  The ordinary ``UnknownOutcome`` path, not a special case: the Gate names
    #  the exception class it caught and carries no external reference, because
    #  this process does not know one.
    assert outcome_code == "EXECUTOR_EXCEPTION"
    assert reference is None
    assert finalized_at is not None
    #  Finalized, and never reconciled -- nothing has observed it yet.
    assert reconciled_at is None
    assert reconciled_from is None
    assert executor.dispatch_count == 1
    #  The external effect is real and singular, which is what makes the
    #  unknown outcome worth reconciling rather than worth retrying.
    assert len(_transfer_rows(migrated_dsn, key)) == 1


#  ---- the proof half: the real reconciliation entry point ------------------


def test_the_real_reconciliation_entry_point_confirms_without_dispatching(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``reconcile_gate_execution`` itself, against PostgreSQL, field by field."""
    key, _setup_executor = _leaves_an_unknown_outcome(migrated_dsn, tenant_id, case_id)
    monkeypatch.setattr(
        "demo.cloud_hero.MetadataServerPrincipal", _MetadataServerSaysThisWorkload
    )
    #  A fresh fleet with no simulation and the execution id the setup printed:
    #  exactly the configuration the second Cloud Run execution carries.
    fleet = _fleet(
        migrated_dsn,
        tenant_id,
        case_id,
        gate_execution_key=ExecutionKey(bytes.fromhex(key)),
    )

    reconciled = reconcile_gate_execution(SqlDatabase(migrated_dsn), fleet)

    #  The projection, checked against the durable row rather than against the
    #  values the function was handed.
    state, outcome_code, reference, _finalized, reconciled_at, reconciled_from = (
        _execution_row(migrated_dsn, tenant_id, key)
    )
    assert state == "CONFIRMED"
    assert reconciled_from == "UNCERTAIN"
    assert reconciled_at is not None
    assert reference is not None

    assert reconciled.execution_key == key
    assert reconciled.state == "CONFIRMED"
    assert reconciled.finality == "DEFINITELY_EXECUTED"
    assert reconciled.outcome_code == outcome_code == "CONFIRMED"
    assert reconciled.external_reference == reference
    assert reconciled.external_reference == f"sandbox-pay-{key}"
    assert reconciled.reconciled_from == "UNCERTAIN"
    assert reconciled.reconciled_at == reconciled_at
    assert reconciled.real_funds is False
    assert reconciled.gate_id == CLOUD_GATE_ID
    assert reconciled.executor_id == CLOUD_EXECUTOR_ID
    assert reconciled.principal_id == PRINCIPAL
    #  Zero, and one.  This process crossed the inspection boundary exactly once
    #  and the dispatch boundary not at all.
    assert reconciled.dispatch_count == 0
    assert reconciled.inspection_count == 1
    #  Still one synthetic transfer: observing it did not create a second.
    assert _transfer_rows(migrated_dsn, key) == [(reference,)]
    assert PRINCIPAL_SOURCE == "METADATA_SERVER"


def test_a_reconciliation_run_may_not_carry_the_simulation(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An observation must not be able to compose the injection that creates state."""
    key, _executor = _leaves_an_unknown_outcome(migrated_dsn, tenant_id, case_id)
    monkeypatch.setattr(
        "demo.cloud_hero.MetadataServerPrincipal", _MetadataServerSaysThisWorkload
    )
    fleet = _fleet(
        migrated_dsn,
        tenant_id,
        case_id,
        gate_simulate_unknown=True,
        gate_execution_key=ExecutionKey(bytes.fromhex(key)),
    )

    with pytest.raises(SystemExit, match="GATE RECONCILIATION REFUSED"):
        reconcile_gate_execution(SqlDatabase(migrated_dsn), fleet)

    #  Refused before anything was observed: the row is untouched.
    state, _code, _reference, _finalized, reconciled_at, _from = _execution_row(
        migrated_dsn, tenant_id, key
    )
    assert state == "UNCERTAIN"
    assert reconciled_at is None


#  ---- and the exact repeat that follows it ---------------------------------


def test_the_exact_repeat_after_reconciliation_dispatches_nothing(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ordinary entry point, a third time, over a reconciled execution."""
    key, _setup_executor = _leaves_an_unknown_outcome(migrated_dsn, tenant_id, case_id)
    monkeypatch.setattr(
        "demo.cloud_hero.MetadataServerPrincipal", _MetadataServerSaysThisWorkload
    )
    fleet = _fleet(
        migrated_dsn,
        tenant_id,
        case_id,
        gate_execution_key=ExecutionKey(bytes.fromhex(key)),
    )
    reconciled = reconcile_gate_execution(SqlDatabase(migrated_dsn), fleet)
    reference = reconciled.external_reference
    assert reference is not None

    #  No simulation, a fresh executor, and no special retry path: this is
    #  ``ActionGate.execute`` re-deriving the same proposal from the same case.
    repeat_fleet = _fleet(migrated_dsn, tenant_id, case_id)
    repeat_casework, repeat_request = _analysed_proposal(
        migrated_dsn, tenant_id, case_id
    )
    repeat_executor = cloud_executor(repeat_fleet)
    assert isinstance(repeat_executor, ReconcilableExecutor)
    caller = GateCaller(PRINCIPAL)

    repeated = _gate(repeat_casework, tenant_id, caller, repeat_executor).execute(
        caller=caller, tenant_id=tenant_id, request=repeat_request, now=ravi.NOW
    )

    assert isinstance(repeated, Ok), repeated
    assert repeated.value.execution_key.hex == key
    assert repeated.value.state is ExecutionState.CONFIRMED
    assert repeated.value.external_reference == reference
    assert repeated.value.reconciled_from is ExecutionState.UNCERTAIN
    assert repeat_executor.dispatch_count == 0
    assert repeat_executor.inspection_count == 0
    assert _transfer_rows(migrated_dsn, key) == [(reference,)]
