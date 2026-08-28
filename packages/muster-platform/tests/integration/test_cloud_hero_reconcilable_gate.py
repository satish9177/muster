"""The cloud executor composes into an ordinary Gate and confirms only once."""

from __future__ import annotations

import psycopg
import pytest
from demo.cloud_hero import (
    CLOUD_ACTION_KIND,
    CLOUD_EXECUTOR_ID,
    CLOUD_GATE_ID,
    CloudFleet,
    CloudSandboxExecutor,
    HeroMode,
    cloud_executor,
)

from muster.core.results import Ok
from muster.platform.adapters.sql.config import DatabaseDeployment
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import Casework
from muster.platform.gate.authority import (
    ExecutionGrant,
    GateCaller,
    LocalExecutionAuthority,
)
from muster.platform.gate.executor import ReconcilableExecutor
from muster.platform.gate.model import ExecuteProposal, ExecutionState
from muster.platform.gate.service import ActionGate
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

pytestmark = pytest.mark.postgres

PRINCIPAL = "cloud-reconciliation-operator"


def _fleet(dsn: str, tenant_id: str, case_id: str) -> CloudFleet:
    """The Gate-mode custody inputs; the inert fleet fields are never contacted."""
    return CloudFleet(
        tenant_id=tenant_id,
        case_id=case_id,
        site_endpoint="https://site.example.invalid",
        employer_endpoint="https://employer.example.invalid",
        site_key_ref="site-key/test",
        employer_key_ref="employer-key/test",
        site_public_key=b"",
        employer_public_key=b"",
        timeout_seconds=None,
        raw_object=None,
        postgres=dsn,
        deployment=DatabaseDeployment.CLOUD_SQL,
        gate_mode=HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX,
        gate_principal=PRINCIPAL,
    )


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
        return connection.execute(
            "SELECT idempotency_key, external_reference "
            "FROM sandbox_rail.transfer WHERE idempotency_key = %s",
            (execution_key,),
        ).fetchall()


def test_cloud_gate_confirms_once_and_a_fresh_executor_reads_the_same_result(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    """A second composition shares PostgreSQL, not an executor's Python state."""
    fleet = _fleet(migrated_dsn, tenant_id, case_id)
    casework, request = _analysed_proposal(migrated_dsn, tenant_id, case_id)
    caller = GateCaller(PRINCIPAL)
    first_executor = cloud_executor(fleet)

    assert isinstance(first_executor, ReconcilableExecutor)
    first = _gate(casework, tenant_id, caller, first_executor).execute(
        caller=caller,
        tenant_id=tenant_id,
        request=request,
        now=ravi.NOW,
    )

    assert isinstance(first, Ok), first
    assert first.value.state is ExecutionState.CONFIRMED
    assert first.value.external_reference is not None
    assert first_executor.dispatch_count == 1
    assert _transfer_rows(migrated_dsn, first.value.execution_key.hex) == [
        (first.value.execution_key.hex, first.value.external_reference)
    ]

    fresh_executor = cloud_executor(fleet)
    fresh_casework = ravi.casework(SqlDatabase(migrated_dsn))
    repeated = _gate(fresh_casework, tenant_id, caller, fresh_executor).execute(
        caller=caller,
        tenant_id=tenant_id,
        request=request,
        now=ravi.NOW,
    )

    assert isinstance(fresh_executor, ReconcilableExecutor)
    assert isinstance(repeated, Ok), repeated
    assert repeated.value.state is ExecutionState.CONFIRMED
    assert repeated.value.execution_key == first.value.execution_key
    assert repeated.value.external_reference == first.value.external_reference
    assert fresh_executor.dispatch_count == 0
    assert _transfer_rows(migrated_dsn, first.value.execution_key.hex) == [
        (first.value.execution_key.hex, first.value.external_reference)
    ]
