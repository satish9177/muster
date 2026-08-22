"""Milestone G: Ravi's exact authorized sandbox action executes once."""

from __future__ import annotations

import pytest

from muster.core.analysis.outcomes import Invariant
from muster.core.results import Ok
from muster.core.values.scalars import VEnum, VScaled
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.executor import SandboxPaymentExecutor
from muster.platform.gate.model import ExecutionState, Finality, GateReadState
from muster.platform.gate.service import ActionGate
from muster.platform.orchestration.status import CaseStatus
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

pytestmark = pytest.mark.postgres


def test_ravi_reaches_invariant_and_the_exact_sandbox_action_executes_once(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(database)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    report, request = proposal(casework, case)
    assert report.status is CaseStatus.PROPOSED
    assert report.analysis is not None

    outcome = report.analysis.kernel.outcome
    assert isinstance(outcome, Invariant)
    action = outcome.action
    fields = {field.name: field.value for field in action.consequential_fields}
    assert fields["recipient"] == VEnum("party_id", "RAVI")
    assert fields["amount"] == VScaled("INR", 2, 510_000)

    caller = GateCaller("hero-sandbox-operator")
    executor = SandboxPaymentExecutor()
    gate = ActionGate(
        casework=casework,
        executor=executor,
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    caller.principal_id,
                    tenant_id,
                    "PAY",
                    executor.trusted_gate_id,
                    executor.executor_id,
                ),
            )
        ),
    )
    first = gate.execute(caller=caller, tenant_id=tenant_id, request=request, now=ravi.NOW)
    second = gate.execute(
        caller=caller, tenant_id=tenant_id, request=request, now=ravi.NOW + 1
    )
    assert isinstance(first, Ok) and isinstance(second, Ok)
    assert first.value == second.value
    assert first.value.state is ExecutionState.CONFIRMED
    assert first.value.finality is Finality.DEFINITELY_EXECUTED
    assert first.value.external_reference is not None
    assert executor.dispatch_count == 1
    assert executor.execution_count == 1

    status = gate.status(tenant_id=tenant_id, case_id=case_id)
    assert isinstance(status, Ok)
    assert status.value.state is GateReadState.EXECUTED
