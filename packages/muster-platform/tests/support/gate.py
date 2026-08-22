"""Composition helpers for the local deterministic Action Gate tests."""

from __future__ import annotations

from muster.core.analysis.outcomes import Invariant
from muster.core.results import Ok
from muster.platform.casework.advance import Casework
from muster.platform.casework.commands import CaseReport, case_status
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.executor import SandboxPaymentExecutor
from muster.platform.gate.model import ExecuteProposal
from muster.platform.gate.service import ActionGate
from support import ravi
from support.ravi import RaviCase

CALLER = GateCaller("local-demo-operator")


def proposal(casework: Casework, case: RaviCase) -> tuple[CaseReport, ExecuteProposal]:
    reported = case_status(
        casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW
    )
    assert isinstance(reported, Ok), reported
    report = reported.value
    assert report.analysis is not None
    assert report.head.revision_digest is not None
    assert report.head.certificate_digest is not None
    outcome = report.analysis.kernel.outcome
    assert isinstance(outcome, Invariant)
    return report, ExecuteProposal(
        case_id=case.case_id,
        revision_digest=report.head.revision_digest,
        certificate_digest=report.head.certificate_digest,
        action_digest=outcome.action.digest(),
    )


def configured_gate(
    casework: Casework, executor: SandboxPaymentExecutor, *callers: GateCaller
) -> ActionGate:
    principals = callers or (CALLER,)
    return ActionGate(
        casework=casework,
        executor=executor,
        authority=LocalExecutionAuthority(
            tuple(
                ExecutionGrant(
                    principal_id=caller.principal_id,
                    tenant_id=tenant_id,
                    action_kind="PAY",
                    gate_id=executor.trusted_gate_id,
                    executor_id=executor.executor_id,
                )
                for caller in principals
                for tenant_id in ("gate-tenant", "ALPHA")
            )
        ),
    )
