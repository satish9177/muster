"""Every imperative-field substitution is refused before reservation."""

from __future__ import annotations

from dataclasses import replace

from muster.core.actions import ActionField, ConsequentialAction
from muster.core.analysis.outcomes import Invariant
from muster.core.results import Err
from muster.core.values.scalars import VEnum, VScaled
from muster.core.wire.digests import Digest
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.gate.executor import SandboxPaymentExecutor
from muster.platform.gate.service import GateFailure
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import CALLER, configured_gate, proposal


def _changed(
    action: ConsequentialAction,
    *,
    kind: str | None = None,
    recipient: str = "RAVI",
    currency: str = "INR",
    amount: int = 510_000,
) -> ConsequentialAction:
    return ConsequentialAction(
        action.action_schema_digest,
        action.kind if kind is None else kind,
        (
            ActionField("recipient", VEnum("party_id", recipient)),
            ActionField("amount", VScaled(currency, 2, amount)),
        ),
    )


def test_recipient_amount_currency_and_kind_cannot_be_substituted() -> None:
    database = MemoryDatabase()
    casework = ravi.casework(database)
    case = ravi.ravi("gate-tenant", "substitution-case", attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    report, request = proposal(casework, case)
    assert report.analysis is not None
    outcome = report.analysis.kernel.outcome
    assert isinstance(outcome, Invariant)

    executor = SandboxPaymentExecutor()
    gate = configured_gate(casework, executor)
    attacks = {
        "recipient": _changed(outcome.action, recipient="MIRA"),
        "amount": _changed(outcome.action, amount=510_100),
        "currency": _changed(outcome.action, currency="USD"),
        "kind": _changed(outcome.action, kind="REFUND"),
    }
    for name, forged in attacks.items():
        refused = gate.execute(
            caller=CALLER,
            tenant_id=case.tenant_id,
            request=replace(request, action_digest=forged.digest()),
            now=ravi.NOW,
        )
        assert isinstance(refused, Err), name
        assert refused.error.failure is GateFailure.PROPOSAL_REFUSED

    assert executor.dispatch_count == 0
    absent = gate.status(tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(absent, Err)


def test_tenant_case_policy_revision_and_certificate_substitution_fail_closed() -> None:
    database = MemoryDatabase()
    casework = ravi.casework(database)
    case = ravi.ravi("gate-tenant", "identity-case", attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    _report, request = proposal(casework, case)
    executor = SandboxPaymentExecutor()
    gate = configured_gate(casework, executor)

    attacks = (
        ("BETA", request),
        (case.tenant_id, replace(request, case_id="other-case")),
        (case.tenant_id, replace(request, revision_digest=Digest(b"\x91" * 32))),
        (case.tenant_id, replace(request, certificate_digest=Digest(b"\x92" * 32))),
    )
    for tenant_id, forged in attacks:
        refused = gate.execute(
            caller=CALLER,
            tenant_id=tenant_id,
            request=forged,
            now=ravi.NOW,
        )
        assert isinstance(refused, Err)
    assert executor.dispatch_count == 0
