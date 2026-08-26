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
from muster.platform.gate.model import ExecuteProposal
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


def test_an_action_bound_to_another_schema_is_refused() -> None:
    """A different action schema is a different action, and the digest says so.

    The public command carries no schema field, so this cannot be forged
    directly -- which is the point.  Rebinding the schema changes the action's
    own digest, and the request that names that digest is refused against the
    current policy-projected action before anything is reserved.
    """
    database = MemoryDatabase()
    casework = ravi.casework(database)
    case = ravi.ravi("gate-tenant", "schema-case", attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    report, request = proposal(casework, case)
    assert report.analysis is not None
    outcome = report.analysis.kernel.outcome
    assert isinstance(outcome, Invariant)

    rebound = ConsequentialAction(
        Digest(b"\x4a" * 32),
        outcome.action.kind,
        outcome.action.consequential_fields,
    )
    assert rebound.digest() != outcome.action.digest()

    executor = SandboxPaymentExecutor()
    gate = configured_gate(casework, executor)
    refused = gate.execute(
        caller=CALLER,
        tenant_id=case.tenant_id,
        request=replace(request, action_digest=rebound.digest()),
        now=ravi.NOW,
    )

    assert isinstance(refused, Err)
    assert refused.error.failure is GateFailure.PROPOSAL_REFUSED
    assert executor.dispatch_count == 0


def test_the_gate_has_nowhere_to_put_a_model_authored_value() -> None:
    """Structural, and it is the strongest form of "a model cannot pay Ravi".

    The two values an application may hand the Gate are an ``ExecuteProposal``
    and an ``ExecutionLookup``.  Between them they carry case identifiers,
    proposal digests and one opaque execution key -- and no recipient, no
    amount, no currency, no action kind, no free text and no bytes.  So there
    is no field for a model's output, a browser form or a request body to
    occupy, whatever a caller intends: the imperative half of an action is
    re-derived server-side from the current head every time.

    The lookup's ``execution_key`` is on this list and is exactly as safe.  It
    is 32 opaque octets that a store either has a row for or does not; it names
    no recipient and authorizes nothing, and the read that accepts it still
    authenticates the caller and still demands an exact grant for whatever
    action kind the *stored* intent turns out to name.

    Checked over the declared fields rather than by trying a substitution,
    because a substitution test proves the current fields are guarded and this
    proves no *new* field arrived to be guarded later.
    """
    from dataclasses import fields

    from muster.core.wire.digests import Digest as WireDigest
    from muster.platform.gate.model import ExecutionKey, ExecutionLookup

    #: Every field either of these two commands may declare, and the only type
    #: each may have.  Written as a table rather than as a rule, so a new field
    #: is a test failure that names it instead of a rule somebody widened.
    permitted = {
        "case_id": "str",
        "expected_case_id": "str | None",
        "revision_digest": WireDigest.__name__,
        "certificate_digest": WireDigest.__name__,
        "bundle_manifest_digest": WireDigest.__name__,
        "authorization_context_digest": WireDigest.__name__,
        "action_digest": WireDigest.__name__,
        "execution_key": ExecutionKey.__name__,
    }
    for command in (ExecuteProposal, ExecutionLookup):
        declared = {field.name: field.type for field in fields(command)}
        assert set(declared) <= set(permitted), command.__name__
        for name, annotation in declared.items():
            assert annotation == permitted[name], (command.__name__, name)
