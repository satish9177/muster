"""Exact action binding, transition legality, and finality are pure."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest

from muster.core.actions import ActionField, ConsequentialAction
from muster.core.results import InvariantViolation, Ok
from muster.core.values.scalars import VEnum, VScaled
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest
from muster.domains.workforce.bundle import action_schema
from muster.platform.gate.model import (
    ActionIntent,
    ExecuteProposal,
    ExecutionRecord,
    ExecutionState,
    Finality,
    binding_mismatches,
    finality,
    read_action_intent,
    transition_is_legal,
)


def _digest(seed: int) -> Digest:
    return Digest(bytes([seed]) * 32)


def _action(
    *,
    kind: str = "PAY",
    recipient: str = "RAVI",
    currency: str = "INR",
    amount: int = 510_000,
    schema_digest: Digest | None = None,
) -> ConsequentialAction:
    return ConsequentialAction(
        action_schema().digest() if schema_digest is None else schema_digest,
        kind,
        (
            ActionField("recipient", VEnum("party_id", recipient)),
            ActionField("amount", VScaled(currency, 2, amount)),
        ),
    )


def _intent() -> ActionIntent:
    action = _action()
    return ActionIntent(
        tenant_id="ALPHA",
        case_id="CASE-RAVI",
        revision_number=7,
        revision_digest=_digest(1),
        certificate_digest=_digest(2),
        kernel_result_digest=_digest(3),
        bundle_manifest_digest=_digest(4),
        authorization_context_digest=_digest(5),
        gate_id="local-action-gate/v1",
        executor_id="sandbox-payment/v1",
        action_schema_digest=action.action_schema_digest,
        action_digest=action.digest(),
        action=action,
    )


def _with_action(intent: ActionIntent, action: ConsequentialAction) -> ActionIntent:
    return replace(
        intent,
        action_schema_digest=action.action_schema_digest,
        action_digest=action.digest(),
        action=action,
    )


@pytest.mark.parametrize(
    ("mutate", "field"),
    [
        (lambda value: replace(value, tenant_id="BETA"), "tenant_id"),
        (lambda value: replace(value, case_id="CASE-OTHER"), "case_id"),
        (lambda value: replace(value, revision_number=8), "revision_number"),
        (lambda value: replace(value, revision_digest=_digest(11)), "revision_digest"),
        (lambda value: replace(value, certificate_digest=_digest(12)), "certificate_digest"),
        (lambda value: replace(value, kernel_result_digest=_digest(13)), "kernel_result_digest"),
        (
            lambda value: replace(value, bundle_manifest_digest=_digest(14)),
            "bundle_manifest_digest",
        ),
        (
            lambda value: replace(value, authorization_context_digest=_digest(15)),
            "authorization_context_digest",
        ),
        (
            lambda value: _with_action(value, _action(recipient="MIRA")),
            "action.fields.recipient",
        ),
        (lambda value: _with_action(value, _action(amount=510_100)), "action.fields.amount"),
        (lambda value: _with_action(value, _action(currency="USD")), "action.fields.amount"),
        (lambda value: _with_action(value, _action(kind="REFUND")), "action.kind"),
        (
            lambda value: _with_action(value, _action(schema_digest=_digest(16))),
            "action_schema_digest",
        ),
        (lambda value: replace(value, gate_id="another-gate"), "gate_id"),
        (lambda value: replace(value, executor_id="another-executor"), "executor_id"),
    ],
)
def test_each_material_substitution_is_detected_and_changes_idempotency(
    mutate: Callable[[ActionIntent], ActionIntent], field: str
) -> None:
    original = _intent()
    offered = mutate(original)
    assert field in binding_mismatches(original, offered)
    assert original.execution_key() != offered.execution_key()


def test_the_intent_round_trips_without_losing_a_binding() -> None:
    intent = _intent()
    node = decode(intent.canonical_octets())
    assert isinstance(node, Ok), node
    assert read_action_intent(node.value) == intent


def test_an_action_digest_cannot_disagree_with_the_action() -> None:
    with pytest.raises(InvariantViolation):
        replace(_intent(), action_digest=_digest(31))


def test_the_public_command_contains_no_imperative_payment_fields() -> None:
    assert set(ExecuteProposal.__annotations__) == {
        "case_id",
        "revision_digest",
        "certificate_digest",
        "action_digest",
    }


def test_the_state_machine_has_only_four_forward_edges() -> None:
    legal = {
        (before, after)
        for before in ExecutionState
        for after in ExecutionState
        if transition_is_legal(before, after)
    }
    assert legal == {
        (ExecutionState.RESERVED, ExecutionState.DISPATCHED),
        (ExecutionState.DISPATCHED, ExecutionState.CONFIRMED),
        (ExecutionState.DISPATCHED, ExecutionState.FAILED),
        (ExecutionState.DISPATCHED, ExecutionState.UNCERTAIN),
    }


def test_finality_distinguishes_no_yes_and_unknown() -> None:
    assert finality(ExecutionState.RESERVED) is Finality.DEFINITELY_NOT_EXECUTED
    assert finality(ExecutionState.FAILED) is Finality.DEFINITELY_NOT_EXECUTED
    assert finality(ExecutionState.CONFIRMED) is Finality.DEFINITELY_EXECUTED
    assert finality(ExecutionState.DISPATCHED) is Finality.OUTCOME_UNKNOWN
    assert finality(ExecutionState.UNCERTAIN) is Finality.OUTCOME_UNKNOWN


def test_an_unknown_record_cannot_claim_a_transaction_reference() -> None:
    with pytest.raises(InvariantViolation):
        ExecutionRecord(
            intent=_intent(),
            state=ExecutionState.UNCERTAIN,
            requested_by="operator",
            reserved_at=1,
            dispatched_at=2,
            finalized_at=3,
            external_reference="not-confirmed",
            outcome_code="TIMEOUT",
        )
