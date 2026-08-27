"""The reconciliation compare-and-swap contract, asserted of both adapters."""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from muster.core.actions import ActionField, ConsequentialAction
from muster.core.case.revision import RebuildInputs, RebuildMode
from muster.core.results import Err, Ok
from muster.core.values.scalars import VEnum, VScaled
from muster.core.wire.digests import Digest, DigestKind
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.schema import migrate
from muster.platform.casework.ports import CaseworkDatabase
from muster.platform.gate.model import ActionIntent, ExecutionKey, ExecutionRecord, ExecutionState
from muster.platform.gate.ports import ExecutionStoreFailure

ADAPTERS = ("memory", "postgres")
NOW = 1_760_000_000_000_000


@dataclass(frozen=True, slots=True)
class Custody:
    database: CaseworkDatabase
    tenant_id: str


@pytest.fixture(params=ADAPTERS, ids=ADAPTERS)
def custody(request: pytest.FixtureRequest, tenant_id: str) -> Iterator[Custody]:
    if request.param == "memory":
        yield Custody(MemoryDatabase(), tenant_id)
        return
    dsn = os.environ.get("MUSTER_TEST_DSN")
    if not dsn:
        pytest.skip("needs a real PostgreSQL instance: set MUSTER_TEST_DSN")
    migrate(dsn)
    yield Custody(SqlDatabase(dsn), tenant_id)


def _digest(seed: int) -> Digest:
    return Digest(bytes([seed]) * 32)


def _intent(custody: Custody, case_id: str) -> ActionIntent:
    with custody.database.writing(custody.tenant_id) as scope:
        construction = scope.content.put(DigestKind.CASE_CONSTRUCTION, b"construction")
        prefix = scope.content.put(DigestKind.TRANSCRIPT_PREFIX, b"prefix")
        authority = scope.content.put(DigestKind.AUTHORIZATION_CONTEXT, b"authority")
    assert isinstance(construction, Ok)
    assert isinstance(prefix, Ok)
    assert isinstance(authority, Ok)
    with custody.database.writing(custody.tenant_id) as scope:
        opened = scope.heads.open(
            RebuildInputs(
                tenant_id=custody.tenant_id,
                case_id=case_id,
                construction_digest=construction.value,
                transcript_prefix_digest=prefix.value,
                bundle_manifest_digest=_digest(4),
                as_of=NOW,
                mode=RebuildMode.OPERATIONAL,
                authorization_context_digest=authority.value,
            )
        )
    assert isinstance(opened, Ok)

    schema = _digest(9)
    action = ConsequentialAction(
        schema,
        "PAY",
        (
            ActionField("recipient", VEnum("party_id", "RAVI")),
            ActionField("amount", VScaled("INR", 2, 510_000)),
        ),
    )
    return ActionIntent(
        tenant_id=custody.tenant_id,
        case_id=case_id,
        revision_number=1,
        revision_digest=_digest(1),
        certificate_digest=_digest(2),
        kernel_result_digest=_digest(3),
        bundle_manifest_digest=_digest(4),
        authorization_context_digest=authority.value,
        gate_id="local-action-gate/v1",
        executor_id="sandbox-payment/v1",
        action_schema_digest=schema,
        action_digest=action.digest(),
        action=action,
    )


def _dispatched(custody: Custody, case_id: str) -> tuple[ExecutionKey, ExecutionRecord]:
    intent = _intent(custody, case_id)
    with custody.database.writing(custody.tenant_id) as scope:
        reserved = scope.executions.reserve(intent, requested_by="operator", now=NOW)
        assert isinstance(reserved, Ok)
        begun = scope.executions.begin_dispatch(intent.execution_key(), now=NOW + 1)
    assert isinstance(begun, Ok) and begun.value.acquired
    return intent.execution_key(), begun.value.record


@pytest.mark.parametrize(
    ("target", "external_reference"),
    (
        (ExecutionState.CONFIRMED, "external-1"),
        (ExecutionState.FAILED, None),
        (ExecutionState.UNCERTAIN, None),
    ),
)
def test_dispatched_reconciliation_is_one_cas_with_provenance(
    custody: Custody,
    case_id: str,
    target: ExecutionState,
    external_reference: str | None,
) -> None:
    key, dispatched = _dispatched(custody, case_id)
    with custody.database.writing(custody.tenant_id) as scope:
        reconciled = scope.executions.reconcile(
            key,
            source_state=ExecutionState.DISPATCHED,
            state=target,
            outcome_code="OBSERVED",
            external_reference=external_reference,
            detail=None,
            now=NOW + 2,
        )
    assert isinstance(reconciled, Ok) and reconciled.value.applied
    assert reconciled.value.record.state is target
    assert reconciled.value.record.finalized_at == NOW + 2
    assert reconciled.value.record.reconciled_at == NOW + 2
    assert reconciled.value.record.reconciled_from is ExecutionState.DISPATCHED
    assert dispatched.finalized_at is None

    with custody.database.writing(custody.tenant_id) as scope:
        loser = scope.executions.reconcile(
            key,
            source_state=ExecutionState.DISPATCHED,
            state=ExecutionState.FAILED,
            outcome_code="CONTRADICTED",
            external_reference=None,
            detail="must not replace the winner",
            now=NOW + 3,
        )
    assert isinstance(loser, Ok) and not loser.value.applied
    assert loser.value.record == reconciled.value.record
    if target is ExecutionState.UNCERTAIN:
        with custody.database.writing(custody.tenant_id) as scope:
            promoted = scope.executions.reconcile(
                key,
                source_state=ExecutionState.UNCERTAIN,
                state=ExecutionState.FAILED,
                outcome_code="FRESH_OBSERVATION",
                external_reference=None,
                detail=None,
                now=NOW + 4,
            )
        assert isinstance(promoted, Ok) and promoted.value.applied
        assert promoted.value.record.finalized_at == reconciled.value.record.finalized_at
        assert promoted.value.record.reconciled_from is ExecutionState.UNCERTAIN


@pytest.mark.parametrize(
    ("target", "external_reference"),
    (
        (ExecutionState.CONFIRMED, "external-2"),
        (ExecutionState.FAILED, None),
    ),
)
def test_uncertain_reconciliation_preserves_the_original_finalization(
    custody: Custody,
    case_id: str,
    target: ExecutionState,
    external_reference: str | None,
) -> None:
    key, _dispatched_record = _dispatched(custody, case_id)
    with custody.database.writing(custody.tenant_id) as scope:
        uncertain = scope.executions.finalize(
            key,
            state=ExecutionState.UNCERTAIN,
            outcome_code="TIMEOUT",
            external_reference=None,
            detail="original uncertainty",
            now=NOW + 2,
        )
    assert isinstance(uncertain, Ok)

    with custody.database.writing(custody.tenant_id) as scope:
        reconciled = scope.executions.reconcile(
            key,
            source_state=ExecutionState.UNCERTAIN,
            state=target,
            outcome_code="OBSERVED",
            external_reference=external_reference,
            detail=None,
            now=NOW + 4,
        )
    assert isinstance(reconciled, Ok) and reconciled.value.applied
    assert reconciled.value.record.finalized_at == NOW + 2
    assert reconciled.value.record.reconciled_at == NOW + 4
    assert reconciled.value.record.reconciled_from is ExecutionState.UNCERTAIN


def test_reserved_is_not_a_reconciliation_source(custody: Custody, case_id: str) -> None:
    intent = _intent(custody, case_id)
    with custody.database.writing(custody.tenant_id) as scope:
        reserved = scope.executions.reserve(intent, requested_by="operator", now=NOW)
        assert isinstance(reserved, Ok)
        refused = scope.executions.reconcile(
            intent.execution_key(),
            source_state=ExecutionState.RESERVED,
            state=ExecutionState.CONFIRMED,
            outcome_code="CONFIRMED",
            external_reference="forbidden",
            detail=None,
            now=NOW + 1,
        )
    assert isinstance(refused, Err)
    assert refused.error.failure is ExecutionStoreFailure.ILLEGAL_TRANSITION
