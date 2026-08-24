"""The same PO-4821 evidence changes significance when only policy changes."""

import json
from dataclasses import fields, replace
from pathlib import Path

import pytest
from demo.procurement_case import _reachable_action_count, analysis, build_read_model

from muster.core.analysis.outcomes import (
    Divergent,
    ExactReachable,
    Invariant,
    NotComputed,
    NotComputedReason,
    TruncatedReachable,
)
from muster.core.analysis.planning import EvidenceRequested, NoActionReason, NoActionRequired
from muster.core.case.constraints import AttestedRelationDeriv
from muster.core.expr.ir import Binary, BinaryOp, Leaf, freevars
from muster.core.values.scalars import VInt, VScaled
from muster.domains.procurement.bundle import (
    ACTION_PAY,
    FIELD_AMOUNT,
    FIXED_AMOUNT_MINOR,
    PO_ID,
    PREDICATE_DELIVERED,
    PREDICATE_ORDERED_QUANTITY,
    SCOPE_PURCHASE_ORDER,
    SOURCE_PROCUREMENT_PO,
    SOURCE_SUPPLIER,
    SOURCE_WAREHOUSE,
    ProcurementPolicy,
    delivered_quantity,
    ordered_quantity,
    predicate_schema,
    supplier_declared_quantity,
    warehouse_received_quantity,
)
from muster.domains.procurement.scenario import (
    ORDERED_QUANTITY,
    ORDERED_QUANTITY_RECEIPT,
    RELATION_CLAIM_ONLY,
    RELATION_CLOSED_LOWER_BOUND,
    RELATION_CLOSED_UPPER_BOUND,
    SUPPLIER_QUANTITY,
    WAREHOUSE_QUANTITY,
    WAREHOUSE_RECEIPT,
    case_fixture,
    revision,
    revision_with_exact_quantity,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
UI_ROOT = REPOSITORY_ROOT / "packages" / "muster-ui"


def _amounts(outcome: Divergent) -> set[int]:
    assert isinstance(outcome.reachable, ExactReachable)
    return {
        value.minor
        for action in outcome.reachable.actions
        for field in action.consequential_fields
        if field.name == FIELD_AMOUNT and isinstance((value := field.value), VScaled)
    }


def test_source_records_preserve_the_disagreement() -> None:
    supplier, warehouse, purchase_order, fixed, rate = case_fixture().records

    assert supplier.source_class == SOURCE_SUPPLIER
    assert supplier.relation == RELATION_CLAIM_ONLY
    assert warehouse.source_class == SOURCE_WAREHOUSE
    assert warehouse.relation == RELATION_CLOSED_LOWER_BOUND
    assert purchase_order.source_class == SOURCE_PROCUREMENT_PO
    assert purchase_order.relation == RELATION_CLOSED_UPPER_BOUND
    assert supplier.proposition != warehouse.proposition
    assert supplier.value == VInt(SUPPLIER_QUANTITY)
    assert warehouse.value == VInt(WAREHOUSE_QUANTITY)
    assert supplier.value != warehouse.value
    assert fixed.source_class == rate.source_class == SOURCE_PROCUREMENT_PO


def test_supplier_self_claim_establishes_no_authoritative_quantity_bound() -> None:
    current = revision(ProcurementPolicy.PER_UNIT)

    assert any(
        fact.ref == supplier_declared_quantity() and fact.value == VInt(SUPPLIER_QUANTITY)
        for fact in current.established
    )
    assert all(
        supplier_declared_quantity() not in freevars(constraint.formula)
        for constraint in current.constraints
    )
    assert any(
        effect.rule_id == "SelfServingClaimIsInert"
        and effect.subject == str(supplier_declared_quantity())
        for effect in current.non_effects
    )


def test_purchase_order_establishes_the_100_unit_ceiling() -> None:
    current = revision(ProcurementPolicy.PER_UNIT)
    ceiling = next(
        constraint
        for constraint in current.constraints
        if constraint.label == "PO-ORDERED-QUANTITY-CEILING"
    )

    assert any(
        fact.ref == ordered_quantity() and fact.value == VInt(ORDERED_QUANTITY)
        for fact in current.established
    )
    assert ceiling.formula == Binary(
        BinaryOp.LE, Leaf(delivered_quantity()), Leaf(ordered_quantity())
    )
    assert ceiling.derivation == AttestedRelationDeriv(1, ORDERED_QUANTITY_RECEIPT)


def test_warehouse_97_is_a_lower_bound_not_an_exact_quantity() -> None:
    current = revision(ProcurementPolicy.PER_UNIT)
    floor = next(
        constraint
        for constraint in current.constraints
        if constraint.label == "WAREHOUSE-CONFIRMED-LOWER-BOUND"
    )

    assert any(
        fact.ref == warehouse_received_quantity() and fact.value == VInt(WAREHOUSE_QUANTITY)
        for fact in current.established
    )
    assert floor.formula == Binary(
        BinaryOp.GE, Leaf(delivered_quantity()), Leaf(warehouse_received_quantity())
    )
    assert floor.derivation == AttestedRelationDeriv(1, WAREHOUSE_RECEIPT)
    assert all(fact.ref != delivered_quantity() for fact in current.established)


def test_exact_delivered_quantity_remains_unresolved() -> None:
    current = revision(ProcurementPolicy.PER_UNIT)

    assert delivered_quantity() in current.unresolved()
    assert current.known().get(delivered_quantity()) is None


def test_quantity_authority_is_po_scoped_and_source_typed() -> None:
    schema = predicate_schema()
    exact = schema.spec(PREDICATE_DELIVERED)
    ordered = schema.spec(PREDICATE_ORDERED_QUANTITY)

    assert exact is not None and ordered is not None
    assert exact.arg_kinds == (SCOPE_PURCHASE_ORDER,)
    assert exact.resource_scope_kinds == (SCOPE_PURCHASE_ORDER,)
    assert exact.permitted_source_classes == (SOURCE_WAREHOUSE,)
    assert ordered.permitted_source_classes == (SOURCE_PROCUREMENT_PO,)
    assert str(delivered_quantity()) == f"{PREDICATE_DELIVERED}({PO_ID})"


def test_fixed_tolerance_is_invariant_without_resolving_quantity() -> None:
    result = analysis(ProcurementPolicy.FIXED_TOLERANCE)
    outcome = result.kernel.outcome

    assert isinstance(outcome, Invariant)
    assert outcome.action.kind == ACTION_PAY
    assert any(
        field.name == FIELD_AMOUNT and field.value == VScaled("INR", 2, FIXED_AMOUNT_MINOR)
        for field in outcome.action.consequential_fields
    )
    assert delivered_quantity() in result.projected.unresolved()
    assert isinstance(result.planning.record.planning_outcome, NoActionRequired)
    assert result.planning.record.planning_outcome.reason is NoActionReason.ACTION_INVARIANT
    assert result.planning.record.support is None


def test_per_unit_policy_is_divergent_and_requests_exact_quantity() -> None:
    result = analysis(ProcurementPolicy.PER_UNIT)
    outcome = result.kernel.outcome

    assert isinstance(outcome, Divergent)
    amounts = _amounts(outcome)
    assert amounts == {
        6_111_000,
        6_174_000,
        6_237_000,
        6_300_000,
    }
    plan = result.planning.record.planning_outcome
    assert isinstance(plan, EvidenceRequested)
    assert tuple(target.proposition for target in plan.request.targets) == (delivered_quantity(),)
    assert plan.request.targets[0].permitted_source_classes == (SOURCE_WAREHOUSE,)
    assert result.planning.necessary == (delivered_quantity(),)


def test_procurement_read_model_refuses_inexact_reachable_counts() -> None:
    outcome = analysis(ProcurementPolicy.PER_UNIT).kernel.outcome
    assert isinstance(outcome, Divergent)
    assert isinstance(outcome.reachable, ExactReachable)

    for reachable in (
        TruncatedReachable(outcome.reachable.actions[:1], 1),
        NotComputed(NotComputedReason.BUDGET_EXHAUSTED),
    ):
        with pytest.raises(RuntimeError, match="requires an exact reachable-action set"):
            _reachable_action_count(replace(outcome, reachable=reachable))


def test_exact_authoritative_warehouse_97_resolves_per_unit_payment() -> None:
    exact_revision = revision_with_exact_quantity(ProcurementPolicy.PER_UNIT)
    result = analysis(ProcurementPolicy.PER_UNIT, exact_revision)
    outcome = result.kernel.outcome

    assert delivered_quantity() not in exact_revision.unresolved()
    assert exact_revision.known()[delivered_quantity()] == VInt(WAREHOUSE_QUANTITY)
    assert isinstance(outcome, Invariant)
    assert any(
        field.name == FIELD_AMOUNT and field.value == VScaled("INR", 2, 6_111_000)
        for field in outcome.action.consequential_fields
    )
    assert isinstance(result.planning.record.planning_outcome, NoActionRequired)
    assert result.planning.record.planning_outcome.reason is NoActionReason.ACTION_INVARIANT


def test_changing_only_the_bundle_pin_causes_the_flip() -> None:
    fixed = revision(ProcurementPolicy.FIXED_TOLERANCE)
    per_unit = revision(ProcurementPolicy.PER_UNIT)
    changed = [
        field.name
        for field in fields(fixed)
        if getattr(fixed, field.name) != getattr(per_unit, field.name)
    ]

    assert changed == ["bundle_pin"]
    assert isinstance(analysis(ProcurementPolicy.FIXED_TOLERANCE).kernel.outcome, Invariant)
    assert isinstance(analysis(ProcurementPolicy.PER_UNIT).kernel.outcome, Divergent)


def test_public_read_models_are_exact_kernel_derivatives() -> None:
    cases = UI_ROOT / "public" / "cases"
    expected = (
        (ProcurementPolicy.FIXED_TOLERANCE, "procurement-fixed.json"),
        (ProcurementPolicy.PER_UNIT, "procurement-per-unit.json"),
    )

    for policy, filename in expected:
        stored = json.loads((cases / filename).read_text(encoding="utf-8"))
        assert stored == build_read_model(policy)


def test_react_does_not_recompute_procurement_policy() -> None:
    component = (UI_ROOT / "src" / "components" / "ProcurementCase.tsx").read_text(
        encoding="utf-8"
    )

    assert "amount_minor" not in component
    assert "630" not in component
    assert "97" not in component
    assert "100" not in component
    assert "resolving ${" not in component
    assert "quantity *" not in component
    assert "quantity >=" not in component


def test_generic_layers_do_not_import_procurement_semantics() -> None:
    roots = (
        REPOSITORY_ROOT / "packages" / "muster-kernel" / "src" / "muster" / "core",
        REPOSITORY_ROOT / "packages" / "muster-kernel" / "src" / "muster" / "policy",
        REPOSITORY_ROOT / "packages" / "muster-kernel" / "src" / "muster" / "solve",
        REPOSITORY_ROOT / "packages" / "muster-kernel" / "src" / "muster" / "hinge",
        REPOSITORY_ROOT / "packages" / "muster-kernel" / "src" / "muster" / "evidence",
        REPOSITORY_ROOT / "packages" / "muster-platform" / "src",
    )

    for root in roots:
        for source in root.rglob("*.py"):
            assert "domains.procurement" not in source.read_text(encoding="utf-8"), source
