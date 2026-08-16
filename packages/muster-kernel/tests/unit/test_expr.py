"""The expression IR: sorts that catch unit mixing, and a total evaluator."""

from __future__ import annotations

import pytest

from muster.core.expr.evaluate import EvalFailure, evaluate, evaluate_bool
from muster.core.expr.ir import (
    Arm,
    Binary,
    BinaryOp,
    EnumTable,
    Ite,
    Leaf,
    LitBool,
    LitEnum,
    LitInt,
    LitScaled,
    NAry,
    NAryOp,
    Not,
    Rescale,
    Scale,
    freevars,
    map_leaves,
)
from muster.core.expr.terms import Term, read_term, term_node
from muster.core.expr.typecheck import SortFailure, check
from muster.core.results import Err, Ok
from muster.core.values.scalars import Value, VEnum, VInt, VScaled
from muster.core.values.sorts import BoolSort, EnumSort, IntSort, ScaledSort, Sort
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import decode, encode
from muster.core.wire.shape import WireFailure

RUPEES = ScaledSort("INR", 2)
DOLLARS = ScaledSort("USD", 2)

QUANTITY = SymbolRef("quantity", ("PO-1",))
RATE = SymbolRef("rate", ("W-1",))
FEE = SymbolRef("fee", ("W-1",))

SORTS: dict[SymbolRef, Sort] = {QUANTITY: IntSort(), RATE: RUPEES, FEE: DOLLARS}


def test_adding_two_currencies_is_a_unit_mismatch() -> None:
    """The unit is part of the sort, so this is a type error, not a rounding bug."""
    mixed: Term = NAry(NAryOp.ADD, (Leaf(RATE), Leaf(FEE)))
    outcome = check(mixed, SORTS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is SortFailure.UNIT_MISMATCH


def test_adding_an_integer_to_money_is_a_sort_mismatch() -> None:
    mixed: Term = NAry(NAryOp.ADD, (Leaf(RATE), Leaf(QUANTITY)))
    outcome = check(mixed, SORTS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is SortFailure.SORT_MISMATCH


def test_comparing_two_currencies_is_a_unit_mismatch() -> None:
    outcome = check(Binary(BinaryOp.LT, Leaf(RATE), Leaf(FEE)), SORTS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is SortFailure.UNIT_MISMATCH


def test_unbound_symbol_is_reported_rather_than_assumed() -> None:
    outcome = check(Leaf(SymbolRef("unknown")), SORTS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is SortFailure.UNBOUND_SYMBOL


def test_guard_must_be_boolean() -> None:
    outcome = check(Not(Leaf(QUANTITY)), SORTS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is SortFailure.EXPECTED_BOOLEAN


def test_conditional_branches_must_agree() -> None:
    outcome = check(Ite(LitBool(True), Leaf(RATE), Leaf(QUANTITY)), SORTS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is SortFailure.SORT_MISMATCH


def test_narrowing_a_scale_is_refused_rather_than_rounded() -> None:
    """The frozen type carries no rounding mode, so there is nothing to choose."""
    outcome = check(Rescale(Leaf(RATE), 0), SORTS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is SortFailure.NARROWING_RESCALE


def test_scale_introduces_a_unit_from_an_integer() -> None:
    outcome = check(Scale(Leaf(QUANTITY), 63_000, RUPEES), SORTS)
    assert isinstance(outcome, Ok)
    assert outcome.value == RUPEES


def test_enum_table_arms_must_be_unique() -> None:
    colour = SymbolRef("colour")
    table = EnumTable(Leaf(colour), (Arm("RED", LitInt(1)), Arm("RED", LitInt(2))))
    outcome = check(table, {colour: EnumSort("colour")})
    assert isinstance(outcome, Err)
    assert outcome.error.failure is SortFailure.DUPLICATE_ARM


def test_evaluation_of_a_well_typed_term() -> None:
    world: dict[SymbolRef, Value] = {QUANTITY: VInt(100), RATE: VScaled("INR", 2, 85_000)}
    total = NAry(NAryOp.ADD, (Leaf(RATE), LitScaled(VScaled("INR", 2, 15_000))))
    outcome = evaluate(total, world)
    assert isinstance(outcome, Ok)
    assert outcome.value == VScaled("INR", 2, 100_000)


def test_evaluation_is_fail_closed_on_a_missing_binding() -> None:
    outcome = evaluate(Leaf(QUANTITY), {})
    assert isinstance(outcome, Err)
    assert outcome.error.failure is EvalFailure.UNBOUND_SYMBOL


def test_evaluation_refuses_to_compare_across_units() -> None:
    world = {RATE: VScaled("INR", 2, 1), FEE: VScaled("USD", 2, 1)}
    outcome = evaluate(Binary(BinaryOp.LT, Leaf(RATE), Leaf(FEE)), world)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is EvalFailure.UNIT_MISMATCH


def test_enum_table_without_a_matching_arm_is_fail_closed() -> None:
    colour = SymbolRef("colour")
    table = EnumTable(Leaf(colour), (Arm("RED", LitInt(1)),))
    outcome = evaluate(table, {colour: VEnum("colour", "BLUE")})
    assert isinstance(outcome, Err)
    assert outcome.error.failure is EvalFailure.NO_MATCHING_ARM


def test_boolean_evaluation_rejects_a_non_boolean() -> None:
    outcome = evaluate_bool(LitInt(1), {})
    assert isinstance(outcome, Err)
    assert outcome.error.failure is EvalFailure.ILL_TYPED


def test_freevars_and_leaf_rewriting_preserve_structure() -> None:
    term: Term = Ite(
        Binary(BinaryOp.GE, Leaf(QUANTITY), LitInt(97)), Leaf(RATE), LitScaled(VScaled("INR", 2, 0))
    )
    assert freevars(term) == frozenset({QUANTITY, RATE})
    renamed = map_leaves(term, lambda ref: SymbolRef(ref.predicate_id, ("X",)))
    assert freevars(renamed) == frozenset(
        {SymbolRef("quantity", ("X",)), SymbolRef("rate", ("X",))}
    )


def test_terms_round_trip_through_the_wire() -> None:
    term: Term = EnumTable(
        Leaf(SymbolRef("colour")),
        (Arm("RED", LitEnum(VEnum("colour", "RED"))), Arm("BLUE", LitBool(False))),
    )
    node = decode(encode(term_node(term)))
    assert isinstance(node, Ok)
    assert read_term(node.value) == term


def test_a_query_leaf_is_not_a_policy_term() -> None:
    """A world-qualified leaf in a policy term is a decoding failure, not a lint."""
    from muster.core.expr.terms import decode_term
    from muster.solve.query import QueryVar, WorldSide, qterm_node

    qualified = qterm_node(Leaf(QueryVar(WorldSide.LEFT, QUANTITY)))
    decoded = decode(encode(qualified))
    assert isinstance(decoded, Ok)
    outcome = decode_term(decoded.value)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is WireFailure.UNKNOWN_VARIANT


def test_a_policy_leaf_is_not_a_query_term() -> None:
    """The symmetric direction, and the one the shared decoder makes non-obvious.

    Both placement rules are schema violations, not lints, and both are proved:
    a world-qualified leaf cannot be read as a policy term, and a bare leaf
    cannot be read as a query term.
    """
    from muster.core.results import Err
    from muster.solve.query import read_qterm

    decoded = decode(encode(term_node(Leaf(QUANTITY))))
    assert isinstance(decoded, Ok)
    from muster.core.wire.shape import decoded as run_decode

    outcome = run_decode(lambda: read_qterm(decoded.value))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is WireFailure.UNKNOWN_VARIANT


def test_the_two_families_have_disjoint_composite_tags() -> None:
    """``Bin/v1`` against ``QBin/v1``: distinguishable at the octet level."""
    from muster.solve.query import QueryVar, WorldSide, qterm_node

    policy = encode(term_node(Binary(BinaryOp.EQ, Leaf(QUANTITY), LitInt(1))))
    query = encode(
        qterm_node(Binary(BinaryOp.EQ, Leaf(QueryVar(WorldSide.SINGLE, QUANTITY)), LitInt(1)))
    )
    #  The negative half is what carries the weight: a check for "Bin/v1" alone
    #  is satisfied by "QBin/v1" too.
    assert b"QBin/v1" not in policy
    assert b"QBin/v1" in query
    assert policy != query


def test_arity_of_an_n_ary_operator_is_enforced() -> None:
    from muster.core.results import InvariantViolation

    with pytest.raises(InvariantViolation):
        NAry(NAryOp.AND, (LitBool(True),))


def test_boolean_sort_of_a_comparison() -> None:
    outcome = check(Binary(BinaryOp.GE, Leaf(QUANTITY), LitInt(97)), SORTS)
    assert isinstance(outcome, Ok)
    assert outcome.value == BoolSort()
