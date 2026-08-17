"""Integer and scaled arithmetic, decided by three semantics that share none.

Each case here is one declared variable, one assertion, and a question every
one of the three can answer independently: enumeration over the declared
domain, the bounded reference backend, and the solver.  The concrete evaluator
is checked pointwise against the same enumeration, so all three legs of the
differential are exercised rather than two.

The sharp cases are the ones where an integer answer and a rational answer
differ.  ``3x = 7`` has no solution over the integers and a perfectly good one
over the rationals; ``100x = 250`` is the same question wearing a currency
scale, and it is the closest thing this fragment has to a halfway rounding
case.  A lowering that quietly reached for a real sort would say satisfiable to
both.

**On rounding.**  The frozen expression IR carries no division and no rounding
mode: the fragment is variable references, literals, negation, constant
multiplication, addition, subtraction, comparison, the boolean connectives,
``ite``, unit introduction, widening rescale and an exhaustive enum table.
There is therefore no ``RoundDiv`` to lower and no five-mode rounding semantics
to attack -- and :func:`test_the_frozen_fragment_carries_no_division_or_rounding`
states that as a checked fact rather than an assumption, so the day one is
added, this file fails until it is covered here too.  What *is* attacked is
everything the fragment does carry that rounding would interact with: negative
operands, exact and inexact scaling, the widening rescale, and the boundaries
of every declared interval.
"""

from __future__ import annotations

import typing
from dataclasses import dataclass

import pytest

from muster.core.expr.evaluate import evaluate_bool
from muster.core.expr.ir import (
    Binary,
    BinaryOp,
    Expr,
    Leaf,
    LitInt,
    LitScaled,
    MulConst,
    NAry,
    NAryOp,
    Neg,
    Rescale,
    Scale,
)
from muster.core.results import Err
from muster.core.values.scalars import VScaled
from muster.core.values.sorts import IntRange, IntSort, ScaledRange, ScaledSort
from muster.solve.query import (
    LabeledAssertion,
    QTerm,
    QueryDecl,
    QueryKind,
    QueryVar,
    SolverQuery,
    WorldSide,
)
from muster.solve.verdict import Sat
from muster.solve.z3.backend import Z3Backend
from muster.solve.z3.lowering import UnsupportedConstruct, lower
from tests.differential import semantics
from tests.differential.backends import Outcome, assert_matches_truth, assert_no_inversion, compare
from tests.differential.scenarios import COUNT, MONEY, PLACEHOLDER, money

VAR = QueryVar(WorldSide.SINGLE, COUNT)
LEAF: QTerm = Leaf(VAR)
NARROW = IntRange(-5, 5)
WIDE = IntRange(-1000, 1000)


@dataclass(frozen=True, slots=True)
class Arithmetic:
    name: str
    formula: QTerm
    domain: IntRange


def _query(case: Arithmetic) -> SolverQuery:
    return SolverQuery(
        QueryKind.FEASIBILITY,
        PLACEHOLDER,
        (),
        (QueryDecl(WorldSide.SINGLE, COUNT, IntSort(), case.domain),),
        (LabeledAssertion("C:x", case.formula),),
    )


def _eq(left: QTerm, right: QTerm) -> QTerm:
    return Binary(BinaryOp.EQ, left, right)


CASES: tuple[Arithmetic, ...] = (
    Arithmetic("zero", _eq(LEAF, LitInt(0)), NARROW),
    Arithmetic("negative-literal", _eq(LEAF, LitInt(-3)), NARROW),
    Arithmetic("negated-variable", _eq(Neg(LEAF), LitInt(3)), NARROW),
    Arithmetic("negated-out-of-domain", _eq(Neg(LEAF), LitInt(9)), NARROW),
    Arithmetic("lower-endpoint", _eq(LEAF, LitInt(-5)), NARROW),
    Arithmetic("upper-endpoint", _eq(LEAF, LitInt(5)), NARROW),
    Arithmetic("one-below-the-lower-endpoint", _eq(LEAF, LitInt(-6)), NARROW),
    Arithmetic("one-above-the-upper-endpoint", _eq(LEAF, LitInt(6)), NARROW),
    #  Exact and inexact constant multiplication: an integer semantics answers
    #  these differently from a rational one.
    Arithmetic("exact-multiple", _eq(MulConst(3, LEAF), LitInt(6)), NARROW),
    Arithmetic("inexact-multiple", _eq(MulConst(3, LEAF), LitInt(7)), NARROW),
    Arithmetic("halfway-multiple", _eq(MulConst(2, LEAF), LitInt(5)), NARROW),
    Arithmetic("one-below-halfway", _eq(MulConst(2, LEAF), LitInt(4)), NARROW),
    Arithmetic("one-above-halfway", _eq(MulConst(2, LEAF), LitInt(6)), NARROW),
    Arithmetic("negative-multiplier-exact", _eq(MulConst(-3, LEAF), LitInt(-6)), NARROW),
    Arithmetic("negative-multiplier-inexact", _eq(MulConst(-3, LEAF), LitInt(-7)), NARROW),
    Arithmetic("negative-multiplier-negative-target", _eq(MulConst(-2, LEAF), LitInt(6)), NARROW),
    #  Sums and differences over signed values.
    Arithmetic(
        "sum-of-negatives",
        _eq(NAry(NAryOp.ADD, (LEAF, LitInt(-2), LitInt(-3))), LitInt(-10)),
        NARROW,
    ),
    Arithmetic("difference", _eq(Binary(BinaryOp.SUB, LitInt(0), LEAF), LitInt(4)), NARROW),
    Arithmetic(
        "difference-of-two-terms",
        _eq(Binary(BinaryOp.SUB, MulConst(2, LEAF), LEAF), LitInt(-5)),
        NARROW,
    ),
    #  Strict against non-strict at the same point.
    Arithmetic(
        "strict-and-non-strict-agree",
        NAry(
            NAryOp.AND,
            (Binary(BinaryOp.GT, LEAF, LitInt(4)), Binary(BinaryOp.GE, LEAF, LitInt(5))),
        ),
        NARROW,
    ),
    Arithmetic(
        "strict-and-non-strict-disagree",
        NAry(
            NAryOp.AND,
            (Binary(BinaryOp.GT, LEAF, LitInt(5)), Binary(BinaryOp.LE, LEAF, LitInt(5))),
        ),
        NARROW,
    ),
    #  Unit introduction, exact and inexact, and the widening rescale.
    Arithmetic("scale-exact", _eq(Scale(LEAF, 100, MONEY), LitScaled(money(300))), NARROW),
    Arithmetic("scale-halfway", _eq(Scale(LEAF, 100, MONEY), LitScaled(money(250))), NARROW),
    Arithmetic("scale-negative", _eq(Scale(LEAF, 100, MONEY), LitScaled(money(-400))), NARROW),
    Arithmetic(
        "rescale-widens-by-a-power-of-ten",
        _eq(Rescale(Scale(LEAF, 1, MONEY), 4), LitScaled(VScaled("INR", 4, 300))),
        NARROW,
    ),
    Arithmetic(
        "rescale-of-a-value-that-cannot-be-reached",
        _eq(Rescale(Scale(LEAF, 1, MONEY), 4), LitScaled(VScaled("INR", 4, 301))),
        NARROW,
    ),
    #  A wider domain, so the bounded backend's threshold abstraction rather
    #  than its enumeration is what answers.
    Arithmetic(
        "wide-interval",
        NAry(
            NAryOp.AND,
            (Binary(BinaryOp.GE, LEAF, LitInt(-999)), Binary(BinaryOp.LE, LEAF, LitInt(-998))),
        ),
        WIDE,
    ),
    Arithmetic(
        "wide-empty-interval",
        NAry(
            NAryOp.AND,
            (Binary(BinaryOp.GE, LEAF, LitInt(10)), Binary(BinaryOp.LT, LEAF, LitInt(10))),
        ),
        WIDE,
    ),
)

IDS = [case.name for case in CASES]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_three_semantics_agree(case: Arithmetic) -> None:
    query = _query(case)
    comparison = compare(query, case.name)
    assert_no_inversion(comparison)
    assert_matches_truth(comparison, semantics.query_truth(query))


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_the_concrete_evaluator_agrees_pointwise(case: Arithmetic) -> None:
    """The third semantics, checked value by value rather than in aggregate."""
    query = _query(case)
    seen = 0
    for model in semantics.query_assignments(query):
        expected = semantics.holds(case.formula, model)
        assert expected is not None, case.name
        produced = evaluate_bool(case.formula, model)
        assert not isinstance(produced, Err), f"{case.name}: {produced}"
        assert produced.value == expected, f"{case.name} at {model}"
        seen += 1
    assert seen == case.domain.hi - case.domain.lo + 1


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_a_satisfiable_answer_carries_an_in_domain_witness(case: Arithmetic) -> None:
    verdict = Z3Backend().check(_query(case))
    if not isinstance(verdict, Sat):
        return
    assert semantics.inside(verdict.model[VAR], case.domain), case.name


def test_the_corpus_reaches_both_answers() -> None:
    answers = {compare(_query(case), case.name).conclusive() for case in CASES}
    assert Outcome.SATISFIABLE in answers
    assert Outcome.UNSATISFIABLE in answers


#  ---- the fragment boundary, stated as a checked fact --------------------


FROZEN_TERMS = frozenset(
    {
        "Leaf",
        "LitBool",
        "LitInt",
        "LitScaled",
        "LitEnum",
        "Not",
        "Neg",
        "NAry",
        "Binary",
        "MulConst",
        "Scale",
        "Rescale",
        "Ite",
        "EnumTable",
    }
)


def test_the_frozen_fragment_carries_no_division_or_rounding() -> None:
    """There is no ``RoundDiv`` in the frozen IR, so there is none to lower.

    The design document's fragment sketch mentions a rounding division; the
    ratified expression IR does not carry one, and neither does any golden
    vector.  Adding one later is a wire-schema change, and it will fail here
    first -- which is better than it arriving with an untested lowering.
    """
    members = {str(member.__name__) for member in typing.get_args(Expr.__value__)}
    assert members == FROZEN_TERMS, f"the expression fragment changed: {sorted(members)}"
    assert not [name for name in members if "Div" in name or "Round" in name]


def test_a_narrowing_rescale_has_no_lowering_because_it_has_no_meaning() -> None:
    """The only place a rounding mode would be needed, and it is refused."""
    scaled = LitScaled(VScaled("INR", 2, 105))
    query = SolverQuery(
        QueryKind.FEASIBILITY,
        PLACEHOLDER,
        (),
        (),
        (LabeledAssertion("C:x", _eq(Rescale(scaled, 1), LitScaled(VScaled("INR", 1, 10)))),),
    )
    assert isinstance(lower(query), UnsupportedConstruct)


def test_a_scaled_variable_is_compared_in_minor_units() -> None:
    """A scaled quantity is an integer count of minor units, and the whole
    differential depends on all three semantics agreeing about that."""
    declaration = QueryDecl(WorldSide.SINGLE, COUNT, ScaledSort("INR", 2), ScaledRange(-3, 3))
    query = SolverQuery(
        QueryKind.FEASIBILITY,
        PLACEHOLDER,
        (),
        (declaration,),
        (LabeledAssertion("C:x", _eq(Leaf(declaration.var()), LitScaled(money(-2)))),),
    )
    comparison = compare(query, "scaled-minor-units")
    assert_no_inversion(comparison)
    assert_matches_truth(comparison, semantics.query_truth(query))
    assert comparison.conclusive() is Outcome.SATISFIABLE
