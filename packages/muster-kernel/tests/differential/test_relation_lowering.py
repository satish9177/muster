"""What a source is allowed to say, decided three ways.

An acquisition relation is the only thing a source may send, and the lowering
table turns it into a fact, a constraint, or nothing.  The constraints it
produces are the ones a real case is mostly made of, so they get the same
three-semantics treatment as everything else -- and, in particular, the same
treatment when two of them land on one proposition.

Combining is where a lowering table gets interesting.  Two bounds that overlap
narrow the interval; two that do not make the case infeasible, and infeasible
is an outcome the kernel *reports* rather than repairs.  Neither may crash, and
both backends must agree about which happened and about which source
constraints contributed.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from muster.core.evidence.relations import (
    AcquisitionRelation,
    ClosedLowerBound,
    ClosedUpperBound,
    EnumSubset,
    ExactValue,
    LoweredConstraint,
    LoweredFact,
    LoweredNonEffect,
    lower_relation,
)
from muster.core.expr.ir import Binary, BinaryOp, Ite, Leaf, LitInt, LitScaled
from muster.core.expr.terms import Term
from muster.core.values.scalars import Value, VEnum, VInt
from muster.core.values.sorts import EnumDomain, IntRange
from muster.core.values.symbols import SymbolRef
from muster.hinge.encode import feasibility_query
from muster.policy.program import DecisionProgram, ProgramRule
from muster.solve.reference.bounded import BoundedEnumerationBackend
from muster.solve.verdict import Unsat
from muster.solve.z3.backend import Z3Backend
from tests.differential import semantics
from tests.differential.backends import (
    ENUMERATION_BUDGET,
    Outcome,
    assert_matches_truth,
    assert_no_inversion,
    compare,
)
from tests.differential.scenarios import (
    COLOURS,
    DURATION,
    ENUM_COLOUR,
    TINT,
    WIDE_SCHEMA,
    Scenario,
    build,
    colour,
    money,
    pay,
    program,
)

QUALIFYING = 240
DURATION_DOMAIN = IntRange(0, 1440)
COLOUR_DOMAIN = EnumDomain(COLOURS)


def _threshold_program() -> DecisionProgram:
    return program(
        rules=(),
        otherwise=pay(
            Ite(
                Binary(BinaryOp.GE, Leaf(DURATION), LitInt(QUALIFYING)),
                LitScaled(money(100_000)),
                LitScaled(money(0)),
            )
        ),
    )


def _case(name: str, relations: tuple[tuple[str, AcquisitionRelation], ...]) -> Scenario:
    """A one-variable case whose constraints come from the lowering table."""
    constraints: list[tuple[str, Term]] = []
    known: dict[SymbolRef, Value] = {}
    for label, relation in relations:
        lowering = lower_relation(relation, DURATION, DURATION_DOMAIN)
        match lowering:
            case LoweredConstraint(formula):
                constraints.append((label, formula))
            case LoweredFact(value):
                known[DURATION] = value
            case LoweredNonEffect():
                continue
    return build(
        name=name,
        universe=(DURATION,),
        known=known,
        constraints=tuple(constraints),
        decision=_threshold_program(),
        schema=WIDE_SCHEMA,
    )


@dataclass(frozen=True, slots=True)
class Relations:
    name: str
    relations: tuple[tuple[str, AcquisitionRelation], ...]


CASES: tuple[Relations, ...] = (
    Relations("exact-on-the-threshold", (("K1", ExactValue(VInt(240))),)),
    Relations("exact-one-below", (("K1", ExactValue(VInt(239))),)),
    Relations("lower-bound-on-the-threshold", (("K1", ClosedLowerBound(VInt(240))),)),
    Relations("lower-bound-one-below", (("K1", ClosedLowerBound(VInt(239))),)),
    Relations("upper-bound-on-the-threshold", (("K1", ClosedUpperBound(VInt(240))),)),
    Relations("upper-bound-one-below", (("K1", ClosedUpperBound(VInt(239))),)),
    Relations(
        "closed-interval-inside-one-class",
        (("K1", ClosedLowerBound(VInt(300))), ("K2", ClosedUpperBound(VInt(400)))),
    ),
    Relations(
        "closed-interval-straddling-the-threshold",
        (("K1", ClosedLowerBound(VInt(239))), ("K2", ClosedUpperBound(VInt(241)))),
    ),
    Relations(
        "two-lower-bounds-the-stronger-wins",
        (("K1", ClosedLowerBound(VInt(100))), ("K2", ClosedLowerBound(VInt(300)))),
    ),
    Relations(
        "contradictory-bounds",
        (("K1", ClosedLowerBound(VInt(400))), ("K2", ClosedUpperBound(VInt(300)))),
    ),
    Relations(
        "bound-outside-the-declared-domain",
        (("K1", ClosedLowerBound(VInt(1441))),),
    ),
    Relations(
        "an-exact-value-and-a-bound-that-excludes-it",
        (("K1", ExactValue(VInt(100))), ("K2", ClosedLowerBound(VInt(400)))),
    ),
)

IDS = [case.name for case in CASES]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_relations_lower_to_the_same_meaning_in_all_three(case: Relations) -> None:
    scenario = _case(case.name, case.relations)
    query = feasibility_query(scenario.case)
    comparison = compare(query, case.name)
    assert_no_inversion(comparison)
    assert_matches_truth(comparison, semantics.feasible(scenario.case))


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_a_lowered_constraint_keeps_its_label(case: Relations) -> None:
    """A certificate repeats source labels, so they must survive the lowering."""
    scenario = _case(case.name, case.relations)
    labels = {assertion.label for assertion in feasibility_query(scenario.case).assertions}
    for label, relation in case.relations:
        if isinstance(lower_relation(relation, DURATION, DURATION_DOMAIN), LoweredConstraint):
            assert f"C:{label}:S" in labels, case.name


def test_contradictory_bounds_are_infeasible_and_name_the_same_constraints() -> None:
    """Reported, not repaired -- and reported identically by both backends."""
    scenario = _case(
        "contradiction",
        (("K1", ClosedLowerBound(VInt(400))), ("K2", ClosedUpperBound(VInt(300)))),
    )
    query = feasibility_query(scenario.case)
    solver = Z3Backend().check(query)
    reference = BoundedEnumerationBackend(ENUMERATION_BUDGET).check(query)
    assert isinstance(solver, Unsat)
    assert isinstance(reference, Unsat)
    assert solver.contributing_source_constraints == reference.contributing_source_constraints
    assert set(solver.contributing_source_constraints) == {"C:K1:S", "C:K2:S"}


def test_an_exact_value_becomes_a_fact_and_not_a_constraint() -> None:
    """Only one relation establishes a value, and it does not also constrain."""
    lowering = lower_relation(ExactValue(VInt(240)), DURATION, DURATION_DOMAIN)
    assert isinstance(lowering, LoweredFact)
    scenario = _case("exact", (("K1", ExactValue(VInt(240))),))
    assert scenario.unresolved() == ()
    assert scenario.case.logical.assignment()[DURATION] == VInt(240)


#  ---- enum subsets --------------------------------------------------------


def _enum_case(name: str, relation: AcquisitionRelation | None) -> Scenario:
    constraints: tuple[tuple[str, Term], ...] = ()
    if relation is not None:
        lowering = lower_relation(relation, TINT, COLOUR_DOMAIN)
        if isinstance(lowering, LoweredConstraint):
            constraints = (("K1", lowering.formula),)
    decision = program(
        rules=(
            ProgramRule(
                guard=Binary(BinaryOp.EQ, Leaf(TINT), colour("BLUE")),
                action=pay(LitScaled(money(1))),
            ),
        ),
        otherwise=pay(LitScaled(money(2))),
    )
    return build(
        name=name,
        universe=(TINT,),
        known={},
        constraints=constraints,
        decision=decision,
        schema=WIDE_SCHEMA,
    )


ENUM_CASES: tuple[tuple[str, AcquisitionRelation | None], ...] = (
    ("no-relation", None),
    ("single-member", EnumSubset((VEnum(ENUM_COLOUR, "RED"),))),
    ("two-members", EnumSubset((VEnum(ENUM_COLOUR, "RED"), VEnum(ENUM_COLOUR, "BLUE")))),
    ("whole-domain", EnumSubset(tuple(VEnum(ENUM_COLOUR, member) for member in COLOURS))),
)


@pytest.mark.parametrize("name,relation", ENUM_CASES, ids=[name for name, _ in ENUM_CASES])
def test_enum_subsets_lower_to_the_same_meaning_in_all_three(
    name: str, relation: AcquisitionRelation | None
) -> None:
    scenario = _enum_case(name, relation)
    query = feasibility_query(scenario.case)
    comparison = compare(query, name)
    assert_no_inversion(comparison)
    assert_matches_truth(comparison, semantics.feasible(scenario.case))
    assert comparison.conclusive() is Outcome.SATISFIABLE


def test_a_subset_covering_the_whole_domain_constrains_nothing() -> None:
    """It must be indistinguishable from having said nothing at all."""
    covering = EnumSubset(tuple(VEnum(ENUM_COLOUR, member) for member in COLOURS))
    assert isinstance(lower_relation(covering, TINT, COLOUR_DOMAIN), LoweredNonEffect)
    silent = _enum_case("silent", None)
    stated = _enum_case("stated", covering)
    assert semantics.reachable_signatures(silent.case) == semantics.reachable_signatures(
        stated.case
    )
    assert feasibility_query(silent.case).digest() == feasibility_query(stated.case).digest()


def test_a_single_member_subset_pins_the_variable_in_every_semantics() -> None:
    scenario = _enum_case("single", EnumSubset((VEnum(ENUM_COLOUR, "BLUE"),)))
    worlds = semantics.admissible_worlds(scenario.case)
    assert [world[TINT] for world in worlds] == [VEnum(ENUM_COLOUR, "BLUE")]
    query = feasibility_query(scenario.case)
    comparison = compare(query, "single-member")
    assert_no_inversion(comparison)
    assert_matches_truth(comparison, semantics.feasible(scenario.case))
    assert comparison.conclusive() is Outcome.SATISFIABLE
