"""Preconditions the query builder states, and what happens when they fail.

A guard nothing tests is a guard nobody knows still works, so each one is
exercised here.

The duplicate-label guard used to be more than that.  It was stated only where
a query is finally assembled, which put an ``InvariantViolation`` -- programmer
error, by definition, and explicitly not a response to input -- at the end of a
path that started in case data.  The rule now lives on the value that carries
the constraints, so the failure is next to the mistake, and case data meets it
far earlier: :func:`muster.application.rebuild.rebuild` reports a repeated label
as a typed value on the public path, which is checked in
``tests/adversarial/test_boundary_typing.py``.
"""

from __future__ import annotations

import dataclasses

import pytest

from muster.core.analysis.logical_case import LogicalCase
from muster.core.case.constraints import Constraint, StructuralDeriv
from muster.core.expr.ir import Binary, BinaryOp, Leaf, LitInt, LitScaled
from muster.core.results import InvariantViolation
from muster.core.values.scalars import VInt
from muster.core.wire.codec import canonical_order
from muster.hinge.encode import feasibility_query, sufficiency_query
from muster.hinge.project import SymbolDeclaration
from muster.solve.query import LabeledAssertion, QTerm, QueryKind, SolverQuery
from tests.differential.scenarios import (
    COUNT,
    FLAG_A,
    PLACEHOLDER,
    SCHEMA,
    Scenario,
    build,
    money,
    pay,
    program,
)


def _one_variable(name: str) -> Scenario:
    return build(
        name=name,
        universe=(COUNT,),
        known={},
        constraints=(),
        decision=program(rules=(), otherwise=pay(LitScaled(money(1)))),
    )


def _declarations() -> tuple[SymbolDeclaration, ...]:
    return _one_variable("one").case.declarations


def test_fixing_an_established_symbol_is_refused_rather_than_answered() -> None:
    """Fixing what is already known silently answers a different question.

    ``Sufficient(S)`` asks whether agreeing on ``S`` determines the action;
    every world already agrees on what is established, so including one in
    ``S`` makes the query weaker than it reads.  Today's callers never do it --
    they draw from the unresolved set -- and this proves the guard still fires
    if one ever does.
    """
    scenario = build(
        name="settled",
        universe=(COUNT,),
        known={COUNT: VInt(2)},
        constraints=(),
        decision=program(rules=(), otherwise=pay(LitScaled(money(1)))),
    )
    assert COUNT not in set(scenario.unresolved())
    with pytest.raises(InvariantViolation, match="established"):
        sufficiency_query(scenario.case, frozenset({COUNT}))


def _duplicated_labels() -> tuple[Constraint, ...]:
    return canonical_order(
        (
            Constraint(label, formula, StructuralDeriv(PLACEHOLDER))
            for label, formula in (
                ("SAME", Binary(BinaryOp.GE, Leaf(COUNT), LitInt(1))),
                ("SAME", Binary(BinaryOp.LE, Leaf(COUNT), LitInt(2))),
            )
        ),
        lambda item: item.to_node(),
    )


def test_a_logical_case_refuses_two_constraints_sharing_a_label() -> None:
    """Refused where the constraints are held, not where a query is assembled.

    The encoder turns each constraint label into an assertion label, and a
    query cannot carry two assertions under one label.  Stating that rule only
    at query construction put the failure a long way from the value that caused
    it; stating it here means a case carrying the ambiguity cannot be built,
    and the query-level guard becomes unreachable rather than merely untriggered.
    """
    decision = program(rules=(), otherwise=pay(LitScaled(money(1))))
    with pytest.raises(InvariantViolation, match="constraint labels are unique"):
        LogicalCase(
            universe=(COUNT,),
            known=(),
            constraints=_duplicated_labels(),
            decision_program_digest=decision.digest(),
            action_schema_digest=SCHEMA.digest(),
            predicate_schema_digest=PLACEHOLDER,
        )


def test_the_two_uniqueness_rules_are_the_same_rule() -> None:
    """The revision and its logical projection must agree, or one is decoration.

    A projection that admitted what the revision refuses would let the rule be
    satisfied on one side of the boundary and violated on the other.
    """
    from tests.support import ravi

    #  Two labels the same, two formulas different: canonically ordered, so the
    #  ordering rule cannot answer for the uniqueness one.
    duplicated = _duplicated_labels()
    assert len({constraint.label for constraint in duplicated}) == 1
    with pytest.raises(InvariantViolation, match=r"duplicate constraints\.label"):
        dataclasses.replace(ravi.revision(), constraints=duplicated)


def test_a_query_rejects_duplicate_assertion_labels_directly() -> None:
    """The rule the case-level guards above make unreachable from a case."""
    formula: QTerm = Binary(BinaryOp.EQ, LitInt(1), LitInt(1))
    with pytest.raises(InvariantViolation, match="assertion labels are unique"):
        SolverQuery(
            QueryKind.FEASIBILITY,
            PLACEHOLDER,
            (),
            (),
            (LabeledAssertion("C:x", formula), LabeledAssertion("C:x", formula)),
        )


def test_a_query_rejects_two_declarations_of_one_symbol_and_side() -> None:
    """The other uniqueness rule, and the one that keeps two worlds apart."""
    scenario = build(
        name="pair",
        universe=(FLAG_A,),
        known={},
        constraints=(),
        decision=program(rules=(), otherwise=pay(LitScaled(money(1)))),
    )
    declarations = feasibility_query(scenario.case).declarations
    with pytest.raises(InvariantViolation, match="unique by"):
        SolverQuery(QueryKind.FEASIBILITY, PLACEHOLDER, (), (*declarations, *declarations), ())
