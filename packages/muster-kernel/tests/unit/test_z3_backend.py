"""The SMT adapter, attacked at the seams a differential cannot reach.

A differential compares answers.  These tests look at how the answer is
produced: whether two worlds really became two variables, whether a witness is
believed without being checked, and whether anything a solver can do other than
answer -- run out of resources, refuse, raise -- can arrive as ``Unsat``.
"""

from __future__ import annotations

from typing import Any

import pytest
import z3

from muster.core.actions import ActionField, ConsequentialAction
from muster.core.expr.evaluate import evaluate_bool
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
    Not,
    Rescale,
)
from muster.core.results import Ok
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled
from muster.core.values.sorts import (
    BoolDomain,
    BoolSort,
    EnumDomain,
    EnumSort,
    IntRange,
    IntSort,
    ScaledRange,
)
from muster.hinge.encode import (
    blocking_query,
    feasibility_query,
    invariance_query,
    sufficiency_query,
)
from muster.hinge.oracle import Feasible, Oracle
from muster.policy.program import ProgramRule
from muster.solve.query import (
    EnumDeclaration,
    LabeledAssertion,
    QTerm,
    QueryDecl,
    QueryKind,
    QueryVar,
    SolverQuery,
    WorldSide,
)
from muster.solve.reference.bounded import BoundedEnumerationBackend
from muster.solve.verdict import Sat, Unknown, UnknownReason, Unsat, UnsupportedFragment
from muster.solve.z3.backend import BACKEND_NAME, BACKEND_VERSION, Z3Backend
from muster.solve.z3.lowering import LoweredQuery, UnsupportedConstruct, lower
from muster.solve.z3.witness import RejectedWitness, witness_of
from tests.differential.scenarios import (
    COUNT,
    DEFINITIONAL_NAME,
    FLAG_A,
    FLAG_B,
    MONEY,
    PAYABLE,
    SCENARIOS,
    TWIN_ARGS,
    TWIN_JOINED,
    Scenario,
    build,
    hold,
    money,
    pay,
    program,
)

DEFINITIONAL = next(item for item in SCENARIOS if item.name == DEFINITIONAL_NAME)
PALETTE = "palette"


def _lower(query: SolverQuery) -> LoweredQuery:
    lowered = lower(query)
    assert not isinstance(lowered, UnsupportedConstruct), lowered
    return lowered


def _names(lowered: LoweredQuery) -> list[str]:
    return [str(variable.constant.decl().name()) for variable in lowered.variables]


#  ---- what the backend declares ------------------------------------------


def test_the_fingerprint_names_the_adapter_not_the_library() -> None:
    """A policy's meaning may not depend on which build of a solver read it.

    So the fingerprint carries the adapter's own contract version.  The solver
    library's version is an operational fact, not a semantic one, and the
    frozen architecture does not make it part of replay.
    """
    fingerprint = Z3Backend().fingerprint()
    assert fingerprint.backend == BACKEND_NAME
    assert fingerprint.version == BACKEND_VERSION
    assert z3.get_version_string() not in (fingerprint.version, fingerprint.logic)


def test_the_declared_budget_is_the_configured_resource_limit() -> None:
    assert Z3Backend().fingerprint().budget == 0
    assert Z3Backend(resource_limit=5_000).fingerprint().budget == 5_000
    with pytest.raises(ValueError, match="negative"):
        Z3Backend(resource_limit=-1)


def test_the_backend_does_not_require_finite_domains() -> None:
    """It decides by reasoning rather than by enumerating, and says so."""
    capabilities = Z3Backend().capabilities()
    assert not capabilities.requires_finite_domains
    assert capabilities.max_enumerated_assignments >= 1


#  ---- world qualification ------------------------------------------------


def test_one_symbol_in_two_worlds_becomes_two_distinct_constants() -> None:
    lowered = _lower(sufficiency_query(DEFINITIONAL.case, frozenset()))
    names = _names(lowered)
    assert len(set(names)) == len(names), "two query variables share one SMT constant"

    paired = [variable for variable in lowered.variables if variable.var.ref == FLAG_A]
    assert {variable.var.side for variable in paired} == {WorldSide.LEFT, WorldSide.RIGHT}
    assert len({str(variable.constant.decl().name()) for variable in paired}) == 2


def test_two_propositions_that_render_alike_stay_apart() -> None:
    """Distinct symbols, one rendering. A name-keyed lowering would merge them."""
    assert str(TWIN_ARGS) == str(TWIN_JOINED)
    scenario = build(
        name="twins",
        universe=(TWIN_ARGS, TWIN_JOINED),
        known={},
        constraints=(),
        decision=program(
            rules=(ProgramRule(guard=Leaf(TWIN_ARGS), action=pay(LitScaled(money(5)))),),
            otherwise=hold("REVIEW"),
        ),
    )
    query = sufficiency_query(scenario.case, frozenset({TWIN_JOINED}))
    names = _names(_lower(query))
    assert len(set(names)) == len(names)

    #  Fixing the twin that no rule reads leaves the action free to vary, so
    #  the query is satisfiable. Had the two symbols merged, fixing one would
    #  have fixed the other and the answer would flip to unsatisfiable.
    assert isinstance(Z3Backend().check(query), Sat)


def test_fixing_a_symbol_adds_an_equality_for_that_symbol_alone() -> None:
    fixed = sufficiency_query(DEFINITIONAL.case, frozenset({PAYABLE}))
    labels = {assertion.label for assertion in fixed.assertions}
    assert f"FIX:{PAYABLE.key()}" in labels
    assert f"FIX:{FLAG_A.key()}" not in labels
    assert f"FIX:{FLAG_B.key()}" not in labels


def test_self_composition_is_not_vacuous_when_nothing_is_fixed() -> None:
    """The guard against a collapsed two-world encoding.

    If both worlds shared their variables the action-difference assertion
    would be unsatisfiable for every case, and every case would read as
    sufficient on the empty set.
    """
    backend = Z3Backend()
    assert isinstance(backend.check(sufficiency_query(DEFINITIONAL.case, frozenset())), Sat)
    assert isinstance(
        backend.check(sufficiency_query(DEFINITIONAL.case, frozenset({PAYABLE}))), Unsat
    )


#  ---- action semantics ---------------------------------------------------


def _amount_case(left: int, right: int) -> Scenario:
    """A case whose payment amount depends on one boolean and nothing else."""
    return build(
        name=f"amount-{left}-{right}",
        universe=(FLAG_A,),
        known={},
        constraints=(),
        decision=program(
            rules=(ProgramRule(guard=Leaf(FLAG_A), action=pay(LitScaled(money(left)))),),
            otherwise=pay(LitScaled(money(right))),
        ),
    )


def test_two_payments_of_different_amounts_are_different_actions() -> None:
    scenario = _amount_case(42, 51)
    verdict = Z3Backend().check(sufficiency_query(scenario.case, frozenset()))
    assert isinstance(verdict, Sat), "a payment that varies in amount must read as divergent"


def test_two_payments_of_the_same_amount_are_the_same_action() -> None:
    scenario = _amount_case(42, 42)
    assert isinstance(Z3Backend().check(sufficiency_query(scenario.case, frozenset())), Unsat)


def test_a_diagnostic_field_that_varies_does_not_make_two_actions() -> None:
    """The executor ignores it, so two actions differing only here are one."""
    scenario = build(
        name="memo",
        universe=(FLAG_A,),
        known={},
        constraints=(),
        decision=program(
            rules=(ProgramRule(guard=Leaf(FLAG_A), action=pay(LitScaled(money(9)), LitInt(1))),),
            otherwise=pay(LitScaled(money(9)), LitInt(2)),
        ),
    )
    assert isinstance(Z3Backend().check(sufficiency_query(scenario.case, frozenset())), Unsat)


def test_a_consequential_field_that_varies_does_make_two_actions() -> None:
    scenario = build(
        name="reason",
        universe=(FLAG_A,),
        known={},
        constraints=(),
        decision=program(
            rules=(ProgramRule(guard=Leaf(FLAG_A), action=hold("REVIEW")),),
            otherwise=hold("BLOCKED"),
        ),
    )
    assert isinstance(Z3Backend().check(sufficiency_query(scenario.case, frozenset())), Sat)


def test_several_reachable_actions_share_one_kind() -> None:
    """Two payments and a hold: the kind alone does not identify an action."""
    scenario = build(
        name="three-actions",
        universe=(FLAG_A, FLAG_B),
        known={},
        constraints=(),
        decision=program(
            rules=(
                ProgramRule(guard=Leaf(FLAG_A), action=pay(LitScaled(money(11)))),
                ProgramRule(guard=Leaf(FLAG_B), action=pay(LitScaled(money(22)))),
            ),
            otherwise=hold("REVIEW"),
        ),
    )
    backend = Z3Backend()
    oracle = Oracle(backend, scenario.case)
    found: list[ConsequentialAction] = []
    while len(found) < 4:
        probe = oracle.reachable_probe(tuple(found))
        if not isinstance(probe, Feasible):
            break
        found.append(probe.action)

    assert len(found) == 3, [action.render() for action in found]
    assert [action.kind for action in found].count("PAY") == 2
    assert isinstance(backend.check(blocking_query(scenario.case, tuple(found))), Unsat)


#  ---- the fragment boundary ----------------------------------------------


def _bare_query(
    assertions: tuple[LabeledAssertion, ...],
    declarations: tuple[QueryDecl, ...] = (),
    enums: tuple[EnumDeclaration, ...] = (),
) -> SolverQuery:
    return SolverQuery(
        QueryKind.FEASIBILITY,
        DEFINITIONAL.case.logical.digest(),
        enums,
        declarations,
        assertions,
    )


def test_a_narrowing_rescale_is_refused_rather_than_rounded() -> None:
    scaled = LitScaled(VScaled("INR", 2, 100))
    query = _bare_query((LabeledAssertion("C:x", Binary(BinaryOp.EQ, Rescale(scaled, 0), scaled)),))
    verdict = Z3Backend().check(query)
    assert isinstance(verdict, UnsupportedFragment)
    assert "narrowing" in verdict.detail


def test_mixing_two_units_is_refused_rather_than_compared() -> None:
    query = _bare_query(
        (
            LabeledAssertion(
                "C:x",
                Binary(
                    BinaryOp.EQ, LitScaled(VScaled("INR", 2, 1)), LitScaled(VScaled("USD", 2, 1))
                ),
            ),
        )
    )
    verdict = Z3Backend().check(query)
    assert isinstance(verdict, UnsupportedFragment)
    assert "sort mismatch" in verdict.detail


def test_ordering_a_boolean_is_refused() -> None:
    """The evaluator refuses to order booleans, so neither does the lowering."""
    query = _bare_query(
        (
            LabeledAssertion(
                "C:x", Binary(BinaryOp.LT, Not(Leaf(QueryVar(WorldSide.SINGLE, FLAG_A))), LitInt(1))
            ),
        ),
        (QueryDecl(WorldSide.SINGLE, FLAG_A, BoolSort(), BoolDomain()),),
    )
    assert isinstance(Z3Backend().check(query), UnsupportedFragment)


def test_an_assertion_over_an_undeclared_variable_is_refused() -> None:
    query = _bare_query((LabeledAssertion("C:x", Leaf(QueryVar(WorldSide.SINGLE, FLAG_A))),))
    verdict = Z3Backend().check(query)
    assert isinstance(verdict, UnsupportedFragment)
    assert "not declared" in verdict.detail


def test_a_declaration_whose_domain_does_not_match_its_sort_is_refused() -> None:
    """Nothing above builds this; a backend that picked one of the two would be
    answering about a variable nobody declared."""
    query = _bare_query(
        (LabeledAssertion("C:x", Leaf(QueryVar(WorldSide.SINGLE, FLAG_A))),),
        (QueryDecl(WorldSide.SINGLE, FLAG_A, BoolSort(), IntRange(0, 1)),),
    )
    assert isinstance(Z3Backend().check(query), UnsupportedFragment)


def test_an_enum_literal_is_lowered_even_where_the_query_declares_no_enum() -> None:
    """Which integer stands for a member is this adapter's private business.

    The encoder declares the enums of symbol sorts and of the action kind, and
    not the enums of action *fields*; a lowering that demanded a declaration
    would be unable to decide any case whose actions carry an enum field, which
    is a capability answer to a semantic question.
    """
    red, blue = VEnum(PALETTE, "RED"), VEnum(PALETTE, "BLUE")
    same = _bare_query((LabeledAssertion("C:x", Binary(BinaryOp.EQ, LitEnum(red), LitEnum(red))),))
    different = _bare_query(
        (LabeledAssertion("C:x", Binary(BinaryOp.EQ, LitEnum(red), LitEnum(blue))),)
    )
    assert isinstance(Z3Backend().check(same), Sat)
    assert isinstance(Z3Backend().check(different), Unsat)


def test_an_enum_table_that_leaves_a_declared_member_uncovered_is_refused() -> None:
    declaration = QueryDecl(
        WorldSide.SINGLE, COUNT, EnumSort(PALETTE), EnumDomain(("RED", "GREEN"))
    )
    table = EnumTable(Leaf(declaration.var()), (Arm("RED", LitInt(1)),))
    query = _bare_query(
        (LabeledAssertion("C:x", Binary(BinaryOp.EQ, table, LitInt(1))),),
        (declaration,),
        (EnumDeclaration(PALETTE, ("RED", "GREEN")),),
    )
    verdict = Z3Backend().check(query)
    assert isinstance(verdict, UnsupportedFragment)
    assert "GREEN" in verdict.detail


#  ---- witnesses ----------------------------------------------------------


class _Model:
    """A model that answers whatever a test wants it to answer."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self._answers = answers

    def eval(self, constant: Any, model_completion: bool = False) -> Any:
        del model_completion
        return self._answers.get(str(constant.decl().name()), constant)


def test_a_model_that_does_not_satisfy_the_query_is_not_a_witness() -> None:
    """The production evaluator is the authority, not the solver's word."""
    query = feasibility_query(DEFINITIONAL.case)
    lowered = _lower(query)
    #  ``payable`` true while both premises are false violates the definitional
    #  constraint, and every value is in domain and of the right sort.
    answers = {
        str(variable.constant.decl().name()): z3.BoolVal(variable.var.ref == PAYABLE)
        for variable in lowered.variables
    }
    outcome = witness_of(lowered, _Model(answers), query)
    assert isinstance(outcome, RejectedWitness)
    assert "not satisfied" in outcome.detail


def test_a_model_value_of_the_wrong_shape_is_not_a_witness() -> None:
    query = feasibility_query(DEFINITIONAL.case)
    lowered = _lower(query)
    #  An integer where a boolean belongs: not decodable, so not a world.
    answers = {str(lowered.variables[0].constant.decl().name()): z3.IntVal(7)}
    outcome = witness_of(lowered, _Model(answers), query)
    assert isinstance(outcome, RejectedWitness)
    assert "boolean value" in outcome.detail


def test_a_model_value_outside_the_declared_domain_is_not_a_witness() -> None:
    scenario = build(
        name="ranged",
        universe=(COUNT,),
        known={},
        constraints=(),
        decision=program(rules=(), otherwise=pay(LitScaled(money(1)))),
    )
    query = feasibility_query(scenario.case)
    lowered = _lower(query)
    answers = {str(lowered.variables[0].constant.decl().name()): z3.IntVal(9_999)}
    outcome = witness_of(lowered, _Model(answers), query)
    assert isinstance(outcome, RejectedWitness)
    assert "outside its declared domain" in outcome.detail


def test_an_undecodable_enum_index_is_not_a_witness() -> None:
    declaration = QueryDecl(
        WorldSide.SINGLE, COUNT, EnumSort(PALETTE), EnumDomain(("RED", "GREEN"))
    )
    query = _bare_query((), (declaration,), (EnumDeclaration(PALETTE, ("RED", "GREEN")),))
    lowered = _lower(query)
    answers = {str(lowered.variables[0].constant.decl().name()): z3.IntVal(17)}
    outcome = witness_of(lowered, _Model(answers), query)
    assert isinstance(outcome, RejectedWitness)
    assert "declared member" in outcome.detail


def test_a_satisfiable_answer_carries_a_model_that_survives_re_evaluation() -> None:
    query = feasibility_query(DEFINITIONAL.case)
    verdict = Z3Backend().check(query)
    assert isinstance(verdict, Sat)
    assert set(verdict.model) == {
        QueryVar(WorldSide.SINGLE, ref) for ref in DEFINITIONAL.case.unresolved()
    }
    #  Re-running the query's own assertions over the decoded model is what the
    #  backend already did; doing it again here proves the model that left is
    #  the one that was checked.
    for assertion in query.assertions:
        outcome = evaluate_bool(assertion.formula, verdict.model)
        assert isinstance(outcome, Ok)
        assert outcome.value, assertion.label


#  ---- resource limits and failures ---------------------------------------


def test_a_reached_resource_limit_is_a_budget_exhaustion_not_an_answer() -> None:
    query = sufficiency_query(DEFINITIONAL.case, frozenset())
    verdict = Z3Backend(resource_limit=1).check(query)
    assert isinstance(verdict, Unknown)
    assert verdict.reason is UnknownReason.BUDGET_EXHAUSTED


def test_a_solver_exception_never_crosses_the_port() -> None:
    def explode(*_: object, **__: object) -> None:
        raise z3.Z3Exception("synthetic")

    backend = Z3Backend()
    query = feasibility_query(DEFINITIONAL.case)
    with pytest.MonkeyPatch.context() as patch:
        #  The adapter holds the library module, so replacing the entry point
        #  on it is exactly what a broken solver install would look like.
        patch.setattr(z3, "Solver", explode)
        verdict = backend.check(query)
    assert isinstance(verdict, Unknown)
    assert verdict.reason is UnknownReason.BACKEND_FAILURE


def test_an_unsatisfiable_answer_names_every_source_constraint() -> None:
    """The same contributing set the bounded backend reports, so one case does
    not produce two different infeasible records depending on who answered."""
    scenario = build(
        name="contradiction",
        universe=(FLAG_A,),
        known={},
        constraints=(("K1", Leaf(FLAG_A)), ("K2", Not(Leaf(FLAG_A)))),
        decision=program(rules=(), otherwise=pay(LitScaled(money(1)))),
    )
    query = feasibility_query(scenario.case)
    solver = Z3Backend().check(query)
    reference = BoundedEnumerationBackend(1000).check(query)
    assert isinstance(solver, Unsat)
    assert isinstance(reference, Unsat)
    assert solver.contributing_source_constraints == reference.contributing_source_constraints
    assert set(solver.contributing_source_constraints) == {"C:K1:S", "C:K2:S"}


def test_an_invariance_query_against_an_unreachable_witness_is_satisfiable() -> None:
    scenario = _amount_case(42, 51)
    witness = ConsequentialAction(
        scenario.case.action_schema.digest(),
        "PAY",
        (ActionField("amount", VScaled("INR", 2, 99)),),
    )
    assert isinstance(Z3Backend().check(invariance_query(scenario.case, witness)), Sat)


def test_the_seed_is_recorded_and_does_not_change_the_verdict() -> None:
    """A seed is an operational knob, never a semantic one.

    It reaches the solver and it reaches the fingerprint, so a record can say
    which run produced it; what it may not do is change the answer.
    """
    query = sufficiency_query(DEFINITIONAL.case, frozenset())
    default, seeded = Z3Backend(), Z3Backend(seed=7919)
    assert isinstance(default.check(query), Sat)
    assert isinstance(seeded.check(query), Sat)
    assert default.fingerprint().seed == 0
    assert seeded.fingerprint().seed == 7919
    assert default.fingerprint() != seeded.fingerprint()


#  ---- regressions, each one a counterexample an adversarial review found ---


def test_a_table_arm_for_an_undeclared_member_is_not_dropped() -> None:
    """The smallest false ``Unsat`` this adapter ever produced.

    The table scrutinises a member the query does not declare and an arm
    matches it.  A lowering that built its selector chain from the *declared*
    members instead of from the *arms* dropped that arm, turned the table into
    a constant, and reported unsatisfiable -- which on the invariance query is
    reported as invariance.
    """
    escaped = VEnum(PALETTE, "AMBER")
    table: QTerm = EnumTable(
        LitEnum(escaped),
        (
            Arm("RED", LitBool(False)),
            Arm("GREEN", LitBool(False)),
            Arm("AMBER", LitBool(True)),
        ),
    )
    query = _bare_query(
        (LabeledAssertion("C:t", table),), (), (EnumDeclaration(PALETTE, ("RED", "GREEN")),)
    )
    #  The concrete evaluator is the authority, and it says the table is true.
    truth = evaluate_bool(table, {})
    assert isinstance(truth, Ok)
    assert truth.value

    assert isinstance(Z3Backend().check(query), Sat)
    assert isinstance(BoundedEnumerationBackend(1000).check(query), Sat)


def test_a_composed_scrutinee_that_escapes_its_domain_does_not_become_invariance() -> None:
    """The same defect in the shape that reaches an authorization-like output.

    The scrutinee is an ``ite`` whose false branch is a member no declaration
    admits, so the world where it is taken is exactly the world an
    action-difference assertion needs.  Reported unsatisfiable, this case reads
    as ``Invariant``; it is satisfiable, and both backends must say so.
    """
    flag = QueryVar(WorldSide.SINGLE, FLAG_A)
    tint = QueryVar(WorldSide.SINGLE, COUNT)
    declarations = (
        QueryDecl(WorldSide.SINGLE, FLAG_A, BoolSort(), BoolDomain()),
        QueryDecl(WorldSide.SINGLE, COUNT, EnumSort(PALETTE), EnumDomain(("RED", "GREEN"))),
    )
    constraint = LabeledAssertion(
        "C:g", Binary(BinaryOp.NE, Leaf(tint), LitEnum(VEnum(PALETTE, "GREEN")))
    )
    difference = LabeledAssertion(
        "DIFF",
        EnumTable(
            Ite(Leaf(flag), Leaf(tint), LitEnum(VEnum(PALETTE, "AMBER"))),
            (
                Arm("RED", LitBool(False)),
                Arm("GREEN", LitBool(False)),
                Arm("AMBER", LitBool(True)),
            ),
        ),
    )
    query = _bare_query(
        (constraint, difference), declarations, (EnumDeclaration(PALETTE, ("RED", "GREEN")),)
    )
    witness: dict[QueryVar, Value] = {flag: VBool(False), tint: VEnum(PALETTE, "RED")}
    for assertion in query.assertions:
        outcome = evaluate_bool(assertion.formula, witness)
        assert isinstance(outcome, Ok)
        assert outcome.value, assertion.label

    #  Feasibility first, because that is the reading the docstring describes:
    #  a satisfiable feasibility query establishes the witness, and an
    #  unsatisfiable difference query against it is reported as invariance.
    feasibility = _bare_query(
        (constraint,), declarations, (EnumDeclaration(PALETTE, ("RED", "GREEN")),)
    )
    assert isinstance(Z3Backend().check(feasibility), Sat)

    assert isinstance(Z3Backend().check(query), Sat)
    assert isinstance(BoundedEnumerationBackend(1000).check(query), Sat)


def test_an_arm_outside_the_declared_members_is_still_sort_checked() -> None:
    """Every arm is checked, not only the ones a declaration happens to name."""
    table: QTerm = EnumTable(
        LitEnum(VEnum(PALETTE, "RED")),
        (
            Arm("RED", LitBool(True)),
            Arm("GREEN", LitBool(True)),
            Arm("AMBER", LitInt(3)),
        ),
    )
    query = _bare_query(
        (LabeledAssertion("C:t", table),), (), (EnumDeclaration(PALETTE, ("RED", "GREEN")),)
    )
    verdict = Z3Backend().check(query)
    assert isinstance(verdict, UnsupportedFragment)
    assert "sort mismatch" in verdict.detail


def test_a_table_covering_its_own_scrutinee_is_decided_whatever_else_is_declared() -> None:
    """Exhaustiveness is a question about the scrutinee, not about the enum.

    Requiring coverage of every member any *other* declaration allows would
    refuse a table the program compiler accepted, which is a capability answer
    to a semantic question.
    """
    narrow = QueryDecl(WorldSide.SINGLE, COUNT, EnumSort(PALETTE), EnumDomain(("RED", "GREEN")))
    wide = QueryDecl(
        WorldSide.SINGLE, FLAG_B, EnumSort(PALETTE), EnumDomain(("RED", "GREEN", "BLUE"))
    )
    table = EnumTable(Leaf(narrow.var()), (Arm("RED", LitBool(True)), Arm("GREEN", LitBool(True))))
    query = _bare_query(
        (LabeledAssertion("C:t", table),),
        (narrow, wide),
        (EnumDeclaration(PALETTE, ("RED", "GREEN", "BLUE")),),
    )
    assert isinstance(Z3Backend().check(query), Sat)


@pytest.mark.parametrize(
    "declaration",
    [
        QueryDecl(WorldSide.SINGLE, COUNT, IntSort(), IntRange(1, 0)),
        QueryDecl(WorldSide.SINGLE, COUNT, MONEY, ScaledRange(5, -5)),
    ],
    ids=["int", "scaled"],
)
def test_an_empty_declared_range_is_refused_rather_than_answered(
    declaration: QueryDecl,
) -> None:
    """A range with no values would make every query mentioning it
    unsatisfiable, presenting a malformed declaration as ``Infeasible``."""
    query = _bare_query(
        (LabeledAssertion("C:t", Leaf(QueryVar(WorldSide.SINGLE, FLAG_A))),),
        (QueryDecl(WorldSide.SINGLE, FLAG_A, BoolSort(), BoolDomain()), declaration),
    )
    verdict = Z3Backend().check(query)
    assert isinstance(verdict, UnsupportedFragment)
    assert "empty range" in verdict.detail


def test_a_single_valued_range_is_still_decided() -> None:
    """The refusal is exactly ``hi < lo``, not "a range that looks small"."""
    for declaration in (
        QueryDecl(WorldSide.SINGLE, COUNT, IntSort(), IntRange(3, 3)),
        QueryDecl(WorldSide.SINGLE, COUNT, MONEY, ScaledRange(-5, -5)),
    ):
        query = _bare_query((), (declaration,))
        assert isinstance(Z3Backend().check(query), Sat)


def test_an_enum_declared_with_a_repeated_member_is_refused() -> None:
    """A repeated member makes the numbering ambiguous, so there is no answer."""
    query = _bare_query(
        (LabeledAssertion("C:t", Binary(BinaryOp.EQ, LitInt(1), LitInt(1))),),
        (),
        (EnumDeclaration(PALETTE, ("RED", "RED", "GREEN")),),
    )
    verdict = Z3Backend().check(query)
    assert isinstance(verdict, UnsupportedFragment)
    assert "twice" in verdict.detail


def test_a_term_too_deep_to_translate_is_indeterminate_not_an_exception() -> None:
    """Translation happens inside the guard, because a term deep enough to
    exhaust the stack does so while it is being read."""
    formula: QTerm = LitBool(True)
    for _ in range(4_000):
        formula = Not(formula)
    verdict = Z3Backend().check(_bare_query((LabeledAssertion("C:t", formula),)))
    assert isinstance(verdict, Unknown)
    assert verdict.reason is UnknownReason.BACKEND_FAILURE


def test_the_lowering_covers_every_sort_the_fragment_declares() -> None:
    """A declaration of each sort, decoded back into a production value."""
    declarations = (
        QueryDecl(WorldSide.SINGLE, FLAG_A, BoolSort(), BoolDomain()),
        QueryDecl(WorldSide.SINGLE, COUNT, IntSort(), IntRange(2, 2)),
        QueryDecl(WorldSide.SINGLE, PAYABLE, MONEY, ScaledRange(7, 7)),
        QueryDecl(WorldSide.SINGLE, FLAG_B, EnumSort(PALETTE), EnumDomain(("RED",))),
    )
    query = _bare_query((), declarations, (EnumDeclaration(PALETTE, ("RED",)),))
    verdict = Z3Backend().check(query)
    assert isinstance(verdict, Sat)
    assert verdict.model[QueryVar(WorldSide.SINGLE, COUNT)] == VInt(2)
    assert verdict.model[QueryVar(WorldSide.SINGLE, PAYABLE)] == VScaled("INR", 2, 7)
    assert verdict.model[QueryVar(WorldSide.SINGLE, FLAG_B)] == VEnum(PALETTE, "RED")
    assert isinstance(verdict.model[QueryVar(WorldSide.SINGLE, FLAG_A)], VBool)
