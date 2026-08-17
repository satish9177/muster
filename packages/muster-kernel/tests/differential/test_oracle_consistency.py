"""Checks on the judge, not on the judged.

A differential is only worth what its oracle is worth, so this module puts the
oracle against itself and the corpus against its own claims.

Three separate jobs:

* **The oracle's two routes to truth must agree.**  ``semantics.sufficient``
  answers by pairing up admissible worlds and never builds a query;
  ``semantics.query_truth`` enumerates the query the encoder produced.  Their
  equivalence is the assumption the whole sufficiency differential rests on,
  and it is checked here rather than assumed.
* **The corpus must contain what it is said to contain.**  Every claim the
  generator makes -- equality chains longer than a pair, three action kinds, a
  kind with two consequential fields, a degenerate domain, a table over a
  computed scrutinee -- is asserted against the generated cases, so a shape
  that quietly stopped being produced fails here instead of silently reducing
  the differential to the easy cases.
* **The transcribed rules must still match their originals.**  Three small
  functions in the oracle restate production rules rather than deriving them
  independently; a transcription that drifts would move both sides of the
  differential together, so each is pinned against the production original and
  against a written-out table.
"""

from __future__ import annotations

import pytest

from muster.core.actions import Consequentiality, FieldSpec, validate_action_schema
from muster.core.analysis.outcomes import Invariant
from muster.core.expr.ir import (
    Binary,
    BinaryOp,
    EnumTable,
    Ite,
    Leaf,
    LitScaled,
    MulConst,
    NAry,
    NAryOp,
    Neg,
    Not,
    Rescale,
    Scale,
)
from muster.core.expr.terms import Term
from muster.core.results import Err, Ok
from muster.core.values.scalars import (
    Value,
    VBool,
    VEnum,
    VInt,
    VScaled,
    derived_filler,
    enumerate_domain,
    value_in_domain,
)
from muster.core.values.sorts import (
    BoolDomain,
    BoolSort,
    Domain,
    EnumDomain,
    EnumSort,
    IntRange,
    IntSort,
    ScaledRange,
    Sort,
)
from muster.hinge.analyze import analyze
from muster.hinge.encode import feasibility_query, sufficiency_query
from muster.hinge.oracle import Oracle
from muster.hinge.prepare import EngineLimits
from muster.policy.program import evaluate_program
from muster.solve.query import SolverQuery
from tests.differential import semantics
from tests.differential.backends import (
    Outcome,
    assert_matches_truth,
    assert_no_inversion,
    compare,
    smt,
)
from tests.differential.scenarios import (
    COUNT,
    MONEY,
    SCENARIOS,
    Scenario,
    build,
    money,
    pay,
    program,
)

LIMITS = EngineLimits(max_unresolved=8, reachable_action_cap=8)

#  Enumerating a two-world query is quadratic in the case's world space, so the
#  cross-check runs where that is affordable.  How much of the corpus it
#  reached is asserted below, because a budget that silently excluded
#  everything would turn this module into decoration.
QUERY_ENUMERATION_BUDGET = 8_192

IDS = [scenario.name for scenario in SCENARIOS]


def _assignments(query: SolverQuery) -> int:
    """How many total assignments enumerating this query would visit."""
    space = 1
    for declaration in query.declarations:
        space *= len(semantics.domain_values(declaration.sort, declaration.domain))
    return space


#  ---- the oracle's two routes to truth -----------------------------------


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_the_two_ways_the_oracle_computes_truth_agree(scenario: Scenario) -> None:
    """Case-level pairing and query-level enumeration must be one claim.

    They are computed from different things -- one from the case, one from the
    query the encoder built out of it -- so agreeing is evidence about the
    encoder, and disagreeing would mean the sufficiency differential has been
    measuring the wrong quantity all along.
    """
    case = scenario.case
    feasibility = feasibility_query(case)
    if _assignments(feasibility) <= QUERY_ENUMERATION_BUDGET:
        assert semantics.query_truth(feasibility) == semantics.feasible(case), scenario.name

    for fixed in semantics.subsets(scenario.unresolved()):
        query = sufficiency_query(case, fixed)
        if _assignments(query) > QUERY_ENUMERATION_BUDGET:
            continue
        where = f"{scenario.name}/{sorted(str(ref) for ref in fixed)}"
        assert semantics.query_truth(query) == (not semantics.sufficient(case, fixed)), where


def test_the_cross_check_actually_ran_on_most_of_the_corpus() -> None:
    """A budget that excluded everything would make the check above vacuous.

    Counted over the *sufficiency* queries, because those are the ones the
    cross-check exists for and the ones the budget could exclude: a two-world
    query is roughly the square of its case's world space, so a feasibility
    count would stay comfortable long after every sufficiency check had been
    skipped.
    """
    feasible = 0
    sufficiency = 0
    skipped = 0
    for scenario in SCENARIOS:
        if _assignments(feasibility_query(scenario.case)) <= QUERY_ENUMERATION_BUDGET:
            feasible += 1
        for fixed in semantics.subsets(scenario.unresolved()):
            if _assignments(sufficiency_query(scenario.case, fixed)) <= QUERY_ENUMERATION_BUDGET:
                sufficiency += 1
            else:
                skipped += 1

    assert feasible >= len(SCENARIOS) - 2, f"only {feasible} of {len(SCENARIOS)} were affordable"
    assert sufficiency > 500, f"only {sufficiency} sufficiency cross-checks were affordable"
    assert skipped == 0, f"{skipped} sufficiency cross-checks were skipped for budget"


#  ---- totality -------------------------------------------------------------


def test_the_program_is_total_over_every_generated_case() -> None:
    """The oracle can only state a truth for a case whose program is total.

    Not a given: the query encoder lowers a field term without its declared
    bounds while the concrete evaluator rejects a value that leaves them, so a
    generator that wandered into that shape would have three semantics
    answering different questions.
    """
    examined = 0
    for scenario in SCENARIOS:
        assert semantics.total(scenario.case), scenario.name
        examined += len(semantics.admissible_worlds(scenario.case))
    #  ``total`` is a universal over the world set, so an infeasible case
    #  satisfies it without examining anything. This is the floor on the part
    #  that was actually examined.
    assert examined > 500, f"totality was only checked over {examined} worlds"


def test_an_established_value_outside_its_domain_admits_no_world() -> None:
    """The oracle has to agree with the encoder about established values.

    Every declaration gets a domain assertion, established ones included, so a
    case contradicting its own schema has an empty world set.  An oracle that
    wrote the established value in unchecked would call such a case feasible
    and disagree with both backends -- and it would be the one that was wrong.
    """
    scenario = build(
        name="established-out-of-domain",
        universe=(COUNT,),
        known={COUNT: VInt(99)},
        constraints=(),
        decision=program(rules=(), otherwise=pay(LitScaled(money(1)))),
    )
    case = scenario.case
    assert semantics.admissible_worlds(case) == []
    assert not semantics.feasible(case)

    comparison = compare(feasibility_query(case), "established-out-of-domain")
    assert_no_inversion(comparison)
    assert_matches_truth(comparison, False)
    assert comparison.conclusive() is Outcome.UNSATISFIABLE


def test_a_field_that_leaves_its_declared_bounds_never_becomes_an_invariant() -> None:
    """The encoder and the evaluator disagree about out-of-bounds fields.

    ``_field_term`` lowers a field without its declared bounds, so the symbolic
    world set is *larger* than the concrete one; ``build_action`` rejects the
    value outright.  That is the safe direction -- more worlds means more
    divergence, never more invariance -- and this pins it: the program is not
    total, the concrete evaluator says so, and the analysis never proposes an
    action.
    """
    scenario = build(
        name="out-of-bounds",
        universe=(COUNT,),
        known={},
        constraints=(),
        #  ``amount`` reaches 600 minor units; its declared bound is 100.
        decision=program(rules=(), otherwise=pay(Scale(MulConst(2, Leaf(COUNT)), 100, MONEY))),
    )
    case = scenario.case
    assert not semantics.total(case)

    undefined = [
        world
        for world in semantics.admissible_worlds(case)
        if isinstance(semantics.signature_of(case, world), semantics.Undefined)
    ]
    assert undefined, "the case was supposed to reach an out-of-bounds field"
    assert isinstance(evaluate_program(case.program, case.action_schema, undefined[0]), Err)

    outcome = analyze(case, Oracle(smt(), case), LIMITS).outcome
    assert not isinstance(outcome, Invariant), "an out-of-bounds field must not read as invariance"


#  ---- the transcribed rules ------------------------------------------------

FILLERS: tuple[tuple[Sort, Domain, Value], ...] = (
    (BoolSort(), BoolDomain(), VBool(False)),
    (IntSort(), IntRange(0, 3), VInt(0)),
    (IntSort(), IntRange(2, 5), VInt(2)),
    (IntSort(), IntRange(-4, -1), VInt(-1)),
    (IntSort(), IntRange(-2, 2), VInt(0)),
    (MONEY, ScaledRange(0, 100), VScaled("INR", 2, 0)),
    (MONEY, ScaledRange(7, 9), VScaled("INR", 2, 7)),
    (MONEY, ScaledRange(-9, -7), VScaled("INR", 2, -7)),
    (EnumSort("palette"), EnumDomain(("RED", "GREEN")), VEnum("palette", "RED")),
)
FILLER_IDS = [f"{item[0]}/{item[1]}" for item in FILLERS]


@pytest.mark.parametrize("sort,domain,expected", FILLERS, ids=FILLER_IDS)
def test_the_derived_filler_is_pinned_and_the_oracles_copy_matches(
    sort: Sort, domain: Domain, expected: Value
) -> None:
    """The filler decides consequential values, so it decides actions.

    The oracle restates this rule rather than importing it, which is a
    shared-bug risk exactly when both copies are edited together.  A written-out
    table is the third statement that neither copy can move alone.
    """
    assert derived_filler(sort, domain) == expected
    field = FieldSpec(
        name="f",
        sort=sort,
        bounds=domain,
        consequentiality=Consequentiality.CONSEQUENTIAL,
        required=False,
    )
    assert field.filler() == expected
    assert semantics._filler(field) == expected
    assert value_in_domain(expected, domain)


@pytest.mark.parametrize("sort,domain,expected", FILLERS, ids=FILLER_IDS)
def test_the_oracles_domain_rules_match_productions(
    sort: Sort, domain: Domain, expected: Value
) -> None:
    del expected
    assert semantics.domain_values(sort, domain) == enumerate_domain(sort, domain)
    for value in semantics.domain_values(sort, domain):
        assert semantics.inside(value, domain) == value_in_domain(value, domain)


#  ---- what the corpus contains ---------------------------------------------


def _terms(scenario: Scenario) -> list[Term]:
    """Every term a case carries: constraints, guards and field terms."""
    case = scenario.case
    found: list[Term] = [constraint.formula for constraint in case.logical.constraints]
    found.extend(rule.guard for rule in case.program.rules)
    for action in case.program.action_terms():
        found.extend(field.term for field in action.fields)
    return found


def _walk(term: Term) -> list[Term]:
    match term:
        case Not(operand) | Neg(operand) | MulConst(_, operand) | Rescale(operand, _):
            return [term, *_walk(operand)]
        case Scale(operand, _, _):
            return [term, *_walk(operand)]
        case NAry(_, operands):
            return [term, *(found for operand in operands for found in _walk(operand))]
        case Binary(_, left, right):
            return [term, *_walk(left), *_walk(right)]
        case Ite(cond, if_true, if_false):
            return [term, *_walk(cond), *_walk(if_true), *_walk(if_false)]
        case EnumTable(scrutinee, arms):
            return [term, *_walk(scrutinee), *(f for arm in arms for f in _walk(arm.term))]
        case _:
            return [term]


NODES: list[Term] = [
    node for scenario in SCENARIOS for term in _terms(scenario) for node in _walk(term)
]


def _is_variable_equality(term: Term) -> bool:
    return (
        isinstance(term, Binary)
        and term.op is BinaryOp.EQ
        and isinstance(term.left, Leaf)
        and isinstance(term.right, Leaf)
    )


def test_the_corpus_states_equalities_between_two_variables() -> None:
    """Without one, the bounded backend's union-find is exercised only by the
    encoder's own ``FIX:`` assertions, which merge exactly two."""
    assert [node for node in NODES if _is_variable_equality(node)], (
        "no case constraint equates two variables"
    )
    chained = [
        scenario
        for scenario in SCENARIOS
        if sum(
            1
            for constraint in scenario.case.logical.constraints
            if _is_variable_equality(constraint.formula)
        )
        >= 2
    ]
    assert chained, "no case chains two variable equalities, so no class exceeds a pair"


def test_the_corpus_states_a_constraint_that_is_a_conjunction() -> None:
    """A pin and a bound inside one source constraint, which is how a rule
    states two facts at once."""
    assert [
        constraint
        for scenario in SCENARIOS
        for constraint in scenario.case.logical.constraints
        if isinstance(constraint.formula, NAry) and constraint.formula.op is NAryOp.AND
    ]


def test_the_corpus_carries_more_than_one_action_schema_shape() -> None:
    schemas = {
        scenario.case.action_schema.schema_id: scenario.case.action_schema for scenario in SCENARIOS
    }
    assert len(schemas) >= 2
    assert max(len(schema.kinds) for schema in schemas.values()) >= 3, "no schema has three kinds"
    assert (
        max(len(spec.consequential()) for schema in schemas.values() for spec in schema.kinds) >= 2
    ), "no action kind carries two consequential fields"

    shared = [
        name
        for schema in schemas.values()
        for name in {field.name for spec in schema.kinds for field in spec.consequential()}
        if sum(1 for spec in schema.kinds if any(f.name == name for f in spec.consequential())) >= 2
    ]
    assert shared, "no consequential field name is shared across two kinds"
    for schema in schemas.values():
        assert isinstance(validate_action_schema(schema), Ok), schema.schema_id


def test_the_corpus_declares_degenerate_domains() -> None:
    domains = [
        declaration.domain for scenario in SCENARIOS for declaration in scenario.case.declarations
    ]
    assert any(isinstance(d, IntRange) and d.lo == d.hi for d in domains), "no single-valued range"
    assert any(isinstance(d, IntRange) and d.hi < 0 for d in domains), "no negative-only range"
    assert any(isinstance(d, EnumDomain) and len(d.members) == 1 for d in domains), "no unit enum"


def test_the_corpus_scrutinises_a_computed_term_and_names_an_undeclared_member() -> None:
    """The shape a lowering keyed on declared members answers wrongly."""
    tables = [node for node in NODES if isinstance(node, EnumTable)]
    assert tables
    composed = [table for table in tables if not isinstance(table.scrutinee, Leaf)]
    assert composed, "every enum table scrutinises a bare variable"

    declared = {
        member
        for scenario in SCENARIOS
        for declaration in scenario.case.declarations
        if isinstance(declaration.domain, EnumDomain)
        for member in declaration.domain.members
    }
    assert {arm.member for table in composed for arm in table.arms} - declared, (
        "no table arm names a member outside every declared domain"
    )


def test_the_corpus_guards_a_rule_with_an_ite() -> None:
    guards = [rule.guard for scenario in SCENARIOS for rule in scenario.case.program.rules]
    assert any(isinstance(guard, Ite) for guard in guards)


def test_the_corpus_reaches_every_kind_of_the_richest_schema() -> None:
    """Declaring three kinds proves nothing if only two are ever produced."""
    rich = [scenario for scenario in SCENARIOS if len(scenario.case.action_schema.kinds) >= 3]
    assert rich
    #  One schema, so a union over the scenarios is a statement about it. A
    #  second rich schema would make the equality below meaningless rather
    #  than false, which is why the premise is asserted rather than assumed.
    schemas = {scenario.case.action_schema.schema_id for scenario in rich}
    assert len(schemas) == 1, sorted(schemas)

    signatures = [
        signature
        for scenario in rich
        for signature in semantics.reachable_signatures(scenario.case)
    ]
    reached = {signature[0] for signature in signatures}
    declared = {spec.kind for spec in rich[0].case.action_schema.kinds}
    assert reached == declared, f"reached {sorted(reached)} of {sorted(declared)}"
    assert [signature for signature in signatures if len(signature[1]) >= 2], (
        "no reachable action carries two consequential fields"
    )

    #  A kind whose consequential value comes from the derived filler must be
    #  the *sole* reachable action somewhere, or the filler decides nothing:
    #  while several kinds are reachable the kind disjunct of the action
    #  comparison is already true.
    sole = [
        scenario
        for scenario in rich
        if len({signature[0] for signature in semantics.reachable_signatures(scenario.case)}) == 1
    ]
    assert sole, "no rich scenario has a single reachable kind, so the filler decides nothing"
