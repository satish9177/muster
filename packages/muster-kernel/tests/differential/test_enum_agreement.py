"""The enum declarations, against both backends and against the truth.

Making a query self-contained is only worth something if the two backends read
the declaration the same way and still answer the same question.  Three claims,
and they are different claims:

* **The declaration reaches the lowering.**  A declared member keeps its
  declared index in the SMT encoding, so the octets decide what integer
  ``RAVI`` is rather than the order the adapter happened to meet it in.  A
  declaration nothing reads would be decoration.
* **The two backends still agree.**  Every query that carries an enum
  declaration is put to both, and two conclusive answers must be the same
  answer -- the rule that must never be relaxed.
* **Both still agree with enumeration.**  The oracle in
  :mod:`tests.differential.semantics` shares no query construction with either
  backend, so it is the thing that catches a declaration that changed the
  *meaning* of a query rather than only its octets.
"""

from __future__ import annotations

import pytest

from muster.core.actions import consequential_of
from muster.core.results import Ok
from muster.core.values.sorts import EnumDomain, EnumSort
from muster.hinge.encode import (
    blocking_query,
    feasibility_query,
    invariance_query,
    sufficiency_query,
)
from muster.hinge.project import ProjectedCase
from muster.policy.program import evaluate_program
from muster.solve.query import SolverQuery
from muster.solve.verdict import Sat
from muster.solve.z3.lowering import LoweredQuery, UnsupportedConstruct, lower
from tests.differential import semantics
from tests.differential.backends import (
    assert_matches_truth,
    assert_no_inversion,
    bounded,
    compare,
)
from tests.differential.scenarios import SCENARIOS, Scenario

IDS = [scenario.name for scenario in SCENARIOS]

#  Enumerating a two-world query is quadratic in the case's world space, so the
#  truth cross-check runs where that is affordable. How much of the corpus it
#  reached is asserted below.
QUERY_ENUMERATION_BUDGET = 8_192


def _queries(case: ProjectedCase) -> list[tuple[str, SolverQuery]]:
    """Every shape the kernel issues for one case, including the action ones."""
    unresolved = case.unresolved()
    feasibility = feasibility_query(case)
    built = [
        ("feasibility", feasibility),
        ("sufficiency/none", sufficiency_query(case, frozenset())),
    ]
    if unresolved:
        built.append(("sufficiency/all", sufficiency_query(case, frozenset(unresolved))))

    verdict = bounded().check(feasibility)
    if isinstance(verdict, Sat):
        world = {var.ref: value for var, value in verdict.model.items()}
        evaluated = evaluate_program(case.program, case.action_schema, world)
        if isinstance(evaluated, Ok):
            action = consequential_of(case.action_schema, evaluated.value)
            built.append(("invariance", invariance_query(case, action)))
            built.append(("blocking", blocking_query(case, (action,))))
    return built


def _declaring(case: ProjectedCase) -> list[tuple[str, SolverQuery]]:
    return [(where, query) for where, query in _queries(case) if query.enums]


def _assignments(query: SolverQuery) -> int:
    space = 1
    for declaration in query.declarations:
        space *= len(semantics.domain_values(declaration.sort, declaration.domain))
        if space > QUERY_ENUMERATION_BUDGET:
            return space
    return space


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_a_declared_member_keeps_its_declared_index_in_the_lowering(
    scenario: Scenario,
) -> None:
    """The declaration is what decides the integer, not the traversal order."""
    for where, query in _declaring(scenario.case):
        lowered = lower(query)
        assert isinstance(lowered, LoweredQuery), f"{scenario.name}/{where}: {lowered}"
        for enum in query.enums:
            used = lowered.enum_members(enum.enum_id)
            assert used is not None, f"{scenario.name}/{where}: {enum.enum_id} was not lowered"
            #  A member met only as a literal is appended after the declared
            #  ones, so the declared prefix is the claim -- and it is the whole
            #  claim, because equality over an enum needs nothing more.
            assert used[: len(enum.members)] == enum.members, f"{scenario.name}/{where}"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_the_two_backends_agree_on_every_query_that_declares_an_enum(
    scenario: Scenario,
) -> None:
    for where, query in _declaring(scenario.case):
        assert_no_inversion(compare(query, f"{scenario.name}/{where}"))


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_both_backends_match_enumeration_on_a_query_that_declares_an_enum(
    scenario: Scenario,
) -> None:
    """The oracle shares no query construction with either backend."""
    for where, query in _declaring(scenario.case):
        if _assignments(query) > QUERY_ENUMERATION_BUDGET:
            continue
        truth = semantics.query_truth(query)
        assert_matches_truth(compare(query, f"{scenario.name}/{where}"), truth)


def test_the_corpus_reaches_these_checks_at_all() -> None:
    """A budget or a filter that excluded everything would prove nothing."""
    declaring = 0
    enumerated = 0
    literal_only = 0
    for scenario in SCENARIOS:
        declared_sorts = {
            declaration.sort.enum_id
            for declaration in scenario.case.declarations
            if isinstance(declaration.sort, EnumSort)
        }
        for _, query in _declaring(scenario.case):
            declaring += 1
            if _assignments(query) <= QUERY_ENUMERATION_BUDGET:
                enumerated += 1
            if {enum.enum_id for enum in query.enums} - declared_sorts:
                literal_only += 1
    assert declaring > 100, declaring
    assert enumerated > 50, enumerated
    assert literal_only > 50, literal_only


def test_a_declaration_naming_no_member_is_unrepresentable() -> None:
    """The empty declaration cannot be built, so no backend has to handle one."""
    from muster.core.results import InvariantViolation
    from muster.solve.query import EnumDeclaration

    with pytest.raises(InvariantViolation, match="declares no members"):
        EnumDeclaration("empty", ())


def test_a_declaration_repeating_a_member_is_refused_by_the_lowering() -> None:
    """An ambiguous numbering is refused rather than resolved by first-match."""
    import dataclasses

    from muster.solve.query import EnumDeclaration

    scenario = next(item for item in SCENARIOS if _declaring(item.case))
    _, query = _declaring(scenario.case)[0]
    enum = query.enums[0]
    repeated = EnumDeclaration(enum.enum_id, (*enum.members, enum.members[0]))
    attacked = dataclasses.replace(
        query, enums=(repeated, *(item for item in query.enums if item is not enum))
    )
    assert isinstance(lower(attacked), UnsupportedConstruct)


def test_the_enum_shape_declares_a_domain_it_does_not_exhaust() -> None:
    """The corpus keeps a case whose literals leave the declared domain.

    ``composed`` scrutinises a computed term that can reach a member no
    declared domain admits.  The declaration binds the *declared* order and
    says nothing about members that are only literals, which is exactly the
    distinction a declaration derived from literals would erase.
    """
    from tests.differential.scenarios import COLOUR_UNDECLARED, ENUM_COLOUR

    scenario = next(item for item in SCENARIOS if item.name.startswith("composed/"))
    declared = {
        declaration.sort.enum_id: declaration.domain
        for declaration in scenario.case.declarations
        if isinstance(declaration.sort, EnumSort)
    }
    domain = declared[ENUM_COLOUR]
    assert isinstance(domain, EnumDomain)
    assert COLOUR_UNDECLARED not in domain.members

    for _, query in _declaring(scenario.case):
        for enum in query.enums:
            if enum.enum_id == ENUM_COLOUR:
                assert enum.members == domain.members
                assert COLOUR_UNDECLARED not in enum.members


def test_every_query_shape_is_represented() -> None:
    """Feasibility alone would leave the action comparison untested."""
    shapes = {where for scenario in SCENARIOS for where, _ in _queries(scenario.case)}
    assert shapes == {
        "feasibility",
        "sufficiency/none",
        "sufficiency/all",
        "invariance",
        "blocking",
    }


def test_only_action_shaped_queries_need_the_kind_enum() -> None:
    """A feasibility query builds no action, so it names no kind.

    Stated as a corpus fact rather than as a docstring: if a future encoder
    started emitting the kind enumeration unconditionally, the declarations
    would stop being a function of what the query says.
    """
    seen = False
    for scenario in SCENARIOS:
        kind_enum = scenario.case.action_schema.kind_enum_id()
        for where, query in _queries(scenario.case):
            declared = {enum.enum_id for enum in query.enums}
            if where == "feasibility":
                assert kind_enum not in declared, scenario.name
                seen = True
            elif where in ("invariance", "blocking"):
                assert kind_enum in declared, f"{scenario.name}/{where}"
    assert seen
