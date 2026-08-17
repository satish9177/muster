"""What a query must say about the enums it names.

An enum literal has no canonical index unless the query binds the enum's member
order.  Two conforming backends handed the same octets could otherwise disagree
about what ``LitEnum(party_id, RAVI)`` denotes -- or, as the Z3 lowering found,
fail to lower it at all.  So the rule is: **every enum a query mentions carries
exactly one declaration, and the order in it is the one the pinned artifacts
state.**

The rule is checked here against the *octets*, not against the walker the
encoder used to build them.  Asking ``enum_ids`` which enums a query mentions
and then checking the encoder against that answer would pass with both of them
wrong in the same way; reading the encoded query back out cannot.

The counterexample that motivated this file is in the Ravi case and is not
exotic.  ``party_id`` is the enum the payment's *recipient* is a constant of.
No case variable has that sort -- the recipient is a literal in the program --
so an encoder that collected enums from declared variables alone emitted a
query naming ``party_id`` without ever declaring it.
"""

from __future__ import annotations

import dataclasses

import pytest

from muster.core.actions import (
    ActionKindSpec,
    ActionSchema,
    Consequentiality,
    FieldSpec,
)
from muster.core.case.constraints import Constraint, StructuralDeriv
from muster.core.case.revision import canonical_constraints
from muster.core.expr.ir import Binary, BinaryOp, LitEnum
from muster.core.results import Err, Ok
from muster.core.values.scalars import VEnum
from muster.core.values.sorts import EnumDomain, EnumSort
from muster.core.wire.nodes import NAtom, NDigest, Node, NRec, NSeq, NSet, NTagged
from muster.domains.workforce.bundle import ACTION_PAY, ENUM_PARTY, FIELD_RECIPIENT
from muster.hinge.encode import (
    blocking_query,
    feasibility_query,
    invariance_query,
    sufficiency_query,
)
from muster.hinge.prepare import (
    PrepareFailure,
    declared_enum_orders,
    prepare,
)
from muster.hinge.project import ProjectedCase
from muster.solve.query import SolverQuery
from tests.differential.scenarios import SCENARIOS, Scenario
from tests.support import ravi

#  Records whose first field *is* an enum id.  ``EnumDeclaration/v1`` is
#  deliberately not among them: the declarations are the answer under test, and
#  counting them as mentions would make the check circular.
NAMES_AN_ENUM = frozenset({"VEnum/v1", "EnumSort/v1"})

IDS = [scenario.name for scenario in SCENARIOS]


def _enums_named_in(node: Node) -> set[str]:
    """Every enum id these octets name, wherever they name it."""
    found: set[str] = set()
    match node:
        case NRec(tag, fields):
            head = fields[0] if fields else None
            if tag in NAMES_AN_ENUM and isinstance(head, NAtom):
                found.add(head.text)
            for field in fields:
                found |= _enums_named_in(field)
        case NTagged(_, payload):
            found |= _enums_named_in(payload)
        case NSeq(items):
            for item in items:
                found |= _enums_named_in(item)
        case NSet(members):
            for member in members:
                found |= _enums_named_in(member)
        case NAtom() | NDigest() | _:
            pass
    return found


def _mentioned(query: SolverQuery) -> set[str]:
    """The enums the query's declarations and assertions name."""
    found: set[str] = set()
    for declaration in query.declarations:
        found |= _enums_named_in(declaration.to_node())
    for assertion in query.assertions:
        found |= _enums_named_in(assertion.to_node())
    return found


def _stated_orders(case: ProjectedCase) -> dict[str, tuple[str, ...]]:
    """The member orders the case's own artifacts state, written out here.

    A second transcription of the rule rather than a call to the production
    resolver, so an encoder reading the wrong artifact is caught rather than
    confirmed.
    """
    orders: dict[str, tuple[str, ...]] = {}
    for declaration in case.declarations:
        if isinstance(declaration.sort, EnumSort) and isinstance(declaration.domain, EnumDomain):
            orders[declaration.sort.enum_id] = declaration.domain.members
    schema = case.action_schema
    orders[schema.kind_enum_id()] = schema.kind_members()
    for kind in schema.kinds:
        for spec in kind.fields:
            if isinstance(spec.sort, EnumSort) and isinstance(spec.bounds, EnumDomain):
                orders[spec.sort.enum_id] = spec.bounds.members
    return orders


def _queries(case: ProjectedCase) -> list[tuple[str, SolverQuery]]:
    """One of every shape the kernel ever issues, for one case."""
    unresolved = case.unresolved()
    built = [
        ("feasibility", feasibility_query(case)),
        ("sufficiency/none", sufficiency_query(case, frozenset())),
    ]
    if unresolved:
        built.append(("sufficiency/one", sufficiency_query(case, frozenset({unresolved[0]}))))
        built.append(("sufficiency/all", sufficiency_query(case, frozenset(unresolved))))
    return built


def _action_queries(case: ProjectedCase) -> list[tuple[str, SolverQuery]]:
    """The shapes that need a concrete action, built from a real feasible world."""
    from muster.core.actions import consequential_of
    from muster.policy.program import evaluate_program
    from muster.solve.reference.bounded import BoundedEnumerationBackend
    from muster.solve.verdict import Sat

    verdict = BoundedEnumerationBackend(200_000).check(feasibility_query(case))
    if not isinstance(verdict, Sat):
        return []
    world = {var.ref: value for var, value in verdict.model.items()}
    built = evaluate_program(case.program, case.action_schema, world)
    if not isinstance(built, Ok):  # pragma: no cover - a feasible world evaluates
        return []
    action = consequential_of(case.action_schema, built.value)
    return [
        ("invariance", invariance_query(case, action)),
        ("blocking", blocking_query(case, (action,))),
    ]


#  ---- the contract, over every generated case ----------------------------


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_every_enum_a_query_mentions_is_declared_exactly_once(scenario: Scenario) -> None:
    """The whole rule, over the systematic corpus: mentioned == declared."""
    for where, query in _queries(scenario.case):
        declared = [enum.enum_id for enum in query.enums]
        assert len(declared) == len(set(declared)), (
            f"{scenario.name}/{where}: duplicate declaration"
        )
        assert set(declared) == _mentioned(query), f"{scenario.name}/{where}"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_every_declaration_carries_the_order_the_artifacts_state(scenario: Scenario) -> None:
    """The order is read off the pinned artifacts, not invented or sorted."""
    stated = _stated_orders(scenario.case)
    for where, query in _queries(scenario.case):
        for enum in query.enums:
            assert enum.enum_id in stated, f"{scenario.name}/{where}: {enum.enum_id}"
            assert enum.members == stated[enum.enum_id], f"{scenario.name}/{where}"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_the_declarations_are_in_canonical_order(scenario: Scenario) -> None:
    """Two runs of one case produce the same octets, so the order is fixed."""
    for _, query in _queries(scenario.case):
        assert list(query.enums) == sorted(query.enums, key=lambda enum: enum.enum_id)


def test_the_corpus_actually_contains_a_literal_only_enum() -> None:
    """Otherwise the checks above would pass on a corpus that never tests them.

    ``hold_reason`` reaches a query only through the ``HOLD`` action's reason
    field -- a literal in the program and a filler in the schema.  No case
    variable carries that sort, so an encoder collecting enums from declared
    variables alone would omit it.
    """
    found = False
    for scenario in SCENARIOS:
        declared_sorts = {
            declaration.sort.enum_id
            for declaration in scenario.case.declarations
            if isinstance(declaration.sort, EnumSort)
        }
        for _, query in _queries(scenario.case):
            literal_only = {enum.enum_id for enum in query.enums} - declared_sorts
            #  The kind enum is induced by the schema rather than declared by a
            #  variable too, so it is excluded to keep the claim sharp.
            literal_only.discard(scenario.case.action_schema.kind_enum_id())
            if literal_only:
                found = True
    assert found, "no generated query declares an enum reached only through a literal"


#  ---- the counterexample this correction was made for --------------------


def test_the_ravi_queries_declare_the_recipient_enum() -> None:
    """``party_id`` is mentioned by the action comparison and by nothing else.

    The recipient of the payment is ``LitEnum(party_id, RAVI)``: a constant in
    the program, of an enum no declared symbol in the case has.  This is the
    query that used to name it without declaring it.
    """
    case = ravi.analysis().projected
    action_shaped = _action_queries(case)
    assert action_shaped, "the Ravi case is feasible and must produce an action"

    declared_sorts = {
        declaration.sort.enum_id
        for declaration in case.declarations
        if isinstance(declaration.sort, EnumSort)
    }
    assert ENUM_PARTY not in declared_sorts

    for where, query in action_shaped:
        assert ENUM_PARTY in _mentioned(query), where
        declarations = {enum.enum_id: enum.members for enum in query.enums}
        assert declarations.get(ENUM_PARTY) == (ravi.RAVI,), where


def test_the_ravi_feasibility_query_declares_no_enum_it_does_not_mention() -> None:
    """The rule has two directions, and this is the one over-declaring breaks.

    Feasibility asks whether an admissible world exists; it never builds an
    action, so no enum reaches it.  A query carrying a declaration for an enum
    its octets never name binds a schema fact it does not use, and its digest
    then moves for reasons the query itself cannot show.
    """
    query = feasibility_query(ravi.analysis().projected)
    assert _mentioned(query) == set()
    assert query.enums == ()


#  ---- fail-closed, at admission rather than by exception ------------------


def _ghost_constraint() -> Constraint:
    """A well-typed constraint naming an enum no pinned artifact declares."""
    ghost = VEnum("ghost_enum", "NOWHERE")
    return Constraint(
        "GHOST",
        Binary(BinaryOp.EQ, LitEnum(ghost), LitEnum(ghost)),
        StructuralDeriv(ravi.revision().construction_digest),
    )


def test_a_case_naming_an_enum_nobody_ordered_is_refused_at_admission() -> None:
    """Malformed case input gets a typed rejection, not an exception.

    Nothing typechecks a case constraint, so an enum literal can reach the
    encoder through the constraint channel without any artifact stating that
    enum's member order.  The encoder could not make such a query
    self-contained, so the case never becomes one.
    """
    revision = ravi.revision()
    attacked = dataclasses.replace(
        revision,
        constraints=canonical_constraints((*revision.constraints, _ghost_constraint())),
    )
    outcome = prepare(attacked, ravi.bundle(), ravi.backend().capabilities(), ravi.limits())
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.UNDECLARED_ENUM_ORDER
    assert "ghost_enum" in outcome.error.detail


def _conflicting_schema() -> ActionSchema:
    """Two kinds whose fields give ``party_id`` two different member orders."""
    original = ravi.bundle().action_schema
    pay = original.kind_spec(ACTION_PAY)
    assert pay is not None
    disagreeing = ActionKindSpec(
        kind="WITHHOLD",
        fields=(
            FieldSpec(
                name=FIELD_RECIPIENT,
                sort=EnumSort(ENUM_PARTY),
                #  Same enum, different membership. Whichever artifact a loop
                #  read first would decide what index ``RAVI`` has.
                bounds=EnumDomain(("SUP-9",)),
                consequentiality=Consequentiality.CONSEQUENTIAL,
                required=True,
            ),
        ),
    )
    return dataclasses.replace(original, kinds=(pay, disagreeing))


def test_two_artifacts_disagreeing_about_one_enum_are_refused() -> None:
    """Resolved by refusal, never by traversal order."""
    bundle = dataclasses.replace(ravi.bundle(), action_schema=_conflicting_schema())
    outcome = prepare(ravi.revision(), bundle, ravi.backend().capabilities(), ravi.limits())
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.CONFLICTING_ENUM_ORDER
    assert ENUM_PARTY in outcome.error.detail


def test_the_order_resolver_refuses_a_conflict_directly() -> None:
    """The same rule at the unit it is implemented in."""
    outcome = declared_enum_orders((), _conflicting_schema())
    assert isinstance(outcome, Err)
    assert outcome.error.enum_id == ENUM_PARTY
    assert {outcome.error.declared, outcome.error.conflicting} == {(ravi.RAVI,), ("SUP-9",)}


def test_the_order_resolver_accepts_agreement_between_two_artifacts() -> None:
    """Two artifacts stating the *same* order is agreement, not a conflict."""
    schema = ravi.bundle().action_schema
    outcome = declared_enum_orders(
        ((EnumSort(ENUM_PARTY), EnumDomain((ravi.RAVI,))),),
        schema,
    )
    assert isinstance(outcome, Ok)
    assert outcome.value[ENUM_PARTY] == (ravi.RAVI,)
    assert outcome.value[schema.kind_enum_id()] == schema.kind_members()
