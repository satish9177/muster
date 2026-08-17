"""Every generated case, decided three ways.

Enumeration is the judge.  For each case the truth of feasibility, of
invariance against a witness, and of sufficiency over **every** subset of the
unresolved universe is computed by brute force in
:mod:`tests.differential.semantics`, which shares no evaluator, no query
construction and no search with either backend.  Both backends are then held
against it.

That ordering matters.  Asserting the two backends against each other would
pass whenever they are wrong together, and they have one plausible way to be
wrong together: the query they are both handed comes from one encoder.  The
enumerated truth never sees a query at all, so a defect in
:mod:`muster.hinge.encode` fails here rather than hiding.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from muster.core.actions import ActionField, ConsequentialAction
from muster.core.analysis.outcomes import (
    Divergent,
    ExactReachable,
    Infeasible,
    Invariant,
    outcome_class,
)
from muster.hinge.analyze import analyze
from muster.hinge.encode import feasibility_query, invariance_query, sufficiency_query
from muster.hinge.oracle import Oracle
from muster.hinge.prepare import EngineLimits
from muster.hinge.project import ProjectedCase
from muster.solve.backend import SolverBackend
from tests.differential import semantics
from tests.differential.backends import (
    Outcome,
    assert_matches_truth,
    assert_no_inversion,
    bounded,
    compare,
    smt,
)
from tests.differential.scenarios import SCENARIOS, Scenario
from tests.differential.semantics import ActionSignature

LIMITS = EngineLimits(max_unresolved=8, reachable_action_cap=8)

IDS = [scenario.name for scenario in SCENARIOS]


def _action(case: ProjectedCase, signature: ActionSignature) -> ConsequentialAction:
    """A consequential action built from the enumerated signature, not decoded."""
    kind, fields = signature
    return ConsequentialAction(
        case.action_schema.digest(),
        kind,
        tuple(ActionField(name, value) for name, value in fields),
    )


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_feasibility_agrees_with_enumeration(scenario: Scenario) -> None:
    case = scenario.case
    comparison = compare(feasibility_query(case), f"{scenario.name}: feasibility")
    assert_no_inversion(comparison)
    assert_matches_truth(comparison, semantics.feasible(case))


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_invariance_against_every_reachable_witness_agrees_with_enumeration(
    scenario: Scenario,
) -> None:
    """One query per reachable action, so the witness is never a lucky choice."""
    case = scenario.case
    reachable = semantics.reachable_signatures(case)
    for signature in sorted(reachable, key=str):
        witness = _action(case, signature)
        query = invariance_query(case, witness)
        comparison = compare(query, f"{scenario.name}: invariance/{witness.render()}")
        assert_no_inversion(comparison)
        #  The query asks for a world whose action differs from the witness, so
        #  it is satisfiable exactly when some other action is reachable.
        assert_matches_truth(comparison, reachable != {signature})


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
def test_sufficiency_over_every_subset_agrees_with_enumeration(scenario: Scenario) -> None:
    case = scenario.case
    for fixed in semantics.subsets(scenario.unresolved()):
        query = sufficiency_query(case, fixed)
        where = f"{scenario.name}: sufficiency/{sorted(str(ref) for ref in fixed)}"
        comparison = compare(query, where)
        assert_no_inversion(comparison)
        #  Sufficiency is unsatisfiability, so the satisfiable direction is
        #  "not sufficient".
        assert_matches_truth(comparison, not semantics.sufficient(case, fixed))


@pytest.mark.parametrize("scenario", SCENARIOS, ids=IDS)
@pytest.mark.parametrize("make", [bounded, smt], ids=["reference", "solver"])
def test_the_analysis_outcome_is_the_enumerated_one(
    scenario: Scenario, make: Callable[[], SolverBackend]
) -> None:
    """The state machine, not just the queries: both backends must land on the
    same outcome class, the same action and the same reachable set."""
    backend = make()
    case = scenario.case
    record = analyze(case, Oracle(backend, case), LIMITS)
    reachable = semantics.reachable_signatures(case)

    if not reachable:
        assert isinstance(record.outcome, Infeasible), scenario.name
        return
    if len(reachable) == 1:
        assert isinstance(record.outcome, Invariant), f"{scenario.name}: {record.outcome}"
        expected = _action(case, next(iter(reachable)))
        assert record.outcome.action == expected, scenario.name
        return

    assert isinstance(record.outcome, Divergent), (
        f"{scenario.name}: {outcome_class(record.outcome)}"
    )
    assert isinstance(record.outcome.reachable, ExactReachable), scenario.name
    found = {_action(case, signature) for signature in reachable}
    assert set(record.outcome.reachable.actions) == found, scenario.name


def test_the_generated_corpus_covers_both_conclusive_answers() -> None:
    """A differential over cases that are all satisfiable proves half of it.

    Also asserts the corpus reaches every outcome class the kernel can produce
    from a conclusive backend, so a generator that quietly stopped producing
    infeasible or invariant cases fails here.
    """
    outcomes = {
        outcome_class(analyze(scenario.case, Oracle(smt(), scenario.case), LIMITS).outcome)
        for scenario in SCENARIOS
    }
    assert {"INVARIANT", "DIVERGENT", "INFEASIBLE"} <= outcomes

    answers = {
        compare(feasibility_query(scenario.case), scenario.name).conclusive()
        for scenario in SCENARIOS
    }
    assert Outcome.SATISFIABLE in answers
    assert Outcome.UNSATISFIABLE in answers
