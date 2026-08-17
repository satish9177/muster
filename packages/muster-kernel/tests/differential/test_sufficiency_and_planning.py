"""Sufficiency, necessity and irredundant planning, against enumeration.

Three claims are separated here because conflating them authorizes wrong
payments, and each is checked against brute force rather than against the other
backend:

* ``Sufficient(S)`` for **every** subset ``S`` of the unresolved universe;
* ``Necessary(v)`` as the derived relation ``not Sufficient(U \\ {v})`` -- and
  in particular the shape where no variable is necessary and evidence is still
  required;
* the planner's post-condition, that what it returns is sufficient and that
  dropping any member of it is not.

The last one is the interesting one.  Greedy deletion is sound because
sufficiency is monotone, but "sound given monotonicity" is an argument, and the
enumerated truth is a check.  Subset-minimality is asserted; cardinality
minimality is not, because the planner does not establish it and claiming it
would be false.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from muster.core.analysis.outcomes import Divergent
from muster.core.analysis.planning import (
    EvidenceRequested,
    ProvenIrredundantSupport,
    SufficientSupportIrredundanceUnproved,
)
from muster.core.evidence.requests import EvidenceTarget
from muster.core.values.classification import AcquisitionClass
from muster.core.wire.digests import Digest
from muster.evidence.planning import Planning, plan_evidence
from muster.hinge.analyze import analyze
from muster.hinge.oracle import Insufficient, Oracle, OracleUnknown, Sufficient
from muster.hinge.prepare import EngineLimits
from muster.solve.backend import SolverBackend
from tests.differential import semantics
from tests.differential.backends import bounded, smt
from tests.differential.scenarios import (
    DEFINITIONAL_NAME,
    FLAG_A,
    FLAG_B,
    PAYABLE,
    SCENARIOS,
    Scenario,
)

LIMITS = EngineLimits(max_unresolved=8, reachable_action_cap=8)
SOURCE = "SYNTHETIC_SOURCE"
REVISION = Digest(bytes(32))

BACKENDS: tuple[tuple[str, Callable[[], SolverBackend]], ...] = (
    ("reference", bounded),
    ("solver", smt),
)

#  Every scenario with at least one unresolved variable: a planner has nothing
#  to say about a case with nothing left to ask for.
OPEN = tuple(scenario for scenario in SCENARIOS if scenario.unresolved())
IDS = [scenario.name for scenario in OPEN]


def _targets(scenario: Scenario) -> tuple[EvidenceTarget, ...]:
    return tuple(
        EvidenceTarget(ref, AcquisitionClass.ATTESTABLE, (SOURCE,)) for ref in scenario.unresolved()
    )


def _plan(scenario: Scenario, make: Callable[[], SolverBackend]) -> tuple[Planning, Oracle]:
    case = scenario.case
    oracle = Oracle(make(), case)
    record = analyze(case, oracle, LIMITS)
    planning = plan_evidence(
        oracle=oracle,
        outcome=record.outcome,
        unresolved=scenario.unresolved(),
        candidates=_targets(scenario),
        tenant_id="ALPHA",
        case_id="CASE",
        revision_digest=REVISION,
    )
    return planning, oracle


@pytest.mark.parametrize("scenario", OPEN, ids=IDS)
@pytest.mark.parametrize("name,make", BACKENDS, ids=[name for name, _ in BACKENDS])
def test_the_oracle_answers_sufficiency_as_enumeration_does(
    scenario: Scenario, name: str, make: Callable[[], SolverBackend]
) -> None:
    oracle = Oracle(make(), scenario.case)
    for fixed in semantics.subsets(scenario.unresolved()):
        verdict = oracle.sufficiency(fixed)
        truth = semantics.sufficient(scenario.case, fixed)
        where = f"{name}/{scenario.name}/{sorted(str(ref) for ref in fixed)}"
        match verdict:
            case Sufficient():
                assert truth, f"{where}: reported sufficient where enumeration disagrees"
            case Insufficient():
                assert not truth, f"{where}: reported insufficient where enumeration disagrees"
            case OracleUnknown():
                #  Inconclusive is allowed and is never resolved by copying the
                #  other backend's answer.
                pass


@pytest.mark.parametrize("scenario", OPEN, ids=IDS)
@pytest.mark.parametrize("name,make", BACKENDS, ids=[name for name, _ in BACKENDS])
def test_necessity_is_exactly_the_derived_relation(
    scenario: Scenario, name: str, make: Callable[[], SolverBackend]
) -> None:
    """``Necessary(v)`` is ``not Sufficient(U \\ {v})`` and nothing else."""
    planning, _ = _plan(scenario, make)
    if planning.necessary is None:
        return
    expected = semantics.necessary(scenario.case, scenario.unresolved())
    assert set(planning.necessary) == set(expected), f"{name}/{scenario.name}"


@pytest.mark.parametrize("scenario", OPEN, ids=IDS)
@pytest.mark.parametrize("name,make", BACKENDS, ids=[name for name, _ in BACKENDS])
def test_a_proven_support_is_sufficient_and_irredundant_by_enumeration(
    scenario: Scenario, name: str, make: Callable[[], SolverBackend]
) -> None:
    planning, _ = _plan(scenario, make)
    support = planning.record.support
    if not isinstance(support, ProvenIrredundantSupport):
        assert support is None or isinstance(support, SufficientSupportIrredundanceUnproved)
        return

    members = frozenset(support.members)
    where = f"{name}/{scenario.name}"
    assert semantics.sufficient(scenario.case, members), f"{where}: the support is not sufficient"
    for member in members:
        assert not semantics.sufficient(scenario.case, members - {member}), (
            f"{where}: dropping {member} leaves a sufficient set, so the support is redundant"
        )
    #  A request is emitted for exactly the retained members.
    outcome = planning.record.planning_outcome
    assert isinstance(outcome, EvidenceRequested)
    assert {target.proposition for target in outcome.request.targets} == members


@pytest.mark.parametrize("scenario", OPEN, ids=IDS)
def test_both_backends_choose_the_same_support(scenario: Scenario) -> None:
    """Deletion order is canonical, so the chosen set is a function of the case."""
    first, _ = _plan(scenario, bounded)
    second, _ = _plan(scenario, smt)
    if isinstance(first.record.support, ProvenIrredundantSupport) and isinstance(
        second.record.support, ProvenIrredundantSupport
    ):
        assert first.record.support.members == second.record.support.members, scenario.name


def test_a_correlated_case_needs_evidence_although_no_variable_is_necessary() -> None:
    """The shape a per-variable relevance flag gets wrong.

    A constraint determines the third variable from the other two, so two
    different subsets are each sufficient and **no** single variable is
    necessary -- while the empty set is not sufficient and evidence is
    unmistakably required.  Only the two premises are acquirable, mirroring a
    derived conclusion no source may attest.
    """
    scenario = next(item for item in SCENARIOS if item.name == DEFINITIONAL_NAME)
    case = scenario.case
    unresolved = scenario.unresolved()
    assert len(unresolved) == 3

    assert not semantics.sufficient(case, frozenset())
    assert semantics.necessary(case, unresolved) == ()
    assert semantics.sufficient(case, frozenset({PAYABLE}))
    assert semantics.sufficient(case, frozenset({FLAG_A, FLAG_B}))

    acquirable = tuple(
        EvidenceTarget(ref, AcquisitionClass.ATTESTABLE, (SOURCE,)) for ref in (FLAG_A, FLAG_B)
    )
    for name, make in BACKENDS:
        oracle = Oracle(make(), case)
        record = analyze(case, oracle, LIMITS)
        planning = plan_evidence(
            oracle=oracle,
            outcome=record.outcome,
            unresolved=unresolved,
            candidates=acquirable,
            tenant_id="ALPHA",
            case_id="CASE",
            revision_digest=REVISION,
        )
        assert planning.necessary == (), name
        support = planning.record.support
        assert isinstance(support, ProvenIrredundantSupport), name
        assert set(support.members) == {FLAG_A, FLAG_B}, name
        assert len(support.deletion_witnesses) == len(support.members), name
        assert planning.unacquirable_unresolved == (PAYABLE,), name


def test_a_divergent_case_is_never_sufficient_on_the_empty_set() -> None:
    """Otherwise the case would have been invariant, and the two answers would
    contradict each other."""
    for scenario in OPEN:
        record = analyze(scenario.case, Oracle(smt(), scenario.case), LIMITS)
        if isinstance(record.outcome, Divergent):
            assert not semantics.sufficient(scenario.case, frozenset()), scenario.name


def test_every_branch_the_guarded_tests_skip_is_reached_by_some_scenario() -> None:
    """Three tests above return early on cases the planner says nothing about.

    That is correct -- an invariant or infeasible case has no support and no
    necessity finding -- but it means each of them asserts nothing on part of
    the corpus.  This is the check that the *other* part is not empty, so a
    corpus that drifted into all-invariant cases would fail here rather than
    passing three tests vacuously.
    """
    computed_necessity = 0
    withheld_necessity = 0
    proven = 0
    absent = 0
    for scenario in OPEN:
        planning, _ = _plan(scenario, smt)
        if planning.necessary is None:
            withheld_necessity += 1
        else:
            computed_necessity += 1
        if isinstance(planning.record.support, ProvenIrredundantSupport):
            proven += 1
        elif planning.record.support is None:
            absent += 1

    assert computed_necessity > 0, "necessity was never computed"
    assert withheld_necessity > 0, "necessity was always computed, so `None` is untested"
    assert proven > 0, "no case produced a proven irredundant support"
    assert absent > 0, "every case produced a support, so the no-support path is untested"


def test_deletion_actually_deletes_somewhere_in_the_corpus() -> None:
    """A suite in which the planner always returns the whole universe would not
    be testing deletion at all."""
    reduced = 0
    kept = 0
    for scenario in OPEN:
        planning, _ = _plan(scenario, smt)
        support = planning.record.support
        if not isinstance(support, ProvenIrredundantSupport):
            continue
        if len(support.members) < len(scenario.unresolved()):
            reduced += 1
        else:
            kept += 1
    assert reduced > 0, "no scenario had a redundant candidate to delete"
    assert kept > 0, "no scenario needed its whole candidate set"
