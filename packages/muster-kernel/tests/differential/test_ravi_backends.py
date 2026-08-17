"""The workforce case, decided by both backends and by brute force.

This is the case the milestone-A exit criterion is written about, so it is the
one where a disagreement would matter most.  It is also the first case in the
suite whose action is a bounded sum over six days, whose payment amount is a
scaled quantity, and whose universe contains a normative conclusion tied to its
premises by a definitional constraint -- the shape the synthetic scenarios
imitate.

Enumeration is affordable here because only three variables are unresolved, so
the whole world set is 2 x 1441 x 2.  That makes the flagship case subject to
exactly the same judge as everything else rather than to the backends' mutual
agreement.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import cache

import pytest

from muster.application.case_file import load_case_file
from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.actions import ActionField, ConsequentialAction
from muster.core.analysis.outcomes import Divergent, ExactReachable, Invariant
from muster.core.analysis.planning import EvidenceRequested, ProvenIrredundantSupport
from muster.core.results import Ok
from muster.core.values.scalars import VScaled
from muster.core.values.symbols import SymbolRef
from muster.domains.workforce.bundle import on_site_duration, present_on_site, shift_payable
from muster.hinge.encode import sufficiency_query
from muster.hinge.project import ProjectedCase
from muster.solve.backend import SolverBackend
from tests.conftest import FIXTURES
from tests.differential import semantics
from tests.differential.backends import (
    assert_matches_truth,
    assert_no_inversion,
    bounded,
    compare,
    smt,
)
from tests.support import ravi

WEEKDAY_TOTAL = VScaled("INR", 2, 425_000)
FULL_WEEK_TOTAL = VScaled("INR", 2, 510_000)

PRESENCE = present_on_site(ravi.RAVI, ravi.SATURDAY)
DURATION = on_site_duration(ravi.RAVI, ravi.SATURDAY)
PAYABLE = shift_payable(ravi.RAVI, ravi.SATURDAY)


def _analysis(case_file: str, make: Callable[[], SolverBackend]) -> CaseAnalysis:
    loaded = load_case_file(FIXTURES / case_file)
    assert isinstance(loaded, Ok), loaded
    case = loaded.value
    bundle = ravi.bundle()
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    built = rebuild(
        case.rebuild_inputs(bundle.digest(), prefix.digest()),
        case.construction,
        case.entries,
        bundle,
        case.authorization_context,
    )
    assert isinstance(built, Ok), built
    produced = analyse_revision(built.value, bundle, make(), ravi.limits())
    assert isinstance(produced, Ok), produced
    return produced.value


@cache
def divergent_by_solver() -> CaseAnalysis:
    return _analysis("ravi-saturday.json", smt)


@cache
def invariant_by_solver() -> CaseAnalysis:
    return _analysis("ravi-saturday-attested.json", smt)


@cache
def invariant_by_reference() -> CaseAnalysis:
    return _analysis("ravi-saturday-attested.json", bounded)


def _amounts(actions: tuple[ConsequentialAction, ...]) -> set[VScaled]:
    return {
        field.value
        for action in actions
        for field in action.consequential_fields
        if field.name == "amount" and isinstance(field.value, VScaled)
    }


def _enumerated(case: ProjectedCase) -> set[ConsequentialAction]:
    return {
        ConsequentialAction(
            case.action_schema.digest(),
            kind,
            tuple(ActionField(name, value) for name, value in fields),
        )
        for kind, fields in semantics.reachable_signatures(case)
    }


#  ---- the divergent revision ---------------------------------------------


def test_the_solver_also_finds_the_case_divergent() -> None:
    outcome = divergent_by_solver().kernel.outcome
    assert isinstance(outcome, Divergent)
    assert isinstance(outcome.reachable, ExactReachable)
    assert _amounts(outcome.reachable.actions) == {WEEKDAY_TOTAL, FULL_WEEK_TOTAL}


def test_both_backends_reach_the_same_actions_as_enumeration() -> None:
    """The flagship case, judged by brute force over its whole world set."""
    reference = ravi.analysis().kernel.outcome
    solver = divergent_by_solver().kernel.outcome
    assert isinstance(reference, Divergent)
    assert isinstance(solver, Divergent)
    assert isinstance(reference.reachable, ExactReachable)
    assert isinstance(solver.reachable, ExactReachable)

    enumerated = _enumerated(divergent_by_solver().projected)
    assert set(reference.reachable.actions) == enumerated
    assert set(solver.reachable.actions) == enumerated


def test_the_solver_plans_the_same_two_observations() -> None:
    outcome = divergent_by_solver().planning.record.planning_outcome
    assert isinstance(outcome, EvidenceRequested)
    assert {target.proposition for target in outcome.request.targets} == {PRESENCE, DURATION}


def test_the_solver_agrees_that_no_variable_is_individually_necessary() -> None:
    """The milestone-A exit criterion, confirmed by an independent decider."""
    assert divergent_by_solver().planning.necessary == ()
    assert ravi.analysis().planning.necessary == ()
    assert semantics.necessary(divergent_by_solver().projected, (PRESENCE, DURATION, PAYABLE)) == ()


def test_the_solver_proves_the_same_irredundant_support() -> None:
    support = divergent_by_solver().planning.record.support
    reference = ravi.analysis().planning.record.support
    assert isinstance(support, ProvenIrredundantSupport)
    assert isinstance(reference, ProvenIrredundantSupport)
    assert support.members == reference.members
    assert set(support.members) == {PRESENCE, DURATION}


@pytest.mark.parametrize(
    "fixed",
    [frozenset(), frozenset({PRESENCE}), frozenset({DURATION}), frozenset({PAYABLE})],
    ids=["nothing", "presence", "duration", "payable"],
)
def test_sufficiency_over_the_real_case_agrees_with_enumeration(
    fixed: frozenset[SymbolRef],
) -> None:
    case = divergent_by_solver().projected
    comparison = compare(
        sufficiency_query(case, fixed), f"ravi/{sorted(str(ref) for ref in fixed)}"
    )
    assert_no_inversion(comparison)
    assert_matches_truth(comparison, not semantics.sufficient(case, fixed))


#  ---- the lower-bound revision -------------------------------------------


def test_the_solver_also_finds_the_attested_case_invariant() -> None:
    """The duration is never established, and the payment is settled anyway."""
    outcome = invariant_by_solver().kernel.outcome
    reference = invariant_by_reference().kernel.outcome
    assert isinstance(outcome, Invariant)
    assert isinstance(reference, Invariant)
    assert outcome.action == reference.action
    assert _amounts((outcome.action,)) == {FULL_WEEK_TOTAL}
    assert DURATION in set(invariant_by_solver().projected.unresolved())


def test_the_attested_case_has_one_reachable_action_by_enumeration() -> None:
    """Invariance is exactly "one action over a non-empty world set", and the
    world set here is 1441 durations wide."""
    case = invariant_by_solver().projected
    enumerated = _enumerated(case)
    assert len(enumerated) == 1
    outcome = invariant_by_solver().kernel.outcome
    assert isinstance(outcome, Invariant)
    assert outcome.action in enumerated
    assert semantics.feasible(case)


def test_the_invariant_outcome_still_carries_a_feasibility_witness() -> None:
    outcome = invariant_by_solver().kernel.outcome
    assert isinstance(outcome, Invariant)
    assert outcome.witness.bindings
    assert outcome.invariance_query_digest in invariant_by_solver().kernel.query_digests


#  ---- what the record says answered it -----------------------------------


def test_the_record_names_whichever_backend_answered() -> None:
    """Two backends, two fingerprints, one outcome.

    The fingerprint is the only thing that may differ between the two records
    for the same case, and it must differ: a certificate that could not say
    what answered it would not be replayable.
    """
    solver = divergent_by_solver().kernel
    reference = ravi.analysis().kernel
    assert solver.fingerprint != reference.fingerprint
    assert solver.fingerprint.backend == "z3"
    assert reference.fingerprint.backend == "reference-bounded"
    assert solver.logical_case_digest == reference.logical_case_digest
