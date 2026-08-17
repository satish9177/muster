"""Backends that fail on purpose, and the paths that must survive them.

Milestone A proved the kernel refuses a *dishonest* backend.  This proves it
refuses an *unhelpful* one, at every point in the sequence where an answer is
consumed: the injected failure walks the query index, so the feasibility query,
the invariance query, each reachable probe, the candidate-set sufficiency
query, each necessity query and each deletion query are all covered without a
test having to know which is which.

The property under test is one sentence.  Replacing any single conclusive
answer with an inconclusive one may turn a decision into ``Indeterminate``; it
may never turn it into a *different* decision, may never produce an action, and
may never produce a claim about evidence that enumeration does not support.

Nothing here lives in a production package: the architecture has no runtime use
for a backend that refuses to answer, so a fake one that shipped would be a
liability rather than a capability.
"""

from __future__ import annotations

import pytest

from muster.application.pipeline import analyse_revision
from muster.core.analysis.outcomes import (
    AnalysisOutcome,
    Indeterminate,
    IndeterminateReason,
    Invariant,
    outcome_class,
    proposed_action,
)
from muster.core.analysis.planning import (
    EvidenceRequested,
    PlanningIndeterminate,
    ProvenIrredundantSupport,
)
from muster.core.evidence.requests import EvidenceTarget
from muster.core.results import Err
from muster.core.values.classification import AcquisitionClass
from muster.core.values.fingerprint import SolverFingerprint
from muster.core.wire.digests import Digest
from muster.evidence.planning import Planning, plan_evidence
from muster.hinge.analyze import analyze
from muster.hinge.oracle import Oracle
from muster.hinge.prepare import EngineLimits, PrepareFailure, prepare
from muster.solve.backend import SolverBackend
from muster.solve.query import SolverQuery
from muster.solve.verdict import (
    FragmentCapabilities,
    SolverVerdict,
    Unknown,
    UnknownReason,
    Unsat,
    UnsupportedFragment,
)
from tests.differential import semantics
from tests.differential.backends import smt
from tests.differential.scenarios import SCENARIOS, Scenario
from tests.support import ravi

LIMITS = EngineLimits(max_unresolved=8, reachable_action_cap=8)
REVISION = Digest(bytes(32))
SOURCE = "SYNTHETIC_SOURCE"

FINGERPRINT = SolverFingerprint("injected", "1", 0, "INJECTED", 0)
CAPABILITIES = FragmentCapabilities(
    backend="injected",
    version="1",
    requires_finite_domains=False,
    max_enumerated_assignments=1,
)

#  A handful of shapes rather than the whole corpus: the injection walks every
#  query of each, so breadth comes from the query index, not the case count.
WANTED = {
    "definitional/DEF/derived/open",
    "count/1/threshold/open",
    "flags/none/kind/open",
    "flags/13/sum/open",
    "trio/none/joint/open",
}
INJECTION_CASES = tuple(scenario for scenario in SCENARIOS if scenario.name in WANTED)
IDS = [scenario.name for scenario in INJECTION_CASES]
MAX_INJECTED_QUERY = 12


class _AlwaysUnknown:
    """Never decides anything, and never pretends to."""

    def capabilities(self) -> FragmentCapabilities:
        return CAPABILITIES

    def fingerprint(self) -> SolverFingerprint:
        return FINGERPRINT

    def check(self, query: SolverQuery) -> SolverVerdict:
        del query
        return Unknown(UnknownReason.BACKEND_FAILURE, "injected")


class _AlwaysUnsat(_AlwaysUnknown):
    """Vacuously unsatisfiable: the shape that would read as invariance."""

    def check(self, query: SolverQuery) -> SolverVerdict:
        del query
        return Unsat(())


class _UnknownOnNthQuery:
    """Honest, except that the nth query it sees comes back inconclusive."""

    def __init__(self, honest: SolverBackend, index: int, verdict: SolverVerdict) -> None:
        self._honest = honest
        self._index = index
        self._verdict = verdict
        self.seen = 0
        self.injected = False

    def capabilities(self) -> FragmentCapabilities:
        return self._honest.capabilities()

    def fingerprint(self) -> SolverFingerprint:
        return self._honest.fingerprint()

    def check(self, query: SolverQuery) -> SolverVerdict:
        self.seen += 1
        if self.seen == self._index:
            self.injected = True
            return self._verdict
        return self._honest.check(query)


class _CapabilityRejecting:
    """Declares a fragment nothing can be asked of."""

    def capabilities(self) -> FragmentCapabilities:
        return FragmentCapabilities(
            backend="rejecting",
            version="1",
            requires_finite_domains=True,
            max_enumerated_assignments=0,
        )

    def fingerprint(self) -> SolverFingerprint:
        return FINGERPRINT

    def check(self, query: SolverQuery) -> SolverVerdict:  # pragma: no cover - never reached
        del query
        return Unknown(UnknownReason.BACKEND_FAILURE, "unreachable")


INJECTED: tuple[tuple[str, SolverVerdict], ...] = (
    ("unknown", Unknown(UnknownReason.BACKEND_FAILURE, "injected")),
    ("budget", Unknown(UnknownReason.BUDGET_EXHAUSTED, "injected")),
    ("unsupported", UnsupportedFragment("injected")),
)


def _outcome(scenario: Scenario, backend: SolverBackend) -> AnalysisOutcome:
    return analyze(scenario.case, Oracle(backend, scenario.case), LIMITS).outcome


def _plan(scenario: Scenario, backend: SolverBackend) -> Planning:
    oracle = Oracle(backend, scenario.case)
    outcome = analyze(scenario.case, oracle, LIMITS).outcome
    candidates = tuple(
        EvidenceTarget(ref, AcquisitionClass.ATTESTABLE, (SOURCE,)) for ref in scenario.unresolved()
    )
    return plan_evidence(
        oracle=oracle,
        outcome=outcome,
        unresolved=scenario.unresolved(),
        candidates=candidates,
        tenant_id="ALPHA",
        case_id="CASE",
        revision_digest=REVISION,
    )


#  ---- a backend that never decides -----------------------------------------


@pytest.mark.parametrize("scenario", INJECTION_CASES, ids=IDS)
def test_a_backend_that_never_decides_produces_no_decision(scenario: Scenario) -> None:
    outcome = _outcome(scenario, _AlwaysUnknown())
    assert isinstance(outcome, Indeterminate)
    assert outcome.reason is IndeterminateReason.BACKEND_FAILURE
    assert proposed_action(outcome) is None


@pytest.mark.parametrize("scenario", INJECTION_CASES, ids=IDS)
def test_evidence_planning_asks_for_nothing_when_nothing_was_decided(
    scenario: Scenario,
) -> None:
    """A source's cooperation is not spent on a solver limitation."""
    planning = _plan(scenario, _AlwaysUnknown())
    assert isinstance(planning.record.planning_outcome, PlanningIndeterminate)
    assert planning.record.support is None
    assert planning.necessary is None


@pytest.mark.parametrize("scenario", INJECTION_CASES, ids=IDS)
def test_a_backend_that_answers_unsatisfiable_to_everything_proposes_nothing(
    scenario: Scenario,
) -> None:
    """Vacuous unsatisfiability on an empty world set is not invariance."""
    outcome = _outcome(scenario, _AlwaysUnsat())
    assert not isinstance(outcome, Invariant)
    assert proposed_action(outcome) is None


#  ---- one inconclusive answer, anywhere in the sequence ---------------------


@pytest.mark.parametrize("scenario", INJECTION_CASES, ids=IDS)
@pytest.mark.parametrize("kind,verdict", INJECTED, ids=[name for name, _ in INJECTED])
def test_one_inconclusive_answer_never_changes_a_decision(
    scenario: Scenario, kind: str, verdict: SolverVerdict
) -> None:
    honest = _outcome(scenario, smt())
    reached = 0
    for index in range(1, MAX_INJECTED_QUERY):
        backend = _UnknownOnNthQuery(smt(), index, verdict)
        outcome = _outcome(scenario, backend)
        if not backend.injected:
            break
        reached = index
        where = f"{scenario.name}/{kind}/query {index}"
        if isinstance(outcome, Indeterminate):
            assert proposed_action(outcome) is None, where
            continue
        assert outcome_class(outcome) == outcome_class(honest), where
        assert proposed_action(outcome) == proposed_action(honest), where
    assert reached > 0, f"{scenario.name}: no query was reached to inject into"


@pytest.mark.parametrize("scenario", INJECTION_CASES, ids=IDS)
def test_an_inconclusive_answer_never_becomes_an_invariant_action(
    scenario: Scenario,
) -> None:
    """The one direction that must never be reached by accident.

    An analysis that is invariant under an injected failure must have been
    invariant honestly, because ``Invariant`` needs both a feasibility witness
    and an unsatisfiable invariance query, and one of them is not being
    supplied.
    """
    honest = _outcome(scenario, smt())
    for index in range(1, MAX_INJECTED_QUERY):
        backend = _UnknownOnNthQuery(
            smt(), index, Unknown(UnknownReason.BUDGET_EXHAUSTED, "injected")
        )
        outcome = _outcome(scenario, backend)
        if not backend.injected:
            break
        if isinstance(outcome, Invariant):
            assert isinstance(honest, Invariant), f"{scenario.name}: invariance out of nowhere"
            assert outcome.action == honest.action


@pytest.mark.parametrize("scenario", INJECTION_CASES, ids=IDS)
@pytest.mark.parametrize("kind,verdict", INJECTED, ids=[name for name, _ in INJECTED])
def test_no_injected_failure_produces_an_evidence_claim_enumeration_denies(
    scenario: Scenario, kind: str, verdict: SolverVerdict
) -> None:
    """Whatever the injection does to the planner, what comes out must be true.

    A requested set must be sufficient, and a support that calls itself proven
    must be irredundant -- both judged by enumeration rather than by the
    planner's own bookkeeping.
    """
    case = scenario.case
    for index in range(1, MAX_INJECTED_QUERY):
        backend = _UnknownOnNthQuery(smt(), index, verdict)
        planning = _plan(scenario, backend)
        if not backend.injected:
            break
        where = f"{scenario.name}/{kind}/query {index}"

        outcome = planning.record.planning_outcome
        if isinstance(outcome, EvidenceRequested):
            requested = frozenset(target.proposition for target in outcome.request.targets)
            assert semantics.sufficient(case, requested), f"{where}: requested set is insufficient"

        support = planning.record.support
        if isinstance(support, ProvenIrredundantSupport):
            members = frozenset(support.members)
            assert semantics.sufficient(case, members), f"{where}: support is not sufficient"
            for member in members:
                assert not semantics.sufficient(case, members - {member}), (
                    f"{where}: {member} is droppable, so the support is not irredundant"
                )

        if planning.necessary is not None:
            expected = set(semantics.necessary(case, scenario.unresolved()))
            #  An inconclusive necessity query drops a variable from the
            #  finding; it may never add one that is not necessary.
            assert set(planning.necessary) <= expected, where


#  ---- capability rejection, before any query is issued ---------------------


def test_a_backend_that_declares_no_budget_is_rejected_at_prepare() -> None:
    rejection = prepare(
        ravi.revision(), ravi.bundle(), _CapabilityRejecting().capabilities(), ravi.limits()
    )
    assert isinstance(rejection, Err)
    assert rejection.error.failure is PrepareFailure.UNSUPPORTED_FRAGMENT


def test_the_composition_root_fails_closed_on_a_rejecting_backend() -> None:
    """No analysis runs, so there is nothing to misread as a decision."""
    outcome = analyse_revision(
        ravi.revision(), ravi.bundle(), _CapabilityRejecting(), ravi.limits()
    )
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.UNSUPPORTED_FRAGMENT


def test_the_engine_limits_still_bound_the_case_size() -> None:
    """The size bound is the operator's, not the backend's, and still applies."""
    tight = EngineLimits(max_unresolved=0, reachable_action_cap=4)
    outcome = analyse_revision(ravi.revision(), ravi.bundle(), smt(), tight)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.UNSUPPORTED_CASE_SIZE
