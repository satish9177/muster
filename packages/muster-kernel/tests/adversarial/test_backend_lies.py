"""What happens when the backend is wrong, unhelpful, or dishonest.

Every fail-closed path in the kernel is reached through the solver port, and the
only backend in the tree is honest -- so without a stub that lies, the whole
defensive half of the oracle and the analysis state machine is dead weight under
test.  Each backend below embodies one specific way an answer can be bad, and
each test asserts the kernel refuses rather than believes.

The sharpest is ``_FabricatingBackend``: it returns a model that is total and in
domain and simply does not satisfy the constraints.  Nothing about its *shape*
is wrong.  If the oracle trusted it, a fabricated world would become a reachable
action and, with one more step, an invariant one.
"""

from __future__ import annotations

import dataclasses

import pytest

from muster.core.analysis.outcomes import (
    Divergent,
    Indeterminate,
    IndeterminateReason,
    Infeasible,
    Invariant,
    KernelAnalysisRecord,
    NotComputed,
    NotComputedReason,
    TruncatedReachable,
    proposed_action,
)
from muster.core.analysis.planning import (
    EvidenceRequested,
    NoActionReason,
    NoActionRequired,
    PlanningIndeterminate,
    ProvenIrredundantSupport,
    SufficientSupportIrredundanceUnproved,
)
from muster.core.values.fingerprint import SolverFingerprint
from muster.core.values.scalars import VBool, VInt
from muster.evidence.planning import plan_evidence
from muster.hinge.analyze import analyze
from muster.hinge.oracle import Oracle
from muster.hinge.project import ProjectedCase
from muster.solve.backend import SolverBackend
from muster.solve.query import QueryKind, QueryVar, SolverQuery, WorldSide
from muster.solve.reference.bounded import BoundedEnumerationBackend
from muster.solve.verdict import (
    FragmentCapabilities,
    Sat,
    SolverModel,
    SolverVerdict,
    Unknown,
    UnknownReason,
    Unsat,
    UnsupportedFragment,
)
from tests.support import ravi

CAPABILITIES = FragmentCapabilities(
    backend="stub",
    version="1",
    requires_finite_domains=True,
    max_enumerated_assignments=1000,
)
FINGERPRINT = SolverFingerprint("stub", "1", 0, "STUB", 1000)


class _Stub:
    """A backend that answers every query the same way."""

    def __init__(self, verdict: SolverVerdict) -> None:
        self._verdict = verdict

    def capabilities(self) -> FragmentCapabilities:
        return CAPABILITIES

    def fingerprint(self) -> SolverFingerprint:
        return FINGERPRINT

    def check(self, query: SolverQuery) -> SolverVerdict:
        del query
        return self._verdict


class _PartialModelBackend(_Stub):
    """Satisfiable, but the model leaves one declared variable unbound."""

    def __init__(self, honest: BoundedEnumerationBackend) -> None:
        super().__init__(Unsat(()))
        self._honest = honest

    def check(self, query: SolverQuery) -> SolverVerdict:
        verdict = self._honest.check(query)
        if isinstance(verdict, Sat) and verdict.model:
            trimmed = dict(verdict.model)
            trimmed.pop(next(iter(trimmed)))
            return Sat(trimmed)
        return verdict


class _OutOfDomainBackend(_Stub):
    """Total, but one value is outside the domain the query declared."""

    def __init__(self, honest: BoundedEnumerationBackend) -> None:
        super().__init__(Unsat(()))
        self._honest = honest

    def check(self, query: SolverQuery) -> SolverVerdict:
        verdict = self._honest.check(query)
        if not isinstance(verdict, Sat):
            return verdict
        model: SolverModel = dict(verdict.model)
        for var, value in model.items():
            if isinstance(value, VInt):
                model[var] = VInt(999_999)
                return Sat(model)
        return verdict


class _ContradictsEstablishedBackend(_Stub):
    """Total and in domain, but it disagrees with an established fact."""

    @classmethod
    def against(cls, case: ProjectedCase) -> _ContradictsEstablishedBackend:
        return cls(ravi.backend(), case)

    def __init__(self, honest: BoundedEnumerationBackend, case: ProjectedCase) -> None:
        super().__init__(Unsat(()))
        self._honest = honest
        self._known = case.logical.assignment()

    def check(self, query: SolverQuery) -> SolverVerdict:
        verdict = self._honest.check(query)
        if not isinstance(verdict, Sat):
            return verdict
        model: SolverModel = dict(verdict.model)
        for ref, value in self._known.items():
            if isinstance(value, VBool):
                model[QueryVar(WorldSide.SINGLE, ref)] = VBool(not value.value)
                return Sat(model)
        return verdict


class _FabricatingBackend(_Stub):
    """Total, in domain, consistent with K -- and violating the constraints."""

    def __init__(self, case: ProjectedCase) -> None:
        super().__init__(Unsat(()))
        self._case = case

    def check(self, query: SolverQuery) -> SolverVerdict:
        known = self._case.logical.assignment()
        model: SolverModel = {}
        for declaration in self._case.declarations:
            established = known.get(declaration.ref)
            #  Presence true and duration zero satisfies every declared domain
            #  and contradicts the definition constraint tying them together.
            value = (
                established
                if established is not None
                else (VBool(True) if declaration.sort.__class__.__name__ == "BoolSort" else VInt(0))
            )
            model[QueryVar(WorldSide.SINGLE, declaration.ref)] = value
        del query
        return Sat(model)


def _analysed(backend: SolverBackend) -> KernelAnalysisRecord:
    projected = ravi.analysis().projected
    return analyze(projected, Oracle(backend, projected), ravi.limits())


#  ---- a model whose shape is wrong is never used -------------------------


@pytest.mark.parametrize(
    "make_backend",
    [
        lambda _case: _PartialModelBackend(ravi.backend()),
        lambda _case: _OutOfDomainBackend(ravi.backend()),
        _ContradictsEstablishedBackend.against,
        _FabricatingBackend,
    ],
    ids=["partial", "out-of-domain", "contradicts-K", "fabricated"],
)
def test_a_bad_model_is_indeterminate_and_never_a_decision(make_backend: object) -> None:
    projected = ravi.analysis().projected
    backend = make_backend(projected)  # type: ignore[operator]
    record = analyze(projected, Oracle(backend, projected), ravi.limits())

    assert isinstance(record.outcome, Indeterminate)
    assert record.outcome.reason is IndeterminateReason.MODEL_NOT_TOTAL
    assert proposed_action(record.outcome) is None


#  ---- every unhelpful answer maps to exactly one public outcome ----------


def test_an_unknown_answer_is_indeterminate_not_permissive() -> None:
    record = _analysed(_Stub(Unknown(UnknownReason.BUDGET_EXHAUSTED, "budget")))
    assert isinstance(record.outcome, Indeterminate)
    assert record.outcome.reason is IndeterminateReason.BUDGET_EXHAUSTED


def test_a_backend_failure_is_indeterminate() -> None:
    record = _analysed(_Stub(Unknown(UnknownReason.BACKEND_FAILURE, "crash")))
    assert isinstance(record.outcome, Indeterminate)
    assert record.outcome.reason is IndeterminateReason.BACKEND_FAILURE


def test_an_unsupported_fragment_is_indeterminate() -> None:
    record = _analysed(_Stub(UnsupportedFragment("nonlinear")))
    assert isinstance(record.outcome, Indeterminate)
    assert record.outcome.reason is IndeterminateReason.UNSUPPORTED_FRAGMENT


def test_an_unsatisfiable_feasibility_query_is_infeasible_and_proposes_nothing() -> None:
    record = _analysed(_Stub(Unsat(("C:C-DOM:x", "C:C-ENT:y"))))
    assert isinstance(record.outcome, Infeasible)
    assert record.outcome.contributing == ("C:C-DOM:x", "C:C-ENT:y")
    assert proposed_action(record.outcome) is None


#  ---- planning never spends a source's cooperation on a solver limit -----


@pytest.mark.parametrize(
    "verdict",
    [
        Unknown(UnknownReason.BUDGET_EXHAUSTED, "budget"),
        UnsupportedFragment("nonlinear"),
        Unsat(("C:C-DOM:x",)),
    ],
    ids=["unknown", "unsupported", "infeasible"],
)
def test_planning_requests_nothing_when_the_analysis_did_not_decide(
    verdict: SolverVerdict,
) -> None:
    projected = ravi.analysis().projected
    oracle = Oracle(_Stub(verdict), projected)
    record = analyze(projected, oracle, ravi.limits())
    planning = plan_evidence(
        oracle=oracle,
        outcome=record.outcome,
        unresolved=projected.unresolved(),
        candidates=ravi.analysis().acquirable,
        tenant_id="ALPHA",
        case_id="CASE",
        revision_digest=ravi.revision().digest(),
    )
    assert not isinstance(planning.record.planning_outcome, EvidenceRequested)
    assert isinstance(planning.record.planning_outcome, PlanningIndeterminate | NoActionRequired)
    assert planning.record.support is None
    assert planning.necessary is None


def test_an_infeasible_case_says_why_nothing_was_requested() -> None:
    projected = ravi.analysis().projected
    oracle = Oracle(_Stub(Unsat(("C:C-DOM:x",))), projected)
    record = analyze(projected, oracle, ravi.limits())
    planning = plan_evidence(
        oracle=oracle,
        outcome=record.outcome,
        unresolved=projected.unresolved(),
        candidates=ravi.analysis().acquirable,
        tenant_id="ALPHA",
        case_id="CASE",
        revision_digest=ravi.revision().digest(),
    )
    outcome = planning.record.planning_outcome
    assert isinstance(outcome, NoActionRequired)
    assert outcome.reason is NoActionReason.INFEASIBLE


#  ---- an inconclusive deletion may not be reported as irredundance -------


class _InconclusiveDeletionBackend:
    """Honest, except that one sufficiency query comes back Unknown."""

    def __init__(self, honest: BoundedEnumerationBackend) -> None:
        self._honest = honest
        self._sufficiency_seen = 0

    def capabilities(self) -> FragmentCapabilities:
        return self._honest.capabilities()

    def fingerprint(self) -> SolverFingerprint:
        return self._honest.fingerprint()

    def check(self, query: SolverQuery) -> SolverVerdict:
        if query.kind is QueryKind.SUFFICIENCY:
            self._sufficiency_seen += 1
            #  The first deletion query in the minimisation loop, after the
            #  candidate-set and necessity queries have gone through honestly.
            if self._sufficiency_seen == 5:
                return Unknown(UnknownReason.BUDGET_EXHAUSTED, "injected")
        return self._honest.check(query)


def test_an_inconclusive_deletion_is_never_reported_as_irredundant() -> None:
    """Treating "inconclusive" as "droppable" would claim a post-condition
    that was never established."""
    projected = ravi.analysis().projected
    backend = _InconclusiveDeletionBackend(ravi.backend())
    oracle = Oracle(backend, projected)
    record = analyze(projected, oracle, ravi.limits())
    assert isinstance(record.outcome, Divergent)

    planning = plan_evidence(
        oracle=oracle,
        outcome=record.outcome,
        unresolved=projected.unresolved(),
        candidates=ravi.analysis().acquirable,
        tenant_id="ALPHA",
        case_id="CASE",
        revision_digest=ravi.revision().digest(),
    )
    support = planning.record.support
    assert not isinstance(support, ProvenIrredundantSupport)
    assert isinstance(support, SufficientSupportIrredundanceUnproved)
    assert support.inconclusive
    assert set(support.inconclusive) <= set(support.members)


#  ---- the cap + 1 probe distinguishes exact from truncated ---------------


def test_a_cap_below_the_reachable_count_reports_truncated_not_exact() -> None:
    projected = ravi.analysis().projected
    tight = dataclasses.replace(ravi.limits(), reachable_action_cap=1)
    record = analyze(projected, Oracle(ravi.backend(), projected), tight)
    assert isinstance(record.outcome, Divergent)
    reachable = record.outcome.reachable
    assert isinstance(reachable, TruncatedReachable)
    assert reachable.cap == 1
    assert len(reachable.sample) == 1


def test_a_cap_at_the_reachable_count_reports_exact() -> None:
    from muster.core.analysis.outcomes import ExactReachable

    projected = ravi.analysis().projected
    exact = dataclasses.replace(ravi.limits(), reachable_action_cap=2)
    record = analyze(projected, Oracle(ravi.backend(), projected), exact)
    assert isinstance(record.outcome, Divergent)
    assert isinstance(record.outcome.reachable, ExactReachable)
    assert len(record.outcome.reachable.actions) == 2


def test_a_backend_that_cannot_enumerate_reports_not_computed_not_a_smaller_set() -> None:
    """An explanation that could not be produced is labelled, never trimmed."""

    class _FailsOnlyTheProbe:
        def __init__(self, honest: BoundedEnumerationBackend) -> None:
            self._honest = honest
            self._feasibility_seen = 0

        def capabilities(self) -> FragmentCapabilities:
            return self._honest.capabilities()

        def fingerprint(self) -> SolverFingerprint:
            return self._honest.fingerprint()

        def check(self, query: SolverQuery) -> SolverVerdict:
            if query.kind is QueryKind.FEASIBILITY:
                self._feasibility_seen += 1
                if self._feasibility_seen > 1:
                    return Unknown(UnknownReason.BUDGET_EXHAUSTED, "probe")
            return self._honest.check(query)

    projected = ravi.analysis().projected
    record = analyze(
        projected,
        Oracle(_FailsOnlyTheProbe(ravi.backend()), projected),
        ravi.limits(),
    )
    assert isinstance(record.outcome, Divergent)
    assert isinstance(record.outcome.reachable, NotComputed)
    assert record.outcome.reachable.reason is NotComputedReason.BUDGET_EXHAUSTED


#  ---- the record is a function of its inputs -----------------------------


def test_analysis_repeats_exactly_because_the_oracle_holds_no_state() -> None:
    from muster.core.wire.codec import encode

    projected = ravi.analysis().projected
    oracle = Oracle(ravi.backend(), projected)
    first = analyze(projected, oracle, ravi.limits())
    again = analyze(projected, oracle, ravi.limits())
    assert encode(first.to_node()) == encode(again.to_node())
    assert first.query_digests == again.query_digests


def test_an_invariant_outcome_is_impossible_without_a_feasibility_witness() -> None:
    """Vacuous unsatisfiability on an empty world set must not read as invariance."""
    projected = ravi.analysis().projected
    record = analyze(projected, Oracle(_Stub(Unsat(())), projected), ravi.limits())
    assert not isinstance(record.outcome, Invariant)
