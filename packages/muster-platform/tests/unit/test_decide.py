"""The pure orchestrator, against real kernel artifacts and no mocks at all.

Every input here is produced by running the real pipeline over the real
fixture.  Nothing is stubbed, patched or faked, which is the milestone's own
exit criterion for this module and also the only way the tests are worth
anything: a mocked ``AnalysisCertificate`` proves that ``decide`` matches the
shape somebody imagined, not the shape the kernel produces.
"""

from __future__ import annotations

from dataclasses import fields, replace
from pathlib import Path

import pytest

import muster.platform.orchestration.decide
import muster.platform.orchestration.decisions
import muster.platform.orchestration.status
from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.analysis.outcomes import Divergent, Invariant
from muster.core.case.revision import Authorizability, RebuildInputs, RebuildMode
from muster.core.results import InvariantViolation, Ok
from muster.core.values.times import Duration
from muster.core.wire.digests import Digest
from muster.platform.orchestration.decide import decide
from muster.platform.orchestration.decisions import (
    Decision,
    Dispatch,
    Escalate,
    EscalationCause,
    Idle,
    Persist,
    Propose,
    decision_class,
)
from support import ravi

TENANT = "tenant-decide"
CASE = "case-decide"


def _analysis(*, attested: bool, mode: RebuildMode = RebuildMode.OPERATIONAL) -> CaseAnalysis:
    case = ravi.ravi(TENANT, CASE, attested=attested)
    bundle = ravi.registry().load_by_digest(
        _resolved(case.policy_id, case.as_of),
    )
    assert isinstance(bundle, Ok), bundle
    prefix = transcript_prefix(TENANT, CASE, case.entries)
    inputs = RebuildInputs(
        tenant_id=TENANT,
        case_id=CASE,
        construction_digest=case.construction.digest(),
        transcript_prefix_digest=prefix.digest(),
        bundle_manifest_digest=bundle.value.digest(),
        as_of=case.as_of,
        mode=mode,
        authorization_context_digest=case.authorization_context.digest(),
    )
    revision = rebuild(
        inputs, case.construction, case.entries, bundle.value, case.authorization_context
    )
    assert isinstance(revision, Ok), revision
    analysed = analyse_revision(
        revision.value, bundle.value, ravi.backend(), ravi.configuration().limits
    )
    assert isinstance(analysed, Ok), analysed
    return analysed.value


def _resolved(policy_id: str, as_of: int) -> Digest:
    resolved = ravi.registry().resolve(policy_id, as_of)
    assert isinstance(resolved, Ok), resolved
    return resolved.value


def _decide(analysis: CaseAnalysis, *, head: Digest | None, now: int = ravi.NOW) -> Decision:
    return decide(
        head_revision_digest=head,
        revision=analysis.revision,
        certificate=analysis.certificate,
        now=now,
        request_ttl=ravi.ONE_HOUR,
    )


def test_a_divergent_case_with_an_acquirable_set_is_dispatched() -> None:
    """The Ravi case as milestone A left it: divergent, two targets, ask for them."""
    analysis = _analysis(attested=False)
    assert isinstance(analysis.kernel.outcome, Divergent)

    decision = _decide(analysis, head=None)

    assert isinstance(decision, Dispatch)
    assert decision.deadline == ravi.ONE_HOUR.after(ravi.NOW)
    #  The request the planner built, not one the orchestrator assembled.
    assert decision.request.revision_semantic_digest == analysis.revision.digest()
    assert len(decision.request.targets) == 2


def test_an_invariant_authorizable_case_is_proposed_and_carries_only_digests() -> None:
    analysis = _analysis(attested=True)
    assert isinstance(analysis.kernel.outcome, Invariant)

    decision = _decide(analysis, head=None)

    assert isinstance(decision, Propose)
    assert decision.revision_digest == analysis.revision.digest()
    assert decision.certificate_digest == analysis.certificate.digest()
    #  Two digests and nothing else. An instruction to pay is not representable.
    assert {field.name for field in fields(decision)} == {
        "revision_digest",
        "certificate_digest",
    }


def test_an_invariant_counterfactual_case_is_recorded_and_never_proposed() -> None:
    """The guard that makes ``Persist`` a real decision rather than a spare one.

    A counterfactual rebuild reaches exactly the same planning outcome as an
    operational one -- the action is invariant either way -- and the *only*
    thing separating "offer this for authorization" from "write it down" is the
    revision's own authorizability. Reading the mode instead would put the
    guard on a field a caller supplies rather than on one ``rebuild`` derived.
    """
    analysis = _analysis(attested=True, mode=RebuildMode.COUNTERFACTUAL)
    assert analysis.revision.authorizability is Authorizability.NEVER_AUTHORIZABLE
    assert isinstance(analysis.kernel.outcome, Invariant)

    decision = _decide(analysis, head=None)

    assert isinstance(decision, Persist)
    assert decision.revision_digest == analysis.revision.digest()


def test_recomputing_the_published_revision_is_idle() -> None:
    """A retry that loses the swap to a writer with the same transcript."""
    analysis = _analysis(attested=False)
    decision = _decide(analysis, head=analysis.revision.digest())
    assert isinstance(decision, Idle)
    assert decision.revision_digest == analysis.revision.digest()


def test_the_same_inputs_and_the_same_clock_reading_decide_identically() -> None:
    """Determinism of the shell, stated as a test rather than as a claim."""
    analysis = _analysis(attested=False)
    first = _decide(analysis, head=None, now=ravi.NOW)
    again = _decide(analysis, head=None, now=ravi.NOW)
    assert first == again


def test_only_the_clock_reading_moves_the_deadline() -> None:
    """``now`` is an argument because it changes the answer, and only this way."""
    analysis = _analysis(attested=False)
    first = _decide(analysis, head=None, now=ravi.NOW)
    later = _decide(analysis, head=None, now=ravi.NOW + 1)

    assert isinstance(first, Dispatch)
    assert isinstance(later, Dispatch)
    assert later.deadline == first.deadline + 1
    assert later.request == first.request


def test_a_certificate_that_does_not_cite_the_revision_is_refused() -> None:
    """Two artifacts from one pipeline call. Letting them diverge is a defect."""
    analysis = _analysis(attested=False)
    other = _analysis(attested=True)
    with pytest.raises(InvariantViolation):
        decide(
            head_revision_digest=None,
            revision=analysis.revision,
            certificate=other.certificate,
            now=ravi.NOW,
            request_ttl=ravi.ONE_HOUR,
        )


def test_a_deadline_that_is_not_in_the_future_is_refused() -> None:
    """Zero is the only unusable TTL that can be built; the rest are unbuildable.

    ``Duration`` refuses a negative count at construction, so the old
    parametrisation over ``-1`` and ``-ONE_HOUR`` no longer describes an input
    ``decide`` can receive. The guard stays, because zero still reaches it.
    """
    analysis = _analysis(attested=False)
    with pytest.raises(InvariantViolation):
        decide(
            head_revision_digest=None,
            revision=analysis.revision,
            certificate=analysis.certificate,
            now=ravi.NOW,
            request_ttl=Duration(0),
        )


@pytest.mark.parametrize("microseconds", [-1, -3_600_000_000])
def test_a_negative_ttl_cannot_be_constructed_at_all(microseconds: int) -> None:
    with pytest.raises(InvariantViolation):
        Duration(microseconds)


def test_swapping_the_reading_and_the_ttl_is_refused_rather_than_computed() -> None:
    """The confusion the two types exist to prevent, at the call site.

    ``now + ttl`` is commutative, so when both were ``int`` a call that had the
    two the wrong way round produced *the same number* and no error anywhere:
    "one hour after the reading" and "one reading after the hour" were the same
    expression. The defect that hides behind that is not the sum, it is that a
    configured instant and a configured length were interchangeable everywhere,
    so a policy holding ``evidence_request_ttl = <an epoch timestamp>`` gave
    every case a deadline in 2081 and typechecked.

    Now each argument has a type that refuses the other, statically and here.
    """
    analysis = _analysis(attested=False)
    correct = _decide(analysis, head=None, now=ravi.NOW)
    assert isinstance(correct, Dispatch)
    assert correct.deadline == ravi.ONE_HOUR.after(ravi.NOW)

    #  An instant offered as a TTL: it has no length to apply.
    with pytest.raises(AttributeError):
        decide(
            head_revision_digest=None,
            revision=analysis.revision,
            certificate=analysis.certificate,
            now=ravi.NOW,
            request_ttl=ravi.NOW,  # type: ignore[arg-type]
        )

    #  A length offered as a reading: there is nothing to date it from.
    with pytest.raises(TypeError):
        decide(
            head_revision_digest=None,
            revision=analysis.revision,
            certificate=analysis.certificate,
            now=ravi.ONE_HOUR,  # type: ignore[arg-type]
            request_ttl=ravi.ONE_HOUR,
        )

    assert int not in Duration.__mro__


def test_an_escalation_names_what_could_not_be_acquired() -> None:
    """Nothing acquirable: the human is told which variables, not just that it failed.

    Built by removing the sources that could attest the two open observations,
    which is what "no acquirable sufficient set" is -- a property of the pinned
    schema, not a state a test can assert into existence.
    """
    analysis = _analysis(attested=False)
    stripped = _without_acquirable_targets(analysis)

    decision = _decide(stripped, head=None)

    assert isinstance(decision, Escalate)
    assert decision.cause is EscalationCause.NO_ACQUIRABLE_SUFFICIENT_SET
    assert decision.unresolved == stripped.revision.unresolved()
    assert decision.unresolved


def _without_acquirable_targets(analysis: CaseAnalysis) -> CaseAnalysis:
    """Re-plan the same revision with an empty candidate set.

    Uses the kernel's own planner rather than hand-building a record, so the
    planning outcome is one the kernel really produces.
    """
    from muster.core.analysis.planning import NoSufficientSetAcquirable
    from muster.evidence.planning import plan_evidence
    from muster.hinge.oracle import Oracle

    oracle = Oracle(ravi.backend(), analysis.projected)
    planning = plan_evidence(
        oracle=oracle,
        outcome=analysis.kernel.outcome,
        unresolved=analysis.projected.unresolved(),
        candidates=(),
        tenant_id=analysis.revision.tenant_id,
        case_id=analysis.revision.case_id,
        revision_digest=analysis.revision.digest(),
    )
    assert isinstance(planning.record.planning_outcome, NoSufficientSetAcquirable)
    certificate = replace(analysis.certificate, planning=planning.record)
    return replace(analysis, planning=planning, certificate=certificate)


def test_every_decision_variant_reports_its_own_name() -> None:
    """A report renders the variant, never ``repr``, so the two cannot drift."""
    analysis = _analysis(attested=False)
    assert decision_class(_decide(analysis, head=None)) == "Dispatch"
    assert decision_class(_decide(analysis, head=analysis.revision.digest())) == "Idle"


def test_every_escalation_cause_has_a_producer() -> None:
    """A closed enum is only closed if every member is reachable.

    ``EVIDENCE_TIMEOUT`` used to sit here with a comment saying the status
    projection produced it.  The status projection produces a ``CaseStatus``
    and has never constructed an ``Escalate``, so the member was a name for a
    condition that no code path could ever attach it to -- which is the same
    defect as a column nothing writes, and it reads as documentation of
    behaviour that does not exist.

    Checked against the source of ``decide`` rather than by exercising each
    branch, because two of the four need a hand-built planning outcome to
    reach and the claim being made is about reachability, not about behaviour.
    """
    source = Path(muster.platform.orchestration.decide.__file__).read_text(encoding="utf-8") + Path(
        muster.platform.orchestration.decisions.__file__
    ).read_text(encoding="utf-8")
    constructed = {
        member for member in EscalationCause if f"EscalationCause.{member.name}" in source
    }
    assert constructed == set(EscalationCause), (
        f"no producer for: {sorted(member.name for member in set(EscalationCause) - constructed)}"
    )
    assert not any(member.name == "EVIDENCE_TIMEOUT" for member in EscalationCause)


def test_the_status_projection_declares_no_escalation_cause() -> None:
    """It reports a status. It has never named a cause, and must not start.

    The other half of the deletion: the vocabulary is gone from the enum, and
    the module the removed comment credited with producing it does not import
    the enum at all.
    """
    text = Path(muster.platform.orchestration.status.__file__).read_text(encoding="utf-8")
    assert "EscalationCause" not in text
    assert "EVIDENCE_TIMEOUT" not in text
