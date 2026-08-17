"""``decide`` -- the next imperative step, as a pure function of two artifacts.

The match is over the kernel's *planning* union rather than over the analysis
outcome, and that is deliberate.  The planner has already folded the outcome
into a total, closed answer -- invariant, infeasible, indeterminate, requested,
nothing acquirable -- so matching on it gives an exhaustive decision with no
catch-all branch and no pair of enums that can drift out of agreement.  Reading
the outcome as well, and deciding what to do when the two disagreed, would be
inventing a second planner.

One refinement sits on top of that match: an action that is invariant is only
*proposed* when the revision it came from is authorizable.  A counterfactual
rebuild produces exactly the same certificate shape and must never be offered
for authorization, so the guard is on the revision's own ``authorizability``
field rather than on a mode the caller passes alongside it.

The two time arguments have two different types, and that is load-bearing.
``now`` is an ``Instant`` -- a reading somebody took -- and ``request_ttl`` is
a ``Duration`` -- a length the operator configured.  They were both integers
once, so swapping them at a call site was a typecheck away from a deadline
somewhere in 1970.
"""

from __future__ import annotations

from muster.core.analysis.certificate import AnalysisCertificate
from muster.core.analysis.planning import (
    EvidenceRequested,
    NoActionReason,
    NoActionRequired,
    NoSufficientSetAcquirable,
    PlanningIndeterminate,
)
from muster.core.case.revision import Authorizability, CaseRevision
from muster.core.results import InvariantViolation
from muster.core.values.times import Duration, Instant
from muster.core.wire.digests import Digest
from muster.platform.orchestration.decisions import (
    Decision,
    Dispatch,
    Escalate,
    EscalationCause,
    Idle,
    Persist,
    Propose,
)


def decide(
    *,
    head_revision_digest: Digest | None,
    revision: CaseRevision,
    certificate: AnalysisCertificate,
    now: Instant,
    request_ttl: Duration,
) -> Decision:
    """What to do with this analysis, given the head it would replace."""
    if certificate.revision_semantic_digest != revision.digest():
        #  A certificate that does not cite this revision cannot speak for it.
        #  Programmer error rather than input: both come out of one pipeline
        #  call, and letting the pair diverge would publish a head whose
        #  certificate describes something else.
        raise InvariantViolation("certificate does not cite the revision it was passed with")
    if not request_ttl.is_positive():
        raise InvariantViolation(f"an evidence deadline must lie in the future: ttl={request_ttl}")

    revision_digest = revision.digest()
    unresolved = revision.unresolved()
    if head_revision_digest == revision_digest:
        #  Recomputation reached the published answer. This is the ordinary
        #  outcome of a retry that lost a compare-and-swap to a writer that
        #  had already read the same transcript, and it is a success.
        return Idle(revision_digest)

    certificate_digest = certificate.digest()
    outcome = certificate.planning.planning_outcome
    match outcome:
        case NoActionRequired(reason):
            return _nothing_requested(reason, revision, certificate_digest)
        case EvidenceRequested(request):
            #  ``after`` rather than ``+``: the deadline is an instant, the TTL
            #  is a length, and the operation that turns one into the other
            #  says which way round it goes.
            return Dispatch(request, request_ttl.after(now))
        case NoSufficientSetAcquirable(escalation):
            return Escalate(
                EscalationCause.NO_ACQUIRABLE_SUFFICIENT_SET,
                escalation.reason,
                escalation.unacquirable,
            )
        case PlanningIndeterminate(reason_text):
            return Escalate(EscalationCause.PLANNING_INDETERMINATE, reason_text, unresolved)


def _nothing_requested(
    reason: NoActionReason, revision: CaseRevision, certificate_digest: Digest
) -> Decision:
    """Nothing was asked for, and the planner said why. Three reasons, three steps."""
    revision_digest = revision.digest()
    match reason:
        case NoActionReason.ACTION_INVARIANT:
            if revision.authorizability is Authorizability.AUTHORIZABLE:
                return Propose(revision_digest, certificate_digest)
            return Persist(revision_digest, certificate_digest)
        case NoActionReason.INFEASIBLE:
            return Escalate(
                EscalationCause.INFEASIBLE, "no admissible world", revision.unresolved()
            )
        case NoActionReason.ANALYSIS_INDETERMINATE:
            #  Never read as "divergent, go and ask someone": spending a
            #  source's cooperation on a solver limitation is the wrong answer.
            return Escalate(
                EscalationCause.ANALYSIS_INDETERMINATE,
                "the analysis did not decide",
                revision.unresolved(),
            )
