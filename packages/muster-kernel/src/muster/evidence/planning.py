"""Deciding what to go and establish.

Three questions, kept apart because conflating them authorizes wrong payments:

* **Is the action already determined?**  Only this licenses "stop asking".
* **Is a variable unavoidable?**  ``not Sufficient(U \\ {v})``.  Reported, never
  used as the primary output.
* **What should we acquire?**  An irredundant sufficient set drawn from the
  variables a source could actually attest.

The trap the second question sets is the whole reason the third exists.  Under
correlation every member of a group can be individually droppable while the
group is jointly required: in the workforce case *no* unresolved variable is
necessary, yet the empty set is not sufficient and evidence is unmistakably
required.  A per-variable relevance flag reports "nothing matters" there.

Deletion is sound because sufficiency is monotone, and it is honest because an
inconclusive deletion aborts the claim.  Treating "inconclusive" as "keep" would
break the post-condition: a later deletion can make the retained variable
redundant, leaving a set that is sufficient and not irredundant while claiming
to be both.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.analysis.outcomes import AnalysisOutcome, Divergent, Indeterminate, Invariant
from muster.core.analysis.outcomes import Infeasible as InfeasibleOutcome
from muster.core.analysis.planning import (
    DeletionWitness,
    EvidenceRequested,
    NoActionReason,
    NoActionRequired,
    NoSufficientSetAcquirable,
    PlanningIndeterminate,
    PlanningRecord,
    ProvenIrredundantSupport,
    SufficientSupportIrredundanceUnproved,
    SupportResult,
)
from muster.core.evidence.requests import EvidenceRequest, EvidenceTarget, HumanEscalation
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import canonical_order, encode
from muster.core.wire.digests import Digest
from muster.hinge.oracle import Insufficient, Oracle, OracleUnknown, Sufficient

ESCALATION_NO_ACQUIRABLE_SUFFICIENT_SET = "NO_ACQUIRABLE_SUFFICIENT_SET"
ESCALATION_INDETERMINATE_SUFFICIENCY = "INDETERMINATE_SUFFICIENCY"


@dataclass(frozen=True, slots=True)
class Planning:
    """The committed planning record, and the findings that explain it.

    ``necessary`` is a derived finding rather than a certificate field: the
    frozen record does not carry it, and inventing a field for it would put a
    number in an audited artifact that nothing else validates.  ``None`` means
    it was not computed -- which is different from "no variable is necessary",
    and a report that conflates the two says something false.
    """

    record: PlanningRecord
    necessary: tuple[SymbolRef, ...] | None
    unacquirable_unresolved: tuple[SymbolRef, ...]


def plan_evidence(
    *,
    oracle: Oracle,
    outcome: AnalysisOutcome,
    unresolved: tuple[SymbolRef, ...],
    candidates: tuple[EvidenceTarget, ...],
    tenant_id: str,
    case_id: str,
    revision_digest: Digest,
) -> Planning:
    """Turn an analysis outcome into a request, an escalation, or a reasoned silence."""
    acquirable = tuple(target for target in candidates if target.proposition in set(unresolved))
    unacquirable = tuple(
        ref for ref in unresolved if ref not in {target.proposition for target in acquirable}
    )

    match outcome:
        case Invariant():
            #  Nothing is requested, and the certificate says why. "Why not" is
            #  a required field, never inferred from an empty request.
            return Planning(
                PlanningRecord(NoActionRequired(NoActionReason.ACTION_INVARIANT), None),
                None,
                unacquirable,
            )
        case InfeasibleOutcome():
            return Planning(
                PlanningRecord(NoActionRequired(NoActionReason.INFEASIBLE), None),
                None,
                unacquirable,
            )
        case Indeterminate(reason):
            #  Spending a source's cooperation on a solver limitation is wrong,
            #  so an indeterminate analysis asks for nothing.
            return Planning(
                PlanningRecord(PlanningIndeterminate(reason.value), None), None, unacquirable
            )
        case Divergent():
            pass

    candidate_refs = frozenset(target.proposition for target in acquirable)
    if not candidate_refs:
        #  Nothing can be asked for, so the case escalates whatever the
        #  necessity of each variable turns out to be. Computing it would
        #  spend |U| self-composed queries to change no decision.
        return Planning(
            PlanningRecord(
                NoSufficientSetAcquirable(
                    HumanEscalation(ESCALATION_NO_ACQUIRABLE_SUFFICIENT_SET, unresolved)
                ),
                None,
            ),
            None,
            unacquirable,
        )

    necessary = _necessary(oracle, unresolved)

    verdict = oracle.sufficiency(candidate_refs)
    match verdict:
        case OracleUnknown(reason, _, _):
            return Planning(
                PlanningRecord(PlanningIndeterminate(reason.value), None), necessary, unacquirable
            )
        case Insufficient():
            #  The policy is closed and the case is decidable in principle, but
            #  nothing MUSTER may ask for settles it. That is a human's problem,
            #  and the escalation names exactly what is missing.
            return Planning(
                PlanningRecord(
                    NoSufficientSetAcquirable(
                        HumanEscalation(ESCALATION_NO_ACQUIRABLE_SUFFICIENT_SET, unresolved)
                    ),
                    None,
                ),
                necessary,
                unacquirable,
            )
        case Sufficient(handle):
            record = _requested(
                oracle=oracle,
                candidates=candidate_refs,
                handle=handle,
                acquirable=acquirable,
                tenant_id=tenant_id,
                case_id=case_id,
                revision_digest=revision_digest,
            )
            return Planning(record, necessary, unacquirable)


def _requested(
    *,
    oracle: Oracle,
    candidates: frozenset[SymbolRef],
    handle: Digest,
    acquirable: tuple[EvidenceTarget, ...],
    tenant_id: str,
    case_id: str,
    revision_digest: Digest,
) -> PlanningRecord:
    """Minimise the acquirable set and turn what survives into a request.

    Returns the committed record only; the derived findings that travel beside
    it are the caller's, which keeps this function about one thing.
    """
    support = _minimise(oracle, candidates, handle)
    members = set(support.members)
    targets = tuple(target for target in acquirable if target.proposition in members)
    request = EvidenceRequest(tenant_id, case_id, revision_digest, targets)
    return PlanningRecord(EvidenceRequested(request), support)


def _necessary(oracle: Oracle, unresolved: tuple[SymbolRef, ...]) -> tuple[SymbolRef, ...]:
    """``Necessary(v)`` for each unresolved variable: one query each.

    Reported so a reader can see the shape of the case -- in particular the
    shape where nothing is individually necessary and evidence is still required.
    """
    universe = frozenset(unresolved)
    found: list[SymbolRef] = []
    for ref in _deletion_order(unresolved):
        verdict = oracle.sufficiency(universe - {ref})
        if isinstance(verdict, Insufficient):
            found.append(ref)
    return tuple(found)


def _minimise(oracle: Oracle, candidates: frozenset[SymbolRef], handle: Digest) -> SupportResult:
    """Greedy deletion in canonical order over a sufficient candidate set."""
    retained = set(candidates)
    witnesses: dict[SymbolRef, DeletionWitness] = {}
    inconclusive: list[SymbolRef] = []
    reasons: list[str] = []

    for ref in _deletion_order(tuple(candidates)):
        verdict = oracle.sufficiency(frozenset(retained - {ref}))
        match verdict:
            case Sufficient():
                retained.discard(ref)
                witnesses.pop(ref, None)
            case Insufficient(left, right, _):
                #  Monotonicity makes this witness valid for every later,
                #  smaller retained set as well: a pair agreeing on a larger
                #  fixed set agrees on any subset of it.
                witnesses[ref] = DeletionWitness(ref, left, right)
            case OracleUnknown(reason, _, _):
                inconclusive.append(ref)
                reasons.append(reason.value)

    members = canonical_order(retained, lambda item: item.to_node())
    if inconclusive:
        return SufficientSupportIrredundanceUnproved(
            members,
            canonical_order(inconclusive, lambda item: item.to_node()),
            tuple(sorted(set(reasons))),
        )
    return ProvenIrredundantSupport(
        members,
        handle,
        tuple(witnesses[ref] for ref in members if ref in witnesses),
    )


def _deletion_order(refs: tuple[SymbolRef, ...]) -> tuple[SymbolRef, ...]:
    """Canonical and lexical.

    The selected support is therefore *not* invariant under renaming, and the
    design says so rather than claiming a symmetry it does not have.
    """
    return tuple(sorted(refs, key=lambda ref: encode(ref.to_node())))
