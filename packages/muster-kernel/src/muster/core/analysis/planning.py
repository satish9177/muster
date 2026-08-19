"""What to go and establish, and the proof that the answer is not padded.

The primary output is a **set**, never a per-variable relevance flag.  Under
correlation every member of a group can be individually droppable while the
group is jointly required -- the workforce case is exactly that shape -- and a
design that ships a boolean per variable reports "nothing matters" there and
authorizes the wrong payment.

``ProvenIrredundantSupport`` carries a deletion witness per member: a pair of
admissible worlds that agree on the rest of the support and disagree on the
action.  Without one for every retained member the result is
``SufficientSupportIrredundanceUnproved`` -- sufficient, honestly labelled, and
never described as minimal.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.analysis.worlds import World, read_world
from muster.core.evidence.requests import (
    EvidenceRequest,
    HumanEscalation,
    read_evidence_request,
    read_human_escalation,
)
from muster.core.values.symbols import SymbolRef, read_symbol_ref, symbol_seq
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import NAtom, Node, NRec, NSeq, NTagged, NUnit
from muster.core.wire.shape import (
    NONE_NODE,
    WireFailure,
    atoms,
    fail,
    read_atom,
    read_digest,
    read_option,
    read_rec,
    read_seq,
    read_tagged,
)

TAG_DELETION_WITNESS = "DeletionWitness/v1"
TAG_PROVEN_SUPPORT = "ProvenSupport/v1"
TAG_UNPROVEN_SUPPORT = "UnprovenSupport/v1"
TAG_PLANNING_RECORD = "PlanningRecord/v1"


class EscalationReason(Enum):
    NO_ACQUIRABLE_SUFFICIENT_SET = "NO_ACQUIRABLE_SUFFICIENT_SET"


class NoActionReason(Enum):
    """Why nothing was requested. A required field, never inferred from silence."""

    ACTION_INVARIANT = "ACTION_INVARIANT"
    INFEASIBLE = "INFEASIBLE"
    ANALYSIS_INDETERMINATE = "ANALYSIS_INDETERMINATE"


@dataclass(frozen=True, slots=True)
class DeletionWitness:
    """Two admissible worlds proving this member cannot be dropped."""

    member: SymbolRef
    left: World
    right: World

    def to_node(self) -> NRec:
        return NRec(
            TAG_DELETION_WITNESS,
            (self.member.to_node(), self.left.to_node(), self.right.to_node()),
        )


@dataclass(frozen=True, slots=True)
class ProvenIrredundantSupport:
    """Subset-minimal, not cardinality-minimum. The name says which."""

    members: tuple[SymbolRef, ...]
    sufficiency_handle: Digest
    deletion_witnesses: tuple[DeletionWitness, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_PROVEN_SUPPORT,
            (
                symbol_seq(self.members),
                self.sufficiency_handle.to_node(),
                NSeq(tuple(witness.to_node() for witness in self.deletion_witnesses)),
            ),
        )


@dataclass(frozen=True, slots=True)
class SufficientSupportIrredundanceUnproved:
    """Sufficient, but at least one deletion query was inconclusive.

    Treating an inconclusive deletion as "keep" would break the post-condition:
    a later deletion can make the retained variable redundant, leaving a set
    that is sufficient and not irredundant while claiming to be both.
    """

    members: tuple[SymbolRef, ...]
    inconclusive: tuple[SymbolRef, ...]
    reasons: tuple[str, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_UNPROVEN_SUPPORT,
            (symbol_seq(self.members), symbol_seq(self.inconclusive), atoms(self.reasons)),
        )


type SupportResult = ProvenIrredundantSupport | SufficientSupportIrredundanceUnproved


def support_node(support: SupportResult) -> Node:
    match support:
        case ProvenIrredundantSupport():
            return NTagged("ProvenIrredundantSupport", support.to_node())
        case SufficientSupportIrredundanceUnproved():
            return NTagged("SufficientSupportIrredundanceUnproved", support.to_node())


def read_deletion_witness(node: Node) -> DeletionWitness:
    member, left, right = read_rec(node, TAG_DELETION_WITNESS, 3)
    return DeletionWitness(read_symbol_ref(member), read_world(left), read_world(right))


def read_support(node: Node) -> SupportResult:
    """The inverse of :func:`support_node`."""
    tag, payload = read_tagged(node, "SupportResult")
    match tag:
        case "ProvenIrredundantSupport":
            members, handle, witnesses = read_rec(payload, TAG_PROVEN_SUPPORT, 3)
            return ProvenIrredundantSupport(
                members=read_seq(members, read_symbol_ref),
                sufficiency_handle=read_digest(handle),
                deletion_witnesses=read_seq(witnesses, read_deletion_witness),
            )
        case "SufficientSupportIrredundanceUnproved":
            members, inconclusive, reasons = read_rec(payload, TAG_UNPROVEN_SUPPORT, 3)
            return SufficientSupportIrredundanceUnproved(
                members=read_seq(members, read_symbol_ref),
                inconclusive=read_seq(inconclusive, read_symbol_ref),
                reasons=read_seq(reasons, read_atom),
            )
        case _:
            raise fail(
                WireFailure.UNKNOWN_VARIANT,
                "ProvenIrredundantSupport | SufficientSupportIrredundanceUnproved",
                tag,
            )


@dataclass(frozen=True, slots=True)
class NoActionRequired:
    reason: NoActionReason


@dataclass(frozen=True, slots=True)
class EvidenceRequested:
    request: EvidenceRequest


@dataclass(frozen=True, slots=True)
class NoSufficientSetAcquirable:
    escalation: HumanEscalation


@dataclass(frozen=True, slots=True)
class PlanningIndeterminate:
    reason: str


type PlanningOutcome = (
    NoActionRequired | EvidenceRequested | NoSufficientSetAcquirable | PlanningIndeterminate
)


def planning_node(outcome: PlanningOutcome) -> Node:
    match outcome:
        case NoActionRequired():
            #  The frozen variant carries no payload; the reason travels in the
            #  certificate's evidence rationale, which is a required field.
            return NTagged("NoActionRequired", NUnit())
        case EvidenceRequested(request):
            return NTagged("EvidenceRequested", request.to_node())
        case NoSufficientSetAcquirable(escalation):
            return NTagged("NoSufficientSetAcquirable", escalation.to_node())
        case PlanningIndeterminate(reason):
            return NTagged("PlanningIndeterminate", NAtom(reason))


def read_planning_outcome(
    node: Node, *, no_action_reason: NoActionReason | None
) -> PlanningOutcome:
    """The inverse of :func:`planning_node`, up to the one field it does not carry.

    ``NoActionRequired`` encodes as a payload-less variant -- the frozen shape --
    so its ``reason`` is genuinely absent from the octets and cannot be read out
    of them.  The caller supplies it instead, from the analysis outcome that
    produced it: ``Invariant`` gives ``ACTION_INVARIANT`` and ``Infeasible``
    gives ``INFEASIBLE``, which is exactly the mapping the planner applied on the
    way in.

    ``None`` means the caller's outcome explains no silence, and then this
    refuses.  The refusal matters more than it looks: re-encoding is *blind*
    here, because the reason is not in the octets -- a wrong reason round-trips
    perfectly and no digest check anywhere can see it.  So the one field a
    round-trip cannot police is the one field this will not fabricate.
    """
    tag, payload = read_tagged(node, "PlanningOutcome")
    match tag:
        case "NoActionRequired":
            if not isinstance(payload, NUnit):
                raise fail(WireFailure.UNEXPECTED_NODE, "unit", type(payload).__name__)
            if no_action_reason is None:
                raise fail(
                    WireFailure.OUT_OF_RANGE,
                    "an outcome that explains a NoActionRequired plan",
                    "a plan requesting nothing under an outcome that requests something",
                )
            return NoActionRequired(no_action_reason)
        case "EvidenceRequested":
            return EvidenceRequested(read_evidence_request(payload))
        case "NoSufficientSetAcquirable":
            return NoSufficientSetAcquirable(read_human_escalation(payload))
        case "PlanningIndeterminate":
            return PlanningIndeterminate(read_atom(payload))
        case _:
            raise fail(
                WireFailure.UNKNOWN_VARIANT,
                "NoActionRequired | EvidenceRequested | NoSufficientSetAcquirable "
                "| PlanningIndeterminate",
                tag,
            )


@dataclass(frozen=True, slots=True)
class PlanningRecord:
    planning_outcome: PlanningOutcome
    support: SupportResult | None

    def to_node(self) -> NRec:
        support = self.support
        return NRec(
            TAG_PLANNING_RECORD,
            (
                planning_node(self.planning_outcome),
                NONE_NODE if support is None else NTagged("Some", support_node(support)),
            ),
        )


def read_planning_record(node: Node, *, no_action_reason: NoActionReason | None) -> PlanningRecord:
    """The inverse of :meth:`PlanningRecord.to_node`."""
    outcome, support = read_rec(node, TAG_PLANNING_RECORD, 2)
    return PlanningRecord(
        planning_outcome=read_planning_outcome(outcome, no_action_reason=no_action_reason),
        support=read_option(support, read_support),
    )
