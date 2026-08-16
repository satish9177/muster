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

from muster.core.analysis.worlds import World
from muster.core.evidence.requests import EvidenceRequest, HumanEscalation
from muster.core.values.symbols import SymbolRef, symbol_seq
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import NAtom, Node, NRec, NSeq, NTagged, NUnit
from muster.core.wire.shape import NONE_NODE, atoms

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
