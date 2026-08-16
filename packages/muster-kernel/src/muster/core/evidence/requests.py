"""What the system asks for, and what it says when it cannot ask.

An evidence request names propositions and the source classes permitted to
attest them.  It never names a normative predicate: those are DERIVED, so no
target can exist for one, and the planner has no way to construct one.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.results import InvariantViolation
from muster.core.values.classification import AcquisitionClass
from muster.core.values.symbols import SymbolRef, symbol_seq
from muster.core.wire.codec import canonical_set
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NRec, NSeq

TAG_EVIDENCE_TARGET = "EvidenceTarget/v1"
TAG_EVIDENCE_REQUEST = "EvidenceRequest/v1"
TAG_HUMAN_ESCALATION = "HumanEscalation/v1"


@dataclass(frozen=True, slots=True)
class EvidenceTarget:
    proposition: SymbolRef
    acquisition_class: AcquisitionClass
    permitted_source_classes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.permitted_source_classes:
            raise InvariantViolation(f"no source may attest {self.proposition}")
        if self.acquisition_class is not AcquisitionClass.ATTESTABLE:
            #  A derived proposition has no source to ask.  Constructing a
            #  target for one is a defect, not a request that will be refused
            #  later.
            raise InvariantViolation(f"{self.proposition} is DERIVED and cannot be requested")

    def to_node(self) -> NRec:
        return NRec(
            TAG_EVIDENCE_TARGET,
            (
                self.proposition.to_node(),
                NAtom(self.acquisition_class.value),
                canonical_set(NAtom(source) for source in self.permitted_source_classes),
            ),
        )


@dataclass(frozen=True, slots=True)
class EvidenceRequest:
    tenant_id: str
    case_id: str
    revision_semantic_digest: Digest
    targets: tuple[EvidenceTarget, ...]

    def __post_init__(self) -> None:
        if not self.targets:
            raise InvariantViolation("an evidence request names at least one target")
        propositions = [target.proposition for target in self.targets]
        if len(set(propositions)) != len(propositions):
            raise InvariantViolation("evidence targets are unique by proposition")

    def to_node(self) -> NRec:
        return NRec(
            TAG_EVIDENCE_REQUEST,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                self.revision_semantic_digest.to_node(),
                NSeq(tuple(target.to_node() for target in self.targets)),
            ),
        )

    def digest(self) -> Digest:
        """The request id every reply must carry, binding the reply to this revision."""
        return digest_node(DigestKind.EVIDENCE_REQUEST, self.to_node())


@dataclass(frozen=True, slots=True)
class HumanEscalation:
    """The case cannot be settled by anything MUSTER is able to ask for."""

    reason: str
    unacquirable: tuple[SymbolRef, ...]

    def __post_init__(self) -> None:
        if not self.unacquirable:
            raise InvariantViolation("an escalation names what could not be acquired")

    def to_node(self) -> NRec:
        return NRec(TAG_HUMAN_ESCALATION, (NAtom(self.reason), symbol_seq(self.unacquirable)))
