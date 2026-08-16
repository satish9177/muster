"""Established facts and the justifications that may carry them.

``Justification`` is a sealed union of exactly two variants, and that is the
OBSERVATION → NORMATIVE barrier in the type system:

* ``AttestedBy`` -- a source said so.  Legal for OBSERVATION and RECORD only.
* ``EntailedBy`` -- the pinned policy derived it.  Required for NORMATIVE, and
  re-validated against the manifest rather than trusted as data.

A claim is not a variant here.  There is no constructor, no flag and no
"trusted" path by which a party's assertion becomes an established fact: it can
only ever become a constraint, or nothing at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.values.scalars import Value
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, Node, NRec, NSeq, NTagged
from muster.core.wire.shape import atoms, digests

TAG_ATTESTED_BY = "AttestedBy/v1"
TAG_ENTAILED_BY = "EntailedBy/v1"
TAG_ESTABLISHED_FACT = "EstablishedFact/v1"


class Modality(Enum):
    IMPLICATION = "IMPLICATION"
    DEFINITION = "DEFINITION"


class DerivationMode(Enum):
    """Which entailment check a justification claims to satisfy.

    The mode selects the check rather than describing it, because one
    materialiser with two behaviours needs two different validations: only
    ``FULL_EVALUATION`` may claim that every premise in the group is closed.
    """

    RULE_FIRED = "RULE_FIRED"
    FULL_EVALUATION = "FULL_EVALUATION"
    WITNESS_DISJUNCT = "WITNESS_DISJUNCT"


@dataclass(frozen=True, slots=True)
class AttestedBy:
    receipt_digest: Digest

    def to_node(self) -> NRec:
        return NRec(TAG_ATTESTED_BY, (self.receipt_digest.to_node(),))


@dataclass(frozen=True, slots=True)
class EntailedBy:
    manifest_digest: Digest
    modality: Modality
    derivation_mode: DerivationMode
    rule_ids: tuple[str, ...]
    premise_digests: tuple[Digest, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_ENTAILED_BY,
            (
                self.manifest_digest.to_node(),
                NAtom(self.modality.value),
                NAtom(self.derivation_mode.value),
                atoms(self.rule_ids),
                digests(self.premise_digests),
            ),
        )


type Justification = AttestedBy | EntailedBy


def justification_node(justification: Justification) -> Node:
    match justification:
        case AttestedBy():
            return NTagged("AttestedBy", justification.to_node())
        case EntailedBy():
            return NTagged("EntailedBy", justification.to_node())


@dataclass(frozen=True, slots=True)
class EstablishedFact:
    ref: SymbolRef
    value: Value
    justification: Justification

    def to_node(self) -> NRec:
        return NRec(
            TAG_ESTABLISHED_FACT,
            (self.ref.to_node(), self.value.to_node(), justification_node(self.justification)),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.ESTABLISHED_FACT, self.to_node())

    def octets(self) -> bytes:
        return encode(self.to_node())


def fact_seq(facts: tuple[EstablishedFact, ...]) -> NSeq:
    return NSeq(tuple(fact.to_node() for fact in facts))
