"""Constraints, their derivations, and recorded non-effects.

A constraint is a boolean term plus the derivation that produced it.  One term
type covers bounds, equalities, enum membership and definitional constraints, so
no domain gets its own hole in the model.

The derivation is not decoration.  It is what a certificate reader uses to tell
a structural domain bound from a policy entailment from a ratified presumption,
and it is what the layer-flow check reads to decide whether a constraint was
entitled to mention a normative variable at all.

``NonEffect`` records what *did not* happen and why: a self-serving claim that
produced no constraint leaves a trace saying so, rather than silence that could
equally mean the rule never ran.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.case.facts import Modality
from muster.core.expr.terms import Term, term_node
from muster.core.results import InvariantViolation
from muster.core.wire.digests import Digest, DigestKind, digest_node, digest_node_of
from muster.core.wire.nodes import NAtom, NInt, Node, NRec, NSeq, NTagged
from muster.core.wire.shape import atoms, option_node

TAG_STRUCTURAL_DERIV = "StructuralDeriv/v1"
TAG_ATTESTED_RELATION_DERIV = "AttestedRelationDeriv/v1"
TAG_POLICY_ENTAILMENT_DERIV = "PolicyEntailmentDeriv/v1"
TAG_CONSTRAINT = "Constraint/v1"
TAG_NON_EFFECT = "NonEffect/v1"

MAX_LABEL_OCTETS = 100


@dataclass(frozen=True, slots=True)
class StructuralDeriv:
    """The declared domain of a variable, restated as a constraint."""

    predicate_schema_digest: Digest

    def to_node(self) -> NRec:
        return NRec(TAG_STRUCTURAL_DERIV, (self.predicate_schema_digest.to_node(),))


@dataclass(frozen=True, slots=True)
class AttestedRelationDeriv:
    """A bound or membership an authorized source attested."""

    rule_version: int
    receipt_digest: Digest

    def to_node(self) -> NRec:
        return NRec(
            TAG_ATTESTED_RELATION_DERIV, (NInt(self.rule_version), self.receipt_digest.to_node())
        )


@dataclass(frozen=True, slots=True)
class PolicyEntailmentDeriv:
    """A compiled output of the pinned bundle's entailment rules.

    The only derivation permitted to mention a NORMATIVE variable.
    """

    manifest_digest: Digest
    modality: Modality
    rule_ids: tuple[str, ...]
    ratification_ref: Digest | None

    def to_node(self) -> NRec:
        return NRec(
            TAG_POLICY_ENTAILMENT_DERIV,
            (
                self.manifest_digest.to_node(),
                NAtom(self.modality.value),
                atoms(self.rule_ids),
                option_node(
                    None if self.ratification_ref is None else digest_node_of(self.ratification_ref)
                ),
            ),
        )


type ConstraintDerivation = StructuralDeriv | AttestedRelationDeriv | PolicyEntailmentDeriv


def derivation_node(derivation: ConstraintDerivation) -> Node:
    match derivation:
        case StructuralDeriv():
            return NTagged("Structural", derivation.to_node())
        case AttestedRelationDeriv():
            return NTagged("AttestedRelation", derivation.to_node())
        case PolicyEntailmentDeriv():
            return NTagged("PolicyEntailment", derivation.to_node())


@dataclass(frozen=True, slots=True)
class Constraint:
    label: str
    formula: Term
    derivation: ConstraintDerivation

    def __post_init__(self) -> None:
        if not self.label or len(self.label.encode("utf-8")) > MAX_LABEL_OCTETS:
            raise InvariantViolation(f"constraint label out of range: {self.label!r}")

    def to_node(self) -> NRec:
        return NRec(
            TAG_CONSTRAINT,
            (NAtom(self.label), term_node(self.formula), derivation_node(self.derivation)),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.CONSTRAINT, self.to_node())


@dataclass(frozen=True, slots=True)
class NonEffect:
    """A rule ran, produced nothing, and said why."""

    rule_id: str
    rule_version: int
    subject: str
    reason: str

    def to_node(self) -> NRec:
        return NRec(
            TAG_NON_EFFECT,
            (
                NAtom(self.rule_id),
                NInt(self.rule_version),
                NAtom(self.subject),
                NAtom(self.reason),
            ),
        )


def constraint_seq(constraints: tuple[Constraint, ...]) -> NSeq:
    return NSeq(tuple(constraint.to_node() for constraint in constraints))


def non_effect_seq(non_effects: tuple[NonEffect, ...]) -> NSeq:
    return NSeq(tuple(non_effect.to_node() for non_effect in non_effects))
