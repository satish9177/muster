"""Bundle subartifacts that are pure data to this kernel.

Admissibility descriptors are *data*: the bundle holds them, the admissibility
module interprets them.  Putting the rules themselves in the bundle while
admissibility consumed the policy IR is what made the Phase-0 dependency graph
cyclic.

The disclosure policy is carried for one reason in Milestone A -- the manifest
commits to its digest, and a bundle with a field left out is not a bundle.  No
redaction logic exists here; that is milestone D.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.evidence.transcript import Signature
from muster.core.results import InvariantViolation
from muster.core.values.times import Instant
from muster.core.wire.codec import canonical_set
from muster.core.wire.digests import Digest, DigestKind, digest_node, digest_node_of
from muster.core.wire.nodes import NAtom, NBool, NInt, NRec, NSeq
from muster.core.wire.shape import atom_or_none, atoms, option_node

TAG_ADMISSIBILITY_DESCRIPTOR = "AdmissibilityDescriptor/v1"
TAG_ADMISSIBILITY_DESCRIPTORS = "AdmissibilityDescriptors/v1"
TAG_DISCLOSURE_ENTRY = "DisclosureEntry/v1"
TAG_DISCLOSURE_POLICY = "DisclosurePolicy/v1"
TAG_RATIFICATION_RECORD = "RatificationRecord/v1"
TAG_RATIFICATION_SET = "RatificationSet/v1"


@dataclass(frozen=True, slots=True)
class AdmissibilityDescriptor:
    rule_id: str
    rule_version: int
    rule_kind: str
    grouping_key: str
    admissible_procedures: tuple[str, ...]
    max_temporal_gap: int
    ratification_ref: Digest | None = None

    def to_node(self) -> NRec:
        return NRec(
            TAG_ADMISSIBILITY_DESCRIPTOR,
            (
                NAtom(self.rule_id),
                NInt(self.rule_version),
                NAtom(self.rule_kind),
                NAtom(self.grouping_key),
                canonical_set(NAtom(procedure) for procedure in self.admissible_procedures),
                NInt(self.max_temporal_gap),
                option_node(
                    None if self.ratification_ref is None else digest_node_of(self.ratification_ref)
                ),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.ADMISSIBILITY_DESCRIPTOR, self.to_node())


@dataclass(frozen=True, slots=True)
class AdmissibilityDescriptors:
    schema_version: int
    descriptors: tuple[AdmissibilityDescriptor, ...]

    def __post_init__(self) -> None:
        ids = [descriptor.rule_id for descriptor in self.descriptors]
        if len(set(ids)) != len(ids):
            raise InvariantViolation("admissibility rule ids are unique")

    def to_node(self) -> NRec:
        return NRec(
            TAG_ADMISSIBILITY_DESCRIPTORS,
            (
                NInt(self.schema_version),
                NSeq(tuple(descriptor.to_node() for descriptor in self.descriptors)),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.ADMISSIBILITY_DESCRIPTORS, self.to_node())

    def descriptor(self, rule_id: str) -> AdmissibilityDescriptor | None:
        for candidate in self.descriptors:
            if candidate.rule_id == rule_id:
                return candidate
        return None


@dataclass(frozen=True, slots=True)
class DisclosureEntry:
    outcome_class: str
    action_kind: str | None
    audience_class: str
    disclosure_context: str
    reveals_sensitive_input: bool
    inference_acknowledgement_ref: Digest | None
    permitted_paths: tuple[str, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_DISCLOSURE_ENTRY,
            (
                NAtom(self.outcome_class),
                option_node(atom_or_none(self.action_kind)),
                NAtom(self.audience_class),
                NAtom(self.disclosure_context),
                NBool(self.reveals_sensitive_input),
                option_node(
                    None
                    if self.inference_acknowledgement_ref is None
                    else digest_node_of(self.inference_acknowledgement_ref)
                ),
                atoms(self.permitted_paths),
            ),
        )


@dataclass(frozen=True, slots=True)
class DisclosurePolicy:
    schema_version: int
    entries: tuple[DisclosureEntry, ...]

    def __post_init__(self) -> None:
        keys = [
            (
                entry.outcome_class,
                entry.action_kind,
                entry.audience_class,
                entry.disclosure_context,
            )
            for entry in self.entries
        ]
        if len(set(keys)) != len(keys):
            raise InvariantViolation("disclosure entries are unique by their four-part key")

    def to_node(self) -> NRec:
        return NRec(
            TAG_DISCLOSURE_POLICY,
            (NInt(self.schema_version), NSeq(tuple(entry.to_node() for entry in self.entries))),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.DISCLOSURE_POLICY, self.to_node())


@dataclass(frozen=True, slots=True)
class RatificationRecord:
    """A human decision, bound to a subject by digest, a tenant and a signer."""

    ratification_id: str
    tenant_scope: str | None
    subject_kind: str
    subject_ref: Digest
    ratified_at: Instant
    signer_key_ref: str
    signature: Signature

    def to_node(self) -> NRec:
        return NRec(
            TAG_RATIFICATION_RECORD,
            (
                NAtom(self.ratification_id),
                option_node(atom_or_none(self.tenant_scope)),
                NAtom(self.subject_kind),
                self.subject_ref.to_node(),
                NInt(self.ratified_at),
                NAtom(self.signer_key_ref),
                self.signature.to_node(),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.RATIFICATION_RECORD, self.to_node())


@dataclass(frozen=True, slots=True)
class RatificationSet:
    schema_version: int
    records: tuple[RatificationRecord, ...]

    def __post_init__(self) -> None:
        ids = [record.ratification_id for record in self.records]
        if len(set(ids)) != len(ids):
            raise InvariantViolation("ratification ids are unique")

    def to_node(self) -> NRec:
        return NRec(
            TAG_RATIFICATION_SET,
            (NInt(self.schema_version), NSeq(tuple(record.to_node() for record in self.records))),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.RATIFICATION_SET, self.to_node())

    def record(self, ref: Digest) -> RatificationRecord | None:
        """The cited ratification, resolved by digest inside this bundle."""
        for candidate in self.records:
            if candidate.digest() == ref:
                return candidate
        return None
