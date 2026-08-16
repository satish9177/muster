"""Transcript entries: everything a principal may put into a case.

Two of the four frozen variants are implemented here, because Milestone A has a
consumer for exactly those two:

* ``Attestation`` -- a signed relation from a source. May become a fact or a
  constraint.
* ``Statement`` -- a party's claim. May become **nothing**: it is not a
  ``Justification`` variant, there is no rule that converts it, and the only
  trace it leaves is a recorded non-effect saying why.

``Retraction`` and ``Declaration`` carry supersession and instance-declaration
semantics that Milestone A does not implement.  Rather than decode them and
ignore their meaning -- which would silently produce a wrong revision -- the
transcript reader refuses a transcript containing one.  Fail closed, not fail
quiet.

**Signatures are carried, not verified.**  Milestone A is local and offline; it
holds no keyring and makes no authenticity claim.  Nothing in this milestone may
be read as evidence that an entry came from the principal it names.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.evidence.relations import AcquisitionRelation, relation_node
from muster.core.values.scalars import Value
from muster.core.values.sorts import Sort
from muster.core.values.symbols import SymbolRef, symbol_seq
from muster.core.values.times import HalfOpenInterval, Instant
from muster.core.wire.codec import canonical_set
from muster.core.wire.digests import Digest, DigestKind, digest_node, digest_node_of
from muster.core.wire.nodes import NAtom, NBytes, NInt, Node, NRec, NSeq, NTagged
from muster.core.wire.shape import atom_or_none, atoms, option_node

TAG_SIGNATURE = "Signature/v1"
TAG_ACQUISITION_PAYLOAD = "AcquisitionPayload/v1"
TAG_VERIFICATION_RECEIPT = "VerificationReceipt/v1"
TAG_STATEMENT_RECORD = "StatementRecord/v1"
TAG_PARTY_RECORD = "PartyRecord/v1"
TAG_CASE_CONSTRUCTION = "CaseConstructionRecord/v1"

NONCE_OCTETS = 16


@dataclass(frozen=True, slots=True)
class Signature:
    algorithm: str
    octets: bytes

    def to_node(self) -> NRec:
        return NRec(TAG_SIGNATURE, (NAtom(self.algorithm), NBytes(self.octets)))


@dataclass(frozen=True, slots=True)
class AcquisitionPayload:
    """The exact octets a source signature covers.

    Everything security-critical is inside: the tenant, the case, the
    proposition, the schema the source validated against, the validity window,
    the nonce, the source class, the signer, and the request the reply answers.
    There is no security-bearing field beside the signature for someone to swap.
    """

    tenant_id: str
    case_id: str
    subject: str
    proposition: SymbolRef
    relation: AcquisitionRelation
    value_sort: Sort
    predicate_schema_digest: Digest
    observed_at: Instant
    issued_at: Instant
    validity: HalfOpenInterval
    nonce: bytes
    source_class: str
    signer_key_ref: str
    authorization_policy_version: int
    request_id: Digest

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACQUISITION_PAYLOAD,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                NAtom(self.subject),
                self.proposition.to_node(),
                relation_node(self.relation),
                self.value_sort.to_node(),
                self.predicate_schema_digest.to_node(),
                NInt(self.observed_at),
                NInt(self.issued_at),
                self.validity.to_node(),
                NBytes(self.nonce),
                NAtom(self.source_class),
                NAtom(self.signer_key_ref),
                NInt(self.authorization_policy_version),
                self.request_id.to_node(),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.ATTESTATION_PAYLOAD, self.to_node())


@dataclass(frozen=True, slots=True)
class VerificationReceipt:
    payload: AcquisitionPayload
    signature: Signature

    def to_node(self) -> NRec:
        return NRec(TAG_VERIFICATION_RECEIPT, (self.payload.to_node(), self.signature.to_node()))

    def digest(self) -> Digest:
        return digest_node(DigestKind.VERIFICATION_RECEIPT, self.to_node())


@dataclass(frozen=True, slots=True)
class StatementRecord:
    """A party's account. Inert by construction.

    It asserts a value, and asserting is all it does: no justification variant
    accepts it, so it can never appear in ``established``.
    """

    tenant_id: str
    case_id: str
    claimant: str
    role_in_case: str
    proposition: SymbolRef
    asserted_value: Value
    value_sort: Sort
    measurement_procedure_id: str | None
    statement_time: Instant
    supersedes: Digest | None
    signer_key_ref: str
    signature: Signature

    def to_node(self) -> NRec:
        return NRec(
            TAG_STATEMENT_RECORD,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                NAtom(self.claimant),
                NAtom(self.role_in_case),
                self.proposition.to_node(),
                self.asserted_value.to_node(),
                self.value_sort.to_node(),
                option_node(atom_or_none(self.measurement_procedure_id)),
                NInt(self.statement_time),
                option_node(None if self.supersedes is None else digest_node_of(self.supersedes)),
                NAtom(self.signer_key_ref),
                self.signature.to_node(),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.STATEMENT, self.to_node())


@dataclass(frozen=True, slots=True)
class PartyRecord:
    tenant_id: str
    principal_id: str
    role_in_case: str
    competences: tuple[str, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_PARTY_RECORD,
            (
                NAtom(self.tenant_id),
                NAtom(self.principal_id),
                NAtom(self.role_in_case),
                canonical_set(NAtom(competence) for competence in self.competences),
            ),
        )


@dataclass(frozen=True, slots=True)
class CaseConstructionRecord:
    """Who the parties are and which proposition instances exist.

    Roles come from here -- signed at case construction by an officer -- and
    never from a party's own assertion about itself.
    """

    tenant_id: str
    case_id: str
    created_at: Instant
    subject_refs: tuple[str, ...]
    contract_ref: str | None
    parties: tuple[PartyRecord, ...]
    declared_instances: tuple[SymbolRef, ...]
    signer_key_ref: str
    signature: Signature

    def to_node(self) -> NRec:
        return NRec(
            TAG_CASE_CONSTRUCTION,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                NInt(self.created_at),
                atoms(self.subject_refs),
                option_node(atom_or_none(self.contract_ref)),
                NSeq(tuple(party.to_node() for party in self.parties)),
                symbol_seq(self.declared_instances),
                NAtom(self.signer_key_ref),
                self.signature.to_node(),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.CASE_CONSTRUCTION, self.to_node())


@dataclass(frozen=True, slots=True)
class Attestation:
    receipt: VerificationReceipt


@dataclass(frozen=True, slots=True)
class Statement:
    record: StatementRecord


type TranscriptEntry = Attestation | Statement


def entry_node(entry: TranscriptEntry) -> Node:
    match entry:
        case Attestation(receipt):
            return NTagged("Attestation", receipt.to_node())
        case Statement(record):
            return NTagged("Statement", record.to_node())


def entry_digest(entry: TranscriptEntry) -> Digest:
    """The identity a transcript prefix commits to."""
    return digest_node(DigestKind.TRANSCRIPT_ENTRY, entry_node(entry))
