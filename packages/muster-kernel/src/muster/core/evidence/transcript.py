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

from muster.core.evidence.relations import AcquisitionRelation, read_relation, relation_node
from muster.core.results import Result
from muster.core.values.scalars import Value, read_value
from muster.core.values.sorts import Sort, read_sort
from muster.core.values.symbols import SymbolRef, read_symbol_ref, symbol_seq
from muster.core.values.times import HalfOpenInterval, Instant, read_half_open
from muster.core.wire.codec import canonical_set
from muster.core.wire.digests import Digest, DigestKind, digest_node, digest_node_of
from muster.core.wire.nodes import NAtom, NBytes, NInt, Node, NRec, NSeq, NTagged
from muster.core.wire.shape import (
    WireError,
    WireFailure,
    atom_or_none,
    atoms,
    decoded,
    fail,
    option_node,
    read_atom,
    read_bytes,
    read_digest,
    read_int,
    read_option,
    read_rec,
    read_seq,
    read_set,
    read_tagged,
)

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


#  ---- readers ------------------------------------------------------------
#
#  The encoders above are the authority; these are their inverses, and nothing
#  else.  They exist because a durable store holds canonical octets -- the
#  artifact itself -- and a process that restarts has nothing else to rebuild
#  from.  The property that matters is octet fidelity, not object identity:
#  ``encode(node(read(decode(octets)))) == octets`` for everything ``decode``
#  admits.  It is deliberately not object equality, because a field encoded as
#  a set comes back in canonical order rather than the order it was authored
#  in -- and the canonical octets, not the authoring order, are what a digest,
#  a signature and a commitment ever covered.


def read_signature(node: Node) -> Signature:
    algorithm, octets = read_rec(node, TAG_SIGNATURE, 2)
    return Signature(read_atom(algorithm), read_bytes(octets))


def read_acquisition_payload(node: Node) -> AcquisitionPayload:
    fields = read_rec(node, TAG_ACQUISITION_PAYLOAD, 15)
    return AcquisitionPayload(
        tenant_id=read_atom(fields[0]),
        case_id=read_atom(fields[1]),
        subject=read_atom(fields[2]),
        proposition=read_symbol_ref(fields[3]),
        relation=read_relation(fields[4]),
        value_sort=read_sort(fields[5]),
        predicate_schema_digest=read_digest(fields[6]),
        observed_at=read_int(fields[7]),
        issued_at=read_int(fields[8]),
        validity=read_half_open(fields[9]),
        nonce=read_bytes(fields[10]),
        source_class=read_atom(fields[11]),
        signer_key_ref=read_atom(fields[12]),
        authorization_policy_version=read_int(fields[13]),
        request_id=read_digest(fields[14]),
    )


def read_verification_receipt(node: Node) -> VerificationReceipt:
    payload, signature = read_rec(node, TAG_VERIFICATION_RECEIPT, 2)
    return VerificationReceipt(read_acquisition_payload(payload), read_signature(signature))


def read_statement_record(node: Node) -> StatementRecord:
    fields = read_rec(node, TAG_STATEMENT_RECORD, 12)
    return StatementRecord(
        tenant_id=read_atom(fields[0]),
        case_id=read_atom(fields[1]),
        claimant=read_atom(fields[2]),
        role_in_case=read_atom(fields[3]),
        proposition=read_symbol_ref(fields[4]),
        asserted_value=read_value(fields[5]),
        value_sort=read_sort(fields[6]),
        measurement_procedure_id=read_option(fields[7], read_atom),
        statement_time=read_int(fields[8]),
        supersedes=read_option(fields[9], read_digest),
        signer_key_ref=read_atom(fields[10]),
        signature=read_signature(fields[11]),
    )


def read_party_record(node: Node) -> PartyRecord:
    tenant_id, principal_id, role_in_case, competences = read_rec(node, TAG_PARTY_RECORD, 4)
    return PartyRecord(
        tenant_id=read_atom(tenant_id),
        principal_id=read_atom(principal_id),
        role_in_case=read_atom(role_in_case),
        competences=read_set(competences, read_atom),
    )


def read_case_construction(node: Node) -> CaseConstructionRecord:
    fields = read_rec(node, TAG_CASE_CONSTRUCTION, 9)
    return CaseConstructionRecord(
        tenant_id=read_atom(fields[0]),
        case_id=read_atom(fields[1]),
        created_at=read_int(fields[2]),
        subject_refs=read_seq(fields[3], read_atom),
        contract_ref=read_option(fields[4], read_atom),
        parties=read_seq(fields[5], read_party_record),
        declared_instances=read_seq(fields[6], read_symbol_ref),
        signer_key_ref=read_atom(fields[7]),
        signature=read_signature(fields[8]),
    )


def read_entry(node: Node) -> TranscriptEntry:
    """The inverse of :func:`entry_node`.

    The union is closed, and an unknown variant tag is a typed rejection rather
    than a skipped entry: ``Retraction`` and ``Declaration`` carry supersession
    semantics nothing here implements, and admitting one silently would produce
    a revision that is wrong rather than one that is refused.
    """
    tag, payload = read_tagged(node, "TranscriptEntry")
    match tag:
        case "Attestation":
            return Attestation(read_verification_receipt(payload))
        case "Statement":
            return Statement(read_statement_record(payload))
        case _:
            raise fail(WireFailure.UNKNOWN_VARIANT, "Attestation | Statement", tag)


def decode_entry(node: Node) -> Result[TranscriptEntry, WireError]:
    return decoded(lambda: read_entry(node))


def decode_case_construction(node: Node) -> Result[CaseConstructionRecord, WireError]:
    return decoded(lambda: read_case_construction(node))
