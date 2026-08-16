"""Domain-separated digests.

    digest(KIND, octets) = SHA-256("muster/v1/" ‖ KIND ‖ 0x00 ‖ octets)

Domain separation is worth nothing unless the namespace is closed, so the kind
is an enumeration rather than a string: an undeclared domain is unrepresentable
at the call site, not merely rejected inside it.  Each kind names the single
wire type whose canonical encoding is its preimage.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from muster.core.results import InvariantViolation
from muster.core.wire.codec import encode
from muster.core.wire.nodes import DIGEST_OCTETS, NDigest, Node

_PREFIX = b"muster/v1/"


class DigestKind(Enum):
    """The digest domains this kernel uses.

    Every member names a frozen Phase-0.8 type domain.  Auxiliary domains
    (Merkle nodes, field salts, commitments) belong to milestone D and are
    deliberately absent: reserving a domain before its preimage exists is how
    two domains end up colliding later.
    """

    SYMBOL_REF = "SYMBOL_REF"
    TERM = "TERM"
    QUERY_TERM = "QUERY_TERM"
    WORLD = "WORLD"

    ACTION = "ACTION"
    CONSEQUENTIAL_ACTION = "CONSEQUENTIAL_ACTION"
    ACTION_SCHEMA = "ACTION_SCHEMA"

    PREDICATE_SCHEMA = "PREDICATE_SCHEMA"
    POLICY_PROGRAM = "POLICY_PROGRAM"
    ENTAILMENT_RULES = "ENTAILMENT_RULES"
    ADMISSIBILITY_DESCRIPTOR = "ADMISSIBILITY_DESCRIPTOR"
    ADMISSIBILITY_DESCRIPTORS = "ADMISSIBILITY_DESCRIPTORS"
    DISCLOSURE_POLICY = "DISCLOSURE_POLICY"
    RATIFICATION_RECORD = "RATIFICATION_RECORD"
    RATIFICATION_SET = "RATIFICATION_SET"
    MANIFEST = "MANIFEST"

    ATTESTATION_PAYLOAD = "ATTESTATION_PAYLOAD"
    VERIFICATION_RECEIPT = "VERIFICATION_RECEIPT"
    STATEMENT = "STATEMENT"
    CASE_CONSTRUCTION = "CASE_CONSTRUCTION"
    TRANSCRIPT_ENTRY = "TRANSCRIPT_ENTRY"
    TRANSCRIPT_PREFIX = "TRANSCRIPT_PREFIX"

    ESTABLISHED_FACT = "ESTABLISHED_FACT"
    CONSTRAINT = "CONSTRAINT"
    AUTHORIZATION_CONTEXT = "AUTHORIZATION_CONTEXT"
    REBUILD_INPUTS = "REBUILD_INPUTS"
    CASE_REVISION = "CASE_REVISION"

    LOGICAL_CASE = "LOGICAL_CASE"
    SOLVER_QUERY = "SOLVER_QUERY"
    KERNEL_ANALYSIS_RECORD = "KERNEL_ANALYSIS_RECORD"
    EVIDENCE_REQUEST = "EVIDENCE_REQUEST"
    ANALYSIS_CERTIFICATE = "ANALYSIS_CERTIFICATE"


@dataclass(frozen=True, slots=True)
class Digest:
    """A SHA-256 digest over a domain-separated preimage."""

    octets: bytes

    def __post_init__(self) -> None:
        if len(self.octets) != DIGEST_OCTETS:
            raise InvariantViolation(
                f"digest is {len(self.octets)} octets, expected {DIGEST_OCTETS}"
            )

    @property
    def hex(self) -> str:
        return self.octets.hex()

    def to_node(self) -> NDigest:
        return NDigest(self.octets)

    def __str__(self) -> str:
        return self.hex


def digest_node_of(digest: Digest) -> NDigest:
    """Encode a digest. Named, so an optional digest field needs no lambda."""
    return digest.to_node()


def digest_octets(kind: DigestKind, octets: bytes) -> Digest:
    """Digest a preimage that is already canonical octets."""
    body = hashlib.sha256(_PREFIX + kind.value.encode("ascii") + b"\x00" + octets)
    return Digest(body.digest())


def digest_node(kind: DigestKind, node: Node) -> Digest:
    """Digest a value: encode canonically, then digest under its own domain."""
    return digest_octets(kind, encode(node))
