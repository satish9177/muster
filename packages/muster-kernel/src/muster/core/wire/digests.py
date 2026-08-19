"""Domain-separated digests.

    digest(KIND, octets) = SHA-256("muster/v1/" ‖ KIND ‖ 0x00 ‖ octets)

Domain separation is worth nothing unless the namespace is closed, so the kind
is an enumeration rather than a string: an undeclared domain is unrepresentable
at the call site, not merely rejected inside it.  Each kind names the single
wire type whose canonical encoding is its preimage.

The namespace has a second half that is not here.  A few domains have a
preimage that is *not* one wire type -- the two children of a commitment-tree
node, the empty tree, a keyed salt label -- and those are declared beside the
code that owns those preimages, in the control plane's commitment layer, which
this kernel does not name and cannot import.  The two enumerations are
disjoint, and a test says so.  Splitting them keeps the
sentence above true: a member of this enumeration always names a type.  What
both halves share is :func:`domain_separator`, so the octets a preimage opens
with are written once.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from muster.core.results import InvariantViolation
from muster.core.wire.codec import encode
from muster.core.wire.nodes import DIGEST_OCTETS, NDigest, Node

DOMAIN_PREFIX: bytes = b"muster/v1/"


class DigestKind(Enum):
    """The type digest domains, each naming one frozen Phase-0.8 wire type.

    A member is added when something encodes that type and digests it, never
    in advance: reserving a domain before its preimage exists is how two
    domains end up colliding later.  The commitment members below arrived with
    milestone D, which is the first thing that builds the preimages they name.
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

    #  Commitment and disclosure.  Each preimage here is the canonical encoding
    #  of the type the member is named after, exactly as above; the domains
    #  whose preimage is not a single type live in the platform's enumeration.
    MERKLE_LEAF = "MERKLE_LEAF"
    MERKLE_ROOT = "MERKLE_ROOT"
    COMMITMENT_ENVELOPE = "COMMITMENT_ENVELOPE"
    DISCLOSURE_ENTRY = "DISCLOSURE_ENTRY"
    PARTICIPANT_VIEW = "PARTICIPANT_VIEW"
    AUDITOR_VIEW = "AUDITOR_VIEW"


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


def domain_separator(domain: str) -> bytes:
    """The octets every preimage under ``domain`` opens with.

    Exported because the auxiliary domains live in another package and this
    construction must not be written twice.  It takes a ``str`` rather than a
    ``DigestKind`` for that reason alone, and it is not a hashing function: a
    caller holding a separator still has to say what it is separating, so
    forgetting the domain is not something this makes possible.
    """
    return DOMAIN_PREFIX + domain.encode("ascii") + b"\x00"


def digest_octets(kind: DigestKind, octets: bytes) -> Digest:
    """Digest a preimage that is already canonical octets."""
    return Digest(hashlib.sha256(domain_separator(kind.value) + octets).digest())


def digest_node(kind: DigestKind, node: Node) -> Digest:
    """Digest a value: encode canonically, then digest under its own domain."""
    return digest_octets(kind, encode(node))
