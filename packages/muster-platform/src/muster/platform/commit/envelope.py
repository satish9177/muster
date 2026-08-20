"""The authenticated envelope, and the smallest signing boundary that carries it.

A commitment tree proves that a disclosed leaf belongs to *some* record.  It
says nothing about whose record, and anyone can build a coherent tree -- so a
reader who checks membership alone is trusting the sender about everything that
matters.  The envelope is what closes that: one signed record naming the tenant,
the case, both salted commitments, the bundle, the pinned disclosure policy, the
schema version, the leaf count, the root, and the key that signed it.

**Every security-critical field is inside the signed body.**  ``Signature``
carries an algorithm and octets and nothing else -- no key reference of its own
-- so the payload and the wrapper have nothing to disagree about, and there is
no field beside the signature for anyone to swap.  In particular the signer's
own identity is *inside* what it signs, which is what stops a valid envelope
being re-attributed to a different key.

The primitive is behind a port and the port is deliberately tiny.  Production
custody is a key management service that signs and never exports; a local
software key is the same computation with weaker custody.  What must not vary
is *which octets are covered*, so that is computed here, once, by
:func:`signing_preimage`, and an implementation of the port receives a value it
could not have constructed itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from muster.core.results import InvariantViolation
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest, DigestKind, digest_octets
from muster.core.wire.nodes import DIGEST_OCTETS, NAtom, NBytes, NInt, Node, NRec
from muster.core.wire.shape import (
    WireDecodeError,
    WireError,
    WireFailure,
    read_atom,
    read_bytes,
    read_digest,
    read_int,
    read_rec,
)
from muster.core.wire.signature import Signature, read_signature

TAG_COMMITMENT_ENVELOPE = "CommitmentEnvelope/v1"
TAG_SIGNED_COMMITMENT_ENVELOPE = "SignedCommitmentEnvelope/v1"


@dataclass(frozen=True, slots=True)
class CommitmentEnvelope:
    """What a participant is handed alongside their leaves.

    Both commitments are the **salted** forms.  Carrying the raw case digest or
    the raw semantic revision digest would turn the envelope into an oracle: a
    party who can enumerate candidate inputs could rebuild each candidate,
    recompute the digest and read off the private one that matched.  The salted
    forms are just as binding -- a verifier only ever compares commitments to
    each other -- and disclose nothing.
    """

    tenant_id: str
    case_id: str
    case_commitment: Digest
    revision_commitment: Digest
    bundle_manifest_digest: Digest
    disclosure_policy_digest: Digest
    certificate_schema_version: int
    leaf_count: int
    root: bytes
    signer_key_ref: str

    def __post_init__(self) -> None:
        if len(self.root) != DIGEST_OCTETS:
            raise InvariantViolation(f"a commitment root is 32 octets, not {len(self.root)}")
        if self.leaf_count < 0:
            raise InvariantViolation(f"a leaf count is not negative: {self.leaf_count}")

    def to_node(self) -> NRec:
        return NRec(
            TAG_COMMITMENT_ENVELOPE,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                self.case_commitment.to_node(),
                self.revision_commitment.to_node(),
                self.bundle_manifest_digest.to_node(),
                self.disclosure_policy_digest.to_node(),
                NInt(self.certificate_schema_version),
                NInt(self.leaf_count),
                NBytes(self.root),
                NAtom(self.signer_key_ref),
            ),
        )

    def digest(self) -> Digest:
        return digest_octets(DigestKind.COMMITMENT_ENVELOPE, encode(self.to_node()))


@dataclass(frozen=True, slots=True)
class SigningPreimage:
    """The exact value a commitment signature covers.

    Constructible only by :func:`signing_preimage`, by convention that the type
    exists at all: a port that took ``bytes`` would let a caller sign anything
    it could assemble, and the one thing a signing boundary must not offer is a
    general-purpose oracle over arbitrary octets.
    """

    octets: bytes


def signing_preimage(envelope: CommitmentEnvelope) -> SigningPreimage:
    """Domain-separated digest of the envelope's canonical encoding.

    The covered value is a digest rather than the encoding itself so that the
    octets handed to a signer are fixed-width whatever the envelope contains --
    which is what a key management service signs, and what a local
    implementation must therefore sign too.
    """
    return SigningPreimage(
        digest_octets(DigestKind.COMMITMENT_ENVELOPE, encode(envelope.to_node())).octets
    )


class EnvelopeSigner(Protocol):
    """Signs commitment envelopes, and nothing else.

    ``key_ref`` is a property rather than an argument: the identity a signer
    signs under is a fact about the signer, so an envelope cannot be built
    naming one key and signed with another.
    """

    @property
    def key_ref(self) -> str: ...

    def sign(self, preimage: SigningPreimage) -> Signature:
        """A signature over exactly these octets, under this signer's key."""
        ...


class EnvelopeVerifier(Protocol):
    """Checks a commitment signature against a key the reader already trusts.

    Separate from the signer because the reader is a different principal: a
    participant verifying their own view holds public verification material and
    no ability to sign.  Where the two are the same object, that is a property
    of the deployment rather than of the contract.
    """

    def verify(self, *, key_ref: str, preimage: SigningPreimage, signature: Signature) -> bool:
        """``False`` for an unknown key, a wrong algorithm or a bad signature.

        Total, and never raises for adversarial input: this runs on octets a
        participant supplied, and an exception escaping here would turn a
        forged view into a crash instead of a rejection.
        """
        ...


@dataclass(frozen=True, slots=True)
class SignedCommitmentEnvelope:
    envelope: CommitmentEnvelope
    signature: Signature

    def to_node(self) -> NRec:
        return NRec(
            TAG_SIGNED_COMMITMENT_ENVELOPE,
            (self.envelope.to_node(), self.signature.to_node()),
        )

    def octets(self) -> bytes:
        return encode(self.to_node())


def sign_envelope(envelope: CommitmentEnvelope, signer: EnvelopeSigner) -> SignedCommitmentEnvelope:
    """Sign, refusing an envelope that names a key this signer does not hold.

    The refusal is not defensive tidying.  An envelope naming key A and signed
    by key B verifies under neither reading -- the reader resolves the key from
    inside the signed body -- so producing one is a defect that would surface
    as an unexplainable verification failure at a participant, long after the
    process that made it exited.
    """
    if envelope.signer_key_ref != signer.key_ref:
        raise InvariantViolation(
            f"envelope names {envelope.signer_key_ref!r}, signer holds {signer.key_ref!r}"
        )
    return SignedCommitmentEnvelope(envelope, signer.sign(signing_preimage(envelope)))


def verify_envelope(
    signed: SignedCommitmentEnvelope, verifier: EnvelopeVerifier, *, trusted_keys: frozenset[str]
) -> bool:
    """Authenticity, and the trust decision that has to accompany it.

    Two questions, and answering only the first is the defect this is written
    against: a signature that verifies proves *a* key signed these octets, not
    that the reader has any reason to accept that key.  The signer reference is
    read from inside the signed body, so an envelope cannot claim one key and
    be checked against another.
    """
    key_ref = signed.envelope.signer_key_ref
    if key_ref not in trusted_keys:
        return False
    return verifier.verify(
        key_ref=key_ref,
        preimage=signing_preimage(signed.envelope),
        signature=signed.signature,
    )


#  ---- reading ------------------------------------------------------------


def read_envelope(node: Node) -> CommitmentEnvelope:
    fields = read_rec(node, TAG_COMMITMENT_ENVELOPE, 10)
    leaf_count = read_int(fields[7])
    if leaf_count < 0:
        #  Checked here rather than left to ``__post_init__``: a reader is the
        #  boundary between octets somebody else wrote and values this process
        #  holds, and its failure has to be a ``WireError`` a caller can turn
        #  into a rejection -- not an ``InvariantViolation`` that escapes.
        raise WireDecodeError(
            WireError(WireFailure.OUT_OF_RANGE, "a non-negative leaf count", str(leaf_count))
        )
    return CommitmentEnvelope(
        tenant_id=read_atom(fields[0]),
        case_id=read_atom(fields[1]),
        case_commitment=read_digest(fields[2]),
        revision_commitment=read_digest(fields[3]),
        bundle_manifest_digest=read_digest(fields[4]),
        disclosure_policy_digest=read_digest(fields[5]),
        certificate_schema_version=read_int(fields[6]),
        leaf_count=leaf_count,
        root=read_bytes(fields[8], DIGEST_OCTETS),
        signer_key_ref=read_atom(fields[9]),
    )


def read_signed_envelope(node: Node) -> SignedCommitmentEnvelope:
    envelope, signature = read_rec(node, TAG_SIGNED_COMMITMENT_ENVELOPE, 2)
    return SignedCommitmentEnvelope(read_envelope(envelope), read_signature(signature))
