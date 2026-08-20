"""Four signing boundaries that must never be one.

MUSTER holds four distinct signing roles, and collapsing any two of them would
be an authority bypass rather than a tidy-up:

* a **source** signs an ``AcquisitionPayload`` -- "SITE_A's access-control
  system observed this";
* an **officer** signs a ``CaseConstructionRecordBody`` -- "this case is about
  these parties, these instances and this site";
* a **publisher** signs an authority, revocation or catalog snapshot -- "the
  control plane says these are the grants in force";
* an **envelope signer** signs a ``CommitmentEnvelope`` -- "this is the record
  MUSTER committed to".  That one is milestone D's and lives in the control
  plane, which this package does not name and cannot import.

A publisher that could sign as a source could grant itself authority and then
exercise it.  A source that could sign as a publisher could write its own
grant.  A source that could sign as an officer could re-site the case it is
attesting into, and Q-12(d) -- which asks whether that key was authorized over
*this case's* resource -- would be answering a question the source wrote.  So
the preimages are **nominally distinct types**, not aliases for ``bytes``:
:class:`AttestationPreimage`, :class:`OfficerPreimage` and
:class:`PublisherPreimage` are not interchangeable under a type checker, and
none is accepted where the commitment envelope's ``SigningPreimage`` belongs.
A caller cannot hand the wrong signer the wrong value by accident, and the
ports below say which role they are for in their names.

Each preimage is a domain-separated digest of a canonical encoding rather than
the encoding itself, for the same reason milestone D chose that: the octets
handed to a signing implementation are fixed-width whatever the artifact
contains, which is what a key management service signs -- so replacing a local
key with a managed one changes custody and nothing about what was covered.

**Nothing here performs cryptography.**  These are value constructions and
protocols.  The primitives live behind them in one adapter, which is the only
module in the system that imports a cryptography library -- and which the
kernel neither names nor could reach.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from muster.core.authority.grants import AuthorityRegistrySnapshotBody
from muster.core.authority.revocation import RevocationSnapshotBody
from muster.core.wire.codec import encode
from muster.core.wire.digests import DigestKind, digest_octets
from muster.core.wire.signature import Signature


@dataclass(frozen=True, slots=True)
class AttestationPreimage:
    """The exact value a *source* attestation signature covers.

    Constructible only by ``muster.core.evidence.signing.attestation_preimage``.
    A port taking ``bytes`` would be a general-purpose signing oracle over
    anything a caller could assemble, and the one thing a signing boundary must
    not offer is that.

    The *type* is here and the *construction* is not, and the split is a
    dependency rather than a preference: authority is beneath evidence -- Q-12
    runs during relation validation -- so a module here that reached for an
    ``AcquisitionPayload`` would close a cycle.  What a signature covers is a
    fact about the payload, so it is declared beside the payload.
    """

    octets: bytes


@dataclass(frozen=True, slots=True)
class OfficerPreimage:
    """The exact value an *officer* signature covers.

    Constructible only by
    ``muster.core.evidence.signing.case_construction_preimage``, for the reason
    :class:`AttestationPreimage` is: a port taking ``bytes`` is a signing
    oracle over anything a caller can assemble.

    Distinct from :class:`AttestationPreimage` because the two roles are the
    two sides of Q-12(d).  The officer declares where the case is; the source
    says what it observed.  One key population doing both would let a source
    declare its own site and then attest to it, which is the clause defeated
    without a single invalid signature.
    """

    octets: bytes


class OfficerSigner(Protocol):
    """Signs case construction records, and nothing else."""

    @property
    def key_ref(self) -> str: ...

    def sign(self, preimage: OfficerPreimage) -> Signature: ...


class OfficerVerifier(Protocol):
    """Checks a construction record against the trusted officer keyring.

    Total by contract, exactly as :class:`SourceVerifier` is: an unknown key
    reference, malformed material and a truncated signature all mean "this
    record was not opened by anybody this reader trusts", and none of them is
    an exception on the admission path.

    The keyring is the reader's and never the record's.  ``False`` for a record
    naming a key the reader does not hold is the common case this exists to
    produce -- an unsigned development record is exactly that case, and it is
    refused rather than admitted-and-inert.
    """

    def verify(self, *, key_ref: str, preimage: OfficerPreimage, signature: Signature) -> bool: ...


class PublisherRole(Enum):
    """Which publication a publisher key is trusted to make.

    Three roles and two key populations was the gap: the control plane signs
    authority snapshots, revocation snapshots and fleet catalogs, and a single
    flat keyring accepted any of those keys for any of those artifacts.  Domain
    separation stops a *signature* being replayed across families -- the
    preimages differ, so the octets do not verify -- and does nothing about the
    holder of a catalog key signing a fresh authority body, which is the attack
    that matters: the fleet-operations key becomes a key that can grant.

    So the role travels with the question.  A verifier is asked "did a key
    trusted **for this role** sign this", and a keyring is a map from role to
    key material rather than one flat map.  Separating the key populations in
    deployment is still the real control; this makes a deployment that failed
    to separate them fail closed rather than silently.
    """

    AUTHORITY = "AUTHORITY"
    REVOCATION = "REVOCATION"
    CATALOG = "CATALOG"


@dataclass(frozen=True, slots=True)
class PublisherPreimage:
    """The exact value a *control-plane publication* signature covers.

    A separate type from :class:`AttestationPreimage` so that a source signer
    and a publisher signer are not substitutable for one another, in either
    direction, at a call site or under a type checker.
    """

    octets: bytes


def authority_snapshot_preimage(body: AuthorityRegistrySnapshotBody) -> PublisherPreimage:
    """What a publisher signs when it publishes who may attest what."""
    return PublisherPreimage(
        digest_octets(DigestKind.AUTHORITY_REGISTRY_SNAPSHOT_BODY, encode(body.to_node())).octets
    )


def revocation_snapshot_preimage(body: RevocationSnapshotBody) -> PublisherPreimage:
    """What a publisher signs when it publishes which keys are withdrawn."""
    return PublisherPreimage(
        digest_octets(DigestKind.REVOCATION_SNAPSHOT_BODY, encode(body.to_node())).octets
    )


class SourceSigner(Protocol):
    """Signs source attestations, and nothing else.

    ``key_ref`` is a property rather than an argument, exactly as it is for the
    envelope signer: the identity a signer signs under is a fact about the
    signer, so a payload cannot be built naming one key and signed with
    another.
    """

    @property
    def key_ref(self) -> str: ...

    def sign(self, preimage: AttestationPreimage) -> Signature: ...


class SourceVerifier(Protocol):
    """Checks a source attestation against public key material.

    Total by contract: a malformed key, a truncated signature and an unknown
    key reference all mean the same thing to a reader -- this attestation is
    not authentic -- and none of them is an exception on the admission path.

    Answering ``True`` establishes **authenticity only**.  It says which key
    signed these octets and says nothing whatever about whether that key was
    permitted to say it; that is Q-12, and it runs afterwards, from the pinned
    authority snapshot.
    """

    def verify(
        self, *, key_ref: str, preimage: AttestationPreimage, signature: Signature
    ) -> bool: ...


class PublisherSigner(Protocol):
    """Signs authority, revocation and catalog publications."""

    @property
    def key_ref(self) -> str: ...

    def sign(self, preimage: PublisherPreimage) -> Signature: ...


class PublisherVerifier(Protocol):
    """Checks a publication against the trusted publisher keyring, per role.

    The keyring is the reader's, never the artifact's: a snapshot naming its
    own signer proves nothing until that name resolves in material the reader
    already trusted.  ``False`` for an unknown publisher is therefore the
    common case this exists to produce, not an edge one.

    ``role`` is not optional and has no default.  A default would be the value
    every call site inherited without deciding, which is how one keyring came
    to serve three roles in the first place.
    """

    def verify(
        self,
        *,
        role: PublisherRole,
        key_ref: str,
        preimage: PublisherPreimage,
        signature: Signature,
    ) -> bool: ...
