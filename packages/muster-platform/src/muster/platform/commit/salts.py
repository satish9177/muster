"""The per-case secret, and everything derived under it.

Three derivations, and each one exists to remove a different oracle:

``field_salt(path)``
    Blinds one leaf.  Without it, a reader who is shown *any* leaf can test a
    guess at an undisclosed one: recompute the leaf hash for a candidate value
    and fold it against the proof they already hold.  With it, the guess also
    needs a 32-octet secret keyed to that exact path.

``case_commitment(construction_digest)``
    Blinds the case's authored identity.  The construction record is signed by
    an officer and its digest is a function of content a party contributed, so
    publishing it raw links one participant's envelope to another's knowledge.

``revision_commitment(revision_digest)``
    Blinds the semantic revision digest, which is the sharpest oracle of the
    three: a revision digest is a deterministic function of inputs a party may
    be able to enumerate, so an envelope carrying it raw lets that party
    rebuild candidate transcripts until the digests match, and read off the
    private input.  The envelope carries the keyed form and every binding
    property the verifier needs survives, because a verifier only ever compares
    commitments to each other.

**The salt itself leaves this boundary in no direction at all.**  It is not a
column, not a field on any outward artifact, not an argument to anything under
``disclose``, and not printable: :class:`CaseSalt` redacts itself, because the
one thing a secret held in memory is reliably exposed by is a log line or a
traceback that formatted the object holding it.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol

from muster.core.results import InvariantViolation
from muster.core.wire.digests import Digest, domain_separator
from muster.platform.commit.domains import CommitmentDomain

#: A case salt is exactly this wide.  It is an HMAC key over SHA-256, so a
#: shorter one is a weaker key and a longer one is silently hashed down to the
#: block size -- neither is a thing to discover at runtime.
CASE_SALT_OCTETS = 32


@dataclass(frozen=True, slots=True)
class CaseSalt:
    """A per-case secret, held only inside the control plane.

    It is a type rather than ``bytes`` for two reasons.  The first is that a
    keyed derivation should be impossible to call with the wrong secret by
    passing the wrong positional argument.  The second is ``__repr__``: a
    ``bytes`` field on a frozen dataclass prints itself in every traceback,
    every ``assert`` message and every structured log line that touched the
    object, and "the salt never leaves the boundary" cannot survive that.
    """

    octets: bytes

    def __post_init__(self) -> None:
        if len(self.octets) != CASE_SALT_OCTETS:
            raise InvariantViolation(
                f"a case salt is {CASE_SALT_OCTETS} octets, not {len(self.octets)}"
            )

    def __repr__(self) -> str:
        return "CaseSalt(<redacted>)"

    def __str__(self) -> str:
        return repr(self)


class CaseSaltSource(Protocol):
    """Where a case salt comes from, as the smallest port that will do.

    Derived, never stored.  The production implementation is a MAC in a key
    management service: the control plane holds no key material, asks for the
    MAC of the case's coordinates, and gets a salt that is reproducible for as
    long as the key exists and unreachable to anyone without permission on it.
    A local implementation is the same computation under a locally held root
    key, which is the same primitive with weaker custody -- and the port is
    what makes that a deployment fact rather than a code change.

    The coordinates are keyword-only and both are required.  A salt derived
    from the case alone would be shared by two tenants that happened to choose
    the same case identifier, and every leaf in both cases would then be
    forgeable by the other tenant.
    """

    def salt_for(self, *, tenant_id: str, case_id: str) -> CaseSalt:
        """The salt for this case.  Deterministic: same coordinates, same salt."""
        ...


def _keyed(domain: CommitmentDomain, salt: CaseSalt, message: bytes) -> bytes:
    return hmac.new(salt.octets, domain_separator(domain.value) + message, hashlib.sha256).digest()


def field_salt(salt: CaseSalt, path: str) -> bytes:
    """The blinding factor for one commitment path.

    Bound to the path, so two leaves in one tree never share a salt and a salt
    disclosed with one leaf says nothing about any other.

    The message is the path's ASCII octets, because the path grammar is ASCII.
    A path outside it is refused by the extractor long before it reaches here,
    so this is a second line rather than the first -- but it is a *typed* second
    line: the raw encode raises ``UnicodeEncodeError``, which is not a failure
    mode any caller of this module is written against.
    """
    try:
        message = path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise InvariantViolation(f"a commitment path is ASCII: {path!r}") from exc
    return _keyed(CommitmentDomain.FIELD_SALT, salt, message)


def case_commitment(salt: CaseSalt, construction_digest: Digest) -> Digest:
    """The salted stand-in for the case's authored identity."""
    return Digest(_keyed(CommitmentDomain.CASE_COMMITMENT, salt, construction_digest.octets))


def revision_commitment(salt: CaseSalt, revision_digest: Digest) -> Digest:
    """The salted stand-in for the semantic revision digest.

    Two different revisions of one case produce two different commitments, so
    a proof cannot be carried from one revision to another; and neither
    commitment discloses the digest it stands for.
    """
    return Digest(_keyed(CommitmentDomain.REVISION_COMMITMENT, salt, revision_digest.octets))
