"""Resolving the authority state a case pinned.

Given an :class:`AuthorizationContext` -- which sits inside the revision digest
and is therefore not swappable -- produce the two snapshots ``rebuild`` needs,
or say why they cannot be produced.

Five checks, in this order, each closing a different door:

1. **the octets exist** under the digest the case pinned.  Absence fails
   closed: a rebuild that cannot resolve its authority snapshot has not
   established that any key is authorized, only that it does not know;
2. **the octets decode and read** as a signed publication;
3. **the publisher signature verifies** against the trusted keyring, *before*
   the snapshot is used for anything.  A tampered snapshot, one signed by the
   wrong key, and one signed by nobody the reader trusts are one refusal here;
4. **the digest re-derives**.  The snapshot inside the verified body must hash
   to the digest the case pinned, so a store that returned the wrong preimage
   -- or a row keyed under a digest that is not its own -- is caught here and
   not three layers later;
5. **the tenant binds**.  The snapshot must name the tenant it was read under.

``rebuild`` then checks the pin again as a value comparison.  The repetition is
deliberate: this check protects the store, the kernel's protects the
derivation, and neither is entitled to assume the other ran.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from muster.core.authority.grants import (
    AuthorityRegistrySnapshot,
    read_signed_authority_registry_snapshot,
)
from muster.core.authority.revocation import RevocationSnapshot, read_signed_revocation_snapshot
from muster.core.authority.signing import (
    PublisherPreimage,
    PublisherRole,
    PublisherVerifier,
    authority_snapshot_preimage,
    revocation_snapshot_preimage,
)
from muster.core.case.revision import AuthorizationContext
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import Node
from muster.core.wire.shape import decoded
from muster.core.wire.signature import Signature
from muster.platform.casework.ports import (
    DecidingScope,
    Publication,
    PublicationError,
)


class AuthorityResolutionFailure(Enum):
    #: The case pins a snapshot this tenant has never published.
    SNAPSHOT_NOT_BOUND = "SNAPSHOT_NOT_BOUND"
    #: The stored octets are not a readable signed publication.
    SNAPSHOT_UNREADABLE = "SNAPSHOT_UNREADABLE"
    #: The publisher signature does not verify against the trusted keyring.
    SNAPSHOT_SIGNATURE_INVALID = "SNAPSHOT_SIGNATURE_INVALID"
    #: The snapshot inside the verified body is not the one the case pinned.
    SNAPSHOT_DIGEST_MISMATCH = "SNAPSHOT_DIGEST_MISMATCH"
    #: Authority state naming a tenant other than the one reading it.
    SNAPSHOT_TENANT_MISMATCH = "SNAPSHOT_TENANT_MISMATCH"


@dataclass(frozen=True, slots=True)
class AuthorityResolutionError:
    failure: AuthorityResolutionFailure
    detail: str


@dataclass(frozen=True, slots=True)
class ResolvedAuthority:
    """The pair every rebuild of this case is judged against."""

    snapshot: AuthorityRegistrySnapshot
    revocation: RevocationSnapshot


def resolve_authority(
    scope: DecidingScope, context: AuthorizationContext, verifier: PublisherVerifier
) -> Result[ResolvedAuthority, AuthorityResolutionError]:
    """The authority and revocation snapshots this context pins, fully checked."""
    registry = _resolve(
        scope=scope,
        pinned=context.authority_registry_snapshot_digest,
        fetch=scope.authority.read_authority,
        read=_read_authority,
        what="AuthorityRegistrySnapshot",
        verifier=verifier,
    )
    if isinstance(registry, Err):
        return registry
    revocation = _resolve(
        scope=scope,
        pinned=context.revocation_snapshot_digest,
        fetch=scope.authority.read_revocation,
        read=_read_revocation,
        what="RevocationSnapshot",
        verifier=verifier,
    )
    if isinstance(revocation, Err):
        return revocation
    return Ok(ResolvedAuthority(registry.value, revocation.value))


@dataclass(frozen=True, slots=True)
class _Opened[T]:
    """A publication taken apart: what it carries, who signed, over what."""

    snapshot: T
    signer_key_ref: str
    preimage: PublisherPreimage
    signature: Signature
    #: Which publisher role the reader must trust this key for.  Carried with
    #: the preimage rather than chosen at the verification site, so the two
    #: cannot drift apart: an authority body is verified against the authority
    #: keyring or against nothing.
    role: PublisherRole


def _read_authority(node: Node) -> _Opened[AuthorityRegistrySnapshot]:
    signed = read_signed_authority_registry_snapshot(node)
    return _Opened(
        snapshot=signed.body.snapshot,
        signer_key_ref=signed.body.signer_key_ref,
        preimage=authority_snapshot_preimage(signed.body),
        signature=signed.signature,
        role=PublisherRole.AUTHORITY,
    )


def _read_revocation(node: Node) -> _Opened[RevocationSnapshot]:
    signed = read_signed_revocation_snapshot(node)
    return _Opened(
        snapshot=signed.body.snapshot,
        signer_key_ref=signed.body.signer_key_ref,
        #  A different digest domain from the authority body above, which is
        #  what makes a signature over one unusable as a signature over the
        #  other even under a single publisher key.
        preimage=revocation_snapshot_preimage(signed.body),
        signature=signed.signature,
        role=PublisherRole.REVOCATION,
    )


def _resolve[T: (AuthorityRegistrySnapshot, RevocationSnapshot)](
    *,
    scope: DecidingScope,
    pinned: Digest,
    fetch: Callable[[Digest], Result[Publication, PublicationError]],
    read: Callable[[Node], _Opened[T]],
    what: str,
    verifier: PublisherVerifier,
) -> Result[T, AuthorityResolutionError]:
    fetched = fetch(pinned)
    if isinstance(fetched, Err):
        return Err(
            AuthorityResolutionError(
                AuthorityResolutionFailure.SNAPSHOT_NOT_BOUND,
                f"{what}: {fetched.error.failure.value} for {pinned.hex}",
            )
        )
    node = decode(fetched.value.signed_octets)
    if isinstance(node, Err):
        return Err(_unreadable(what, str(node.error)))
    payload = node.value
    try:
        opened = decoded(lambda: read(payload))
    except InvariantViolation as violation:
        #  A typed reader reports an unparseable shape by raising
        #  ``WireDecodeError``, which ``decoded`` turns into a value.  A
        #  *constructor* reports an invariant the parsed shape violates -- a
        #  snapshot binding one key to two principals, two grants on one
        #  ``(key, class)`` pair -- by raising ``InvariantViolation``.  Those
        #  octets came from a store, so that is a finding about the row and has
        #  to reach the caller as a value rather than as an exception on the
        #  rebuild path.
        return Err(_unreadable(what, str(violation)))
    if isinstance(opened, Err):
        return Err(_unreadable(what, str(opened.error)))
    carried = opened.value

    if not verifier.verify(
        role=carried.role,
        key_ref=carried.signer_key_ref,
        preimage=carried.preimage,
        signature=carried.signature,
    ):
        return Err(
            AuthorityResolutionError(
                AuthorityResolutionFailure.SNAPSHOT_SIGNATURE_INVALID,
                f"{what}: {carried.signer_key_ref} did not sign this publication",
            )
        )
    snapshot = carried.snapshot
    if snapshot.digest() != pinned:
        return Err(
            AuthorityResolutionError(
                AuthorityResolutionFailure.SNAPSHOT_DIGEST_MISMATCH,
                f"{what}: stored under {pinned.hex}, carries {snapshot.digest().hex}",
            )
        )
    if snapshot.tenant_id != scope.tenant_id:
        return Err(
            AuthorityResolutionError(
                AuthorityResolutionFailure.SNAPSHOT_TENANT_MISMATCH,
                f"{what}: {snapshot.tenant_id!r} read under {scope.tenant_id!r}",
            )
        )
    return Ok(snapshot)


def _unreadable(what: str, detail: str) -> AuthorityResolutionError:
    return AuthorityResolutionError(
        AuthorityResolutionFailure.SNAPSHOT_UNREADABLE, f"{what}: {detail}"
    )


def published_revocations(
    scope: DecidingScope, verifier: PublisherVerifier
) -> Result[frozenset[str], AuthorityResolutionError]:
    """Every key this tenant has ever withdrawn, from every published snapshot.

    The admission-time counterpart to :func:`resolve_authority`, and a
    deliberately different question.  ``resolve_authority`` answers *"what was
    pinned"* -- the state a revision is derived under, which must not move, or
    replay would stop reproducing.  This answers *"what has been withdrawn"*,
    which is the question a receipt arriving **now** has to face: a key revoked
    after a case was opened is still revoked, and the case's pin predates the
    revocation.

    A union over every publication rather than a lookup of the newest.  Three
    reasons, and the first is the one that matters:

    * **it cannot un-revoke.**  Taking only the newest snapshot would let a
      later publication that omits a key silently re-enable a compromised one.
      Withdrawal is monotone here by construction;
    * **it needs no total order**, so there are no ties to arbitrate -- and
      arbitrating a tie is how a retirement gets silently discarded;
    * **it fails closed**: a snapshot that will not verify is a refusal, not a
      skipped row.

    Every snapshot is signature-verified before it is believed.  An unverified
    one could only ever cause a *refusal*, so believing it would be safe in the
    direction that matters -- but a reader that skipped verification when the
    answer suited it is a reader that has stopped verifying.
    """
    listed = scope.authority.revocations()
    if isinstance(listed, Err):
        return Err(
            AuthorityResolutionError(
                AuthorityResolutionFailure.SNAPSHOT_NOT_BOUND,
                f"RevocationSnapshot: {listed.error.failure.value}",
            )
        )
    revoked: set[str] = set()
    for publication in listed.value:
        opened = _open_revocation(scope, publication, verifier)
        if isinstance(opened, Err):
            return opened
        revoked.update(opened.value.revoked_key_refs)
    return Ok(frozenset(revoked))


def _open_revocation(
    scope: DecidingScope, publication: Publication, verifier: PublisherVerifier
) -> Result[RevocationSnapshot, AuthorityResolutionError]:
    """One stored revocation publication, fully checked.

    The same four checks :func:`resolve_authority` applies -- readable, signed
    by a trusted publisher, hashing to the digest it is filed under, and naming
    this tenant -- because a revocation snapshot is authority state and a
    borrowed one would be another tenant's withdrawal decided here.
    """
    node = decode(publication.signed_octets)
    if isinstance(node, Err):
        return Err(_unreadable("RevocationSnapshot", str(node.error)))
    payload = node.value
    try:
        read = decoded(lambda: _read_revocation(payload))
    except InvariantViolation as violation:
        return Err(_unreadable("RevocationSnapshot", str(violation)))
    if isinstance(read, Err):
        return Err(_unreadable("RevocationSnapshot", str(read.error)))
    carried = read.value

    if not verifier.verify(
        role=PublisherRole.REVOCATION,
        key_ref=carried.signer_key_ref,
        preimage=carried.preimage,
        signature=carried.signature,
    ):
        return Err(
            AuthorityResolutionError(
                AuthorityResolutionFailure.SNAPSHOT_SIGNATURE_INVALID,
                f"RevocationSnapshot: {carried.signer_key_ref} did not sign this publication",
            )
        )
    snapshot = carried.snapshot
    if snapshot.digest() != publication.snapshot_digest:
        return Err(
            AuthorityResolutionError(
                AuthorityResolutionFailure.SNAPSHOT_DIGEST_MISMATCH,
                f"RevocationSnapshot: stored under {publication.snapshot_digest.hex}, "
                f"carries {snapshot.digest().hex}",
            )
        )
    if snapshot.tenant_id != scope.tenant_id:
        return Err(
            AuthorityResolutionError(
                AuthorityResolutionFailure.SNAPSHOT_TENANT_MISMATCH,
                f"RevocationSnapshot: {snapshot.tenant_id!r} read under {scope.tenant_id!r}",
            )
        )
    return Ok(snapshot)
