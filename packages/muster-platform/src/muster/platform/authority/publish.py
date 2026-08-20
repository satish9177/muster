"""Publishing authority and revocation snapshots.

The one gate an agent can never get through.  A snapshot reaching this function
must already be signed by a key in the reader's **publisher** keyring, and the
signature is checked here rather than at read time as well as at read time --
because a row that was never valid should not exist, and a store holding
unverifiable authority is a store somebody will eventually read past a broken
check.

Publication is idempotent by content.  Two publications of one snapshot keep
the first: the octets differ only in the signature, ECDSA is randomised, and
choosing the later one would mean an auditor who verified a publication
yesterday is handed different octets today.

There is no ``update`` and no ``revoke_grant``.  Withdrawing authority is
publishing a successor snapshot -- a new digest, a new artifact, and no effect
whatever on a case that pinned the predecessor.  That is the whole of the
immutability discipline milestone C established, applied to the artifact that
decides who may speak.

**Publishing also moves the publication state, and that is G7 [section 20.2].**
A successor has no effect on a case that pinned the predecessor -- that is the
sentence above and it still holds -- but it must have an effect on a case that
has not been opened yet, or "withdrawing a grant" would be something a new case
could decline to notice by pinning the snapshot that still had it.  So one
transaction does both: the snapshot becomes durable, and the row naming what a
*new* case may open under becomes this snapshot.  The publisher named in G7 is
this module, its cadence is "whenever authority changes", and the staleness
bound it enforces is zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.authority.grants import (
    AuthorityRegistrySnapshot,
    AuthorityRegistrySnapshotBody,
    SignedAuthorityRegistrySnapshot,
)
from muster.core.authority.revocation import (
    RevocationSnapshot,
    RevocationSnapshotBody,
    SignedRevocationSnapshot,
)
from muster.core.authority.signing import (
    PublisherRole,
    PublisherSigner,
    PublisherVerifier,
    authority_snapshot_preimage,
    revocation_snapshot_preimage,
)
from muster.core.results import Err, Ok, Result
from muster.core.values.times import Instant
from muster.core.wire.codec import encode
from muster.platform.casework.ports import (
    CaseworkDatabase,
    Publication,
    PublicationError,
    TenantScope,
)


class PublishAuthorityFailure(Enum):
    #: The snapshot names a tenant other than the one publishing it.
    TENANT_MISMATCH = "TENANT_MISMATCH"
    #: The publisher signature does not verify against the trusted keyring.
    #: Covers a tampered snapshot, a wrong signer, an unknown signer and a
    #: signature over a different version -- all of which are one statement to
    #: a reader: this is not a publication.
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    STORE_REFUSED = "STORE_REFUSED"


@dataclass(frozen=True, slots=True)
class PublishAuthorityRejection:
    failure: PublishAuthorityFailure
    detail: str


@dataclass(frozen=True, slots=True)
class AuthorityPublisher:
    """Everything publishing authority needs. Holds no state.

    The signer and the verifier are separate collaborators even though a local
    deployment could derive one from the other: publishing checks its own work
    against the keyring a *reader* would use, so a publisher configured with a
    key nobody trusts fails at publication rather than at the first rebuild
    that needed the snapshot.
    """

    database: CaseworkDatabase
    signer: PublisherSigner
    verifier: PublisherVerifier


def publish_authority_snapshot(
    publisher: AuthorityPublisher,
    *,
    tenant_id: str,
    snapshot: AuthorityRegistrySnapshot,
    now: Instant,
) -> Result[SignedAuthorityRegistrySnapshot, PublishAuthorityRejection]:
    """Sign, verify and store an authority registry snapshot."""
    if snapshot.tenant_id != tenant_id:
        return Err(
            PublishAuthorityRejection(
                PublishAuthorityFailure.TENANT_MISMATCH,
                f"{snapshot.tenant_id!r} published under {tenant_id!r}",
            )
        )
    body = AuthorityRegistrySnapshotBody(snapshot, publisher.signer.key_ref)
    preimage = authority_snapshot_preimage(body)
    signed = SignedAuthorityRegistrySnapshot(body, publisher.signer.sign(preimage))
    if not publisher.verifier.verify(
        role=PublisherRole.AUTHORITY,
        key_ref=body.signer_key_ref,
        preimage=preimage,
        signature=signed.signature,
    ):
        return Err(
            PublishAuthorityRejection(
                PublishAuthorityFailure.SIGNATURE_INVALID,
                f"{body.signer_key_ref} is not a trusted publisher",
            )
        )
    stored = _store(
        publisher.database,
        tenant_id,
        Publication(snapshot.digest(), encode(signed.to_node()), now),
        authority=True,
    )
    if isinstance(stored, Err):
        return Err(stored.error)
    return Ok(signed)


def publish_revocation_snapshot(
    publisher: AuthorityPublisher,
    *,
    tenant_id: str,
    snapshot: RevocationSnapshot,
    now: Instant,
) -> Result[SignedRevocationSnapshot, PublishAuthorityRejection]:
    """Sign, verify and store a revocation snapshot."""
    if snapshot.tenant_id != tenant_id:
        return Err(
            PublishAuthorityRejection(
                PublishAuthorityFailure.TENANT_MISMATCH,
                f"{snapshot.tenant_id!r} published under {tenant_id!r}",
            )
        )
    body = RevocationSnapshotBody(snapshot, publisher.signer.key_ref)
    preimage = revocation_snapshot_preimage(body)
    signed = SignedRevocationSnapshot(body, publisher.signer.sign(preimage))
    if not publisher.verifier.verify(
        role=PublisherRole.REVOCATION,
        key_ref=body.signer_key_ref,
        preimage=preimage,
        signature=signed.signature,
    ):
        return Err(
            PublishAuthorityRejection(
                PublishAuthorityFailure.SIGNATURE_INVALID,
                f"{body.signer_key_ref} is not a trusted publisher",
            )
        )
    stored = _store(
        publisher.database,
        tenant_id,
        Publication(snapshot.digest(), encode(signed.to_node()), now),
        authority=False,
    )
    if isinstance(stored, Err):
        return Err(stored.error)
    return Ok(signed)


class _Rejected(Exception):
    """Roll the publication back and report. Never leaves this module.

    A ``return`` out of a transaction block is a *normal* exit and **commits**.
    ``_write`` inserts the snapshot and then names it in the publication state,
    so a rejection returned as a value between those two steps would leave the
    snapshot durable with the pointer never moved -- a published successor that
    is not in force, which is the exact staleness this module exists to remove.

    The failure is not reachable through today's adapters (an upsert with
    ``RETURNING`` always returns a row), and that is precisely why it is worth
    closing now: it is one new error path in ``_write`` away from being live,
    and the defect it would produce is silent. ``casework.commands`` uses the
    same discipline for the same reason, and states it at its module head.
    """

    def __init__(self, error: PublicationError) -> None:
        super().__init__(f"{error.failure.value}: {error.detail}")
        self.error = error


def _store(
    database: CaseworkDatabase, tenant_id: str, publication: Publication, *, authority: bool
) -> Result[bool, PublishAuthorityRejection]:
    try:
        with database.writing(tenant_id) as scope:
            written = _write(scope, publication, authority=authority)
            if isinstance(written, Err):
                raise _Rejected(written.error)
            created = written.value
    except _Rejected as rejection:
        return Err(
            PublishAuthorityRejection(
                PublishAuthorityFailure.STORE_REFUSED,
                f"{rejection.error.failure.value}: {rejection.error.detail}",
            )
        )
    return Ok(created)


def _write(
    scope: TenantScope, publication: Publication, *, authority: bool
) -> Result[bool, PublicationError]:
    """Make the snapshot durable **and** move the publication state, together.

    One transaction, and the whole of both G7 obligations rests on that.

    *Freshness.*  Publishing a registry snapshot is what makes it the one new
    cases must open under, so the row that says so moves here rather than in a
    second call an operator could forget: an authority publication that did not
    become current would leave "the authority in force" naming a snapshot the
    publisher had already replaced, which is precisely the staleness this
    closes.

    *Ordering.*  The epoch advance takes the publication-state row
    **exclusively**, and admission holds it in share mode for the length of its
    own transaction.  So an admission either commits before this transaction
    takes the row, or it starts after this one committed and reads the
    revocation state this one published.  There is no schedule in which an
    admission reads the old revocation state and commits after the new one is
    durable -- which is exactly the race read-committed leaves open, and the
    reason the lock is taken here and not merely documented.

    A revocation publication names a revocation list without naming a registry,
    and the registry branch is the mirror image: each successor replaces only
    its own kind, and each advances the epoch.  A case may open only when both
    are present and both are the current ones -- see ``_open``.
    """
    if authority:
        stored = scope.authority.publish_authority(publication)
        if isinstance(stored, Err):
            return stored
        #  After the snapshot is durable, never before: the state names a
        #  snapshot by digest under a foreign key, so a pointer written first
        #  would name a row that does not exist yet.
        in_force = scope.authority.set_in_force_authority(publication.snapshot_digest)
        if isinstance(in_force, Err):
            return in_force
        return stored
    stored = scope.authority.publish_revocation(publication)
    if isinstance(stored, Err):
        return stored
    #  The revocation half of the freshness state, and it advances the epoch on
    #  the way past -- so this one call does both G7 jobs, exactly as the
    #  registry branch above does.  There is no ``advance_epoch`` here any more:
    #  a publication that moved the epoch without moving what is in force would
    #  be a lock taken for a change nobody recorded.
    in_force = scope.authority.set_in_force_revocation(publication.snapshot_digest)
    if isinstance(in_force, Err):
        return in_force
    return stored
