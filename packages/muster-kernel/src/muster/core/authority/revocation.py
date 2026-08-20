"""The revocation snapshot: keys whose grants no longer hold.

Revocation is *current* state, so it is pinned rather than consulted.  A
revision names one revocation snapshot by digest inside its authorization
context, and that pin sits inside the revision digest -- so re-reading a
historical case under today's revocation list is not something an
implementation can do by accident.  It would change the revision digest, and
the head names the digest it published.

**Revocation is not retroactive, and that is the ratified semantics rather
than a convenience.**  Q-12(f) evaluates against ``revision.as_of`` and against
the snapshots the revision pinned.  A case decided in March under a snapshot
that did not revoke a key replays in December to the same answer, because it
replays against March's pins.  A case being decided *now* pins the current
snapshot and obeys it.  Making revocation reach backwards would mean a
published case could change its outcome without any new evidence and without
any new revision, which is the property the whole design exists to deny.

**Why this is a tenant-bound signed artifact rather than a bare digest list.**
A snapshot has to be *resolved* before Q-12(f) can ask whether a key is in it,
and something resolved by digest alone can be borrowed: an untenanted list of
key references is equally valid under every tenant, and a publisher's
revocation of a key in tenant A would be indistinguishable from the same octets
offered as tenant B's list.  Binding the tenant and the publisher inside the
signed body is what makes "this tenant revoked this key" a statement with an
author.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

from muster.core.results import InvariantViolation, Result
from muster.core.values.times import Instant
from muster.core.wire.codec import canonical_set
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NInt, Node, NRec
from muster.core.wire.shape import WireError, decoded, read_atom, read_int, read_rec, read_set
from muster.core.wire.signature import Signature, read_signature

TAG_REVOCATION_SNAPSHOT = "RevocationSnapshot/v1"
TAG_REVOCATION_SNAPSHOT_BODY = "RevocationSnapshotBody/v1"
TAG_SIGNED_REVOCATION_SNAPSHOT = "SignedRevocationSnapshot/v1"


@dataclass(frozen=True, slots=True)
class RevocationSnapshot:
    """The signing keys this tenant has withdrawn, as of ``published_at``.

    An empty snapshot is a real and normal value -- "nothing is revoked" -- and
    is not the same thing as an absent one.  Absence fails closed at
    resolution, because a rebuild that could not find the revocation list it
    pinned has not established that a key is unrevoked; it has established that
    it does not know.
    """

    registry_id: str
    tenant_id: str
    revoked_key_refs: tuple[str, ...]
    published_at: Instant

    def __post_init__(self) -> None:
        if not self.registry_id or not self.tenant_id:
            raise InvariantViolation("a revocation snapshot names a registry and a tenant")
        if any(a >= b for a, b in pairwise(self.revoked_key_refs)):
            raise InvariantViolation("revoked key references must ascend and be unique")

    def to_node(self) -> NRec:
        return NRec(
            TAG_REVOCATION_SNAPSHOT,
            (
                NAtom(self.registry_id),
                NAtom(self.tenant_id),
                canonical_set(NAtom(key_ref) for key_ref in self.revoked_key_refs),
                NInt(self.published_at),
            ),
        )

    def digest(self) -> Digest:
        """What ``AuthorizationContext.revocation_snapshot_digest`` names."""
        return digest_node(DigestKind.REVOCATION_SNAPSHOT, self.to_node())

    def revokes(self, key_ref: str) -> bool:
        return key_ref in self.revoked_key_refs


def read_revocation_snapshot(node: Node) -> RevocationSnapshot:
    registry_id, tenant_id, revoked, published_at = read_rec(node, TAG_REVOCATION_SNAPSHOT, 4)
    return RevocationSnapshot(
        registry_id=read_atom(registry_id),
        tenant_id=read_atom(tenant_id),
        revoked_key_refs=read_set(revoked, read_atom),
        published_at=read_int(published_at),
    )


@dataclass(frozen=True, slots=True)
class RevocationSnapshotBody:
    """What a publisher signature over a revocation snapshot covers."""

    snapshot: RevocationSnapshot
    signer_key_ref: str

    def __post_init__(self) -> None:
        if not self.signer_key_ref:
            raise InvariantViolation("a revocation publication names its signer")

    def to_node(self) -> NRec:
        return NRec(
            TAG_REVOCATION_SNAPSHOT_BODY,
            (self.snapshot.to_node(), NAtom(self.signer_key_ref)),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.REVOCATION_SNAPSHOT_BODY, self.to_node())


def read_revocation_snapshot_body(node: Node) -> RevocationSnapshotBody:
    snapshot, signer_key_ref = read_rec(node, TAG_REVOCATION_SNAPSHOT_BODY, 2)
    return RevocationSnapshotBody(
        snapshot=read_revocation_snapshot(snapshot), signer_key_ref=read_atom(signer_key_ref)
    )


@dataclass(frozen=True, slots=True)
class SignedRevocationSnapshot:
    body: RevocationSnapshotBody
    signature: Signature

    def to_node(self) -> NRec:
        return NRec(TAG_SIGNED_REVOCATION_SNAPSHOT, (self.body.to_node(), self.signature.to_node()))


def read_signed_revocation_snapshot(node: Node) -> SignedRevocationSnapshot:
    body, signature = read_rec(node, TAG_SIGNED_REVOCATION_SNAPSHOT, 2)
    return SignedRevocationSnapshot(
        body=read_revocation_snapshot_body(body), signature=read_signature(signature)
    )


def decode_signed_revocation_snapshot(node: Node) -> Result[SignedRevocationSnapshot, WireError]:
    return decoded(lambda: read_signed_revocation_snapshot(node))
