"""The authority registry: one grant is one authorization to say one thing.

``KEY_REGISTRY_SNAPSHOT`` committed to key **existence** -- ``key_ref`` and a
digest of the key material -- so the only question it could answer was "does
this key exist".  The question that decides whether evidence is admissible is
"**may this key say this, here, now**", and nothing authenticated the answer.

An :class:`AuthorityGrant` is that answer, and every element of it is inside
the signature: the key, the institutional principal holding it, the tenant,
exactly one source class, the enumerated predicates, the enumerated resource
scope, the validity window, and the authorization-policy version the grant was
issued under.

Three properties are structural rather than checked at use:

* **one class per grant.**  ``source_class`` is a single ATOM, not a set, so a
  grant that covers two classes is unrepresentable.  Widening a key's authority
  means publishing a second grant, which is a visible act in a signed snapshot;
* **no wildcards, anywhere.**  Both enumerated fields have a minimum of one
  member and :mod:`muster.core.authority.scope` refuses wildcard spellings.  An
  empty set is not "unrestricted", it is unrepresentable;
* **the snapshot is a value.**  Changing what a key may say means publishing a
  new snapshot with a new digest.  There is no ``UPDATE`` that could revise a
  grant under a case that already pinned it.

The snapshot is signed through a generated body carrying the publisher's own
key reference, exactly as a receipt is signed through its payload: the signer's
identity is inside what it signs, so a valid publication cannot be
re-attributed, and there is no security-bearing field beside the signature for
anyone to swap.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise

from muster.core.authority.scope import ResourceScope, read_scope_set, scope_set
from muster.core.results import InvariantViolation, Result
from muster.core.values.times import HalfOpenInterval, Instant, read_half_open
from muster.core.wire.codec import canonical_set, encode
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NInt, Node, NRec, NSeq
from muster.core.wire.shape import (
    WireError,
    decoded,
    read_atom,
    read_int,
    read_rec,
    read_seq,
    read_set,
)
from muster.core.wire.signature import Signature, read_signature

TAG_AUTHORITY_GRANT = "AuthorityGrant/v1"
TAG_AUTHORITY_REGISTRY_SNAPSHOT = "AuthorityRegistrySnapshot/v1"
TAG_AUTHORITY_REGISTRY_SNAPSHOT_BODY = "AuthorityRegistrySnapshotBody/v1"
TAG_SIGNED_AUTHORITY_REGISTRY_SNAPSHOT = "SignedAuthorityRegistrySnapshot/v1"


@dataclass(frozen=True, slots=True)
class AuthorityGrant:
    """One authorization: this key, as this principal, may say these things here."""

    key_ref: str
    principal_id: str
    tenant_scope: str
    source_class: str
    permitted_predicates: tuple[str, ...]
    resource_scope: tuple[ResourceScope, ...]
    validity: HalfOpenInterval
    authorization_policy_version: int

    def __post_init__(self) -> None:
        for name, value in (
            ("key_ref", self.key_ref),
            ("principal_id", self.principal_id),
            ("tenant_scope", self.tenant_scope),
            ("source_class", self.source_class),
        ):
            if not value:
                raise InvariantViolation(f"an authority grant names a {name}")
        if not self.permitted_predicates:
            #  Not "unrestricted": a grant that permits no predicate authorizes
            #  nothing and would be dead weight in a snapshot, so it is refused
            #  where the reading "empty means anything" could otherwise start.
            raise InvariantViolation(
                f"{self.key_ref} holds a grant permitting no predicate; "
                "an empty predicate set is not a wildcard"
            )
        if not self.resource_scope:
            raise InvariantViolation(
                f"{self.key_ref} holds a grant over no resource; "
                "an empty resource scope is not a wildcard"
            )
        if self.authorization_policy_version < 0:
            raise InvariantViolation(
                f"an authorization policy version is not negative: "
                f"{self.authorization_policy_version}"
            )

    def to_node(self) -> NRec:
        return NRec(
            TAG_AUTHORITY_GRANT,
            (
                NAtom(self.key_ref),
                NAtom(self.principal_id),
                NAtom(self.tenant_scope),
                NAtom(self.source_class),
                canonical_set(NAtom(predicate) for predicate in self.permitted_predicates),
                scope_set(self.resource_scope),
                self.validity.to_node(),
                NInt(self.authorization_policy_version),
            ),
        )

    def covers_predicate(self, predicate_id: str) -> bool:
        """Q-12(e), as membership. Exact identifiers, never a prefix."""
        return predicate_id in self.permitted_predicates

    def covers(self, coordinates: Iterable[ResourceScope]) -> bool:
        """Q-12(d), as set inclusion over whole coordinates.

        ``set(...) <= set(...)`` and nothing else: no prefix rule, no
        normalisation, no case folding.  ``site-1`` and ``site-10`` are two
        coordinates and neither reaches the other.
        """
        return set(coordinates) <= set(self.resource_scope)

    def key(self) -> tuple[str, str]:
        """The pair a lookup resolves on: exactly one grant may hold it."""
        return (self.key_ref, self.source_class)


def read_authority_grant(node: Node) -> AuthorityGrant:
    fields = read_rec(node, TAG_AUTHORITY_GRANT, 8)
    return AuthorityGrant(
        key_ref=read_atom(fields[0]),
        principal_id=read_atom(fields[1]),
        tenant_scope=read_atom(fields[2]),
        source_class=read_atom(fields[3]),
        permitted_predicates=read_set(fields[4], read_atom, minimum=1),
        resource_scope=read_scope_set(fields[5], minimum=1),
        validity=read_half_open(fields[6]),
        authorization_policy_version=read_int(fields[7]),
    )


@dataclass(frozen=True, slots=True)
class AuthorityRegistrySnapshot:
    """Every grant in force for one tenant under one authorization-policy version.

    Grants ascend by canonical octets and are unique, checked on construction:
    an unordered collection would give two publishers of the same authority two
    digests, and a duplicated grant would make "exactly one grant matches" a
    statement about the *reader's* iteration order.

    Two further invariants are enforced here rather than at lookup, because a
    snapshot that violates either is malformed and no amount of care at the
    call site can repair it:

    * **at most one grant per ``(key_ref, source_class)``.**  Two matching
      grants mean the publisher disagrees with itself.  Resolving that by
      precedence is how authority systems are defeated -- picking the more
      permissive one grants what nobody wrote, and picking the narrower one
      hides the defect -- so the pair is unique and a second one is refused;
    * **one key belongs to one principal.**  ``key_ref -> principal_id`` is a
      function across the whole snapshot.  Without it, one key could hold a
      SITE grant as one principal and a payroll grant as another, and
      "which institution signed this" would have no answer;
    * **every grant is scoped to the snapshot's own tenant.**  A snapshot for
      one tenant carrying a grant scoped to another was publishable before this
      check, and the admission path would never have seen it: the entry-binding
      check compares the *entry's* tenant to the *case's*, both of which would
      be the publishing tenant, so Q-12(c) was the only thing between a
      mis-scoped grant and an authorization.  Making the state unpublishable is
      the first line; Q-12(c) stays as the second, because octets read back
      from a store went through no constructor an adversary could not also have
      gone around.
    """

    registry_id: str
    tenant_id: str
    authorization_policy_version: int
    grants: tuple[AuthorityGrant, ...]
    published_at: Instant

    def __post_init__(self) -> None:
        if not self.registry_id or not self.tenant_id:
            raise InvariantViolation("an authority registry snapshot names a registry and a tenant")
        encoded = [encode(grant.to_node()) for grant in self.grants]
        if any(a >= b for a, b in pairwise(encoded)):
            raise InvariantViolation(
                "authority grants must ascend by canonical octets and be unique"
            )
        seen: set[tuple[str, str]] = set()
        principals: dict[str, str] = {}
        for grant in self.grants:
            if grant.tenant_scope != self.tenant_id:
                raise InvariantViolation(
                    f"{grant.key_ref!r} is scoped to {grant.tenant_scope!r} "
                    f"in a snapshot for {self.tenant_id!r}"
                )
            if grant.key() in seen:
                raise InvariantViolation(
                    f"two grants bind {grant.key_ref!r} to {grant.source_class!r}; "
                    "ambiguity is not resolved by precedence"
                )
            seen.add(grant.key())
            held = principals.setdefault(grant.key_ref, grant.principal_id)
            if held != grant.principal_id:
                raise InvariantViolation(
                    f"{grant.key_ref!r} is claimed by two principals: {held!r} and "
                    f"{grant.principal_id!r}"
                )

    def to_node(self) -> NRec:
        return NRec(
            TAG_AUTHORITY_REGISTRY_SNAPSHOT,
            (
                NAtom(self.registry_id),
                NAtom(self.tenant_id),
                NInt(self.authorization_policy_version),
                NSeq(tuple(grant.to_node() for grant in self.grants)),
                NInt(self.published_at),
            ),
        )

    def digest(self) -> Digest:
        """What ``AuthorizationContext.authority_registry_snapshot_digest`` names."""
        return digest_node(DigestKind.AUTHORITY_REGISTRY_SNAPSHOT, self.to_node())

    def resolve(self, key_ref: str, source_class: str) -> tuple[AuthorityGrant, ...]:
        """Every grant matching the pair. Q-12(b) accepts exactly one.

        Returns the whole match set rather than an optional grant, so the
        caller distinguishes "no grant" from "an ambiguous snapshot" and
        reports two different failures instead of one.  The constructor already
        refuses a snapshot in which this can return more than one; the lookup
        still says so, because a snapshot decoded from a store went around no
        constructor an attacker could not also go around.
        """
        return tuple(
            grant
            for grant in self.grants
            if grant.key_ref == key_ref and grant.source_class == source_class
        )

    def principal_for(self, key_ref: str) -> str | None:
        """The single institutional principal this snapshot binds the key to.

        This snapshot *is* the source directory: a key's expected principal is
        the one its own grants name, and the constructor guarantees they agree.
        ``None`` means the snapshot knows no such key.
        """
        for grant in self.grants:
            if grant.key_ref == key_ref:
                return grant.principal_id
        return None


def read_authority_registry_snapshot(node: Node) -> AuthorityRegistrySnapshot:
    registry_id, tenant_id, version, grants, published_at = read_rec(
        node, TAG_AUTHORITY_REGISTRY_SNAPSHOT, 5
    )
    return AuthorityRegistrySnapshot(
        registry_id=read_atom(registry_id),
        tenant_id=read_atom(tenant_id),
        authorization_policy_version=read_int(version),
        grants=read_seq(grants, read_authority_grant),
        published_at=read_int(published_at),
    )


@dataclass(frozen=True, slots=True)
class AuthorityRegistrySnapshotBody:
    """The exact value a publisher signature covers.

    The publisher's own key reference is inside it, so the snapshot and the
    identity that published it cannot disagree, and a valid publication cannot
    be re-attributed to another publisher by rewriting a field beside the
    signature.  This is the *publisher* boundary and not the source boundary: a
    control plane publishing who may attest is not thereby a source that may
    attest, and the two key sets are disjoint by deployment.
    """

    snapshot: AuthorityRegistrySnapshot
    signer_key_ref: str

    def __post_init__(self) -> None:
        if not self.signer_key_ref:
            raise InvariantViolation("an authority registry publication names its signer")

    def to_node(self) -> NRec:
        return NRec(
            TAG_AUTHORITY_REGISTRY_SNAPSHOT_BODY,
            (self.snapshot.to_node(), NAtom(self.signer_key_ref)),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.AUTHORITY_REGISTRY_SNAPSHOT_BODY, self.to_node())


def read_authority_registry_snapshot_body(node: Node) -> AuthorityRegistrySnapshotBody:
    snapshot, signer_key_ref = read_rec(node, TAG_AUTHORITY_REGISTRY_SNAPSHOT_BODY, 2)
    return AuthorityRegistrySnapshotBody(
        snapshot=read_authority_registry_snapshot(snapshot),
        signer_key_ref=read_atom(signer_key_ref),
    )


@dataclass(frozen=True, slots=True)
class SignedAuthorityRegistrySnapshot:
    """A published snapshot, as the body and the signature over it."""

    body: AuthorityRegistrySnapshotBody
    signature: Signature

    def to_node(self) -> NRec:
        return NRec(
            TAG_SIGNED_AUTHORITY_REGISTRY_SNAPSHOT,
            (self.body.to_node(), self.signature.to_node()),
        )


def read_signed_authority_registry_snapshot(node: Node) -> SignedAuthorityRegistrySnapshot:
    body, signature = read_rec(node, TAG_SIGNED_AUTHORITY_REGISTRY_SNAPSHOT, 2)
    return SignedAuthorityRegistrySnapshot(
        body=read_authority_registry_snapshot_body(body), signature=read_signature(signature)
    )


def decode_signed_authority_registry_snapshot(
    node: Node,
) -> Result[SignedAuthorityRegistrySnapshot, WireError]:
    return decoded(lambda: read_signed_authority_registry_snapshot(node))


def canonical_grants(grants: Iterable[AuthorityGrant]) -> tuple[AuthorityGrant, ...]:
    """Grants in the order a snapshot holds them: ascending by canonical octets."""
    return tuple(sorted(grants, key=lambda grant: encode(grant.to_node())))
