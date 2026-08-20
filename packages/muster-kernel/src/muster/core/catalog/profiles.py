"""Agent profiles and the catalog snapshot that publishes them.

A profile is a **routing fact**: this institutional agent exists, it belongs to
this principal in this tenant, it presents itself as this source class, it can
be asked to acquire these predicates over these enumerated resources, it is
reachable at this reference, and it is in this lifecycle state.

It is deliberately *not* a capability grant, and three decisions keep it from
becoming one by accident:

* a profile carries no validity interval, no permitted-predicate *authority*,
  and no key.  It names an ``endpoint_ref`` and a ``principal_id``; it does not
  name the key that will sign, because a catalog able to say "and this key
  speaks for it" would be a second authority registry with weaker rules;
* the catalog snapshot references the authority snapshot it was published
  against by digest.  That reference is a **provenance record**, not an input
  to any authority decision: Q-12 resolves its snapshot from the revision's
  authorization context and takes no catalog argument at all, so a catalog
  pointing at a different snapshot cannot move a single authority answer;
* publication is a control-plane act signed by a publisher key, exactly like
  the authority registry.  An agent cannot publish its own profile, so
  "I am SITE_B and I can attest attendance" is not a sentence the system has a
  way to hear.

Kept minimal on purpose.  There is no metadata map, no capability expression
language, no health field, no tag set and no plugin descriptor.  Every one of
those would be a place for a caller to put something a reader might later treat
as permission.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import pairwise

from muster.core.authority.scope import ResourceScope, read_scope_set, scope_set
from muster.core.results import InvariantViolation, Result
from muster.core.values.times import Instant
from muster.core.wire.codec import canonical_set, encode
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NInt, Node, NRec, NSeq
from muster.core.wire.shape import (
    WireError,
    decoded,
    read_atom,
    read_digest,
    read_int,
    read_member,
    read_rec,
    read_seq,
    read_set,
)
from muster.core.wire.signature import Signature, read_signature

TAG_AGENT_PROFILE = "AgentProfile/v1"
TAG_AGENT_CATALOG_SNAPSHOT = "AgentCatalogSnapshot/v1"
TAG_AGENT_CATALOG_SNAPSHOT_BODY = "AgentCatalogSnapshotBody/v1"
TAG_SIGNED_AGENT_CATALOG_SNAPSHOT = "SignedAgentCatalogSnapshot/v1"


class AgentLifecycle(Enum):
    """Whether an agent is a candidate for routing today.

    Two states and no third.  ``RETIRED`` profiles stay in the snapshot rather
    than being deleted, because a catalog is published as a whole and a reader
    comparing two snapshots should be able to see that an agent went away
    rather than infer it from an absence.  Discovery skips them.
    """

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


_LIFECYCLES = frozenset(member.value for member in AgentLifecycle)


@dataclass(frozen=True, slots=True)
class AgentProfile:
    """One institutional agent, at one version, as a routing candidate."""

    agent_id: str
    version: int
    tenant_id: str
    principal_id: str
    source_class: str
    acquirable_predicates: tuple[str, ...]
    resource_scope: tuple[ResourceScope, ...]
    endpoint_ref: str
    lifecycle: AgentLifecycle

    def __post_init__(self) -> None:
        for name, value in (
            ("agent_id", self.agent_id),
            ("tenant_id", self.tenant_id),
            ("principal_id", self.principal_id),
            ("source_class", self.source_class),
            ("endpoint_ref", self.endpoint_ref),
        ):
            if not value:
                raise InvariantViolation(f"an agent profile names a {name}")
        if self.version < 1:
            raise InvariantViolation(f"an agent profile version starts at 1: {self.version}")
        if not self.acquirable_predicates:
            #  An agent that can acquire nothing is not a routing candidate,
            #  and an empty set here is the same "absence means everything"
            #  hazard the authority registry refuses for the same reason.
            raise InvariantViolation(f"{self.agent_id} declares no acquirable predicate")
        if not self.resource_scope:
            raise InvariantViolation(f"{self.agent_id} declares no resource scope")

    def to_node(self) -> NRec:
        return NRec(
            TAG_AGENT_PROFILE,
            (
                NAtom(self.agent_id),
                NInt(self.version),
                NAtom(self.tenant_id),
                NAtom(self.principal_id),
                NAtom(self.source_class),
                canonical_set(NAtom(predicate) for predicate in self.acquirable_predicates),
                scope_set(self.resource_scope),
                NAtom(self.endpoint_ref),
                NAtom(self.lifecycle.value),
            ),
        )

    def identity(self) -> tuple[str, int]:
        """``(agent_id, version)`` -- what a snapshot requires to be unique."""
        return (self.agent_id, self.version)


def read_agent_profile(node: Node) -> AgentProfile:
    fields = read_rec(node, TAG_AGENT_PROFILE, 9)
    return AgentProfile(
        agent_id=read_atom(fields[0]),
        version=read_int(fields[1]),
        tenant_id=read_atom(fields[2]),
        principal_id=read_atom(fields[3]),
        source_class=read_atom(fields[4]),
        acquirable_predicates=read_set(fields[5], read_atom, minimum=1),
        resource_scope=read_scope_set(fields[6], minimum=1),
        endpoint_ref=read_atom(fields[7]),
        lifecycle=AgentLifecycle(read_member(fields[8], _LIFECYCLES, "AgentLifecycle")),
    )


@dataclass(frozen=True, slots=True)
class AgentCatalogSnapshot:
    """Every profile a tenant publishes, as one immutable versioned artifact.

    Profiles ascend by canonical octets and are unique by ``(agent_id,
    version)``.  Two profiles sharing that pair would make discovery's answer
    depend on iteration order, and an ambiguous route is refused rather than
    arbitrated -- the same rule the authority registry applies to two grants on
    one key, for the same reason.

    A stronger rule applies to *active* profiles: one agent identifier may have
    at most one ``ACTIVE`` version at a time.  Two live versions of one agent
    is an operator mid-rollout, and routing to whichever one sorted first would
    make the choice invisible.
    """

    catalog_id: str
    tenant_id: str
    profiles: tuple[AgentProfile, ...]
    published_at: Instant
    #: Provenance only.  Which authority snapshot this catalog was published
    #: against, so an operator can see the two together.  Nothing reads it to
    #: decide authority -- Q-12 takes no catalog argument.
    authority_registry_snapshot_digest: Digest

    def __post_init__(self) -> None:
        if not self.catalog_id or not self.tenant_id:
            raise InvariantViolation("an agent catalog snapshot names a catalog and a tenant")
        encoded = [encode(profile.to_node()) for profile in self.profiles]
        if any(a >= b for a, b in pairwise(encoded)):
            raise InvariantViolation("agent profiles must ascend by canonical octets and be unique")
        identities: set[tuple[str, int]] = set()
        live: set[str] = set()
        for profile in self.profiles:
            if profile.tenant_id != self.tenant_id:
                raise InvariantViolation(
                    f"{profile.agent_id} names {profile.tenant_id!r} in a catalog "
                    f"for {self.tenant_id!r}"
                )
            if profile.identity() in identities:
                raise InvariantViolation(
                    f"two profiles are {profile.agent_id!r} version {profile.version}"
                )
            identities.add(profile.identity())
            if profile.lifecycle is AgentLifecycle.ACTIVE:
                if profile.agent_id in live:
                    raise InvariantViolation(
                        f"{profile.agent_id!r} has two active versions; "
                        "an ambiguous route is refused, not arbitrated"
                    )
                live.add(profile.agent_id)

    def to_node(self) -> NRec:
        return NRec(
            TAG_AGENT_CATALOG_SNAPSHOT,
            (
                NAtom(self.catalog_id),
                NAtom(self.tenant_id),
                NSeq(tuple(profile.to_node() for profile in self.profiles)),
                NInt(self.published_at),
                self.authority_registry_snapshot_digest.to_node(),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.AGENT_CATALOG_SNAPSHOT, self.to_node())

    def active(self) -> tuple[AgentProfile, ...]:
        return tuple(
            profile for profile in self.profiles if profile.lifecycle is AgentLifecycle.ACTIVE
        )


def read_agent_catalog_snapshot(node: Node) -> AgentCatalogSnapshot:
    catalog_id, tenant_id, profiles, published_at, authority_digest = read_rec(
        node, TAG_AGENT_CATALOG_SNAPSHOT, 5
    )
    return AgentCatalogSnapshot(
        catalog_id=read_atom(catalog_id),
        tenant_id=read_atom(tenant_id),
        profiles=read_seq(profiles, read_agent_profile),
        published_at=read_int(published_at),
        authority_registry_snapshot_digest=read_digest(authority_digest),
    )


@dataclass(frozen=True, slots=True)
class AgentCatalogSnapshotBody:
    """What a catalog publisher signature covers.

    The catalog publisher is not the source principal and not the authority
    publisher.  Three roles, three key sets: an agent that could sign this
    would be publishing its own routing entry, and a source that could sign it
    would be one step from publishing its own grant.
    """

    snapshot: AgentCatalogSnapshot
    signer_key_ref: str

    def __post_init__(self) -> None:
        if not self.signer_key_ref:
            raise InvariantViolation("a catalog publication names its signer")

    def to_node(self) -> NRec:
        return NRec(
            TAG_AGENT_CATALOG_SNAPSHOT_BODY,
            (self.snapshot.to_node(), NAtom(self.signer_key_ref)),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.AGENT_CATALOG_SNAPSHOT_BODY, self.to_node())


def read_agent_catalog_snapshot_body(node: Node) -> AgentCatalogSnapshotBody:
    snapshot, signer_key_ref = read_rec(node, TAG_AGENT_CATALOG_SNAPSHOT_BODY, 2)
    return AgentCatalogSnapshotBody(
        snapshot=read_agent_catalog_snapshot(snapshot), signer_key_ref=read_atom(signer_key_ref)
    )


@dataclass(frozen=True, slots=True)
class SignedAgentCatalogSnapshot:
    body: AgentCatalogSnapshotBody
    signature: Signature

    def to_node(self) -> NRec:
        return NRec(
            TAG_SIGNED_AGENT_CATALOG_SNAPSHOT, (self.body.to_node(), self.signature.to_node())
        )


def read_signed_agent_catalog_snapshot(node: Node) -> SignedAgentCatalogSnapshot:
    body, signature = read_rec(node, TAG_SIGNED_AGENT_CATALOG_SNAPSHOT, 2)
    return SignedAgentCatalogSnapshot(
        body=read_agent_catalog_snapshot_body(body), signature=read_signature(signature)
    )


def decode_signed_agent_catalog_snapshot(
    node: Node,
) -> Result[SignedAgentCatalogSnapshot, WireError]:
    return decoded(lambda: read_signed_agent_catalog_snapshot(node))


def canonical_profiles(profiles: tuple[AgentProfile, ...]) -> tuple[AgentProfile, ...]:
    return tuple(sorted(profiles, key=lambda profile: encode(profile.to_node())))
