"""The case revision -- the only thing analysis ever reads.

A revision is *derived*, never authored: it is a pure function of the eight
``RebuildInputs`` fields against an immutable content store.  Nothing here has a
setter, and repinning a policy, advancing ``as_of``, or admitting one more
transcript entry all produce a new revision rather than mutating this one.

Two consequences are load-bearing:

* the authorization context is pinned *inside* the revision, so changing what a
  key is permitted to say changes the revision digest.  There is no field beside
  a signature that an attacker could swap;
* every collection is canonically ordered and key-unique, checked on
  construction.  Two schema-valid members mapping to one key is exactly how a
  commitment ends up binding less than the whole record.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from itertools import pairwise

from muster.core.case.constraints import Constraint, NonEffect, constraint_seq, non_effect_seq
from muster.core.case.facts import EstablishedFact, fact_seq
from muster.core.results import InvariantViolation
from muster.core.values.scalars import Value
from muster.core.values.symbols import SymbolRef, symbol_seq
from muster.core.values.times import HalfOpenInterval, Instant
from muster.core.wire.codec import canonical_order, is_canonically_ordered
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NInt, Node, NRec
from muster.core.wire.shape import digests

TAG_AUTHORIZATION_CONTEXT = "AuthorizationContext/v1"
TAG_REBUILD_INPUTS = "RebuildInputs/v1"
TAG_CASE_REVISION = "CaseRevision/v1"
TAG_TRANSCRIPT_PREFIX = "TranscriptPrefix/v1"


class RebuildMode(Enum):
    """Operational rebuilds may authorize; counterfactual ones never can."""

    OPERATIONAL = "OPERATIONAL"
    COUNTERFACTUAL = "COUNTERFACTUAL"


class Authorizability(Enum):
    AUTHORIZABLE = "AUTHORIZABLE"
    NEVER_AUTHORIZABLE = "NEVER_AUTHORIZABLE"


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """External authority state, pinned once per rebuild.

    Revocation and the key registry are current-state, so they are pinned rather
    than consulted: a revision that was analysed under one revocation snapshot
    cannot silently be re-read under another.
    """

    authorization_policy_version: int
    key_registry_snapshot_digest: Digest
    revocation_snapshot_digest: Digest
    context_validity: HalfOpenInterval

    def to_node(self) -> NRec:
        return NRec(
            TAG_AUTHORIZATION_CONTEXT,
            (
                NInt(self.authorization_policy_version),
                self.key_registry_snapshot_digest.to_node(),
                self.revocation_snapshot_digest.to_node(),
                self.context_validity.to_node(),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.AUTHORIZATION_CONTEXT, self.to_node())


@dataclass(frozen=True, slots=True)
class TranscriptPrefix:
    """The evidence a revision was built from, as a set of entry digests."""

    tenant_id: str
    case_id: str
    entry_digests: tuple[Digest, ...]

    def __post_init__(self) -> None:
        ordered = [digest.octets for digest in self.entry_digests]
        if any(a >= b for a, b in pairwise(ordered)):
            raise InvariantViolation("transcript entry digests must ascend and be unique")

    def to_node(self) -> NRec:
        return NRec(
            TAG_TRANSCRIPT_PREFIX,
            (NAtom(self.tenant_id), NAtom(self.case_id), digests(self.entry_digests)),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.TRANSCRIPT_PREFIX, self.to_node())


@dataclass(frozen=True, slots=True)
class RebuildInputs:
    """The complete input tuple of ``rebuild``. Nothing else may influence it.

    Not on this list, deliberately: the wall clock, the environment, a registry
    handle, and the previous revision.  ``as_of`` and ``mode`` are here because
    they change the result -- a receipt valid until an instant is accepted at
    the microsecond before and rejected at it.
    """

    tenant_id: str
    case_id: str
    construction_digest: Digest
    transcript_prefix_digest: Digest
    bundle_manifest_digest: Digest
    as_of: Instant
    mode: RebuildMode
    authorization_context_digest: Digest

    def to_node(self) -> NRec:
        return NRec(
            TAG_REBUILD_INPUTS,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                self.construction_digest.to_node(),
                self.transcript_prefix_digest.to_node(),
                self.bundle_manifest_digest.to_node(),
                NInt(self.as_of),
                NAtom(self.mode.value),
                self.authorization_context_digest.to_node(),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.REBUILD_INPUTS, self.to_node())


@dataclass(frozen=True, slots=True)
class CaseRevision:
    tenant_id: str
    case_id: str
    construction_digest: Digest
    transcript_prefix_digest: Digest
    bundle_pin: Digest
    as_of: Instant
    mode: RebuildMode
    authorization_context_digest: Digest
    authorizability: Authorizability
    declared: tuple[SymbolRef, ...]
    established: tuple[EstablishedFact, ...]
    constraints: tuple[Constraint, ...]
    non_effects: tuple[NonEffect, ...]

    def __post_init__(self) -> None:
        _require_canonical(self.declared, lambda ref: ref.to_node(), "declared")
        _require_canonical(self.established, lambda fact: fact.to_node(), "established")
        _require_canonical(self.constraints, lambda item: item.to_node(), "constraints")
        _require_canonical(self.non_effects, lambda item: item.to_node(), "non_effects")
        _require_unique((fact.ref for fact in self.established), "established.ref")
        _require_unique((item.label for item in self.constraints), "constraints.label")
        _require_unique(
            ((item.rule_id, item.subject) for item in self.non_effects),
            "non_effects.(rule_id, subject)",
        )

    def to_node(self) -> NRec:
        return NRec(
            TAG_CASE_REVISION,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                self.construction_digest.to_node(),
                self.transcript_prefix_digest.to_node(),
                self.bundle_pin.to_node(),
                NInt(self.as_of),
                NAtom(self.mode.value),
                self.authorization_context_digest.to_node(),
                NAtom(self.authorizability.value),
                symbol_seq(self.declared),
                fact_seq(self.established),
                constraint_seq(self.constraints),
                non_effect_seq(self.non_effects),
            ),
        )

    def digest(self) -> Digest:
        """The semantic digest: the identity every downstream artifact cites."""
        return digest_node(DigestKind.CASE_REVISION, self.to_node())

    def known(self) -> dict[SymbolRef, Value]:
        return {fact.ref: fact.value for fact in self.established}

    def unresolved(self) -> tuple[SymbolRef, ...]:
        """``U`` -- derived, never stored alongside ``established``.

        Storing it would create a second source of truth that can disagree with
        the first.
        """
        settled = {fact.ref for fact in self.established}
        return tuple(ref for ref in self.declared if ref not in settled)


def canonical_declared(refs: Iterable[SymbolRef]) -> tuple[SymbolRef, ...]:
    return canonical_order(refs, lambda ref: ref.to_node())


def canonical_facts(facts: Iterable[EstablishedFact]) -> tuple[EstablishedFact, ...]:
    return canonical_order(facts, lambda fact: fact.to_node())


def canonical_constraints(constraints: Iterable[Constraint]) -> tuple[Constraint, ...]:
    return canonical_order(constraints, lambda item: item.to_node())


def canonical_non_effects(non_effects: Iterable[NonEffect]) -> tuple[NonEffect, ...]:
    return canonical_order(non_effects, lambda item: item.to_node())


def _require_canonical[T](items: tuple[T, ...], as_node: Callable[[T], Node], what: str) -> None:
    if not is_canonically_ordered(items, as_node):
        raise InvariantViolation(f"{what} is not in canonical order")


def _require_unique(keys: Iterable[object], what: str) -> None:
    seen: set[object] = set()
    for key in keys:
        if key in seen:
            raise InvariantViolation(f"duplicate {what}: {key!r}")
        seen.add(key)
