"""The frozen commitment-path inventory, and the extractor that is its meaning.

Two things have to be true at once for a commitment to bind anything.  The leaf
set must be **decided by the record**, not by whoever builds the tree -- so
:func:`extract` is total and its output *is* the leaf set, with no discretion
anywhere about what gets committed.  And the *names* of the leaves must be
fixed in advance, so that "this path was not disclosed" is a statement about a
known universe rather than about whatever the writer chose to enumerate.
:data:`INVENTORY` is that universe, frozen per certificate schema version.

    path    ::= segment ( "." segment )*
    segment ::= [A-Za-z0-9_:-]{1,64}

A collection contributes one leaf per member, under a **dynamic** segment: the
lowercase hex of a domain-separated digest of the member's identifying key.
That is total, injective, fixed-width, inside the charset, and -- the reason it
is a digest rather than the key itself -- it does not spell out the identifier
of an item nobody was shown.  A reader of a redacted view learns that the
revision established *some* fact, not which proposition it was about.

Injectivity is not assumed.  Two members mapping to one path would silently
drop a leaf, leaving a tree that is internally consistent and no longer binds
the whole record; :class:`DuplicateCommitmentPath` refuses that rather than
letting the smaller tree be published.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from muster.core.analysis.certificate import AnalysisCertificate
from muster.core.analysis.outcomes import (
    Divergent,
    Indeterminate,
    Infeasible,
    Invariant,
    outcome_class,
    reachable_node,
)
from muster.core.analysis.planning import planning_node, support_node
from muster.core.case.constraints import Constraint, NonEffect
from muster.core.case.facts import EstablishedFact
from muster.core.case.revision import CaseRevision
from muster.core.results import Err, Ok, Result
from muster.core.values.symbols import symbol_seq
from muster.core.wire.codec import encode
from muster.core.wire.digests import DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NInt, Node, NSeq
from muster.core.wire.shape import option_node
from muster.platform.commit.domains import CommitmentDomain, unkeyed_digest

#: The inventory is frozen per certificate schema version.  A record built
#: under another version is a different universe of paths and is refused rather
#: than extracted under this one.
CERTIFICATE_SCHEMA_VERSION = 1

_SEGMENT = re.compile(r"^[A-Za-z0-9_:-]{1,64}$")
_HEX = frozenset("0123456789abcdef")
_DYNAMIC_SEGMENT_WIDTH = 64


class Presence(Enum):
    """When a path appears in the leaf set.

    ``ALWAYS`` is decidable by a reader who holds nothing; the four outcome
    classes are decidable by a reader who was shown ``kernel.outcome.tag``.
    That distinction is what lets the reader-side check demand a leaf the
    writer left out, instead of only refusing one it added.
    """

    ALWAYS = "always"
    INVARIANT = "INVARIANT"
    DIVERGENT = "DIVERGENT"
    INFEASIBLE = "INFEASIBLE"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class PathSpec:
    path: str
    declared_type: str
    presence: Presence
    #: A prefix that collections hang members off, rather than a leaf itself.
    dynamic: bool = False
    #: True when presence also depends on the record carrying an optional
    #: value, so a reader cannot decide it from the outcome class alone.
    optional_in_record: bool = False


INVENTORY: tuple[PathSpec, ...] = (
    PathSpec("case.tenant_id", "ATOM", Presence.ALWAYS),
    PathSpec("case.case_id", "ATOM", Presence.ALWAYS),
    PathSpec("certificate.schema_version", "INT", Presence.ALWAYS),
    PathSpec("bundle.manifest_digest", "DIGEST", Presence.ALWAYS),
    PathSpec("revision.construction_digest", "DIGEST", Presence.ALWAYS),
    PathSpec("revision.transcript_prefix_digest", "DIGEST", Presence.ALWAYS),
    PathSpec("revision.bundle_pin", "DIGEST", Presence.ALWAYS),
    PathSpec("revision.as_of", "Instant", Presence.ALWAYS),
    PathSpec("revision.mode", "ATOM", Presence.ALWAYS),
    PathSpec("revision.authorization_context_digest", "DIGEST", Presence.ALWAYS),
    PathSpec("revision.authorizability", "ATOM", Presence.ALWAYS),
    PathSpec("revision.declared", "SEQ[SymbolRef]", Presence.ALWAYS),
    PathSpec("revision.established", "EstablishedFact", Presence.ALWAYS, dynamic=True),
    PathSpec("revision.constraints", "Constraint", Presence.ALWAYS, dynamic=True),
    PathSpec("revision.non_effects", "NonEffect", Presence.ALWAYS, dynamic=True),
    PathSpec("kernel.logical_case_digest", "DIGEST", Presence.ALWAYS),
    PathSpec("kernel.determinism_class", "ATOM", Presence.ALWAYS),
    PathSpec("kernel.fingerprint", "SolverFingerprint", Presence.ALWAYS),
    PathSpec("kernel.outcome.tag", "ATOM", Presence.ALWAYS),
    PathSpec("kernel.outcome.action", "ConsequentialAction", Presence.INVARIANT),
    PathSpec("kernel.outcome.witness", "World", Presence.INVARIANT),
    PathSpec("kernel.outcome.reachable", "ReachableActions", Presence.DIVERGENT),
    PathSpec("kernel.outcome.left", "World", Presence.DIVERGENT),
    PathSpec("kernel.outcome.right", "World", Presence.DIVERGENT),
    PathSpec("kernel.outcome.contributing", "SEQ[ATOM]", Presence.INFEASIBLE),
    PathSpec("kernel.outcome.reason", "ATOM", Presence.INDETERMINATE),
    #  The only path whose presence a reader cannot decide.  The kernel record
    #  keeps the *projected* action; the pre-projection one is an input this
    #  layer is handed or is not, so a view that omits it is not evidence of
    #  anything and the reader-side check must not demand it.
    PathSpec("action.full", "Action", Presence.INVARIANT, optional_in_record=True),
    PathSpec("planning.outcome", "PlanningOutcome", Presence.ALWAYS),
    PathSpec("planning.support", "Option[SupportResult]", Presence.ALWAYS),
)

SPEC_BY_PATH: dict[str, PathSpec] = {spec.path: spec for spec in INVENTORY}
STATIC_PATHS = frozenset(spec.path for spec in INVENTORY if not spec.dynamic)
DYNAMIC_PREFIXES = tuple(spec.path for spec in INVENTORY if spec.dynamic)


class PathFailure(Enum):
    #: A path outside the inventory for this certificate schema version.
    UNKNOWN_COMMITMENT_PATH = "UNKNOWN_COMMITMENT_PATH"
    #: Two members of one collection produced the same path.  Refused rather
    #: than resolved: either resolution commits to less than the whole record.
    DUPLICATE_COMMITMENT_PATH = "DUPLICATE_COMMITMENT_PATH"
    #: The record's certificate is not the schema version this inventory is
    #: frozen for, so the leaf set it implies is not the one described here.
    UNSUPPORTED_SCHEMA_VERSION = "UNSUPPORTED_SCHEMA_VERSION"


@dataclass(frozen=True, slots=True)
class PathError:
    failure: PathFailure
    detail: str


def check_segments(path: str) -> bool:
    """Does this path satisfy the grammar, independently of the inventory?"""
    return bool(path) and all(_SEGMENT.match(segment) for segment in path.split("."))


def path_in_inventory(path: str) -> bool:
    """Is this a path the frozen inventory can produce?

    A dynamic path is accepted on its shape -- prefix, then exactly the width
    and charset a digest segment has -- because the members that will exist are
    a function of the case rather than of the inventory.
    """
    if path in STATIC_PATHS:
        return True
    for prefix in DYNAMIC_PREFIXES:
        if path.startswith(prefix + "."):
            tail = path[len(prefix) + 1 :]
            return len(tail) == _DYNAMIC_SEGMENT_WIDTH and set(tail) <= _HEX
    return False


def presence_of(path: str) -> Presence | None:
    """When this path appears, or ``None`` if the inventory has never heard of it."""
    spec = SPEC_BY_PATH.get(path)
    if spec is not None:
        return spec.presence
    for prefix in DYNAMIC_PREFIXES:
        if path.startswith(prefix + "."):
            return SPEC_BY_PATH[prefix].presence
    return None


def is_dynamic(path: str) -> bool:
    return any(path.startswith(prefix + ".") for prefix in DYNAMIC_PREFIXES)


def is_optional_in_record(path: str) -> bool:
    spec = SPEC_BY_PATH.get(path)
    return spec is not None and spec.optional_in_record


#  ---- extraction ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CommittedRecord:
    """Path -> the canonical octets committed at it.

    Immutable and ordered by the codec, not by construction.  ``paths`` is
    ascending by the encoding of the path atom, which is the order the tree is
    built in -- so the root is a function of the mapping and not of the order
    anything was discovered, iterated or inserted.
    """

    values: tuple[tuple[str, bytes], ...]

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(path for path, _ in self.values)

    def octets_at(self, path: str) -> bytes | None:
        for candidate, octets in self.values:
            if candidate == path:
                return octets
        return None


def _canonical(mapping: dict[str, bytes]) -> CommittedRecord:
    ordered = sorted(mapping.items(), key=lambda item: encode(NAtom(item[0])))
    return CommittedRecord(tuple(ordered))


def dynamic_segment(domain: DigestKind | CommitmentDomain, key: Node) -> str:
    """The hex segment a collection member hangs off.

    Two domains are possible because one of the three keys is a whole wire type
    with a type domain of its own, and the other two are not.  Taking the union
    here rather than a string keeps both closed.
    """
    if isinstance(domain, DigestKind):
        return digest_node(domain, key).hex
    return unkeyed_digest(domain, encode(key)).hex()


def _established_key(fact: EstablishedFact) -> tuple[DigestKind, Node]:
    return DigestKind.SYMBOL_REF, fact.ref.to_node()


def _constraint_key(constraint: Constraint) -> tuple[CommitmentDomain, Node]:
    return CommitmentDomain.CONSTRAINT_LABEL, NAtom(constraint.label)


def _non_effect_key(non_effect: NonEffect) -> tuple[CommitmentDomain, Node]:
    #  (rule_id, subject) and not the whole record: those two are what the
    #  revision's own uniqueness invariant is stated over, so a segment built
    #  from them is injective for exactly the reason the collection is unique.
    return CommitmentDomain.NON_EFFECT_KEY, NSeq(
        (NAtom(non_effect.rule_id), NAtom(non_effect.subject))
    )


def extract(
    *,
    certificate: AnalysisCertificate,
    revision: CaseRevision,
    full_action_octets: bytes | None,
) -> Result[CommittedRecord, PathError]:
    """The record's leaf set.  Total, and the only definition of what is committed.

    Takes the certificate and the revision separately rather than reaching into
    a wrapper, because the wrapper also holds the case salt and nothing that
    computes public octets should be able to see one.
    """
    if certificate.certificate_schema_version != CERTIFICATE_SCHEMA_VERSION:
        return Err(
            PathError(
                PathFailure.UNSUPPORTED_SCHEMA_VERSION,
                f"certificate schema {certificate.certificate_schema_version}, "
                f"inventory {CERTIFICATE_SCHEMA_VERSION}",
            )
        )

    kernel = certificate.kernel
    planning = certificate.planning
    outcome = kernel.outcome

    values: dict[str, bytes] = {
        "case.tenant_id": encode(NAtom(certificate.tenant_id)),
        "case.case_id": encode(NAtom(certificate.case_id)),
        "certificate.schema_version": encode(NInt(certificate.certificate_schema_version)),
        "bundle.manifest_digest": encode(certificate.bundle_manifest_digest.to_node()),
        "revision.construction_digest": encode(revision.construction_digest.to_node()),
        "revision.transcript_prefix_digest": encode(revision.transcript_prefix_digest.to_node()),
        "revision.bundle_pin": encode(revision.bundle_pin.to_node()),
        "revision.as_of": encode(NInt(revision.as_of)),
        "revision.mode": encode(NAtom(revision.mode.value)),
        "revision.authorization_context_digest": encode(
            revision.authorization_context_digest.to_node()
        ),
        "revision.authorizability": encode(NAtom(revision.authorizability.value)),
        "revision.declared": encode(symbol_seq(revision.declared)),
        "kernel.logical_case_digest": encode(kernel.logical_case_digest.to_node()),
        "kernel.determinism_class": encode(NAtom(kernel.determinism_class.value)),
        "kernel.fingerprint": encode(kernel.fingerprint.to_node()),
        "kernel.outcome.tag": encode(NAtom(outcome_class(outcome))),
        "planning.outcome": encode(planning_node(planning.planning_outcome)),
        "planning.support": encode(
            option_node(None if planning.support is None else support_node(planning.support))
        ),
    }

    members: list[tuple[str, str, bytes]] = []
    for fact in revision.established:
        domain, key = _established_key(fact)
        members.append(
            ("revision.established", dynamic_segment(domain, key), encode(fact.to_node()))
        )
    for constraint in revision.constraints:
        label_domain, label_key = _constraint_key(constraint)
        members.append(
            (
                "revision.constraints",
                dynamic_segment(label_domain, label_key),
                encode(constraint.to_node()),
            )
        )
    for non_effect in revision.non_effects:
        key_domain, non_effect_key = _non_effect_key(non_effect)
        members.append(
            (
                "revision.non_effects",
                dynamic_segment(key_domain, non_effect_key),
                encode(non_effect.to_node()),
            )
        )
    for prefix, segment, octets in members:
        path = f"{prefix}.{segment}"
        if path in values:
            return Err(
                PathError(
                    PathFailure.DUPLICATE_COMMITMENT_PATH,
                    f"{path}: two members of {prefix} share a commitment path, so one would "
                    f"be dropped and the tree would stop binding the whole record",
                )
            )
        values[path] = octets

    match outcome:
        case Invariant():
            values["kernel.outcome.action"] = encode(outcome.action.to_node())
            values["kernel.outcome.witness"] = encode(outcome.witness.to_node())
            if full_action_octets is not None:
                values["action.full"] = full_action_octets
        case Divergent():
            values["kernel.outcome.reachable"] = encode(reachable_node(outcome.reachable))
            values["kernel.outcome.left"] = encode(outcome.left.to_node())
            values["kernel.outcome.right"] = encode(outcome.right.to_node())
        case Infeasible():
            values["kernel.outcome.contributing"] = encode(
                NSeq(tuple(NAtom(label) for label in outcome.contributing))
            )
        case Indeterminate():
            values["kernel.outcome.reason"] = encode(NAtom(outcome.reason.value))

    for path in values:
        if not check_segments(path) or not path_in_inventory(path):
            return Err(PathError(PathFailure.UNKNOWN_COMMITMENT_PATH, path))
    return Ok(_canonical(values))
