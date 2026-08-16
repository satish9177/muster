"""Frozen commitment-path inventory and the total path extractor.

NON-PRODUCTION SPECIFICATION MATERIAL.

Phase 0.7 said the inventory was "frozen per certificate_schema_version and
published as an ordered list" and then did not publish one, and supplied no
extractor -- so the leaf set was undefined and `04 01 01` at an unknown path
could have been an INT or an Instant.  Both are supplied here.

    path    ::= segment ( "." segment )*
    segment ::= [A-Za-z0-9_:-]{1,64}

Dynamic segments are the lowercase hex of a domain-separated digest of the
identifying key, so they are total, injective, charset-safe, fixed width, and do
not leak the identifier of an undisclosed item.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .digests import digest_node
from .nodes import Atom, Int, Node, Rec, Seq, Tagged, encode

SEGMENT_RE = re.compile(r"^[A-Za-z0-9_:-]{1,64}$")

CERTIFICATE_SCHEMA_VERSION = 1


class PathError(Exception):
    pass


class DuplicateCommitmentPath(PathError):
    """Two members of a collection mapped to one commitment path.

    Found by adversarial review.  `extract()` built a dict, so a collision
    silently dropped a leaf: the committed tree omitted part of the authoritative
    record while `leaf_count` stayed internally consistent, and nothing detected
    that the commitment was no longer binding on the whole revision.
    """


def check_path(path: str) -> None:
    segments = path.split(".")
    if not segments:
        raise PathError("empty path")
    for s in segments:
        if not SEGMENT_RE.match(s):
            raise PathError(f"illegal path segment {s!r} in {path!r}")


@dataclass(frozen=True, slots=True)
class PathSpec:
    path: str
    type_name: str
    presence: str  # "always" | "INVARIANT" | "DIVERGENT" | "INFEASIBLE" | "INDETERMINATE"
    dynamic: bool = False


#: The frozen inventory for certificate_schema_version 1.  A path outside it is
#: `UnknownCommitmentPath`; a missing required path is `IncompleteCommitmentSet`.
INVENTORY: tuple[PathSpec, ...] = (
    PathSpec("case.tenant_id", "ATOM", "always"),
    PathSpec("case.case_id", "ATOM", "always"),
    PathSpec("certificate.schema_version", "INT", "always"),
    PathSpec("bundle.manifest_digest", "DIGEST", "always"),
    PathSpec("revision.construction_digest", "DIGEST", "always"),
    PathSpec("revision.transcript_prefix_digest", "DIGEST", "always"),
    PathSpec("revision.bundle_pin", "DIGEST", "always"),
    PathSpec("revision.as_of", "Instant", "always"),
    PathSpec("revision.mode", "ATOM", "always"),
    PathSpec("revision.authorization_context_digest", "DIGEST", "always"),
    PathSpec("revision.authorizability", "ATOM", "always"),
    PathSpec("revision.declared", "SEQ[SymbolRef]", "always"),
    PathSpec("revision.established", "EstablishedFact", "always", dynamic=True),
    PathSpec("revision.constraints", "Constraint", "always", dynamic=True),
    PathSpec("revision.non_effects", "NonEffect", "always", dynamic=True),
    PathSpec("kernel.logical_case_digest", "DIGEST", "always"),
    PathSpec("kernel.determinism_class", "ATOM", "always"),
    PathSpec("kernel.fingerprint", "SolverFingerprint", "always"),
    PathSpec("kernel.outcome.tag", "ATOM", "always"),
    PathSpec("kernel.outcome.action", "ConsequentialAction", "INVARIANT"),
    PathSpec("kernel.outcome.witness", "World", "INVARIANT"),
    PathSpec("kernel.outcome.reachable", "ReachableActions", "DIVERGENT"),
    PathSpec("kernel.outcome.left", "World", "DIVERGENT"),
    PathSpec("kernel.outcome.right", "World", "DIVERGENT"),
    PathSpec("kernel.outcome.contributing", "SEQ[ATOM]", "INFEASIBLE"),
    PathSpec("kernel.outcome.reason", "ATOM", "INDETERMINATE"),
    PathSpec("action.full", "Action", "INVARIANT"),
    PathSpec("planning.outcome", "PlanningOutcome", "always"),
    PathSpec("planning.support", "Option[SupportResult]", "always"),
)

#: prefix -> (owning type, collection field, the key fields the segment digests,
#: digest domain).  A dynamic segment is only injective if the source collection
#: is unique by EXACTLY these fields, which CHK_DYNAMIC_PATHS_ARE_INJECTIVE checks.
DYNAMIC_SOURCES: dict[str, tuple[str, str, tuple[str, ...], str]] = {
    "revision.established": ("CaseRevision", "established", ("ref",), "SYMBOL_REF"),
    "revision.constraints": ("CaseRevision", "constraints", ("label",), "CONSTRAINT_LABEL"),
    "revision.non_effects": (
        "CaseRevision",
        "non_effects",
        ("rule_id", "subject"),
        "NON_EFFECT_KEY",
    ),
}

STATIC_PATHS = frozenset(p.path for p in INVENTORY if not p.dynamic)
DYNAMIC_PREFIXES = tuple(p.path for p in INVENTORY if p.dynamic)

PATH_TYPE: dict[str, str] = {p.path: p.type_name for p in INVENTORY}


def dynamic_segment(kind: str, key_node: Node) -> str:
    """Total, injective, charset-safe.  64 hex characters, so within the segment limit."""
    return digest_node(kind, key_node).hex()


def path_in_inventory(path: str) -> bool:
    if path in STATIC_PATHS:
        return True
    for prefix in DYNAMIC_PREFIXES:
        if path.startswith(prefix + "."):
            tail = path[len(prefix) + 1 :]
            return len(tail) == 64 and all(c in "0123456789abcdef" for c in tail)
    return False


def declared_type(path: str) -> str:
    if path in PATH_TYPE:
        return PATH_TYPE[path]
    for prefix in DYNAMIC_PREFIXES:
        if path.startswith(prefix + "."):
            return PATH_TYPE[prefix]
    raise PathError(f"UnknownCommitmentPath: {path!r}")


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------

OUTCOME_TAGS = {
    "Invariant": "INVARIANT",
    "Divergent": "DIVERGENT",
    "Infeasible": "INFEASIBLE",
    "Indeterminate": "INDETERMINATE",
}


def outcome_class(outcome: Node) -> str:
    assert isinstance(outcome, Tagged)
    try:
        return OUTCOME_TAGS[outcome.variant]
    except KeyError as exc:
        raise PathError(f"unknown AnalysisOutcome variant {outcome.variant!r}") from exc


def extract(record: Rec) -> dict[str, bytes]:
    """InternalAnalysisRecord -> {path: canonical value octets}.  Total.

    The result IS the leaf set.  A tree whose leaf paths differ from this output
    is `IncompleteCommitmentSet` -- there is no discretion about what is committed,
    only about what is later disclosed.
    """
    assert isinstance(record, Rec) and record.tag == "InternalAnalysisRecord/v1"
    certificate, revision, full_action, _salt = record.fields
    assert isinstance(certificate, Rec) and isinstance(revision, Rec)

    (
        cert_schema_version,
        cert_tenant,
        cert_case,
        _rev_digest,
        bundle_manifest_digest,
        kernel,
        planning,
        _annex,
    ) = certificate.fields
    assert isinstance(kernel, Rec) and isinstance(planning, Rec)

    (
        _tenant,
        _case,
        construction_digest,
        transcript_prefix_digest,
        bundle_pin,
        as_of,
        mode,
        authorization_context_digest,
        authorizability,
        declared,
        established,
        constraints,
        non_effects,
    ) = revision.fields

    logical_case_digest, outcome, _query_digests, fingerprint, determinism_class = kernel.fields

    out: dict[str, bytes] = {
        "case.tenant_id": encode(cert_tenant),
        "case.case_id": encode(cert_case),
        "certificate.schema_version": encode(cert_schema_version),
        "bundle.manifest_digest": encode(bundle_manifest_digest),
        "revision.construction_digest": encode(construction_digest),
        "revision.transcript_prefix_digest": encode(transcript_prefix_digest),
        "revision.bundle_pin": encode(bundle_pin),
        "revision.as_of": encode(as_of),
        "revision.mode": encode(mode),
        "revision.authorization_context_digest": encode(authorization_context_digest),
        "revision.authorizability": encode(authorizability),
        "revision.declared": encode(declared),
        "kernel.logical_case_digest": encode(logical_case_digest),
        "kernel.determinism_class": encode(determinism_class),
        "kernel.fingerprint": encode(fingerprint),
        "kernel.outcome.tag": encode(Atom(outcome_class(outcome))),
        "planning.outcome": encode(planning.fields[0]),
        "planning.support": encode(planning.fields[1]),
    }

    def emit_dynamic(prefix: str, collection: Node, key_of) -> None:
        assert isinstance(collection, Seq)
        _owner, _field, _keys, domain = DYNAMIC_SOURCES[prefix]
        for member in collection.items:
            assert isinstance(member, Rec)
            path = f"{prefix}.{dynamic_segment(domain, key_of(member))}"
            if path in out:
                raise DuplicateCommitmentPath(
                    f"{path}: two members of {prefix} share a commitment path.  "
                    f"One would be dropped and the tree would stop binding the "
                    f"whole record."
                )
            out[path] = encode(member)

    emit_dynamic("revision.established", established, lambda f: f.fields[0])
    emit_dynamic("revision.constraints", constraints, lambda c: c.fields[0])
    emit_dynamic(
        "revision.non_effects", non_effects, lambda n: Seq([n.fields[0], n.fields[2]])
    )

    assert isinstance(outcome, Tagged)
    body = outcome.value
    if outcome.variant == "Invariant":
        assert isinstance(body, Rec)
        out["kernel.outcome.action"] = encode(body.fields[0])
        out["kernel.outcome.witness"] = encode(body.fields[1])
        if isinstance(full_action, Tagged) and full_action.variant == "Some":
            out["action.full"] = encode(full_action.value)
    elif outcome.variant == "Divergent":
        assert isinstance(body, Rec)
        out["kernel.outcome.reachable"] = encode(body.fields[0])
        out["kernel.outcome.left"] = encode(body.fields[1])
        out["kernel.outcome.right"] = encode(body.fields[2])
    elif outcome.variant == "Infeasible":
        assert isinstance(body, Rec)
        out["kernel.outcome.contributing"] = encode(body.fields[0])
    elif outcome.variant == "Indeterminate":
        assert isinstance(body, Rec)
        out["kernel.outcome.reason"] = encode(body.fields[0])

    for path in out:
        check_path(path)
        if not path_in_inventory(path):
            raise PathError(f"UnknownCommitmentPath: {path!r}")
    return out
