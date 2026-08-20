"""Reading a local case file.

A deterministic JSON document describing one case: its identity, its
construction record, its declared instances and its transcript.  Parsing is
fail-closed -- an unknown key, a missing field or a value of the wrong shape is
a typed rejection naming the path, never a default.

**Nothing here is *authenticated*.**  This path holds no keyring, so every
entry is loaded with an explicitly unsigned signature and the CLI says so on
every run.  A case file is a local fixture, not evidence.

**Authority, by contrast, *is* checked here** -- and the pair is the clearest
statement of the milestone-E principle anywhere in the tree.  A case file
carries an authority registry snapshot and a revocation snapshot, and Q-12 runs
over them exactly as it does on the durable path, so a local run refuses a
worker key attesting a goods receipt while cheerfully admitting that no
signature was ever verified.  Authenticity and authority are separable; this
file separates them in the most visible way available, by doing one and not the
other.

The two digests in the authorization context are **computed from the snapshots
in the same document** rather than transcribed beside them.  A pin an author
cannot compute by hand is a pin that goes stale the first time a fixture is
edited, and a stale local fixture is a rebuild failure rather than a security
control.  On the durable path the context is supplied by the caller and both
pins are checked against what was actually published -- which is where
transcription *is* a control worth having, and where it is enforced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from muster.core.authority.grants import (
    AuthorityGrant,
    AuthorityRegistrySnapshot,
    canonical_grants,
)
from muster.core.authority.revocation import RevocationSnapshot
from muster.core.authority.scope import ResourceScope
from muster.core.case.revision import AuthorizationContext, RebuildInputs, RebuildMode
from muster.core.evidence.relations import (
    AcquisitionRelation,
    ClosedLowerBound,
    ClosedUpperBound,
    EnumSubset,
    ExactValue,
)
from muster.core.evidence.requests import EvidenceRequest, EvidenceTarget
from muster.core.evidence.transcript import (
    AcquisitionPayload,
    Attestation,
    CaseConstructionRecord,
    PartyRecord,
    Statement,
    StatementRecord,
    TranscriptEntry,
    VerificationReceipt,
)
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.classification import AcquisitionClass
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled
from muster.core.values.sorts import BoolSort, EnumSort, IntSort, ScaledSort, Sort
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import HalfOpenInterval, Instant
from muster.core.wire.digests import Digest
from muster.core.wire.signature import Signature
from muster.hinge.prepare import EngineLimits

UNVERIFIED = Signature("UNSIGNED-LOCAL-DEVELOPMENT", b"")

NONCE_OCTETS = 16
DIGEST_HEX_CHARS = 64


class CaseFileFailure(Enum):
    UNREADABLE = "UNREADABLE"
    MALFORMED_JSON = "MALFORMED_JSON"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    REJECTED_BY_DOMAIN = "REJECTED_BY_DOMAIN"
    MISSING_FIELD = "MISSING_FIELD"
    UNEXPECTED_TYPE = "UNEXPECTED_TYPE"
    UNKNOWN_VARIANT = "UNKNOWN_VARIANT"
    OUT_OF_RANGE = "OUT_OF_RANGE"


@dataclass(frozen=True, slots=True)
class CaseFileError:
    failure: CaseFileFailure
    path: str
    detail: str = ""


class _Rejected(Exception):
    def __init__(self, error: CaseFileError) -> None:
        super().__init__(f"{error.failure.value} at {error.path}: {error.detail}")
        self.error = error


def _reject(failure: CaseFileFailure, path: str, detail: object = "") -> _Rejected:
    return _Rejected(CaseFileError(failure, path, str(detail)))


@dataclass(frozen=True, slots=True)
class CaseFile:
    """A parsed case file: identity, inputs, construction record and transcript."""

    policy_id: str
    construction: CaseConstructionRecord
    entries: tuple[TranscriptEntry, ...]
    authorization_context: AuthorizationContext
    authority_snapshot: AuthorityRegistrySnapshot
    revocation_snapshot: RevocationSnapshot
    as_of: Instant
    mode: RebuildMode
    #: The evidence requests this case issued, which carry the second half of
    #: check Q-12(a) into ``rebuild``.  A case file that omits them describes a
    #: case in which every receipt was volunteered -- which is what the three
    #: worked fixtures are -- and a case file that has them must carry them, or
    #: replaying it from disk would apply a weaker clause than the control
    #: plane applied when the case was live.
    solicitations: tuple[EvidenceRequest, ...] = ()

    def rebuild_inputs(self, bundle_digest: Digest, transcript_digest: Digest) -> RebuildInputs:
        return RebuildInputs(
            tenant_id=self.construction.tenant_id,
            case_id=self.construction.case_id,
            construction_digest=self.construction.digest(),
            transcript_prefix_digest=transcript_digest,
            bundle_manifest_digest=bundle_digest,
            as_of=self.as_of,
            mode=self.mode,
            authorization_context_digest=self.authorization_context.digest(),
        )


def load_case_file(path: Path) -> Result[CaseFile, CaseFileError]:
    document = _read_document(path)
    if isinstance(document, Err):
        return document
    try:
        return Ok(_read_case(document.value))
    except _Rejected as rejection:
        return Err(rejection.error)
    except (ValueError, InvariantViolation) as failure:
        #  A domain constructor refused the value: an enum subset with no
        #  members, a negative scale, an odd-length nonce.  At this boundary
        #  that is a statement about the *input*, not about the code, so it
        #  leaves as a typed rejection rather than as a traceback.  Without
        #  this the CLI aborts instead of reporting, and "fail closed" becomes
        #  "fall over".
        return Err(CaseFileError(CaseFileFailure.REJECTED_BY_DOMAIN, str(path), str(failure)))


def _read_document(path: Path) -> Result[Any, CaseFileError]:
    """Read and parse, distinguishing "cannot read it" from "it is not JSON"."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as failure:
        return Err(CaseFileError(CaseFileFailure.UNREADABLE, str(path), str(failure)))
    try:
        return Ok(json.loads(text))
    except json.JSONDecodeError as failure:
        return Err(CaseFileError(CaseFileFailure.MALFORMED_JSON, str(path), str(failure)))


@dataclass(frozen=True, slots=True)
class EngineConfiguration:
    """The operator's numbers: the kernel's bounds and the backend's budget."""

    limits: EngineLimits
    enumeration_budget: int


def load_engine_limits(path: Path) -> Result[EngineConfiguration, CaseFileError]:
    """Read the operator's bounds.

    There is no default anywhere in the kernel: a missing bound is a startup
    failure, because an unbounded case size is the difference between an
    escalation the user understands and an outage nobody predicted.
    """
    document = _read_document(path)
    if isinstance(document, Err):
        return document
    try:
        _exact_keys(
            _object(document.value, "limits"),
            "limits",
            {"max_unresolved", "reachable_action_cap", "max_enumerated_assignments"},
        )
        configuration = EngineConfiguration(
            limits=EngineLimits(
                max_unresolved=_positive(document.value, "max_unresolved", "limits"),
                reachable_action_cap=_positive(document.value, "reachable_action_cap", "limits"),
            ),
            enumeration_budget=_positive(document.value, "max_enumerated_assignments", "limits"),
        )
    except _Rejected as rejection:
        return Err(rejection.error)
    return Ok(configuration)


def _read_case(document: Any) -> CaseFile:
    root = _exact_keys(
        _object(document, "$"),
        "$",
        {
            "tenant_id",
            "case_id",
            "policy_id",
            "as_of",
            "mode",
            "authorization_context",
            "authority_registry",
            "revocation",
            "case_construction",
            "declared_instances",
            "transcript",
            "solicitations",
        },
    )
    tenant_id = _text(root, "tenant_id", "$")
    case_id = _text(root, "case_id", "$")
    as_of = _integer(root, "as_of", "$")
    mode = RebuildMode(_member(root, "mode", "$", {mode.value for mode in RebuildMode}))
    policy_id = _text(root, "policy_id", "$")

    construction = _read_construction(
        _object(_field(root, "case_construction", "$"), "$.case_construction"),
        tenant_id,
        case_id,
        _read_instances(_array(_field(root, "declared_instances", "$"), "$.declared_instances")),
    )
    authority = _read_authority_registry(
        _object(_field(root, "authority_registry", "$"), "$.authority_registry"), tenant_id
    )
    revocation = _read_revocation(
        _object(_field(root, "revocation", "$"), "$.revocation"), tenant_id
    )
    context = _read_authorization_context(
        _object(_field(root, "authorization_context", "$"), "$.authorization_context"),
        authority,
        revocation,
    )
    entries = tuple(
        _read_entry(
            _object(entry, f"$.transcript[{index}]"), f"$.transcript[{index}]", tenant_id, case_id
        )
        for index, entry in enumerate(_array(_field(root, "transcript", "$"), "$.transcript"))
    )
    #  Optional, because the three worked fixtures predate evidence requests and
    #  describe cases in which nothing was solicited.  Optional here means
    #  "absent is a value with a meaning", not "absent skips a check": absent
    #  produces the empty tuple, which ``rebuild`` requires to be passed and
    #  which means every receipt in this case is volunteered.
    solicitations = tuple(
        _read_evidence_request(
            _object(request, f"$.solicitations[{index}]"),
            f"$.solicitations[{index}]",
            tenant_id,
            case_id,
        )
        for index, request in enumerate(_array(root.get("solicitations", []), "$.solicitations"))
    )
    return CaseFile(
        policy_id,
        construction,
        entries,
        context,
        authority,
        revocation,
        as_of,
        mode,
        solicitations,
    )


def _read_evidence_request(
    node: dict[str, Any], path: str, tenant_id: str, case_id: str
) -> EvidenceRequest:
    """One evidence request, bound to this case rather than to what it claims.

    ``tenant_id`` and ``case_id`` come from the case file's own header and not
    from the request's object, for the reason every other reader here does the
    same: a request naming another case would be a request this case may not
    cite, and the reader declines to build the confusion rather than building it
    and refusing it later.
    """
    _exact_keys(node, path, {"revision_semantic_digest", "targets"})
    targets = tuple(
        _read_evidence_target(
            _object(target, f"{path}.targets[{index}]"), f"{path}.targets[{index}]"
        )
        for index, target in enumerate(_array(_field(node, "targets", path), f"{path}.targets"))
    )
    return EvidenceRequest(
        tenant_id=tenant_id,
        case_id=case_id,
        revision_semantic_digest=_digest(node, "revision_semantic_digest", path),
        targets=targets,
    )


def _read_evidence_target(node: dict[str, Any], path: str) -> EvidenceTarget:
    _exact_keys(node, path, {"proposition", "acquisition_class", "permitted_source_classes"})
    return EvidenceTarget(
        proposition=_read_symbol(_object(_field(node, "proposition", path), f"{path}.proposition")),
        acquisition_class=AcquisitionClass(
            _member(
                node,
                "acquisition_class",
                path,
                {member.value for member in AcquisitionClass},
            )
        ),
        permitted_source_classes=tuple(_text_list(node, "permitted_source_classes", path)),
    )


def _read_construction(
    node: dict[str, Any], tenant_id: str, case_id: str, instances: tuple[SymbolRef, ...]
) -> CaseConstructionRecord:
    path = "$.case_construction"
    _exact_keys(
        node,
        path,
        {
            "created_at",
            "subject_refs",
            "contract_ref",
            "parties",
            "case_scope_coordinates",
            "signer_key_ref",
        },
    )
    parties = tuple(
        PartyRecord(
            tenant_id=tenant_id,
            principal_id=_text(_object(party, f"{path}.parties[{index}]"), "principal_id", path),
            role_in_case=_text(_object(party, f"{path}.parties[{index}]"), "role_in_case", path),
            competences=tuple(
                _text_list(_object(party, f"{path}.parties[{index}]"), "competences", path)
            ),
        )
        for index, party in enumerate(_array(_field(node, "parties", path), f"{path}.parties"))
    )
    return CaseConstructionRecord(
        tenant_id=tenant_id,
        case_id=case_id,
        created_at=_integer(node, "created_at", path),
        subject_refs=tuple(_text_list(node, "subject_refs", path)),
        contract_ref=_optional_text(node, "contract_ref", path),
        parties=parties,
        declared_instances=instances,
        case_scope_coordinates=_read_scopes(
            _array(_field(node, "case_scope_coordinates", path), f"{path}.case_scope_coordinates"),
            f"{path}.case_scope_coordinates",
        ),
        signer_key_ref=_text(node, "signer_key_ref", path),
        signature=UNVERIFIED,
    )


def _read_authorization_context(
    node: dict[str, Any],
    authority: AuthorityRegistrySnapshot,
    revocation: RevocationSnapshot,
) -> AuthorizationContext:
    path = "$.authorization_context"
    _exact_keys(node, path, {"authorization_policy_version", "validity"})
    version = _integer(node, "authorization_policy_version", path)
    if version != authority.authorization_policy_version:
        #  Q-12(f) requires the context, the snapshot and every grant to agree
        #  about the authorization-policy version.  A fixture that disagreed
        #  with itself would produce a case in which nothing is ever
        #  admissible, which is a confusing way to spell a typo.
        raise _reject(
            CaseFileFailure.OUT_OF_RANGE,
            f"{path}.authorization_policy_version",
            f"{version} but the registry publishes {authority.authorization_policy_version}",
        )
    return AuthorizationContext(
        authorization_policy_version=version,
        #  Derived from the snapshots in this document rather than transcribed
        #  beside them; see the module docstring.
        authority_registry_snapshot_digest=authority.digest(),
        revocation_snapshot_digest=revocation.digest(),
        context_validity=_interval(_object(_field(node, "validity", path), f"{path}.validity")),
    )


def _read_authority_registry(node: dict[str, Any], tenant_id: str) -> AuthorityRegistrySnapshot:
    path = "$.authority_registry"
    _exact_keys(
        node, path, {"registry_id", "authorization_policy_version", "published_at", "grants"}
    )
    version = _integer(node, "authorization_policy_version", path)
    grants = canonical_grants(
        _read_grant(_object(grant, f"{path}.grants[{index}]"), f"{path}.grants[{index}]", tenant_id)
        for index, grant in enumerate(_array(_field(node, "grants", path), f"{path}.grants"))
    )
    return AuthorityRegistrySnapshot(
        registry_id=_text(node, "registry_id", path),
        #  The tenant is the case's rather than a field of its own.  A local
        #  registry naming another tenant would describe authority this case
        #  could never use, and the reader declines to build the confusion.
        tenant_id=tenant_id,
        authorization_policy_version=version,
        grants=grants,
        published_at=_integer(node, "published_at", path),
    )


def _read_grant(node: dict[str, Any], path: str, tenant_id: str) -> AuthorityGrant:
    _exact_keys(
        node,
        path,
        {
            "key_ref",
            "principal_id",
            "source_class",
            "permitted_predicates",
            "resource_scope",
            "validity",
            "authorization_policy_version",
        },
    )
    return AuthorityGrant(
        key_ref=_text(node, "key_ref", path),
        principal_id=_text(node, "principal_id", path),
        tenant_scope=tenant_id,
        source_class=_text(node, "source_class", path),
        permitted_predicates=tuple(sorted(set(_text_list(node, "permitted_predicates", path)))),
        resource_scope=_read_scopes(
            _array(_field(node, "resource_scope", path), f"{path}.resource_scope"),
            f"{path}.resource_scope",
        ),
        validity=_interval(_object(_field(node, "validity", path), f"{path}.validity")),
        authorization_policy_version=_integer(node, "authorization_policy_version", path),
    )


def _read_revocation(node: dict[str, Any], tenant_id: str) -> RevocationSnapshot:
    path = "$.revocation"
    _exact_keys(node, path, {"registry_id", "published_at", "revoked_key_refs"})
    return RevocationSnapshot(
        registry_id=_text(node, "registry_id", path),
        tenant_id=tenant_id,
        revoked_key_refs=tuple(sorted(set(_text_list(node, "revoked_key_refs", path)))),
        published_at=_integer(node, "published_at", path),
    )


def _read_scopes(nodes: list[Any], path: str) -> tuple[ResourceScope, ...]:
    return tuple(
        ResourceScope(
            _text(_object(scope, f"{path}[{index}]"), "kind", f"{path}[{index}]"),
            _text(_object(scope, f"{path}[{index}]"), "value", f"{path}[{index}]"),
        )
        for index, scope in enumerate(nodes)
    )


def _read_entry(node: dict[str, Any], path: str, tenant_id: str, case_id: str) -> TranscriptEntry:
    kind = _member(node, "kind", path, {"attestation", "statement"})
    if kind == "attestation":
        return Attestation(_read_receipt(node, path, tenant_id, case_id))
    return Statement(_read_statement(node, path, tenant_id, case_id))


def _read_receipt(
    node: dict[str, Any], path: str, tenant_id: str, case_id: str
) -> VerificationReceipt:
    _exact_keys(
        node,
        path,
        {
            "kind",
            "subject",
            "proposition",
            "relation",
            "value_sort",
            "predicate_schema_digest",
            "observed_at",
            "issued_at",
            "validity",
            "nonce",
            "source_class",
            "signer_key_ref",
            "authorization_policy_version",
            "request_id",
        },
    )
    nonce = _octets(node, "nonce", path, NONCE_OCTETS)
    payload = AcquisitionPayload(
        tenant_id=tenant_id,
        case_id=case_id,
        subject=_text(node, "subject", path),
        proposition=_read_symbol(_object(_field(node, "proposition", path), f"{path}.proposition")),
        relation=_read_relation(_object(_field(node, "relation", path), f"{path}.relation")),
        value_sort=_read_sort(_object(_field(node, "value_sort", path), f"{path}.value_sort")),
        predicate_schema_digest=_digest(node, "predicate_schema_digest", path),
        observed_at=_integer(node, "observed_at", path),
        issued_at=_integer(node, "issued_at", path),
        validity=_interval(_object(_field(node, "validity", path), f"{path}.validity")),
        nonce=nonce,
        source_class=_text(node, "source_class", path),
        signer_key_ref=_text(node, "signer_key_ref", path),
        authorization_policy_version=_integer(node, "authorization_policy_version", path),
        request_id=_digest(node, "request_id", path),
    )
    return VerificationReceipt(payload, UNVERIFIED)


def _read_statement(
    node: dict[str, Any], path: str, tenant_id: str, case_id: str
) -> StatementRecord:
    _exact_keys(
        node,
        path,
        {
            "kind",
            "claimant",
            "role_in_case",
            "proposition",
            "asserted_value",
            "value_sort",
            "measurement_procedure_id",
            "statement_time",
            "signer_key_ref",
        },
    )
    return StatementRecord(
        tenant_id=tenant_id,
        case_id=case_id,
        claimant=_text(node, "claimant", path),
        role_in_case=_text(node, "role_in_case", path),
        proposition=_read_symbol(_object(_field(node, "proposition", path), f"{path}.proposition")),
        asserted_value=_read_value(
            _object(_field(node, "asserted_value", path), f"{path}.asserted_value")
        ),
        value_sort=_read_sort(_object(_field(node, "value_sort", path), f"{path}.value_sort")),
        measurement_procedure_id=_optional_text(node, "measurement_procedure_id", path),
        statement_time=_integer(node, "statement_time", path),
        supersedes=None,
        signer_key_ref=_text(node, "signer_key_ref", path),
        signature=UNVERIFIED,
    )


def _read_instances(nodes: list[Any]) -> tuple[SymbolRef, ...]:
    return tuple(
        _read_symbol(_object(node, f"$.declared_instances[{index}]"))
        for index, node in enumerate(nodes)
    )


def _read_symbol(node: dict[str, Any]) -> SymbolRef:
    _exact_keys(node, "$.proposition", {"predicate", "args"})
    return SymbolRef(_text(node, "predicate", "$"), tuple(_text_list(node, "args", "$")))


def _read_sort(node: dict[str, Any]) -> Sort:
    kind = _member(node, "kind", "$.sort", {"bool", "int", "scaled", "enum"})
    match kind:
        case "bool":
            return BoolSort()
        case "int":
            return IntSort()
        case "scaled":
            return ScaledSort(_text(node, "unit", "$.sort"), _integer(node, "scale", "$.sort"))
        case _:
            return EnumSort(_text(node, "enum_id", "$.sort"))


def _read_value(node: dict[str, Any]) -> Value:
    kind = _member(node, "kind", "$.value", {"bool", "int", "scaled", "enum"})
    match kind:
        case "bool":
            return VBool(_boolean(node, "value", "$.value"))
        case "int":
            return VInt(_integer(node, "value", "$.value"))
        case "scaled":
            return VScaled(
                _text(node, "unit", "$.value"),
                _integer(node, "scale", "$.value"),
                _integer(node, "minor", "$.value"),
            )
        case _:
            return VEnum(_text(node, "enum_id", "$.value"), _text(node, "member", "$.value"))


def _read_relation(node: dict[str, Any]) -> AcquisitionRelation:
    kind = _member(
        node,
        "kind",
        "$.relation",
        {"exact_value", "closed_lower_bound", "closed_upper_bound", "enum_subset"},
    )
    match kind:
        case "exact_value":
            return ExactValue(
                _read_value(_object(_field(node, "value", "$.relation"), "$.relation.value"))
            )
        case "closed_lower_bound":
            return ClosedLowerBound(
                _read_value(_object(_field(node, "bound", "$.relation"), "$.relation.bound"))
            )
        case "closed_upper_bound":
            return ClosedUpperBound(
                _read_value(_object(_field(node, "bound", "$.relation"), "$.relation.bound"))
            )
        case _:
            return EnumSubset(
                tuple(
                    _read_value(_object(member, "$.relation.allowed[]"))
                    for member in _array(
                        _field(node, "allowed", "$.relation"), "$.relation.allowed"
                    )
                )
            )


def _interval(node: dict[str, Any]) -> HalfOpenInterval:
    _exact_keys(node, "$.validity", {"start", "end"})
    end = node.get("end")
    if end is not None and not isinstance(end, int):
        raise _reject(CaseFileFailure.UNEXPECTED_TYPE, "$.validity.end", type(end).__name__)
    return HalfOpenInterval(_integer(node, "start", "$.validity"), end)


#  ---- primitive readers --------------------------------------------------


def _exact_keys(node: dict[str, Any], path: str, permitted: set[str]) -> dict[str, Any]:
    """Reject a key the reader does not understand.

    A misspelled field that is merely ignored is worse than one that is
    rejected: the author believes it took effect.  Requiring the key set to be
    exactly what this reader knows makes a typo loud.
    """
    unknown = sorted(set(node) - permitted)
    if unknown:
        raise _reject(CaseFileFailure.UNKNOWN_FIELD, path, ", ".join(unknown))
    return node


def _field(node: dict[str, Any], name: str, path: str) -> Any:
    if name not in node:
        raise _reject(CaseFileFailure.MISSING_FIELD, f"{path}.{name}")
    return node[name]


def _object(node: Any, path: str) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise _reject(CaseFileFailure.UNEXPECTED_TYPE, path, type(node).__name__)
    return node


def _array(node: Any, path: str) -> list[Any]:
    if not isinstance(node, list):
        raise _reject(CaseFileFailure.UNEXPECTED_TYPE, path, type(node).__name__)
    return node


def _text(node: dict[str, Any], name: str, path: str) -> str:
    value = _field(node, name, path)
    if not isinstance(value, str):
        raise _reject(CaseFileFailure.UNEXPECTED_TYPE, f"{path}.{name}", type(value).__name__)
    return value


def _optional_text(node: dict[str, Any], name: str, path: str) -> str | None:
    value = node.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _reject(CaseFileFailure.UNEXPECTED_TYPE, f"{path}.{name}", type(value).__name__)
    return value


def _text_list(node: dict[str, Any], name: str, path: str) -> list[str]:
    values = _array(_field(node, name, path), f"{path}.{name}")
    for value in values:
        if not isinstance(value, str):
            raise _reject(CaseFileFailure.UNEXPECTED_TYPE, f"{path}.{name}[]", type(value).__name__)
    return [value for value in values if isinstance(value, str)]


def _integer(node: dict[str, Any], name: str, path: str) -> int:
    value = _field(node, name, path)
    #  ``bool`` is an ``int`` in Python and would silently become 0 or 1.
    if not isinstance(value, int) or isinstance(value, bool):
        raise _reject(CaseFileFailure.UNEXPECTED_TYPE, f"{path}.{name}", type(value).__name__)
    return value


def _positive(node: Any, name: str, path: str) -> int:
    value = _integer(_object(node, path), name, path)
    if value < 1:
        raise _reject(CaseFileFailure.OUT_OF_RANGE, f"{path}.{name}", value)
    return value


def _boolean(node: dict[str, Any], name: str, path: str) -> bool:
    value = _field(node, name, path)
    if not isinstance(value, bool):
        raise _reject(CaseFileFailure.UNEXPECTED_TYPE, f"{path}.{name}", type(value).__name__)
    return value


def _member(node: dict[str, Any], name: str, path: str, permitted: set[str]) -> str:
    value = _text(node, name, path)
    if value not in permitted:
        raise _reject(CaseFileFailure.UNKNOWN_VARIANT, f"{path}.{name}", value)
    return value


def _octets(node: dict[str, Any], name: str, path: str, width: int) -> bytes:
    text = _text(node, name, path)
    try:
        value = bytes.fromhex(text)
    except ValueError as failure:
        raise _reject(CaseFileFailure.UNEXPECTED_TYPE, f"{path}.{name}", failure) from None
    if len(value) != width:
        raise _reject(CaseFileFailure.OUT_OF_RANGE, f"{path}.{name}", len(value))
    return value


def _digest(node: dict[str, Any], name: str, path: str) -> Digest:
    value = _text(node, name, path)
    if len(value) != DIGEST_HEX_CHARS:
        raise _reject(CaseFileFailure.OUT_OF_RANGE, f"{path}.{name}", len(value))
    try:
        return Digest(bytes.fromhex(value))
    except ValueError as failure:
        raise _reject(CaseFileFailure.UNEXPECTED_TYPE, f"{path}.{name}", failure) from None
