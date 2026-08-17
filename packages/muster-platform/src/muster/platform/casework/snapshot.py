"""Turning durable octets back into the values ``rebuild`` takes.

Two reads, and the difference between them is the difference between "what is
true now" and "what the head committed to".

``read_working`` resolves the *current* membership set: it is what a case is
advanced from.  ``read_published`` resolves the membership the head's own
transcript prefix names: it is what the head is *replayed* from.  They differ
exactly when an entry has arrived and not yet been published, which is a normal
state and not a fault, and conflating them would either replay a head that
never existed or advance a case while ignoring evidence it already holds.

``read_published`` is why the prefix is stored at all.  A prefix digest is a
hash of a digest list and nothing recovers the list from it, so a revision
cannot be rebuilt from ``RebuildInputs`` and a store unless the store holds the
prefix.  Replay is defined as ``rebuild(RebuildInputs, store)``; the prefix is
the part of the store that makes the definition true.

Every artifact is re-bound on the way in.  The store is keyed by tenant, so a
cross-tenant read is already unrepresentable, but a case naming another case's
construction record inside one tenant is not -- and an artifact that says which
case it belongs to should be believed about it or refused, never ignored.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from muster.core.case.revision import (
    AuthorizationContext,
    TranscriptPrefix,
    read_authorization_context,
    read_transcript_prefix,
)
from muster.core.evidence.transcript import (
    Attestation,
    CaseConstructionRecord,
    Statement,
    TranscriptEntry,
    read_case_construction,
    read_entry,
)
from muster.core.results import Err, Ok, Result
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest, DigestKind
from muster.core.wire.nodes import Node
from muster.core.wire.shape import decoded
from muster.platform.casework.ports import CaseHead, StoreError, StoreFailure, TenantScope


class SnapshotFailure(Enum):
    UNKNOWN_CASE = "UNKNOWN_CASE"
    CONTENT_ABSENT = "CONTENT_ABSENT"
    #  Stored octets that the codec or a typed reader refuses. Not a decode
    #  detail a caller can recover from: an artifact the store cannot read back
    #  is an artifact the case can no longer be rebuilt from.
    CONTENT_UNREADABLE = "CONTENT_UNREADABLE"
    #  A stored artifact naming a different tenant or case than the one that
    #  reached for it.
    BINDING_MISMATCH = "BINDING_MISMATCH"
    NOT_ANALYSED = "NOT_ANALYSED"


@dataclass(frozen=True, slots=True)
class SnapshotError:
    failure: SnapshotFailure
    detail: str


@dataclass(frozen=True, slots=True)
class CaseSnapshot:
    """Everything ``rebuild`` needs, read at one instant."""

    head: CaseHead
    construction: CaseConstructionRecord
    authorization_context: AuthorizationContext
    entries: tuple[TranscriptEntry, ...]


def read_working(scope: TenantScope, case_id: str) -> Result[CaseSnapshot, SnapshotError]:
    """The head, and every transcript member that has arrived so far."""
    head = scope.heads.read(case_id)
    if isinstance(head, Err):
        return Err(SnapshotError(SnapshotFailure.UNKNOWN_CASE, head.error.detail))
    members = scope.transcript.members(case_id)
    if isinstance(members, Err):
        return Err(SnapshotError(SnapshotFailure.UNKNOWN_CASE, members.error.detail))
    return _assemble(scope, head.value, members.value)


def read_published(scope: TenantScope, case_id: str) -> Result[CaseSnapshot, SnapshotError]:
    """The head, and exactly the members its own transcript prefix names."""
    head = scope.heads.read(case_id)
    if isinstance(head, Err):
        return Err(SnapshotError(SnapshotFailure.UNKNOWN_CASE, head.error.detail))
    if head.value.revision_digest is None:
        return Err(SnapshotError(SnapshotFailure.NOT_ANALYSED, case_id))
    prefix = _read_prefix(scope, head.value)
    if isinstance(prefix, Err):
        return prefix
    return _assemble(scope, head.value, prefix.value.entry_digests)


def _read_prefix(scope: TenantScope, head: CaseHead) -> Result[TranscriptPrefix, SnapshotError]:
    octets = scope.content.get(DigestKind.TRANSCRIPT_PREFIX, head.inputs.transcript_prefix_digest)
    if isinstance(octets, Err):
        return Err(_store_error(octets.error))
    prefix = _read(octets.value, read_transcript_prefix, "TranscriptPrefix")
    if isinstance(prefix, Err):
        return prefix
    bound = _bound(
        (prefix.value.tenant_id, prefix.value.case_id),
        scope.tenant_id,
        head.case_id,
        "TranscriptPrefix",
    )
    if isinstance(bound, Err):
        return bound
    return prefix


def _assemble(
    scope: TenantScope, head: CaseHead, members: tuple[Digest, ...]
) -> Result[CaseSnapshot, SnapshotError]:
    construction = _read_construction(scope, head)
    if isinstance(construction, Err):
        return construction
    context = _read_context(scope, head)
    if isinstance(context, Err):
        return context

    entries: list[TranscriptEntry] = []
    for member in members:
        octets = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, member)
        if isinstance(octets, Err):
            return Err(_store_error(octets.error))
        entry = _read(octets.value, read_entry, "TranscriptEntry")
        if isinstance(entry, Err):
            return entry
        bound = _bound(_binding_of(entry.value), scope.tenant_id, head.case_id, "TranscriptEntry")
        if isinstance(bound, Err):
            return bound
        entries.append(entry.value)

    return Ok(CaseSnapshot(head, construction.value, context.value, tuple(entries)))


def _read_construction(
    scope: TenantScope, head: CaseHead
) -> Result[CaseConstructionRecord, SnapshotError]:
    octets = scope.content.get(DigestKind.CASE_CONSTRUCTION, head.inputs.construction_digest)
    if isinstance(octets, Err):
        return Err(_store_error(octets.error))
    record = _read(octets.value, read_case_construction, "CaseConstructionRecord")
    if isinstance(record, Err):
        return record
    bound = _bound(
        (record.value.tenant_id, record.value.case_id),
        scope.tenant_id,
        head.case_id,
        "CaseConstructionRecord",
    )
    if isinstance(bound, Err):
        return bound
    for party in record.value.parties:
        #  Re-checked on the way out as well as on the way in. Admission is one
        #  of two doors into the store -- the other is an operator with SQL --
        #  and a role declaration for another tenant's principal is exactly the
        #  thing a case must not be rebuilt from because somebody put it there.
        party_bound = _bound(
            (party.tenant_id, head.case_id), scope.tenant_id, head.case_id, "PartyRecord"
        )
        if isinstance(party_bound, Err):
            return party_bound
    return record


def _read_context(
    scope: TenantScope, head: CaseHead
) -> Result[AuthorizationContext, SnapshotError]:
    octets = scope.content.get(
        DigestKind.AUTHORIZATION_CONTEXT, head.inputs.authorization_context_digest
    )
    if isinstance(octets, Err):
        return Err(_store_error(octets.error))
    #  An authorization context carries no tenant of its own -- it pins external
    #  authority state, not case identity -- so there is nothing to re-bind. Its
    #  digest is in the head, and ``rebuild`` checks it against the inputs.
    return _read(octets.value, read_authorization_context, "AuthorizationContext")


def _read[T](octets: bytes, reader: Callable[[Node], T], what: str) -> Result[T, SnapshotError]:
    node = decode(octets)
    if isinstance(node, Err):
        return Err(SnapshotError(SnapshotFailure.CONTENT_UNREADABLE, f"{what}: {node.error}"))
    decoded_node = node.value
    read = decoded(lambda: reader(decoded_node))
    if isinstance(read, Err):
        return Err(SnapshotError(SnapshotFailure.CONTENT_UNREADABLE, f"{what}: {read.error}"))
    return Ok(read.value)


def _binding_of(entry: TranscriptEntry) -> tuple[str, str]:
    match entry:
        case Attestation(receipt):
            return receipt.payload.tenant_id, receipt.payload.case_id
        case Statement(record):
            return record.tenant_id, record.case_id


def _bound(
    binding: tuple[str, str], tenant_id: str, case_id: str, what: str
) -> Result[None, SnapshotError]:
    carried_tenant, carried_case = binding
    if carried_tenant != tenant_id or carried_case != case_id:
        return Err(
            SnapshotError(
                SnapshotFailure.BINDING_MISMATCH,
                f"{what} names {carried_tenant!r}/{carried_case!r}, "
                f"read under {tenant_id!r}/{case_id!r}",
            )
        )
    return Ok(None)


def _store_error(error: StoreError) -> SnapshotError:
    failure = (
        SnapshotFailure.CONTENT_ABSENT
        if error.failure is StoreFailure.CONTENT_ABSENT
        else SnapshotFailure.CONTENT_UNREADABLE
    )
    return SnapshotError(failure, f"{error.failure.value} {error.digest} {error.detail}")
