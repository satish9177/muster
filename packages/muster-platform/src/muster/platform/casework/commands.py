"""The three operations a caller has, as direct calls rather than endpoints.

``OpenCase`` and ``AppendTranscriptEntry`` are commands; ``GetCaseStatus`` is a
query.  There is no HTTP here.  A transport is an adapter over these functions
and it changes none of their semantics, so building one now would mean testing
the transport instead of the thing this milestone is about.

Every one of them is idempotent, and none of them needed an idempotency key to
get there: a case is identified by inputs that are digests, an entry by its own
digest, and a request by the digest of a record naming the revision it answers.
That is structural idempotency, and it is the reason there is no saga, no
outbox and no deduplication table anywhere in this package.

**A rejected command writes nothing.**  A ``return`` out of a transaction block
is a *normal* exit and commits, so every rejection here leaves by exception and
is caught outside the block.  Without that, refusing to open a case would still
deposit its construction record in the store forever -- the content store has
no delete, by design, so a rejection that wrote would be permanent.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.case.revision import (
    AuthorizationContext,
    RebuildInputs,
    RebuildMode,
    TranscriptPrefix,
)
from muster.core.evidence.transcript import CaseConstructionRecord, TranscriptEntry
from muster.core.results import Err, Ok, Result
from muster.core.values.times import Instant
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest, DigestKind
from muster.platform.casework.advance import Advanced, AdvanceRejection, Casework, advance_case
from muster.platform.casework.ports import CaseHead, RecordedRequest, StoreFailure, TenantScope
from muster.platform.casework.snapshot import CaseSnapshot, read_published, read_working
from muster.platform.ingest.admission import admit_case_construction, admit_entry
from muster.platform.orchestration.status import CaseStatus, status

#  ---- OpenCase -----------------------------------------------------------


class OpenFailure(Enum):
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    ADMISSION_REFUSED = "ADMISSION_REFUSED"
    STORE_REFUSED = "STORE_REFUSED"
    HEAD_REFUSED = "HEAD_REFUSED"


@dataclass(frozen=True, slots=True)
class OpenRejection:
    failure: OpenFailure
    detail: str


class _Rejected(Exception):
    """Roll the transaction back and report. Never leaves this module."""

    def __init__(self, rejection: OpenRejection | AppendRejection) -> None:
        super().__init__(f"{rejection.failure.value}: {rejection.detail}")
        self.rejection = rejection


def open_case(
    casework: Casework,
    *,
    tenant_id: str,
    construction: CaseConstructionRecord,
    authorization_context: AuthorizationContext,
    policy_id: str,
    as_of: Instant,
) -> Result[CaseHead, OpenRejection]:
    """Make a case durable, with an empty transcript and no revision yet.

    There is no ``mode`` parameter.  A counterfactual rebuild answers a
    question and persists nothing, so "open a counterfactual case" is not a
    thing a caller can express here -- which is a stronger guarantee than
    refusing it would be.

    Nothing is analysed.  A case that has been opened and never analysed is a
    real state, and running a solver inside the command that creates a case
    would put the slowest operation in the system in the fastest one.
    """
    resolved = casework.registry.resolve(policy_id, as_of)
    if isinstance(resolved, Err):
        return Err(
            OpenRejection(
                OpenFailure.POLICY_UNAVAILABLE,
                f"{resolved.error.failure.value}: {resolved.error.detail}",
            )
        )
    case_id = construction.case_id

    try:
        with casework.database.writing(tenant_id) as scope:
            return Ok(
                _open(
                    scope,
                    tenant_id=tenant_id,
                    case_id=case_id,
                    construction=construction,
                    authorization_context=authorization_context,
                    as_of=as_of,
                    pin=resolved.value,
                )
            )
    except _Rejected as rejection:
        assert isinstance(rejection.rejection, OpenRejection)
        return Err(rejection.rejection)


def _open(
    scope: TenantScope,
    *,
    tenant_id: str,
    case_id: str,
    construction: CaseConstructionRecord,
    authorization_context: AuthorizationContext,
    as_of: Instant,
    pin: Digest,
) -> CaseHead:
    admitted = admit_case_construction(scope, case_id, construction)
    if isinstance(admitted, Err):
        raise _Rejected(
            OpenRejection(
                OpenFailure.ADMISSION_REFUSED,
                f"{admitted.error.failure.value}: {admitted.error.detail}",
            )
        )
    context = _store(
        scope, DigestKind.AUTHORIZATION_CONTEXT, encode(authorization_context.to_node())
    )

    #  The prefix of an empty transcript is still an artifact the head points
    #  at, and replay resolves it like any other. Storing it here means a case
    #  is replayable from the instant it exists rather than from its first
    #  analysis.
    prefix = TranscriptPrefix(tenant_id, case_id, ())
    stored_prefix = _store(scope, DigestKind.TRANSCRIPT_PREFIX, encode(prefix.to_node()))

    opened = scope.heads.open(
        RebuildInputs(
            tenant_id=tenant_id,
            case_id=case_id,
            construction_digest=admitted.value,
            transcript_prefix_digest=stored_prefix,
            bundle_manifest_digest=pin,
            as_of=as_of,
            mode=RebuildMode.OPERATIONAL,
            authorization_context_digest=context,
        )
    )
    if isinstance(opened, Err):
        raise _Rejected(
            OpenRejection(
                OpenFailure.HEAD_REFUSED, f"{opened.error.failure.value}: {opened.error.detail}"
            )
        )
    return opened.value


def _store(scope: TenantScope, kind: DigestKind, octets: bytes) -> Digest:
    stored = scope.content.put(kind, octets)
    if isinstance(stored, Err):
        raise _Rejected(OpenRejection(OpenFailure.STORE_REFUSED, str(stored.error)))
    return stored.value


#  ---- AppendTranscriptEntry ----------------------------------------------


class AppendFailure(Enum):
    ADMISSION_REFUSED = "ADMISSION_REFUSED"
    MEMBERSHIP_REFUSED = "MEMBERSHIP_REFUSED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    SNAPSHOT_REFUSED = "SNAPSHOT_REFUSED"
    #  Admitting this entry would leave the case unable to rebuild at all.
    #  Refused *before* the membership commits, because the transcript is
    #  append-only and there is no operation that could take it back out.
    TRANSCRIPT_WOULD_NOT_REBUILD = "TRANSCRIPT_WOULD_NOT_REBUILD"


@dataclass(frozen=True, slots=True)
class AppendRejection:
    failure: AppendFailure
    detail: str


@dataclass(frozen=True, slots=True)
class Appended:
    entry_digest: Digest
    #  ``False`` when the entry was already a member: a duplicate delivery, and
    #  a success. The case still advances, because a duplicate that arrives
    #  while the previous one is unpublished must not leave it unpublished.
    created: bool
    #  The advance is reported *inside* the success, not instead of it.
    #
    #  Appending succeeds when the entry is durable, which is what the caller
    #  asked for and what every later advance of this case will see. Whether
    #  the analysis that followed could publish is a different question with
    #  its own answer, and it can legitimately be "not yet": a case whose facts
    #  are still arriving can exceed the engine's case-size bound in the middle
    #  and fall back under it at the end. Collapsing the two would either
    #  discard a durable entry's receipt or hide a refusal, and a caller has to
    #  be able to see both.
    advanced: Result[Advanced, AdvanceRejection]


def append_transcript_entry(
    casework: Casework, *, tenant_id: str, case_id: str, entry: TranscriptEntry, now: Instant
) -> Result[Appended, AppendRejection]:
    """Admit an entry, then advance the case.

    Two transactions with the analysis between them.  The first one is short
    and it is the one that matters for durability: once it commits, the entry
    is in the transcript and every later advance of this case sees it, whatever
    happens to this process next.

    **The first transaction rebuilds before it commits, and that is
    deliberate.**  Membership is append-only and nothing can remove a member,
    so an entry that leaves the transcript unrebuildable would freeze the case
    permanently -- every later advance would refuse, and no operation in this
    package could undo it.  Two admissible receipts establishing one
    proposition do exactly that: each is individually valid, and the pair is
    refused by ``rebuild`` as a duplicate established reference.  So the check
    has to happen where it can still be rolled back, which is inside the
    transaction that commits the membership.

    **And the case is held for the length of that transaction.**  Rolling back
    is not enough on its own: two appenders inserting two different membership
    rows conflict on nothing, so under read-committed each rebuilds against a
    transcript that omits the other's entry, each is satisfied, and both
    commit.  The pair is then durable and the case is frozen exactly as if
    neither check existed.  ``heads.hold`` serialises admission per case so
    that the transcript a rebuild is checked against is the transcript the
    commit produces.  It is one row lock on one case: appends to other cases
    do not wait for it and no read takes it at all.

    The transaction is therefore held across a ``rebuild`` -- and across
    nothing else.  No solver runs inside it, no Hinge projection and no
    planning: those are the operations whose cost is data-dependent and
    unbounded, and they run with no transaction open, which is the property
    that matters. A rebuild is admissibility and entailment over the entries
    already in hand, measured at roughly twenty milliseconds for this case's
    transcript, and bounded by the per-case entry cap.  That bound is what
    makes the hold affordable: the longest anything can wait behind an
    admission is one rebuild, not one analysis.
    """
    try:
        with casework.database.writing(tenant_id) as scope:
            entry_digest, created = _admit(casework, scope, tenant_id, case_id, entry)
    except _Rejected as rejection:
        assert isinstance(rejection.rejection, AppendRejection)
        return Err(rejection.rejection)

    return Ok(
        Appended(
            entry_digest,
            created,
            advance_case(casework, tenant_id=tenant_id, case_id=case_id, now=now),
        )
    )


def _admit(
    casework: Casework,
    scope: TenantScope,
    tenant_id: str,
    case_id: str,
    entry: TranscriptEntry,
) -> tuple[Digest, bool]:
    #  The hold comes first, before any write, and the order is deliberate
    #  twice over.
    #
    #  It has to come before the *membership*, because otherwise two appenders
    #  insert two differently-keyed rows, neither blocks, neither sees the
    #  other under read-committed, both rebuild against a transcript that is
    #  missing the other's entry, and both commit -- leaving a transcript that
    #  rebuilds for nobody and cannot be shortened. Two admissible receipts
    #  establishing one proposition, delivered at once, do exactly that.
    #
    #  It has to come before the *octets* as well, so that every appender takes
    #  its locks in one order: the case, then the content, then the membership.
    #  Admitting first would mean an appender holding content and waiting for
    #  the case while another held the case and waited for that content.
    held = scope.heads.hold(case_id)
    if isinstance(held, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.MEMBERSHIP_REFUSED,
                f"{held.error.failure.value}: {held.error.detail}",
            )
        )

    admitted = admit_entry(scope, case_id, entry)
    if isinstance(admitted, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.ADMISSION_REFUSED,
                f"{admitted.error.failure.value}: {admitted.error.detail}",
            )
        )
    added = scope.transcript.add(case_id, admitted.value.entry_digest)
    if isinstance(added, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.MEMBERSHIP_REFUSED,
                f"{added.error.failure.value}: {added.error.detail}",
            )
        )
    if added.value:
        _require_rebuildable(casework, scope, tenant_id, case_id)
    return admitted.value.entry_digest, added.value


def _require_rebuildable(
    casework: Casework, scope: TenantScope, tenant_id: str, case_id: str
) -> None:
    """Refuse a membership that the case could not be rebuilt from.

    Reads the transcript *including* the row this transaction just inserted --
    the scope is the writing transaction, so it sees its own work -- and
    derives the revision it would produce. Only whether it succeeds is used;
    the revision itself is discarded, because publishing is the next
    transaction's job and this one must not hold a solver.
    """
    snapshot = read_working(scope, case_id)
    if isinstance(snapshot, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.SNAPSHOT_REFUSED,
                f"{snapshot.error.failure.value}: {snapshot.error.detail}",
            )
        )
    bundle = casework.registry.load_by_digest(snapshot.value.head.inputs.bundle_manifest_digest)
    if isinstance(bundle, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.POLICY_UNAVAILABLE,
                f"{bundle.error.failure.value}: {bundle.error.detail}",
            )
        )
    working = snapshot.value
    prefix = transcript_prefix(tenant_id, case_id, working.entries)
    derived = rebuild(
        replace(working.head.inputs, transcript_prefix_digest=prefix.digest()),
        working.construction,
        working.entries,
        bundle.value,
        working.authorization_context,
    )
    if isinstance(derived, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.TRANSCRIPT_WOULD_NOT_REBUILD,
                f"{derived.error.failure.value}: {derived.error.detail}",
            )
        )


#  ---- GetCaseStatus ------------------------------------------------------


class StatusFailure(Enum):
    UNKNOWN_CASE = "UNKNOWN_CASE"
    SNAPSHOT_REFUSED = "SNAPSHOT_REFUSED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    REBUILD_REFUSED = "REBUILD_REFUSED"
    ANALYSIS_REFUSED = "ANALYSIS_REFUSED"
    #  Replaying the head's own inputs produced a different revision than the
    #  head names. Unlike a certificate that fails to reproduce, this one is
    #  fatal: a revision is a pure function of the rebuild inputs and the
    #  store, so a mismatch means one of those is not what it was.
    REVISION_DIVERGED = "REVISION_DIVERGED"


@dataclass(frozen=True, slots=True)
class StatusRejection:
    failure: StatusFailure
    detail: str


@dataclass(frozen=True, slots=True)
class CaseReport:
    head: CaseHead
    status: CaseStatus
    #  ``None`` only for a case that has never been analysed. Everything else
    #  here is recomputed on the way past, not read out of a column.
    analysis: CaseAnalysis | None
    outstanding: tuple[RecordedRequest, ...]
    #  Outstanding requests whose deadline has passed. Reported rather than
    #  inferred, so a caller escalating a case can name which source went quiet
    #  instead of only that one did.
    expired: tuple[RecordedRequest, ...]
    #  Did replaying the head under *this* process's engine configuration
    #  reproduce the certificate the head names?
    #
    #  Reported, never enforced.  A certificate binds the solver fingerprint --
    #  backend, version, logic, budget -- and the query digests, whose count
    #  depends on the engine's action cap. None of those is a rebuild input or
    #  a stored column, so they are properties of the *process*, not of the
    #  case. Changing the configured backend or a bound therefore changes the
    #  certificate a replay produces, legitimately and by design; treating that
    #  as an integrity failure would make every already-published case
    #  permanently unreadable the first time an operator raised the case-size
    #  cap. The published digest stays on the head, where an auditor can see
    #  what was certified at the time.
    certificate_reproduced: bool


def case_status(
    casework: Casework, *, tenant_id: str, case_id: str, now: Instant
) -> Result[CaseReport, StatusRejection]:
    """Replay the head and project its status. Nothing here was stored.

    The replay is the point.  It resolves the head's own transcript prefix,
    rebuilds from exactly the entries that prefix names, and re-analyses. A
    status query that agreed with a stored column would prove the column; this
    one proves the derivation.
    """
    with casework.database.reading(tenant_id) as scope:
        head_read = scope.heads.read(case_id)
        if isinstance(head_read, Err):
            return Err(StatusRejection(StatusFailure.UNKNOWN_CASE, head_read.error.detail))
        head = head_read.value
        if head.revision_digest is None:
            return Ok(CaseReport(head, CaseStatus.INTAKE, None, (), (), True))

        snapshot = read_published(scope, case_id)
        if isinstance(snapshot, Err):
            return Err(
                StatusRejection(
                    StatusFailure.SNAPSHOT_REFUSED,
                    f"{snapshot.error.failure.value}: {snapshot.error.detail}",
                )
            )
        listed = scope.requests.outstanding(case_id)
        if isinstance(listed, Err):
            return Err(StatusRejection(StatusFailure.UNKNOWN_CASE, listed.error.detail))
        outstanding = listed.value
        cached_revision = scope.content.get(DigestKind.CASE_REVISION, head.revision_digest)

    replayed = _replay(casework, head, snapshot.value)
    if isinstance(replayed, Err):
        return replayed
    analysis = replayed.value

    #  The cached revision is read, not merely written. A hit must be exactly
    #  the octets the replay produced -- which is the whole content-addressing
    #  claim, checked on every status read rather than only in a test. A miss
    #  costs the recomputation that already happened and nothing else, which is
    #  what makes it a cache.
    if isinstance(cached_revision, Ok):
        if cached_revision.value != encode(analysis.revision.to_node()):
            return Err(
                StatusRejection(
                    StatusFailure.REVISION_DIVERGED,
                    f"the cached revision is not {head.revision_digest.hex}",
                )
            )
    elif cached_revision.error.failure is not StoreFailure.CONTENT_ABSENT:
        return Err(StatusRejection(StatusFailure.REVISION_DIVERGED, str(cached_revision.error)))

    return Ok(
        CaseReport(
            head=head,
            status=status(
                certificate=analysis.certificate,
                outstanding_deadlines=tuple(request.deadline for request in outstanding),
                now=now,
            ),
            analysis=analysis,
            outstanding=outstanding,
            expired=tuple(request for request in outstanding if request.deadline <= now),
            certificate_reproduced=analysis.certificate.digest() == head.certificate_digest,
        )
    )


def _replay(
    casework: Casework, head: CaseHead, snapshot: CaseSnapshot
) -> Result[CaseAnalysis, StatusRejection]:
    loaded = casework.registry.load_by_digest(head.inputs.bundle_manifest_digest)
    if isinstance(loaded, Err):
        return Err(
            StatusRejection(
                StatusFailure.POLICY_UNAVAILABLE,
                f"{loaded.error.failure.value}: {loaded.error.detail}",
            )
        )
    bundle = loaded.value

    revision = rebuild(
        head.inputs,
        snapshot.construction,
        snapshot.entries,
        bundle,
        snapshot.authorization_context,
    )
    if isinstance(revision, Err):
        return Err(
            StatusRejection(
                StatusFailure.REBUILD_REFUSED,
                f"{revision.error.failure.value}: {revision.error.detail}",
            )
        )
    if revision.value.digest() != head.revision_digest:
        return Err(
            StatusRejection(
                StatusFailure.REVISION_DIVERGED, f"replay produced {revision.value.digest().hex}"
            )
        )

    analysed = analyse_revision(revision.value, bundle, casework.backend(), casework.limits)
    if isinstance(analysed, Err):
        return Err(StatusRejection(StatusFailure.ANALYSIS_REFUSED, str(analysed.error)))
    return Ok(analysed.value)
