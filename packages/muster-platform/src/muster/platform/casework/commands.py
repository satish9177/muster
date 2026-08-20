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
from muster.core.authority.check import AuthorityView
from muster.core.authority.signing import OfficerVerifier
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
from muster.platform.authority.resolve import published_revocations
from muster.platform.casework.advance import Advanced, AdvanceRejection, Casework, advance_case
from muster.platform.casework.ports import (
    CaseHead,
    DecidingScope,
    PublicationFailure,
    RecordedRequest,
    StoreFailure,
)
from muster.platform.casework.snapshot import (
    CaseSnapshot,
    read_case_inputs,
    read_published,
    read_working,
)
from muster.platform.ingest.admission import (
    AdmissionAuthority,
    admit_case_construction,
    admit_entry,
)
from muster.platform.orchestration.status import CaseStatus, status

#  ---- OpenCase -----------------------------------------------------------


class OpenFailure(Enum):
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    ADMISSION_REFUSED = "ADMISSION_REFUSED"
    STORE_REFUSED = "STORE_REFUSED"
    HEAD_REFUSED = "HEAD_REFUSED"
    #  The authorization context offers an authority registry snapshot that is
    #  not the one this tenant currently has in force -- a superseded one, one
    #  belonging to another tenant, or one that was never published.  Also the
    #  refusal when the tenant has no authority in force at all: G7's
    #  fail-closed absence, which is not the same event as a stale pin and does
    #  not share its detail.
    AUTHORITY_NOT_IN_FORCE = "AUTHORITY_NOT_IN_FORCE"


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

    **The authorization context is checked, not merely stored.**  It arrives
    from the caller and names the authority registry snapshot this case will be
    decided under for the rest of its life; ``_open`` refuses it unless it is
    the snapshot this tenant currently has in force.  See the comment there --
    it is the one place in this package where a present-tense authority fact is
    consulted, and the reasoning for why that is the right place and the only
    one belongs beside the check.
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
                    officer_verifier=casework.officer_verifier,
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
    scope: DecidingScope,
    *,
    officer_verifier: OfficerVerifier,
    tenant_id: str,
    case_id: str,
    construction: CaseConstructionRecord,
    authorization_context: AuthorizationContext,
    as_of: Instant,
    pin: Digest,
) -> CaseHead:
    #  ---- G7: a new case opens under the authority that is in force ---------
    #
    #  **First, before the construction record is even stored.**  A case that
    #  may not be opened should leave nothing behind, and this is the cheapest
    #  refusal available.
    #
    #  A case pins the authority it is decided under and replays against that
    #  pin forever, which is right and is not in question here.  What was open
    #  is *which* pin a case may choose at the moment it is created: nothing
    #  compared the offered snapshot against anything, so a caller could open a
    #  brand-new case naming a registry snapshot the publisher had already
    #  replaced -- and a grant withdrawn by publishing a successor would go on
    #  authorizing evidence in every case opened afterwards that simply named
    #  the older snapshot.  The key never had to be revoked for this to work,
    #  which is what made it a hole rather than a slow revocation.
    #
    #  The rule is equality with the snapshot the publisher currently names,
    #  which is the strongest staleness bound and the only one that needs no
    #  clock.  A bound expressed as a duration would have to be measured
    #  against *some* instant, and the only instant available here is ``as_of``
    #  -- which the caller supplies, and a freshness rule a caller can satisfy
    #  by choosing a number is not a freshness rule.
    #
    #  A **historical** case is untouched by any of this.  It is not reopened,
    #  it does not re-pin, and its rebuild resolves the snapshot its own
    #  authorization context names.  Publishing a successor is still invisible
    #  to it, exactly as ``AuthorityRepository`` promises.
    #
    #  The read holds the publication-state row in share mode for the rest of
    #  this transaction, so a successor published between this check and the
    #  head insert cannot slip through the gap: the publisher takes the row
    #  exclusively and waits.
    in_force = scope.authority.in_force_authority()
    if isinstance(in_force, Err):
        raise _Rejected(
            OpenRejection(
                OpenFailure.AUTHORITY_NOT_IN_FORCE,
                f"{in_force.error.failure.value}: {in_force.error.detail}",
            )
        )
    #  **Both pins, not only the registry.**  G7 names revocation snapshots
    #  alongside authority snapshots, and the asymmetry was real: a caller could
    #  pin the current registry beside a revocation list published before a key
    #  was withdrawn.  Admission refuses that key anyway -- it unions every
    #  published revocation list rather than reading the pin -- so the gap
    #  admitted no evidence.  What it did leave was a case whose *pinned* state
    #  disagrees with the publisher's, which every later reader of that pin
    #  inherits, including a chain that re-runs Q-12(f) from the pin alone.
    #  Refused here, once, rather than compensated for everywhere afterwards.
    for offered, current, what in (
        (
            authorization_context.authority_registry_snapshot_digest,
            in_force.value.in_force_authority_digest,
            "authority",
        ),
        (
            authorization_context.revocation_snapshot_digest,
            in_force.value.in_force_revocation_digest,
            "revocation state",
        ),
    ):
        if current is None:
            raise _Rejected(
                OpenRejection(
                    OpenFailure.AUTHORITY_NOT_IN_FORCE,
                    f"{PublicationFailure.PUBLICATION_STATE_ABSENT.value}: "
                    f"{scope.tenant_id} has published no {what}",
                )
            )
        if offered != current:
            raise _Rejected(
                OpenRejection(
                    OpenFailure.AUTHORITY_NOT_IN_FORCE,
                    f"{PublicationFailure.PUBLICATION_SUPERSEDED.value}: this case would open "
                    f"under {what} {offered.hex}, which is not the {what} in force",
                )
            )

    admitted = admit_case_construction(scope, case_id, construction, officer_verifier)
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


def _store(scope: DecidingScope, kind: DigestKind, octets: bytes) -> Digest:
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
    transcript, and bounded by the per-case entry cap.

    **The honest bound, which is not one rebuild.**  The transaction also
    resolves the case's pinned authority, re-verifies every stored attestation
    signature, and unions this tenant's revocation snapshots -- and that last
    one verifies a publisher signature *per published snapshot*, so the work
    grows with how many times the tenant has ever revoked anything.  Nothing
    data-dependent and unbounded *per call* runs here -- no solver, no Hinge
    projection, no planning, which is the property that made the hold
    affordable in the first place -- but a tenant with a long revocation
    history pays for it on every admission, and a publisher waits behind it.
    The fix is a publisher-maintained index of withdrawn keys, so the union
    becomes one indexed lookup; it is recorded rather than done here because it
    is a schema change and this milestone is a security closure.
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
    scope: DecidingScope,
    tenant_id: str,
    case_id: str,
    entry: TranscriptEntry,
) -> tuple[Digest, bool]:
    #  Two locks, taken in one order everywhere: the tenant's publication
    #  state, then this case.  The second is the older of the two and its
    #  reasoning is below; the first is milestone E's, and it is here.
    #
    #  **For linearization.**  This holds the tenant's publication-state row in
    #  share mode for the rest of this transaction, which is what gives
    #  revocation and admission a defined order.  Without it the schedule
    #      T1 reads revocation state -> T2 publishes revocation, commits ->
    #      T1 commits the receipt
    #  is permitted by read-committed, and it makes a receipt durable under a
    #  key that was already durably revoked.  With it, T2 waits for T1 or T1
    #  waits for T2, and either way the admission is judged against the
    #  revocation state that was current when it committed.  Share mode is what
    #  keeps this from being a global bottleneck: two admissions never wait for
    #  each other, and only a publisher -- rare, and taking the row exclusively
    #  -- makes anybody wait.
    #
    #  **For deadlock freedom.**  Every path that takes both this row and a
    #  case head takes them in this order: publication state, then the case.
    #  ``open_case`` does the same.  A publisher takes only this row and never a
    #  case.  There is therefore no cycle to close, and no path anywhere holds
    #  a case head while waiting for the publication state.
    #
    #  What is deliberately *not* done here is reading the in-force authority
    #  digest.  This transaction takes the lock and reads the epoch; the
    #  snapshot a receipt is judged against is the one the case pinned, resolved
    #  by digest below, and no admission may consult what is current.
    ordered = scope.authority.hold_publication_state()
    if isinstance(ordered, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.SNAPSHOT_REFUSED,
                f"{ordered.error.failure.value}: {ordered.error.detail}",
            )
        )

    #  The case hold comes before any write, and that order is deliberate twice
    #  over.
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
    #
    #  ``open_case`` is the one path that inserts content *before* a head, and
    #  it has to: the head does not exist yet and its row references the
    #  content by foreign key.  That is safe rather than an exception to the
    #  rule, because every artifact it writes is case-bound -- a construction
    #  record, an authorization context and an empty prefix all carry the case
    #  inside the octets that name them -- so no two cases ever contend for one
    #  content row.  Stated here because the ordering claim above is what a
    #  reader checks it against.
    held = scope.heads.hold(case_id)
    if isinstance(held, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.MEMBERSHIP_REFUSED,
                f"{held.error.failure.value}: {held.error.detail}",
            )
        )

    #  The case's own pinned state, read before anything is written.  The
    #  authority a receipt is judged against belongs to the case, not to the
    #  receipt, and resolving it after the membership row existed would be
    #  resolving it too late to refuse.
    inputs = read_case_inputs(
        scope, case_id, casework.publisher_verifier, casework.officer_verifier
    )
    if isinstance(inputs, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.SNAPSHOT_REFUSED,
                f"{inputs.error.failure.value}: {inputs.error.detail}",
            )
        )
    loaded = casework.registry.load_by_digest(inputs.value.head.inputs.bundle_manifest_digest)
    if isinstance(loaded, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.POLICY_UNAVAILABLE,
                f"{loaded.error.failure.value}: {loaded.error.detail}",
            )
        )
    withdrawn = published_revocations(scope, casework.publisher_verifier)
    if isinstance(withdrawn, Err):
        raise _Rejected(
            AppendRejection(
                AppendFailure.SNAPSHOT_REFUSED,
                f"{withdrawn.error.failure.value}: {withdrawn.error.detail}",
            )
        )
    admitted = admit_entry(
        scope,
        case_id,
        entry,
        AdmissionAuthority(
            source_verifier=casework.source_verifier,
            schema=loaded.value.predicate_schema,
            pinned_schema_digest=loaded.value.predicate_schema.digest(),
            view=AuthorityView(
                snapshot=inputs.value.authority.snapshot,
                revocation=inputs.value.authority.revocation,
                tenant_id=tenant_id,
                authorization_policy_version=(
                    inputs.value.authorization_context.authorization_policy_version
                ),
                case_scope_coordinates=inputs.value.construction.case_scope_coordinates,
                as_of=inputs.value.head.inputs.as_of,
            ),
            withdrawn_keys=withdrawn.value,
        ),
    )
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
    casework: Casework, scope: DecidingScope, tenant_id: str, case_id: str
) -> None:
    """Refuse a membership that the case could not be rebuilt from.

    Reads the transcript *including* the row this transaction just inserted --
    the scope is the writing transaction, so it sees its own work -- and
    derives the revision it would produce. Only whether it succeeds is used;
    the revision itself is discarded, because publishing is the next
    transaction's job and this one must not hold a solver.
    """
    snapshot = read_working(
        scope,
        case_id,
        casework.publisher_verifier,
        casework.officer_verifier,
        casework.source_verifier,
    )
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
        working.authority.snapshot,
        working.authority.revocation,
        working.solicitations,
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

        snapshot = read_published(
            scope,
            case_id,
            casework.publisher_verifier,
            casework.officer_verifier,
            casework.source_verifier,
        )
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
        snapshot.authority.snapshot,
        snapshot.authority.revocation,
        snapshot.solicitations,
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
