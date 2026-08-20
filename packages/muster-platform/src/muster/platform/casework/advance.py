"""Advancing a case: two short transactions with the analysis between them.

```
TX A   hold the case                     (append_transcript_entry only)
       admit canonical octets
       add transcript membership
       rebuild -- refuse if the case would not rebuild
COMMIT

--     read a consistent snapshot: head + membership + the octets behind them
       rebuild, prepare, project, analyse, plan, assemble
       decide                                        no transaction is open

TX B   hold the case
       refuse if the head moved or the membership grew
       cache the prefix
       compare-and-swap the head from the parent that was analysed
       cache the revision and certificate; record the request
COMMIT
```

**Why a concurrent append cannot be lost.**  Membership is an append-only set,
and the prefix is a function of the whole set rather than of what this caller
contributed.  TX B holds the case, re-reads the membership, and refuses to
publish unless it is exactly the set that was analysed -- so a computation that
started before an entry committed loses and retries over the larger set,
exactly as it would have lost a swap.

That check is not redundant with the compare-and-swap, and the difference is
the whole reason it exists: **a head that has not moved is not the same as a
transcript that has not grown.**  An entry committed while this analysis was
running leaves the head untouched, so the swap matches and publishes a prefix
that omits evidence which was already durable.  Relying on the writer that
committed the entry to correct it afterwards assumes that writer is still
alive, and this milestone has no process that would notice if it were not.

What the head can be is *behind* the transcript -- an entry committed with no
advance yet is a normal state -- but never inconsistent with what was durable
at the instant it published.

**Why a stale analysis cannot overwrite a newer head.**  The swap is
conditional on the entire parent state, so a computation that started from one
head matches no row once the head is any other.  Bounded at
``max_publication_attempts``; after that the caller is told there is contention,
because a loop that retries until it wins is a loop that stops reporting.

**Why the analysis is outside the transaction.**  A solver call is the slowest
thing in the system and its duration is data-dependent.  Holding a transaction
across it would hold a snapshot, and on a contended case it would hold it for
as long as the hardest query in the queue takes.

**What a crash between the two costs.**  Nothing but time.  TX A leaves a
durable entry that no revision cites yet; the next advance cites it.  TX B is
atomic, so there is no state in which the head moved and the artifacts it names
did not appear with it.  There is no compensating action anywhere here, because
every step is idempotent by construction rather than by bookkeeping.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum

from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.authority.signing import OfficerVerifier, PublisherVerifier, SourceVerifier
from muster.core.case.revision import TranscriptPrefix
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.times import Duration, Instant
from muster.core.wire.codec import encode
from muster.core.wire.digests import DigestKind
from muster.hinge.prepare import EngineLimits
from muster.platform.casework.ports import (
    CaseHead,
    CaseworkDatabase,
    DecidingScope,
    HeadFailure,
    RecordedRequest,
    is_durable_instant,
)
from muster.platform.casework.snapshot import CaseSnapshot, read_working
from muster.platform.orchestration.decide import decide
from muster.platform.orchestration.decisions import Decision, Dispatch, Idle
from muster.policy.registry import BundleRegistry
from muster.solve.backend import SolverBackend


@dataclass(frozen=True, slots=True)
class CaseworkPolicy:
    """The operator's numbers for the shell, as the kernel has for the engine.

    There is no default for either, on purpose: an unbounded retry loop and an
    absent deadline are both failures that look like working software until a
    case is contended or a source goes quiet.

    The TTL is a ``Duration``, not an ``Instant``.  An operator configures "how
    long a source has", which is a length; the deadline it produces is a point,
    and only ``Duration.after`` turns the one into the other.  Spelling both as
    integers let a configured instant be read as a TTL and the reverse, and
    neither mistake had a signature that could refuse it.
    """

    max_publication_attempts: int
    evidence_request_ttl: Duration

    def __post_init__(self) -> None:
        if self.max_publication_attempts < 1:
            raise InvariantViolation(
                f"at least one publication attempt: {self.max_publication_attempts}"
            )
        if not self.evidence_request_ttl.is_positive():
            raise InvariantViolation(f"a deadline lies ahead of now: {self.evidence_request_ttl}")


@dataclass(frozen=True, slots=True)
class Casework:
    """Everything advancing a case needs, and nothing that holds state.

    The backend is a factory rather than an instance because a solver is
    single-use per analysis and a retry runs a second one; sharing one across
    attempts would carry assertions from a discarded computation into the next.
    """

    database: CaseworkDatabase
    registry: BundleRegistry
    backend: Callable[[], SolverBackend]
    limits: EngineLimits
    policy: CaseworkPolicy
    #  Three verifiers, never one.  ``source_verifier`` holds the public
    #  material of the agents that attest; ``publisher_verifier`` holds the
    #  public material of the control plane that publishes who may attest;
    #  ``officer_verifier`` holds the public material of the officers who open
    #  cases and thereby fix what each case is *about*.  A single keyring for
    #  any two would collapse a boundary: a source key that could authenticate
    #  an authority publication is the shortest path from "a source" to "a
    #  source that granted itself authority", and a source key that could
    #  authenticate a construction record is the shortest path to a source that
    #  declared the site it already held a grant over.
    source_verifier: SourceVerifier
    publisher_verifier: PublisherVerifier
    officer_verifier: OfficerVerifier


class AdvanceFailure(Enum):
    SNAPSHOT_REFUSED = "SNAPSHOT_REFUSED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    REBUILD_REFUSED = "REBUILD_REFUSED"
    ANALYSIS_REFUSED = "ANALYSIS_REFUSED"
    STORE_REFUSED = "STORE_REFUSED"
    HEAD_REFUSED = "HEAD_REFUSED"
    REQUEST_REFUSED = "REQUEST_REFUSED"
    #  Every attempt lost the swap. Reported, never hidden behind more retries:
    #  sustained contention on one case is an operational fact somebody needs.
    CONCURRENCY_CONFLICT = "CONCURRENCY_CONFLICT"
    #  The deadline this decision computed does not fit in the column that would
    #  hold it -- a TTL large enough to push it past a signed 64-bit instant.
    #  Refused here, before any transaction opens, because the value type also
    #  refuses it and would do so *after* the head had already swapped.
    DEADLINE_NOT_DURABLE = "DEADLINE_NOT_DURABLE"


@dataclass(frozen=True, slots=True)
class AdvanceRejection:
    failure: AdvanceFailure
    detail: str


@dataclass(frozen=True, slots=True)
class Advanced:
    """What one advance did, including having found nothing to do."""

    head: CaseHead
    analysis: CaseAnalysis
    decision: Decision
    attempts: int
    published: bool


def advance_case(
    casework: Casework, *, tenant_id: str, case_id: str, now: Instant
) -> Result[Advanced, AdvanceRejection]:
    """Rebuild this case from everything it durably holds, and publish the result.

    Idempotent and re-drivable.  Calling it twice with nothing in between
    reaches the head that already exists and reports ``Idle``, which is what
    makes recovery after a crash "call it again" rather than a procedure.
    """
    for attempt in range(1, casework.policy.max_publication_attempts + 1):
        computed = _compute(casework, tenant_id=tenant_id, case_id=case_id, now=now)
        if isinstance(computed, Err):
            return computed
        work = computed.value

        if isinstance(work.decision, Idle):
            return Ok(Advanced(work.snapshot.head, work.analysis, work.decision, attempt, False))

        published = _publish(casework, tenant_id=tenant_id, work=work)
        if isinstance(published, Err):
            return published
        head = published.value
        if head is not None:
            return Ok(Advanced(head, work.analysis, work.decision, attempt, True))

    return Err(
        AdvanceRejection(
            AdvanceFailure.CONCURRENCY_CONFLICT,
            f"{tenant_id}/{case_id} lost {casework.policy.max_publication_attempts} swaps",
        )
    )


@dataclass(frozen=True, slots=True)
class _Work:
    """One attempt's pure result: what was read, what it derived, what to do.

    The rebuild inputs are deliberately absent.  They were used to derive the
    revision and nothing downstream may read them again: the swap builds the
    new inputs from the *parent* plus the prefix, so the transcript prefix is
    structurally the only rebuild input advancing a case can change. Carrying
    them here would offer a second copy for something to reach for.
    """

    snapshot: CaseSnapshot
    prefix: TranscriptPrefix
    analysis: CaseAnalysis
    decision: Decision


def _compute(
    casework: Casework, *, tenant_id: str, case_id: str, now: Instant
) -> Result[_Work, AdvanceRejection]:
    """Read a snapshot, then leave the database alone until there is an answer."""
    with casework.database.reading(tenant_id) as scope:
        read = read_working(
            scope,
            case_id,
            casework.publisher_verifier,
            casework.officer_verifier,
            casework.source_verifier,
        )
    if isinstance(read, Err):
        return Err(
            AdvanceRejection(
                AdvanceFailure.SNAPSHOT_REFUSED, f"{read.error.failure.value}: {read.error.detail}"
            )
        )
    snapshot = read.value

    loaded = casework.registry.load_by_digest(snapshot.head.inputs.bundle_manifest_digest)
    if isinstance(loaded, Err):
        #  The registry is immutable and content-addressed, so a miss is not a
        #  transient condition: the pin the head carries names a bundle this
        #  process does not have, and deciding under any other bundle would be
        #  answering a different question.
        return Err(
            AdvanceRejection(
                AdvanceFailure.POLICY_UNAVAILABLE,
                f"{loaded.error.failure.value}: {loaded.error.detail}",
            )
        )
    bundle = loaded.value

    prefix = transcript_prefix(tenant_id, case_id, snapshot.entries)
    inputs = replace(snapshot.head.inputs, transcript_prefix_digest=prefix.digest())
    revision = rebuild(
        inputs,
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
            AdvanceRejection(
                AdvanceFailure.REBUILD_REFUSED,
                f"{revision.error.failure.value}: {revision.error.detail}",
            )
        )

    analysed = analyse_revision(revision.value, bundle, casework.backend(), casework.limits)
    if isinstance(analysed, Err):
        return Err(AdvanceRejection(AdvanceFailure.ANALYSIS_REFUSED, str(analysed.error)))
    analysis = analysed.value

    decision = decide(
        head_revision_digest=snapshot.head.revision_digest,
        revision=analysis.revision,
        certificate=analysis.certificate,
        now=now,
        request_ttl=casework.policy.evidence_request_ttl,
    )
    if isinstance(decision, Dispatch) and not is_durable_instant(decision.deadline):
        #  Checked here, with no transaction open, because ``RecordedRequest``
        #  refuses it too -- and there it would refuse *after* the swap had
        #  already moved the head, turning a misconfigured TTL into an exception
        #  escaping a function that promises a ``Result``. The value invariant
        #  stays as the backstop for anything reaching a repository directly.
        return Err(
            AdvanceRejection(
                AdvanceFailure.DEADLINE_NOT_DURABLE,
                f"{decision.deadline} is not a durable instant",
            )
        )
    return Ok(_Work(snapshot, prefix, analysis, decision))


class _Abort(Exception):
    """Roll TX B back and report. Never leaves this module."""

    def __init__(self, rejection: AdvanceRejection) -> None:
        super().__init__(f"{rejection.failure.value}: {rejection.detail}")
        self.rejection = rejection


def _publish(
    casework: Casework, *, tenant_id: str, work: _Work
) -> Result[CaseHead | None, AdvanceRejection]:
    """TX B. ``Ok(None)`` means the swap was lost and the caller should retry."""
    try:
        with casework.database.writing(tenant_id) as scope:
            return Ok(_swap(scope, work))
    except _Abort as abort:
        return Err(abort.rejection)


def _swap(scope: DecidingScope, work: _Work) -> CaseHead | None:
    #  Hold the case before anything else. Two reasons, and the first one is a
    #  correctness bug the compare-and-swap does not catch.
    #
    #  **A head that has not moved is not the same as a transcript that has not
    #  grown.** An entry can commit while this analysis is running: the head is
    #  untouched, so the swap below matches, and this computation publishes a
    #  prefix that omits evidence which was already durable when it committed.
    #  Nothing later is guaranteed to correct it -- the writer that committed
    #  the entry may have died before its own advance, and re-driving is a
    #  caller's act rather than a background one. So the membership is re-read
    #  under the hold and compared against the set that was analysed.
    #
    #  Holding also puts every writer in one lock order -- case, then content,
    #  then row -- which is the order an admission takes, so a publication and
    #  an admission cannot wait on each other.
    held = scope.heads.hold(work.snapshot.head.case_id)
    if isinstance(held, Err):
        raise _Abort(
            AdvanceRejection(
                AdvanceFailure.HEAD_REFUSED, f"{held.error.failure.value}: {held.error.detail}"
            )
        )
    if held.value != work.snapshot.head:
        #  Someone published while this was analysing. The swap would refuse it
        #  anyway; refusing here means the attempt costs no writes at all.
        return None

    members = scope.transcript.members(work.snapshot.head.case_id)
    if isinstance(members, Err):
        raise _Abort(
            AdvanceRejection(
                AdvanceFailure.SNAPSHOT_REFUSED,
                f"{members.error.failure.value}: {members.error.detail}",
            )
        )
    if members.value != work.prefix.entry_digests:
        #  The transcript grew under this analysis. Retry, which recomputes over
        #  the larger set -- the same answer the design gives for a lost swap,
        #  reached for the same reason: the computation describes a state that
        #  is no longer the one being published onto.
        return None

    #  The prefix goes in first because the head's foreign key requires it, and
    #  it is the one write that survives a lost swap. That is deliberate and it
    #  is harmless: it is content-addressed, unreferenced until some head names
    #  it, and reused rather than duplicated by whichever attempt wins next.
    _put(scope, DigestKind.TRANSCRIPT_PREFIX, encode(work.prefix.to_node()))

    revision = work.analysis.revision
    certificate = work.analysis.certificate
    advanced = scope.heads.advance(
        parent=work.snapshot.head,
        prefix_digest=work.prefix.digest(),
        revision_digest=revision.digest(),
        certificate_digest=certificate.digest(),
    )
    if isinstance(advanced, Err):
        if advanced.error.failure is HeadFailure.HEAD_MOVED:
            return None
        #  Not a lost swap: the head refused the publication for a reason
        #  the caller cannot retry away, such as a prefix whose octets are
        #  absent. Rolls TX B back rather than committing half of it.
        raise _Abort(
            AdvanceRejection(
                AdvanceFailure.HEAD_REFUSED,
                f"{advanced.error.failure.value}: {advanced.error.detail}",
            )
        )

    #  Written after the swap succeeded, in the same transaction, so a lost
    #  swap writes no cache at all and a won one is atomic with it. There is no
    #  instant at which a head names a certificate that is not there.
    _put(scope, DigestKind.CASE_REVISION, encode(revision.to_node()))
    _put(scope, DigestKind.ANALYSIS_CERTIFICATE, encode(certificate.to_node()))

    if isinstance(work.decision, Dispatch):
        request = work.decision.request
        _put(scope, DigestKind.EVIDENCE_REQUEST, encode(request.to_node()))
        recorded = scope.requests.record(
            RecordedRequest(
                case_id=work.snapshot.head.case_id,
                request_id=request.digest(),
                revision_digest=revision.digest(),
                deadline=work.decision.deadline,
            )
        )
        if isinstance(recorded, Err):
            raise _Abort(
                AdvanceRejection(
                    AdvanceFailure.REQUEST_REFUSED,
                    f"{recorded.error.failure.value}: {recorded.error.detail}",
                )
            )
    return advanced.value


def _put(scope: DecidingScope, kind: DigestKind, octets: bytes) -> None:
    stored = scope.content.put(kind, octets)
    if isinstance(stored, Err):
        raise _Abort(
            AdvanceRejection(
                AdvanceFailure.STORE_REFUSED,
                f"{stored.error.failure.value} {stored.error.digest} {stored.error.detail}",
            )
        )
