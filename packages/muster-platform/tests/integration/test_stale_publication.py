"""A publication never commits a head that omits evidence already durable.

The defect this file exists for: the compare-and-swap is conditional on the
head, and **a head that has not moved is not the same as a transcript that has
not grown.**  An entry that commits while an analysis is running leaves the
head exactly where it was, so the swap matches and publishes a prefix that
omits it.

The old argument for why that was safe assumed the writer which committed the
entry would publish it on its own next advance.  That writer can die between
its two transactions -- which is the ordinary crash this design already plans
for -- and this milestone has no process that would notice.  The published
head then names a revision derived without evidence the system already holds,
a ``Propose`` decision made from it is offered for authorization, and nothing
re-drives the case until a caller happens to.

The correction is that TX B holds the case, re-reads the membership, and
refuses to publish unless it is exactly the set that was analysed.  Losing is
a retry, which recomputes over the larger set -- the same answer the design
already gives for a lost swap, reached for the same reason.

Reproduced before the fix: a published head whose prefix held 19 of the case's
20 durable members.
"""

from __future__ import annotations

import threading

import pytest

from muster.core.case.revision import TranscriptPrefix, read_transcript_prefix
from muster.core.results import Err, Ok
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest, DigestKind
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import AdvanceFailure, Casework, advance_case
from muster.platform.casework.commands import append_transcript_entry
from muster.platform.ingest.admission import admit_entry
from muster.solve.backend import SolverBackend
from support import ravi
from support.fixtures import open_ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres


@pytest.fixture
def case(tenant_id: str, case_id: str) -> RaviCase:
    return ravi.ravi(tenant_id, case_id, attested=True)


def _commit_entry(database: SqlDatabase, case: RaviCase, index: int) -> Digest:
    """What a writer that dies between its two transactions leaves behind.

    Exactly TX A and nothing after it: the octets and the membership commit,
    and no advance follows. Written through the real repositories rather than
    with SQL, because the durable state has to be the state the command
    produces.
    """
    with database.writing(case.tenant_id) as scope:
        held = scope.heads.hold(case.case_id)
        assert isinstance(held, Ok), held
        admitted = admit_entry(scope, case.case_id, case.entries[index])
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add(case.case_id, admitted.value.entry_digest)
        assert isinstance(added, Ok), added
    return admitted.value.entry_digest


def _published_prefix(database: SqlDatabase, case: RaviCase) -> TranscriptPrefix:
    """The membership the head actually committed to, read back out of the store."""
    with database.reading(case.tenant_id) as scope:
        head = scope.heads.read(case.case_id)
        assert isinstance(head, Ok), head
        octets = scope.content.get(
            DigestKind.TRANSCRIPT_PREFIX, head.value.inputs.transcript_prefix_digest
        )
    assert isinstance(octets, Ok), octets
    node = decode(octets.value)
    assert isinstance(node, Ok), node
    return read_transcript_prefix(node.value)


def _members(database: SqlDatabase, case: RaviCase) -> tuple[Digest, ...]:
    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok), members
    return members.value


def _prefixed(database: SqlDatabase, case: RaviCase, count: int) -> None:
    """Open the case and publish the first ``count`` entries through the command."""
    casework = ravi.casework(database)
    open_ravi(casework, case)
    for index in range(count):
        appended = append_transcript_entry(
            casework,
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            entry=case.entries[index],
            now=ravi.NOW,
        )
        assert isinstance(appended, Ok), appended


def test_an_entry_committed_during_the_analysis_is_not_published_around(
    database: SqlDatabase, case: RaviCase
) -> None:
    """The whole correction, in one case.

    An entry lands while the solver is running. The head has not moved, so the
    swap would match. It must not publish, because what it would publish is a
    revision derived without evidence the system already holds durably.
    """
    total = len(case.entries)
    _prefixed(database, case, total - 2)
    #  A writer that committed and died. The head is now behind the transcript,
    #  which is a legitimate state.
    early = _commit_entry(database, case, total - 2)

    late: list[Digest] = []

    def landing_backend() -> SolverBackend:
        #  Fires once, on the first attempt, between the snapshot and the swap.
        if not late:
            late.append(_commit_entry(database, case, total - 1))
        return ravi.backend()

    advanced = advance_case(
        ravi.casework(database, solver=landing_backend),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        now=ravi.NOW,
    )
    assert isinstance(advanced, Ok), advanced
    assert advanced.value.published
    #  It took a second attempt, because the first one was refused.
    assert advanced.value.attempts == 2

    published = _published_prefix(database, case)
    members = _members(database, case)
    assert set(published.entry_digests) == set(members)
    assert early in published.entry_digests
    assert late[0] in published.entry_digests


def test_a_publication_that_keeps_losing_reports_contention_rather_than_stale_state(
    database: SqlDatabase, case: RaviCase
) -> None:
    """Refusing is bounded, and the bound is reported rather than hidden.

    An entry lands on every attempt, so no attempt ever sees a settled
    transcript. The advance runs out of attempts and says so. What it must not
    do is give up and publish the stale prefix -- which is the failure mode the
    whole file is about, arrived at by a different route.
    """
    total = len(case.entries)
    _prefixed(database, case, total - 4)
    #  One entry already durable and unpublished, so the first attempt has real
    #  work to do rather than reaching ``Idle`` immediately.
    _commit_entry(database, case, total - 4)
    before = _published_prefix(database, case)

    landed: list[Digest] = []

    def landing_backend() -> SolverBackend:
        #  One more lands during every attempt, so no attempt ever sees a
        #  settled transcript.
        if len(landed) < 3:
            landed.append(_commit_entry(database, case, total - 3 + len(landed)))
        return ravi.backend()

    refused = advance_case(
        ravi.casework(database, solver=landing_backend, max_publication_attempts=3),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        now=ravi.NOW,
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is AdvanceFailure.CONCURRENCY_CONFLICT

    #  The head is exactly where it was. Nothing stale was published.
    after = _published_prefix(database, case)
    assert after == before

    #  And the case is not stuck: one more advance, with nothing landing, works.
    recovered = advance_case(
        ravi.casework(database), tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW
    )
    assert isinstance(recovered, Ok), recovered
    assert recovered.value.published
    assert set(_published_prefix(database, case).entry_digests) == set(_members(database, case))


def test_a_publication_refused_for_staleness_writes_nothing(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    """Refused before the prefix is stored, so a losing attempt costs no writes.

    The check is the first thing TX B does after the hold, which is what makes
    this true. A version that checked after caching would leave an orphan
    prefix for every entry that ever raced a publication.
    """
    from support.fixtures import count_content

    total = len(case.entries)
    _prefixed(database, case, total - 2)
    _commit_entry(database, case, total - 2)
    prefixes = count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_PREFIX")

    landed: list[Digest] = []

    def landing_backend() -> SolverBackend:
        if not landed:
            landed.append(_commit_entry(database, case, total - 1))
        return ravi.backend()

    refused = advance_case(
        ravi.casework(database, solver=landing_backend, max_publication_attempts=1),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        now=ravi.NOW,
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is AdvanceFailure.CONCURRENCY_CONFLICT
    assert count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_PREFIX") == prefixes


def test_concurrent_appenders_all_end_up_inside_the_published_head(
    database: SqlDatabase, case: RaviCase
) -> None:
    """Real threads, real database, and the property stated at the end.

    Four entries delivered at once through the public command. Whatever order
    the transactions interleave in, the head that is published last commits to
    every entry that is durable -- which is the invariant the compare-and-swap
    alone did not give.
    """
    total = len(case.entries)
    _prefixed(database, case, total - 4)
    casework: Casework = ravi.casework(database, max_publication_attempts=8)

    started = threading.Barrier(4)
    outcomes: list[object] = [None] * 4

    def run(slot: int) -> None:
        started.wait(timeout=60.0)
        try:
            outcomes[slot] = append_transcript_entry(
                casework,
                tenant_id=case.tenant_id,
                case_id=case.case_id,
                entry=case.entries[total - 4 + slot],
                now=ravi.NOW,
            )
        except BaseException as error:  # the failure is the finding, not an escape
            outcomes[slot] = error

    threads = [threading.Thread(target=run, args=(slot,)) for slot in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=300.0)
        assert not thread.is_alive(), "an appending thread did not finish"

    for outcome in outcomes:
        assert isinstance(outcome, Ok), outcome

    members = _members(database, case)
    assert len(members) == total
    #  One last advance, in case the final appender's own advance lost every
    #  attempt. Re-driving is the documented recovery and it is idempotent.
    advance_case(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert set(_published_prefix(database, case).entry_digests) == set(members)
