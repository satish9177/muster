"""Concurrent writers, real threads, real PostgreSQL.

The invariant every test here attacks is one sentence:

    the head may reference only a revision derived from a complete transcript
    snapshot for the parent state it successfully replaced, and no concurrent
    path may erase an accepted transcript member.

The interleavings are forced rather than hoped for.  ``Rendezvous`` holds both
threads inside the analysis phase at the same instant, which is the window the
whole design is about: the transaction is closed, the solver is running, and
the head is free to move underneath.  A test that merely started two threads
and waited would pass on a machine where one finished before the other began.

The fixture case is set up to the point where it is *analysable* before the
race starts.  Its instances are all declared from the beginning and its facts
arrive one at a time, so an early revision is over the engine's case-size bound
and refuses to analyse at all -- which is correct behaviour, and would make a
race between two refusals prove nothing.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytest

from muster.core.evidence.transcript import TranscriptEntry, entry_digest
from muster.core.results import Err, Ok
from muster.core.wire.digests import Digest, DigestKind
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import AdvanceFailure, Casework, advance_case
from muster.platform.casework.commands import Appended, append_transcript_entry
from muster.platform.casework.ports import CaseHead
from support import ravi
from support.fixtures import open_ravi
from support.interference import Interfering, Rendezvous
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

#  The attested fixture has twenty entries. Through index 17 the case is
#  analysable and divergent; the last two are the Saturday observations that
#  settle it. Racing those two is a race between two analyses that both
#  succeed, which is the only kind that can lose an update.
SETTLED_PREFIX = 18


@dataclass(frozen=True, slots=True)
class Prepared:
    case: RaviCase
    head: CaseHead
    left: TranscriptEntry
    right: TranscriptEntry


@pytest.fixture
def prepared(database: SqlDatabase, tenant_id: str, case_id: str) -> Prepared:
    """A published case, one swap away from being settled by either of two entries."""
    casework = ravi.casework(database)
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)

    last: Appended | None = None
    for index in range(SETTLED_PREFIX):
        appended = append_transcript_entry(
            casework,
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            entry=case.entries[index],
            now=ravi.NOW,
        )
        assert isinstance(appended, Ok), appended
        last = appended.value
    assert last is not None
    assert isinstance(last.advanced, Ok), last.advanced
    assert last.advanced.value.published

    return Prepared(
        case=case,
        head=last.advanced.value.head,
        left=case.entries[SETTLED_PREFIX],
        right=case.entries[SETTLED_PREFIX + 1],
    )


def _racing_casework(database: SqlDatabase, rendezvous: Rendezvous) -> Casework:
    """A control plane whose solver waits for its counterpart before running.

    The wait is in the backend *factory*, which is called once per analysis
    attempt, so both threads are guaranteed to have read the head and the
    membership before either of them can publish.
    """

    def solver() -> object:
        rendezvous.arrive()
        return ravi.backend()

    return ravi.casework(database, solver=solver)  # type: ignore[arg-type]


def _append(casework: Casework, case: RaviCase, entry: TranscriptEntry) -> Appended:
    appended = append_transcript_entry(
        casework,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=entry,
        now=ravi.NOW,
    )
    assert isinstance(appended, Ok), appended
    return appended.value


def _members(database: SqlDatabase, case: RaviCase) -> set[Digest]:
    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok), members
    return set(members.value)


def _head(database: SqlDatabase, case: RaviCase) -> CaseHead:
    with database.reading(case.tenant_id) as scope:
        head = scope.heads.read(case.case_id)
    assert isinstance(head, Ok), head
    return head.value


def _admit_without_advancing(
    database: SqlDatabase, case: RaviCase, entry: TranscriptEntry
) -> Digest:
    """Run TX A alone: the entry becomes durable and no analysis follows.

    Exactly the durable state a crash between the two transactions leaves, and
    the setup a publication test needs when it wants something new to publish
    without publishing it first.
    """
    from muster.platform.ingest.admission import admit_entry

    with database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, entry)
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add(case.case_id, admitted.value.entry_digest)
        assert isinstance(added, Ok), added
    return admitted.value.entry_digest


def _published_prefix(database: SqlDatabase, case: RaviCase) -> set[Digest]:
    """The membership the head's own transcript prefix names."""
    from muster.core.case.revision import read_transcript_prefix
    from muster.core.wire.codec import decode

    head = _head(database, case)
    with database.reading(case.tenant_id) as scope:
        octets = scope.content.get(
            DigestKind.TRANSCRIPT_PREFIX, head.inputs.transcript_prefix_digest
        )
    assert isinstance(octets, Ok), octets
    node = decode(octets.value)
    assert isinstance(node, Ok), node
    return set(read_transcript_prefix(node.value).entry_digests)


#  ---- A: two distinct entries, appended at the same instant ---------------


def test_two_distinct_entries_appended_at_once_both_reach_the_head(
    database: SqlDatabase, prepared: Prepared
) -> None:
    """The exit criterion: one linear revision chain, no lost update.

    Both threads are held inside the analysis phase together, so both read the
    same parent head. Exactly one swap can match it. The loser re-reads, finds
    the larger transcript, recomputes and publishes on top -- so the entry it
    contributed is in the head's prefix even though its first attempt lost.
    """
    rendezvous = Rendezvous(2)
    casework = _racing_casework(database, rendezvous)
    case = prepared.case

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_append, casework, case, prepared.left),
            pool.submit(_append, casework, case, prepared.right),
        ]
        results = [future.result() for future in futures]

    left = entry_digest(prepared.left)
    right = entry_digest(prepared.right)

    #  Both appends created their member, and neither erased the other.
    assert {result.created for result in results} == {True}
    assert {left, right} <= _members(database, case)

    #  And the published head is derived from a snapshot containing both.
    assert {left, right} <= _published_prefix(database, case)

    #  One linear chain: two publications on top of the parent, never a fork.
    head = _head(database, case)
    assert head.revision_number == prepared.head.revision_number + 2 or (
        #  If both threads computed the identical larger revision, the second
        #  finds the head already naming it and does nothing -- also linear.
        head.revision_number == prepared.head.revision_number + 1
    )


def test_the_head_after_the_race_is_the_revision_over_every_member(
    database: SqlDatabase, prepared: Prepared
) -> None:
    """The head is not merely "one of the two"; it is the join of both."""
    rendezvous = Rendezvous(2)
    casework = _racing_casework(database, rendezvous)
    case = prepared.case

    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [
            pool.submit(_append, casework, case, prepared.left),
            pool.submit(_append, casework, case, prepared.right),
        ]:
            future.result()

    assert _published_prefix(database, case) == _members(database, case)

    #  Recomputing changes nothing: the head already names the revision the
    #  complete transcript produces.
    settled = advance_case(
        ravi.casework(database), tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW
    )
    assert isinstance(settled, Ok), settled
    assert settled.value.published is False


#  ---- B: the same entry, appended at the same instant ---------------------


def test_the_same_entry_appended_at_once_is_one_member(
    database: SqlDatabase, prepared: Prepared
) -> None:
    """At-least-once delivery of one receipt, twice, concurrently."""
    rendezvous = Rendezvous(2)
    casework = _racing_casework(database, rendezvous)
    case = prepared.case

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_append, casework, case, prepared.left),
            pool.submit(_append, casework, case, prepared.left),
        ]
        results = [future.result() for future in futures]

    #  Exactly one call created the membership; both succeeded.
    assert sorted(result.created for result in results) == [False, True]
    assert {result.entry_digest for result in results} == {entry_digest(prepared.left)}

    members = _members(database, case)
    assert entry_digest(prepared.left) in members
    assert len(members) == SETTLED_PREFIX + 1


def test_the_same_entry_appended_at_once_publishes_one_revision(
    database: SqlDatabase, prepared: Prepared
) -> None:
    """Two threads compute the identical revision; one publishes, one is idle."""
    rendezvous = Rendezvous(2)
    casework = _racing_casework(database, rendezvous)
    case = prepared.case

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_append, casework, case, prepared.left),
            pool.submit(_append, casework, case, prepared.left),
        ]
        advances = []
        for future in futures:
            advanced = future.result().advanced
            assert isinstance(advanced, Ok), advanced
            advances.append(advanced.value)

    #  The head moved exactly once, whichever thread got there first.
    head = _head(database, case)
    assert head.revision_number == prepared.head.revision_number + 1
    assert sorted(advance.published for advance in advances) == [False, True]
    #  Both threads agree on which revision is current.
    assert {advance.head.revision_digest for advance in advances} == {head.revision_digest}


#  ---- D: an entry arrives while an older analysis is still running --------


def test_an_entry_arriving_mid_analysis_is_not_lost_by_the_analysis_it_raced(
    database: SqlDatabase, prepared: Prepared
) -> None:
    """The dangerous shape, stated directly.

    One thread reads the transcript and starts analysing. A second entry lands
    while it is in the solver. The first thread's revision does not contain the
    newcomer -- and must not be able to become a head that quietly excludes it
    forever. Either the first thread loses the swap and retries over the larger
    set, or it wins and the second thread publishes on top. Both end with the
    newcomer in the head's prefix.
    """
    rendezvous = Rendezvous(2)
    casework = _racing_casework(database, rendezvous)
    case = prepared.case

    def slow_analysis() -> Appended:
        return _append(casework, case, prepared.left)

    def late_arrival() -> Appended:
        return _append(casework, case, prepared.right)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(slow_analysis)
        second = pool.submit(late_arrival)
        first.result()
        second.result()

    published = _published_prefix(database, case)
    assert entry_digest(prepared.left) in published
    assert entry_digest(prepared.right) in published


#  ---- E: retry exhaustion is reported, never hidden -----------------------


def test_repeated_lost_swaps_are_reported_rather_than_retried_forever(
    database: SqlDatabase, prepared: Prepared
) -> None:
    """A competing writer wins every time. The caller is told, after three tries.

    The interference is a real compare-and-swap by a real repository on its own
    connection, so the head genuinely moves before each attempt rather than
    being pretended to.
    """
    case = prepared.case
    moved: list[int] = []

    def steal_the_head(_write: int) -> None:
        with database.writing(case.tenant_id) as scope:
            head = scope.heads.read(case.case_id)
            assert isinstance(head, Ok), head
            prefix = scope.content.put(
                DigestKind.TRANSCRIPT_PREFIX, b"competing-prefix-%d" % len(moved)
            )
            assert isinstance(prefix, Ok), prefix
            marker = Digest(bytes([len(moved) + 1]) * 32)
            advanced = scope.heads.advance(
                parent=head.value,
                prefix_digest=prefix.value,
                revision_digest=marker,
                certificate_digest=marker,
            )
            assert isinstance(advanced, Ok), advanced
        moved.append(1)

    contended = ravi.casework(Interfering(database, steal_the_head), max_publication_attempts=3)
    #  Admit the entry first, so the failure under test is publication and not
    #  admission.
    admitted = _admit_without_advancing(database, case, prepared.left)

    refused = advance_case(contended, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(refused, Err)
    assert refused.error.failure is AdvanceFailure.CONCURRENCY_CONFLICT
    assert len(moved) == 3

    #  And the entry is still durable. Nothing about losing a race removes it.
    assert admitted in _members(database, case)


def test_a_single_attempt_policy_reports_the_first_lost_swap(
    database: SqlDatabase, prepared: Prepared
) -> None:
    """The bound is honoured exactly, not approximately."""
    case = prepared.case
    attempts: list[int] = []

    def steal_the_head(_write: int) -> None:
        with database.writing(case.tenant_id) as scope:
            head = scope.heads.read(case.case_id)
            assert isinstance(head, Ok), head
            prefix = scope.content.put(DigestKind.TRANSCRIPT_PREFIX, b"one-shot-competitor")
            assert isinstance(prefix, Ok), prefix
            marker = Digest(b"\x5a" * 32)
            scope.heads.advance(
                parent=head.value,
                prefix_digest=prefix.value,
                revision_digest=marker,
                certificate_digest=marker,
            )
        attempts.append(1)

    #  There has to be something new to publish, or the recomputation reaches
    #  the head that already exists and correctly reports ``Idle`` without ever
    #  attempting a swap.
    _admit_without_advancing(database, case, prepared.right)

    contended = ravi.casework(Interfering(database, steal_the_head), max_publication_attempts=1)
    refused = advance_case(contended, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(refused, Err)
    assert refused.error.failure is AdvanceFailure.CONCURRENCY_CONFLICT
    assert len(attempts) == 1


def test_advancing_a_case_with_nothing_new_is_idle_and_writes_nothing(
    database: SqlDatabase, prepared: Prepared
) -> None:
    """Re-driving after a crash is "call it again", not a recovery procedure.

    Nothing arrived, so the recomputation reaches the revision the head already
    names, and the operation reports that rather than performing a swap onto
    itself.
    """
    writes: list[int] = []
    watched = ravi.casework(Interfering(database, writes.append))
    case = prepared.case

    idle = advance_case(watched, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(idle, Ok), idle
    assert idle.value.published is False
    assert idle.value.head.revision_digest == prepared.head.revision_digest
    #  No read-write transaction was opened at all.
    assert writes == []


#  ---- F: the same case identifier in two tenants --------------------------


def test_the_same_case_id_in_two_tenants_advances_independently(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    """One name, two cases, and no interaction of any kind between them."""
    casework = ravi.casework(database)
    mine = ravi.ravi(tenant_id, case_id, attested=True)
    theirs = ravi.ravi(other_tenant_id, case_id, attested=True)
    open_ravi(casework, mine)
    open_ravi(casework, theirs)

    def fill(case: RaviCase, count: int) -> None:
        for index in range(count):
            _append(casework, case, case.entries[index])

    with ThreadPoolExecutor(max_workers=2) as pool:
        left = pool.submit(fill, mine, SETTLED_PREFIX)
        right = pool.submit(fill, theirs, SETTLED_PREFIX + 2)
        left.result()
        right.result()

    assert len(_members(database, mine)) == SETTLED_PREFIX
    assert len(_members(database, theirs)) == SETTLED_PREFIX + 2

    #  Different transcripts, so different revisions under the same case name.
    assert _head(database, mine).revision_digest != _head(database, theirs).revision_digest
