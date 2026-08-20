"""An entry that would leave the case unrebuildable never becomes durable.

The defect this file exists for: membership is an append-only set and nothing
in this package can remove a member, so an entry whose admission makes
``rebuild`` refuse would freeze the case *permanently* -- every later advance
would fail on the same transcript, and there is no operation that could take it
back out.  The command layer used to admit first and rebuild afterwards, in a
later transaction, which meant exactly one badly-formed delivery could end a
case.

The correction has two halves and neither works without the other.

**TX A rebuilds before it commits**, so the membership and the check that it is
admissible are the same transaction and the check can roll it back.  What is
asserted here is the whole of that claim and not merely its happy path: the
entry is individually valid, its admission is genuinely attempted, the refusal
comes from the semantic rebuild rather than from a parser, nothing durable
survives it -- not the membership and not the content-addressed octets either --
the head is exactly where it was, retrying produces the same answer, and the
case is still able to accept a different entry afterwards.

**And TX A holds the case while it does it.**  Rolling back is not enough on its
own: two membership rows for two different entries conflict on nothing, so
under read-committed two appenders each rebuild against a transcript missing
the other's entry, both are satisfied, and both commit -- freezing the case
exactly as if no check existed.  That interleaving was measured at five frozen
cases in six attempts before the hold was taken.  The concurrency section below
covers it, along with the two things the hold must *not* do: refuse compatible
concurrent appends, or make one case wait for another.

**The duplicate is a real one.**  Two attestations of ``present_on_site(RAVI,
SAT)`` differing only in their nonce are each individually admissible -- same
proposition, same exact value, same schema, same validity, different signed
octets and therefore different digests -- and ``rebuild`` refuses the pair as
``DUPLICATE_ESTABLISHED_REF``.  That is precisely the shape of at-least-once
delivery from a re-signing source, so it is not a contrived input.
"""

from __future__ import annotations

import threading
from dataclasses import replace

import pytest

from muster.core.evidence.transcript import Attestation, TranscriptEntry, entry_digest
from muster.core.results import Err, Ok
from muster.core.wire.codec import encode
from muster.core.wire.digests import DigestKind
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import Casework
from muster.platform.casework.commands import AppendFailure, append_transcript_entry
from muster.platform.casework.ports import CaseHead, CaseworkDatabase, StoreFailure
from support import ravi
from support.authority import sign_receipt
from support.fixtures import append_all, count_content, open_ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

#  The entry that establishes ``present_on_site(RAVI, SAT)`` by exact value.
#  A second establishment of the same reference is what ``rebuild`` refuses.
ESTABLISHING_ENTRY = 18


@pytest.fixture
def casework(database: SqlDatabase) -> Casework:
    return ravi.casework(database)


@pytest.fixture
def case(tenant_id: str, case_id: str) -> RaviCase:
    return ravi.ravi(tenant_id, case_id, attested=True)


def _twin(entry: TranscriptEntry, nonce: bytes) -> TranscriptEntry:
    """The same attested relation, re-signed with a different nonce.

    Every security-bearing field is unchanged and the octets are not: this is
    what a source that re-issues a receipt produces, and it is admissible on
    its own terms. What it is not is a second *fact*, and the revision is the
    thing that knows that.
    """
    assert isinstance(entry, Attestation)
    #  Re-signed, not merely re-nonced.  The nonce is inside the payload the
    #  signature covers, so carrying the old signature over would produce a
    #  receipt that fails admission on authenticity -- and the property under
    #  test here is about *rebuildability*, which is two checks further on.
    return Attestation(
        sign_receipt(replace(entry.receipt, payload=replace(entry.receipt.payload, nonce=nonce)))
    )


def _members(database: CaseworkDatabase, case: RaviCase) -> set[object]:
    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok), members
    return set(members.value)


def _head(database: CaseworkDatabase, case: RaviCase) -> CaseHead:
    with database.reading(case.tenant_id) as scope:
        head = scope.heads.read(case.case_id)
    assert isinstance(head, Ok), head
    return head.value


def _append(casework: Casework, case: RaviCase, entry: TranscriptEntry) -> object:
    return append_transcript_entry(
        casework, tenant_id=case.tenant_id, case_id=case.case_id, entry=entry, now=ravi.NOW
    )


#  ---- the twin is individually admissible ----------------------------------


def test_the_duplicate_is_a_valid_entry_that_only_the_rebuild_can_refuse(
    casework: Casework, case: RaviCase
) -> None:
    """It parses, it decodes, it binds to this tenant and case, and it re-encodes.

    Stated first so that the refusal below cannot be explained by the entry
    being malformed. ``admit_entry`` is the whole of the syntactic and binding
    check, and it accepts this entry -- on an empty case, where no duplicate
    exists yet, it is simply a member.
    """
    from muster.platform.ingest.admission import admit_entry

    twin = _twin(case.entries[ESTABLISHING_ENTRY], b"\x5a" * 16)
    assert entry_digest(twin) != entry_digest(case.entries[ESTABLISHING_ENTRY])

    open_ravi(casework, case)
    with casework.database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, twin, ravi.admission_authority(case))
    assert isinstance(admitted, Ok), admitted
    assert admitted.value.entry_digest == entry_digest(twin)


#  ---- the refusal, and everything it must leave behind ----------------------


def test_an_entry_that_would_make_the_case_unrebuildable_is_refused(
    casework: Casework, case: RaviCase, migrated_dsn: str
) -> None:
    """The whole correction, in one case.

    Every assertion below would fail on an implementation that admitted first
    and rebuilt in a later transaction: the entry would be durable, the
    membership would be permanent, and the case would refuse every advance from
    then on with nothing able to undo it.
    """
    open_ravi(casework, case)
    published = append_all(casework, case, now=ravi.NOW)
    before_head = _head(casework.database, case)
    before_members = _members(casework.database, case)
    before_entries = count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_ENTRY")

    twin = _twin(case.entries[ESTABLISHING_ENTRY], b"\x5a" * 16)
    refused = _append(casework, case, twin)

    #  1. The refusal names the semantic rebuild, not a parser and not a store.
    assert isinstance(refused, Err), refused
    assert refused.error.failure is AppendFailure.TRANSCRIPT_WOULD_NOT_REBUILD
    assert "DUPLICATE_ESTABLISHED_REF" in refused.error.detail

    #  2. Membership is not durable. This is the one that matters: it cannot be
    #     undone by any later operation, so it must never have happened.
    assert entry_digest(twin) not in _members(casework.database, case)
    assert _members(casework.database, case) == before_members

    #  3. Nor are the octets. TX A puts the preimage and the membership in one
    #     transaction, so the rollback takes both -- there is no orphan blob to
    #     reason about here, which is stronger than an orphan that is merely
    #     harmless.
    assert count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_ENTRY") == before_entries
    with casework.database.reading(case.tenant_id) as scope:
        stored = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, entry_digest(twin))
    assert isinstance(stored, Err)
    assert stored.error.failure is StoreFailure.CONTENT_ABSENT

    #  4. And even if a future transaction structure did leave orphan bytes,
    #     bytes in the store are not membership: the prefix is built from the
    #     membership set, so an unreferenced blob cannot enter a revision.
    assert entry_digest(twin) not in _members(casework.database, case)

    #  5. The head has not moved.
    assert _head(casework.database, case) == before_head
    assert before_head.revision_digest == published.head.revision_digest
    assert before_head.revision_number == published.head.revision_number


def test_retrying_the_refused_entry_is_deterministic(
    casework: Casework, case: RaviCase, migrated_dsn: str
) -> None:
    """Same answer, same durable state, however many times it is delivered.

    At-least-once delivery means this entry arrives again. A refusal that
    became an acceptance on the second attempt -- or that accumulated state on
    each one -- would be worse than the original defect, because it would be
    intermittent.
    """
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    twin = _twin(case.entries[ESTABLISHING_ENTRY], b"\x5a" * 16)

    before_head = _head(casework.database, case)
    before_entries = count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_ENTRY")

    failures = []
    for _attempt in range(3):
        refused = _append(casework, case, twin)
        assert isinstance(refused, Err), refused
        failures.append((refused.error.failure, refused.error.detail))

    assert len(set(failures)) == 1
    assert _head(casework.database, case) == before_head
    assert count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_ENTRY") == before_entries


#  ---- the same refusal, under genuine concurrency --------------------------


def _append_together(
    casework: Casework, case: RaviCase, entries: tuple[TranscriptEntry, ...]
) -> list[object]:
    """Append each entry from its own thread, released at the same instant."""
    started = threading.Barrier(len(entries))
    results: list[object] = [None] * len(entries)

    def run(slot: int, entry: TranscriptEntry) -> None:
        started.wait(timeout=60.0)
        try:
            results[slot] = _append(casework, case, entry)
        except BaseException as error:  # the failure is the finding, not an escape
            results[slot] = error

    threads = [
        threading.Thread(target=run, args=(slot, entry)) for slot, entry in enumerate(entries)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=300.0)
        assert not thread.is_alive(), "an appending thread did not finish: the hold deadlocked"
    return results


def test_two_concurrent_admissions_cannot_both_pass_a_guard_the_other_invalidates(
    casework: Casework, case: RaviCase
) -> None:
    """Rolling back is not enough on its own, and this is why.

    Two membership rows for two different entries have two different primary
    keys, so the inserts conflict on nothing. Under read-committed neither
    transaction sees the other's uncommitted row, so each rebuilds against a
    transcript that omits the other's entry, each is satisfied, and both
    commit. The pair is then durable and the case is frozen exactly as if the
    guard had never run.

    Measured at five frozen cases in six attempts before ``heads.hold`` was
    taken, on this machine and this fixture. Exactly one appender may win.
    """
    open_ravi(casework, case)
    for index in range(len(case.entries)):
        if index == ESTABLISHING_ENTRY:
            continue
        assert isinstance(_append(casework, case, case.entries[index]), Ok)

    establishing = case.entries[ESTABLISHING_ENTRY]
    twin = _twin(establishing, b"\x5a" * 16)
    results = _append_together(casework, case, (establishing, twin))

    for result in results:
        assert not isinstance(result, BaseException), result
    accepted = [result for result in results if isinstance(result, Ok)]
    refused = [result for result in results if isinstance(result, Err)]
    assert len(accepted) == 1, f"{len(accepted)} of 2 concurrent admissions were accepted"
    assert len(refused) == 1
    assert refused[0].error.failure is AppendFailure.TRANSCRIPT_WOULD_NOT_REBUILD

    members = _members(casework.database, case)
    assert (entry_digest(establishing) in members) != (entry_digest(twin) in members)

    #  And the case still works, which is the property the whole file is about.
    from muster.platform.casework.advance import advance_case

    advanced = advance_case(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(advanced, Ok), advanced


def test_concurrent_admissions_of_compatible_entries_all_succeed(
    casework: Casework, case: RaviCase
) -> None:
    """The hold serialises admission; it does not refuse it.

    Four different entries, none of which conflicts with any other, delivered
    at once. All four become members. A guard that turned contention into
    refusals would be a worse defect than the one it replaced -- it would look
    like working software right up until two sources answered at the same time.
    """
    open_ravi(casework, case)
    entries = case.entries[:4]
    results = _append_together(casework, case, entries)

    for result in results:
        assert isinstance(result, Ok), result
    members = _members(casework.database, case)
    for entry in entries:
        assert entry_digest(entry) in members


def test_the_hold_is_per_case_and_does_not_serialise_other_cases(
    casework: Casework, tenant_id: str
) -> None:
    """One row lock on one case. Two cases in one tenant do not wait for each other.

    Written as a rendezvous rather than as a timing measurement: the second
    case's append is started *while* the first case's transaction is open, and
    it has to finish. A tenant-wide or store-wide lock would deadlock here
    instead of passing, which is what makes this an assertion and not a
    stopwatch.
    """
    first = ravi.ravi(tenant_id, "case-hold-one", attested=True)
    second = ravi.ravi(tenant_id, "case-hold-two", attested=True)
    open_ravi(casework, first)
    open_ravi(casework, second)

    with casework.database.writing(tenant_id) as scope:
        held = scope.heads.hold(first.case_id)
        assert isinstance(held, Ok), held

        #  A different case, from a different connection, while the first is held.
        appended = _append(casework, second, second.entries[0])

    assert isinstance(appended, Ok), appended
    assert entry_digest(second.entries[0]) in _members(casework.database, second)
    assert _members(casework.database, first) == set()


def test_the_case_still_accepts_a_different_entry_afterwards(
    casework: Casework, case: RaviCase
) -> None:
    """A refusal is not a quarantine. The case is untouched and still working.

    Built the other way round from the test above -- the last real entry is
    held back, the duplicate is offered against the shorter transcript, and
    then the real one is appended -- so what is shown is that the refusal cost
    the case nothing at all, not merely that it left it readable.
    """
    open_ravi(casework, case)
    for index in range(len(case.entries) - 1):
        appended = _append(casework, case, case.entries[index])
        assert isinstance(appended, Ok), appended

    twin = _twin(case.entries[ESTABLISHING_ENTRY], b"\x5a" * 16)
    refused = _append(casework, case, twin)
    assert isinstance(refused, Err)
    assert refused.error.failure is AppendFailure.TRANSCRIPT_WOULD_NOT_REBUILD

    last = _append(casework, case, case.entries[-1])
    assert isinstance(last, Ok), last
    assert last.value.created is True
    assert isinstance(last.value.advanced, Ok), last.value.advanced
    assert last.value.advanced.value.published
    assert entry_digest(case.entries[-1]) in _members(casework.database, case)
    assert entry_digest(twin) not in _members(casework.database, case)


def test_a_duplicate_of_an_entry_already_present_is_a_success_and_not_a_refusal(
    casework: Casework, case: RaviCase
) -> None:
    """The distinction the refusal must not blur.

    The *same* entry delivered twice is one member and a success -- that is what
    makes at-least-once delivery free. A *different* entry establishing the same
    reference is the one that would freeze the case. Collapsing the two would
    either break redelivery or admit the poison.
    """
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    before = _members(casework.database, case)

    redelivered = _append(casework, case, case.entries[ESTABLISHING_ENTRY])
    assert isinstance(redelivered, Ok), redelivered
    assert redelivered.value.created is False
    assert _members(casework.database, case) == before


def test_the_rebuild_guard_runs_only_when_the_membership_is_new(
    casework: Casework, case: RaviCase
) -> None:
    """A redelivery does not pay for a rebuild it cannot change the answer of.

    Asserted through the store rather than by counting calls: a redelivered
    entry adds no member, so the transcript the guard would rebuild from is the
    one already published -- and nothing new is written by the attempt.
    """
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    with casework.database.reading(case.tenant_id) as scope:
        before = scope.transcript.members(case.case_id)
    assert isinstance(before, Ok)

    for _redelivery in range(3):
        again = _append(casework, case, case.entries[0])
        assert isinstance(again, Ok), again
        assert again.value.created is False

    with casework.database.reading(case.tenant_id) as scope:
        after = scope.transcript.members(case.case_id)
    assert isinstance(after, Ok)
    assert after.value == before.value


def test_the_refusal_survives_a_process_restart_as_an_absence(
    casework: Casework, case: RaviCase, migrated_dsn: str
) -> None:
    """Nothing was written, so there is nothing for a restart to recover.

    The check that the rollback is the database's and not this process's
    memory: a second ``SqlDatabase`` over the same DSN, which is what a restart
    is, sees a case with the published transcript and no trace of the refused
    entry.
    """
    open_ravi(casework, case)
    published = append_all(casework, case, now=ravi.NOW)
    twin = _twin(case.entries[ESTABLISHING_ENTRY], b"\x5a" * 16)
    assert isinstance(_append(casework, case, twin), Err)

    reopened = ravi.casework(SqlDatabase(migrated_dsn))
    from muster.platform.casework.commands import case_status

    report = case_status(reopened, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(report, Ok), report
    assert report.value.head.revision_digest == published.head.revision_digest
    assert report.value.certificate_reproduced is True

    with SqlDatabase(migrated_dsn).reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
        stored = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, entry_digest(twin))
    assert isinstance(members, Ok)
    assert entry_digest(twin) not in set(members.value)
    assert isinstance(stored, Err)


def test_admitting_the_duplicate_without_the_guard_freezes_the_case_forever(
    casework: Casework, case: RaviCase
) -> None:
    """What the guard prevents, produced deliberately so the cost is not a claim.

    This is the previous implementation's behaviour, reconstructed by reaching
    past the command and doing what it used to do: admit the octets, add the
    membership, commit, and check afterwards. The membership is then durable,
    every advance refuses on the same transcript, ``case_status`` cannot replay
    the case, and **nothing in this package can undo it** -- there is no remove,
    no supersession and no retraction, by design.

    The case is left broken at the end of this test on purpose. Its tenant is
    its own, so the damage is exactly as isolated as the design says it is.
    """
    from muster.platform.casework.advance import AdvanceFailure, advance_case
    from muster.platform.casework.commands import case_status
    from muster.platform.ingest.admission import admit_entry

    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    twin = _twin(case.entries[ESTABLISHING_ENTRY], b"\x5a" * 16)

    with casework.database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, twin, ravi.admission_authority(case))
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add(case.case_id, admitted.value.entry_digest)
        assert isinstance(added, Ok), added
        assert added.value is True

    assert entry_digest(twin) in _members(casework.database, case)

    frozen = advance_case(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(frozen, Err)
    assert frozen.error.failure is AdvanceFailure.REBUILD_REFUSED
    assert "DUPLICATE_ESTABLISHED_REF" in frozen.error.detail

    #  And it stays refused: re-driving is the only recovery this package has,
    #  and re-driving cannot remove a member.
    again = advance_case(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(again, Err)
    assert again.error.failure is AdvanceFailure.REBUILD_REFUSED

    #  The published head is still readable, because ``case_status`` replays the
    #  head's own prefix rather than the current membership. That is the only
    #  mercy available, and it does not make the case workable again: no further
    #  entry can ever be published.
    report = case_status(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(report, Ok), report

    blocked = _append(casework, case, _twin(case.entries[ESTABLISHING_ENTRY], b"\x6b" * 16))
    assert isinstance(blocked, Err)
    assert blocked.error.failure is AppendFailure.TRANSCRIPT_WOULD_NOT_REBUILD


def test_the_octets_the_refusal_discarded_are_the_ones_it_was_offered(case: RaviCase) -> None:
    """A guard against the refusal being right for the wrong reason.

    If the twin's octets happened to equal an entry already stored, the whole
    file would be testing redelivery rather than duplication. They do not: the
    nonce is inside the signed payload, so the preimage and the digest both
    differ from every entry in the case.
    """
    twin = _twin(case.entries[ESTABLISHING_ENTRY], b"\x5a" * 16)
    from muster.core.evidence.transcript import entry_node

    octets = encode(entry_node(twin))
    assert octets not in {encode(entry_node(entry)) for entry in case.entries}
    assert entry_digest(twin) not in {entry_digest(entry) for entry in case.entries}
