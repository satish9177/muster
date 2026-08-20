"""Failure injected at each point in the two-transaction pattern.

For every point the same three questions are asked and answered by assertion
rather than by prose: what durable state exists, can the operation simply be
run again, and can anything have been lost or duplicated.

The answer is the same everywhere, and that is the design working: **re-drive
it.**  There is no compensating action in this package, no outbox, no saga and
no reconciliation table, because every step is idempotent by construction --
a case is identified by digests it was opened with, an entry by its own digest,
a request by the digest of a record naming the revision it answers.
"""

from __future__ import annotations

import psycopg
import pytest

from muster.core.evidence.transcript import entry_digest
from muster.core.results import Err, Ok
from muster.core.wire.digests import DigestKind
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import AdvanceFailure, Casework, advance_case
from muster.platform.casework.commands import append_transcript_entry, case_status
from muster.platform.casework.ports import CaseworkDatabase
from muster.platform.ingest.admission import admit_entry
from muster.platform.orchestration.status import CaseStatus
from muster.solve.backend import SolverBackend
from support import ravi
from support.fixtures import append_all, count_content, open_ravi, reset_tenant
from support.interference import Interfering
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

SETTLED_PREFIX = 18


class _Injected(RuntimeError):
    """A failure a test caused on purpose."""


@pytest.fixture(autouse=True)
def _fresh(migrated_dsn: str) -> None:
    reset_tenant(migrated_dsn, ravi.FIXTURE_TENANT)


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


@pytest.fixture
def case(database: SqlDatabase) -> RaviCase:
    """The attested case, published up to the point where it is analysable."""
    casework = ravi.casework(database)
    built = ravi.unbound(attested=True)
    open_ravi(casework, built)
    for index in range(SETTLED_PREFIX):
        appended = append_transcript_entry(
            casework,
            tenant_id=built.tenant_id,
            case_id=built.case_id,
            entry=built.entries[index],
            now=ravi.NOW,
        )
        assert isinstance(appended, Ok), appended
    return built


def _members(database: SqlDatabase, case: RaviCase) -> set[object]:
    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok), members
    return set(members.value)


#  ---- 1. before the content insert ----------------------------------------


def test_a_failure_before_any_write_leaves_no_durable_state(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    before = count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_ENTRY")
    with pytest.raises(_Injected):  # noqa: SIM117
        with database.writing(case.tenant_id):
            raise _Injected("before anything was written")
    assert count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_ENTRY") == before


#  ---- 2. after the content insert, before membership ----------------------


def test_a_failure_between_the_octets_and_the_membership_rolls_back_both(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    """They are one transaction, so there is no "between" that survives.

    Membership without a preimage would make the prefix undecodable, and a
    preimage without membership would be an orphan blob. The first is
    impossible because they commit together; the second is harmless and is
    what a crash in the *other* order would leave.
    """
    entry = case.entries[SETTLED_PREFIX]
    before = count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_ENTRY")

    with pytest.raises(_Injected), database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, entry, ravi.admission_authority(case))
        assert isinstance(admitted, Ok), admitted
        raise _Injected("crash before the membership row")

    assert count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_ENTRY") == before
    assert entry_digest(entry) not in _members(database, case)

    #  Retrying is safe and complete.
    casework = ravi.casework(database)
    retried = append_transcript_entry(
        casework,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=entry,
        now=ravi.NOW,
    )
    assert isinstance(retried, Ok), retried
    assert retried.value.created is True
    assert entry_digest(entry) in _members(database, case)


#  ---- 3. after TX A commits, before the analysis ---------------------------


def test_an_entry_committed_and_never_published_is_published_by_the_next_advance(
    database: SqlDatabase, case: RaviCase
) -> None:
    """The crash that actually happens, and the recovery that is just a retry."""
    entry = case.entries[SETTLED_PREFIX]
    with database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, entry, ravi.admission_authority(case))
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add(case.case_id, admitted.value.entry_digest)
        assert isinstance(added, Ok), added

    with database.reading(case.tenant_id) as scope:
        stale_head = scope.heads.read(case.case_id)
    assert isinstance(stale_head, Ok)

    casework = ravi.casework(database)
    recovered = advance_case(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(recovered, Ok), recovered
    assert recovered.value.published
    assert recovered.value.head.revision_number == stale_head.value.revision_number + 1


def test_the_status_of_a_case_with_an_unpublished_entry_is_the_head_not_the_transcript(
    database: SqlDatabase, case: RaviCase
) -> None:
    """A head behind the transcript is a legitimate state, reported honestly.

    ``case_status`` replays the head's *own* prefix, not the current
    membership, so it describes what was published rather than what would be
    published next. Conflating the two would report an answer nothing has
    committed to.
    """
    published = case_status(
        ravi.casework(database), tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW
    )
    assert isinstance(published, Ok), published

    entry = case.entries[SETTLED_PREFIX]
    with database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, entry, ravi.admission_authority(case))
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add(case.case_id, admitted.value.entry_digest)
        assert isinstance(added, Ok), added

    after = case_status(
        ravi.casework(database), tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW
    )
    assert isinstance(after, Ok), after
    assert after.value.head == published.value.head
    assert after.value.analysis is not None
    assert published.value.analysis is not None
    assert (
        after.value.analysis.certificate.digest() == published.value.analysis.certificate.digest()
    )


#  ---- 4. the rebuild cannot run --------------------------------------------


def test_a_pin_the_registry_does_not_hold_fails_closed_and_writes_nothing(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    """The registry is immutable and content-addressed, so a miss is not transient.

    Deciding under any other bundle would be answering a different question, so
    the case simply does not advance.
    """
    from muster.policy.registry import BundleRegistry

    empty = ravi.casework(database)
    starved = Casework(
        database=empty.database,
        registry=BundleRegistry(()),
        backend=empty.backend,
        limits=empty.limits,
        policy=empty.policy,
        source_verifier=empty.source_verifier,
        publisher_verifier=empty.publisher_verifier,
        officer_verifier=empty.officer_verifier,
    )
    before = count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_PREFIX")

    refused = advance_case(starved, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(refused, Err)
    assert refused.error.failure is AdvanceFailure.POLICY_UNAVAILABLE
    assert count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_PREFIX") == before


#  ---- 5. the solver fails ---------------------------------------------------


def test_a_solver_that_dies_mid_analysis_leaves_the_head_where_it_was(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    """No transaction is open while the solver runs, so there is nothing to undo."""
    entry = case.entries[SETTLED_PREFIX]
    with database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, entry, ravi.admission_authority(case))
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add(case.case_id, admitted.value.entry_digest)
        assert isinstance(added, Ok), added

    with database.reading(case.tenant_id) as scope:
        before_head = scope.heads.read(case.case_id)
    assert isinstance(before_head, Ok)
    before_prefixes = count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_PREFIX")

    def exploding() -> SolverBackend:
        raise _Injected("the solver process died")

    broken = ravi.casework(database, solver=exploding)
    with pytest.raises(_Injected):
        advance_case(broken, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)

    with database.reading(case.tenant_id) as scope:
        after_head = scope.heads.read(case.case_id)
    assert isinstance(after_head, Ok)
    assert after_head.value == before_head.value
    assert count_content(migrated_dsn, case.tenant_id, "TRANSCRIPT_PREFIX") == before_prefixes

    #  And a working process picks it up unchanged.
    recovered = advance_case(
        ravi.casework(database), tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW
    )
    assert isinstance(recovered, Ok), recovered
    assert recovered.value.published


#  ---- 6-7. the swap is lost --------------------------------------------------


def test_a_lost_swap_caches_no_revision_and_no_certificate(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    """The derived cache is written after the swap succeeds, in the same commit.

    So a lost swap writes no revision, no certificate and no request. The one
    thing it can leave behind is the transcript prefix, which the head's
    foreign key requires before the swap can be attempted at all -- and that is
    an unreferenced content-addressed blob the next attempt reuses.
    """
    entry = case.entries[SETTLED_PREFIX]
    with database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, entry, ravi.admission_authority(case))
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add(case.case_id, admitted.value.entry_digest)
        assert isinstance(added, Ok), added

    revisions_before = count_content(migrated_dsn, case.tenant_id, "CASE_REVISION")
    certificates_before = count_content(migrated_dsn, case.tenant_id, "ANALYSIS_CERTIFICATE")

    def steal(_write: int) -> None:
        with database.writing(case.tenant_id) as scope:
            head = scope.heads.read(case.case_id)
            assert isinstance(head, Ok), head
            prefix = scope.content.put(DigestKind.TRANSCRIPT_PREFIX, b"thief")
            assert isinstance(prefix, Ok), prefix
            from muster.core.wire.digests import Digest

            marker = Digest(b"\x33" * 32)
            scope.heads.advance(
                parent=head.value,
                prefix_digest=prefix.value,
                revision_digest=marker,
                certificate_digest=marker,
            )

    contended = ravi.casework(Interfering(database, steal), max_publication_attempts=1)
    refused = advance_case(contended, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(refused, Err)
    assert refused.error.failure is AdvanceFailure.CONCURRENCY_CONFLICT

    assert count_content(migrated_dsn, case.tenant_id, "CASE_REVISION") == revisions_before
    assert (
        count_content(migrated_dsn, case.tenant_id, "ANALYSIS_CERTIFICATE") == certificates_before
    )
    #  The entry is untouched by any of it.
    assert admitted.value.entry_digest in _members(database, case)


#  ---- H. the database fails between the two transactions ---------------------


def test_a_database_outage_between_the_transactions_keeps_the_entry(
    database: SqlDatabase, case: RaviCase
) -> None:
    """TX A committed; TX B never opened. The entry is durable and re-drivable."""
    entry = case.entries[SETTLED_PREFIX]

    def fail_after_the_first_write(write: int) -> None:
        if write > 1:
            raise psycopg.OperationalError("connection lost")

    flaky: CaseworkDatabase = Interfering(database, fail_after_the_first_write)
    casework = ravi.casework(flaky)

    with pytest.raises(psycopg.OperationalError):
        append_transcript_entry(
            casework,
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            entry=entry,
            now=ravi.NOW,
        )

    assert entry_digest(entry) in _members(database, case)

    healthy = ravi.casework(database)
    recovered = advance_case(healthy, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(recovered, Ok), recovered
    assert recovered.value.published


#  ---- I. restart with orphan cached artifacts --------------------------------


def test_orphan_derived_artifacts_are_reused_rather_than_duplicated(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    """A crash leaves content-addressed blobs nothing references. That is fine.

    The next attempt computes the same artifact, stores it under the same
    digest, and the insert is a no-op. Orphans cost storage, never correctness,
    and they are never duplicated because their key is their content.
    """
    entry = case.entries[SETTLED_PREFIX]
    with database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, entry, ravi.admission_authority(case))
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add(case.case_id, admitted.value.entry_digest)
        assert isinstance(added, Ok), added

    casework = ravi.casework(database)
    first = advance_case(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(first, Ok), first
    revisions = count_content(migrated_dsn, case.tenant_id, "CASE_REVISION")

    #  Re-drive after a "restart". Nothing new arrived, so nothing is published
    #  and nothing is stored a second time.
    reopened = ravi.casework(SqlDatabase(migrated_dsn))
    again = advance_case(reopened, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(again, Ok), again
    assert again.value.published is False
    assert count_content(migrated_dsn, case.tenant_id, "CASE_REVISION") == revisions


def test_a_duplicate_derived_artifact_insert_is_a_no_op(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    casework = ravi.casework(database)
    append_all(casework, case, now=ravi.NOW)
    revisions = count_content(migrated_dsn, case.tenant_id, "CASE_REVISION")

    report = case_status(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(report, Ok), report
    assert report.value.analysis is not None

    from muster.core.wire.codec import encode

    octets = encode(report.value.analysis.revision.to_node())
    with database.writing(case.tenant_id) as scope:
        for _ in range(3):
            stored = scope.content.put(DigestKind.CASE_REVISION, octets)
            assert isinstance(stored, Ok), stored
    assert count_content(migrated_dsn, case.tenant_id, "CASE_REVISION") == revisions


#  ---- corruption is detected, not read past ----------------------------------


def test_a_tampered_stored_entry_stops_the_replay_rather_than_changing_it(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    """The database is not trusted to have kept what it was given.

    Every read re-derives the digest, so octets that were altered under a key
    are refused. The case becomes unreadable, which is the correct answer --
    the alternative is a revision derived from evidence nobody signed.
    """
    from support.fixtures import forge_content

    casework = ravi.casework(database)
    append_all(casework, case, now=ravi.NOW)

    victim = entry_digest(case.entries[0])
    forge_content(migrated_dsn, case.tenant_id, victim, "TRANSCRIPT_ENTRY", b"\x00tampered")

    report = case_status(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(report, Err)
    assert report.error.failure.value in {"SNAPSHOT_REFUSED", "REBUILD_REFUSED"}


def test_a_status_that_cannot_be_replayed_is_refused_rather_than_guessed(
    database: SqlDatabase, case: RaviCase, migrated_dsn: str
) -> None:
    """There is no stored status to fall back to, and that is the safety.

    A design that kept a status column would answer this query from the column
    and report a case as ``AWAITING_EVIDENCE`` while its construction record was
    unreadable. This one has nothing to fall back to, so it says so.
    """
    from support.fixtures import forge_content

    casework = ravi.casework(database)
    append_all(casework, case, now=ravi.NOW)
    forge_content(
        migrated_dsn,
        case.tenant_id,
        case.construction.digest(),
        "CASE_CONSTRUCTION",
        b"\x00not a construction record",
    )
    report = case_status(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(report, Err)
    assert report.error.failure.value == "SNAPSHOT_REFUSED"
    assert CaseStatus.AWAITING_EVIDENCE.value not in report.error.detail
