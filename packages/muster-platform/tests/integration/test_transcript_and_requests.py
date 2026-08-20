"""Transcript membership and evidence-request durability, against PostgreSQL.

Membership is a set: duplicates collapse, order is not recorded, nothing
removes a member.  Requests are immutable rows whose identity is a digest of
their own content, and whose outstandingness is a join against the head rather
than a column somebody has to remember to update.
"""

from __future__ import annotations

import pytest

from muster.core.evidence.transcript import entry_digest, entry_node
from muster.core.results import Err, Ok
from muster.core.values.times import Instant
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest, DigestKind
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import AdvanceFailure, Casework
from muster.platform.casework.commands import append_transcript_entry
from muster.platform.casework.ports import RecordedRequest, RequestFailure, TranscriptFailure
from muster.platform.ingest.admission import AdmissionFailure, admit_entry
from muster.platform.orchestration.decisions import Dispatch
from support import ravi
from support.fixtures import append, append_all, open_ravi
from support.ravi import RaviCase


def _members(database: SqlDatabase, case: RaviCase) -> set[Digest]:
    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok)
    return set(members.value)


pytestmark = pytest.mark.postgres


@pytest.fixture
def casework(database: SqlDatabase) -> Casework:
    return ravi.casework(database)


@pytest.fixture
def case(casework: Casework, tenant_id: str, case_id: str) -> RaviCase:
    built = ravi.ravi(tenant_id, case_id)
    open_ravi(casework, built)
    return built


#  ---- membership ---------------------------------------------------------


def test_a_member_is_added_once_and_reported_as_created(
    database: SqlDatabase, case: RaviCase
) -> None:
    digest = entry_digest(case.entries[0])
    with database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, case.entries[0], ravi.admission_authority(case))
        assert isinstance(admitted, Ok), admitted
        first = scope.transcript.add(case.case_id, digest)
        second = scope.transcript.add(case.case_id, digest)
        third = scope.transcript.add(case.case_id, digest)
    assert isinstance(first, Ok) and first.value is True
    assert isinstance(second, Ok) and second.value is False
    assert isinstance(third, Ok) and third.value is False

    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok)
    assert members.value == (digest,)


def test_membership_comes_back_ascending_whatever_order_it_went_in(
    database: SqlDatabase, case: RaviCase
) -> None:
    """Arrival order is not recorded, because a prefix does not commit to it."""
    chosen = case.entries[:6]
    with database.writing(case.tenant_id) as scope:
        for entry in reversed(chosen):
            admitted = admit_entry(scope, case.case_id, entry, ravi.admission_authority(case))
            assert isinstance(admitted, Ok), admitted
            added = scope.transcript.add(case.case_id, admitted.value.entry_digest)
            assert isinstance(added, Ok), added

    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok)
    octets = [digest.octets for digest in members.value]
    assert octets == sorted(octets)
    assert set(members.value) == {entry_digest(entry) for entry in chosen}


def test_membership_for_an_unopened_case_is_a_typed_absence(
    database: SqlDatabase, tenant_id: str
) -> None:
    with database.reading(tenant_id) as scope:
        members = scope.transcript.members("never-opened")
    assert isinstance(members, Err)
    assert members.error.failure is TranscriptFailure.UNKNOWN_CASE


def test_a_member_cannot_be_added_to_a_case_that_does_not_exist(
    database: SqlDatabase, tenant_id: str, case: RaviCase
) -> None:
    with database.writing(tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, case.entries[0], ravi.admission_authority(case))
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add("never-opened", admitted.value.entry_digest)
    assert isinstance(added, Err)
    assert added.error.failure is TranscriptFailure.UNKNOWN_CASE


def test_membership_without_stored_octets_is_refused_as_a_value(
    database: SqlDatabase, case: RaviCase
) -> None:
    """A member whose preimage is absent makes the prefix undecodable.

    The database refuses it, and the repository turns the refusal into a value
    inside a savepoint so the caller's transaction survives to report it.
    """
    orphan = Digest(b"\x77" * 32)
    with database.writing(case.tenant_id) as scope:
        added = scope.transcript.add(case.case_id, orphan)
        assert isinstance(added, Err)
        assert added.error.failure is TranscriptFailure.CONTENT_NOT_STORED
        #  The transaction is still usable.
        members = scope.transcript.members(case.case_id)
        assert isinstance(members, Ok)


def test_the_repository_offers_no_way_to_remove_a_member() -> None:
    """Append-only is a shape, not a convention somebody follows."""
    from muster.platform.adapters.sql.transcript import SqlTranscriptRepository

    surface = {name for name in dir(SqlTranscriptRepository) if not name.startswith("_")}
    assert surface == {"add", "members", "connection", "tenant_id"}


#  ---- admission ----------------------------------------------------------


def test_an_entry_bound_to_another_case_is_refused_before_it_is_stored(
    database: SqlDatabase, tenant_id: str, case_id: str, casework: Casework, case: RaviCase
) -> None:
    elsewhere = ravi.ravi(tenant_id, f"{case_id}-other")
    open_ravi(casework, elsewhere)
    with database.writing(tenant_id) as scope:
        refused = admit_entry(
            scope, case.case_id, elsewhere.entries[0], ravi.admission_authority(elsewhere)
        )
    assert isinstance(refused, Err)
    assert refused.error.failure is AdmissionFailure.CASE_MISMATCH

    #  And nothing was stored: the refusal happens before the write.
    with database.reading(tenant_id) as scope:
        read = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, entry_digest(elsewhere.entries[0]))
    assert isinstance(read, Err)


def test_an_entry_bound_to_another_tenant_is_refused(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case: RaviCase
) -> None:
    foreign = ravi.ravi(other_tenant_id, case.case_id)
    with database.writing(tenant_id) as scope:
        refused = admit_entry(
            scope, case.case_id, foreign.entries[0], ravi.admission_authority(foreign)
        )
    assert isinstance(refused, Err)
    assert refused.error.failure is AdmissionFailure.TENANT_MISMATCH


def test_admission_stores_the_octets_it_was_given(database: SqlDatabase, case: RaviCase) -> None:
    """The artifact is the octets, and they go in unchanged."""
    entry = case.entries[0]
    expected = encode(entry_node(entry))
    with database.writing(case.tenant_id) as scope:
        admitted = admit_entry(scope, case.case_id, entry, ravi.admission_authority(case))
    assert isinstance(admitted, Ok), admitted

    with database.reading(case.tenant_id) as scope:
        read = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, admitted.value.entry_digest)
    assert isinstance(read, Ok)
    assert read.value == expected


#  ---- evidence requests --------------------------------------------------


def _dispatched(casework: Casework, case: RaviCase, now: Instant) -> RecordedRequest:
    """Append the whole transcript; the case then asks for its two observations."""
    advanced = append_all(casework, case, now=now)
    decision = advanced.decision
    assert isinstance(decision, Dispatch), decision
    assert advanced.head.revision_digest is not None
    return RecordedRequest(
        case_id=case.case_id,
        request_id=decision.request.digest(),
        revision_digest=advanced.head.revision_digest,
        deadline=decision.deadline,
    )


def test_a_case_over_the_engine_bound_keeps_its_entries_and_catches_up_later(
    database: SqlDatabase, casework: Casework, case: RaviCase
) -> None:
    """Fail-closed in the middle, published at the end, and nothing lost between.

    The fixture declares every proposition instance up front and establishes
    them one entry at a time, so an early revision has far more unresolved
    variables than the engine's admission bound permits. ``prepare`` refuses
    it, which is correct -- and the entry is durable anyway, because admission
    committed before the analysis was attempted. The head simply stays where it
    is until the case is analysable again.
    """
    first = append(casework, case, 0, now=ravi.NOW)
    assert isinstance(first.advanced, Err)
    assert first.advanced.error.failure is AdvanceFailure.ANALYSIS_REFUSED
    assert "UnsupportedCaseSize" in first.advanced.error.detail

    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
        head = scope.heads.read(case.case_id)
    assert isinstance(members, Ok)
    assert first.entry_digest in members.value
    assert isinstance(head, Ok)
    assert head.value.revision_digest is None  # still in intake, and honestly so

    advanced = append_all(casework, case, now=ravi.NOW)
    assert advanced.published
    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok)
    #  Every entry, including the one whose own advance was refused.
    assert len(members.value) == len(case.entries)
    assert first.entry_digest in members.value


def test_a_dispatched_request_is_durable_and_outstanding(
    database: SqlDatabase, casework: Casework, case: RaviCase
) -> None:
    expected = _dispatched(casework, case, ravi.NOW)

    with database.reading(case.tenant_id) as scope:
        outstanding = scope.requests.outstanding(case.case_id)
    assert isinstance(outstanding, Ok)
    assert outstanding.value == (expected,)
    assert outstanding.value[0].deadline == ravi.ONE_HOUR.after(ravi.NOW)


def test_the_request_payload_round_trips_out_of_the_store(
    database: SqlDatabase, casework: Casework, case: RaviCase
) -> None:
    """Persisted intent, read back as the value the planner produced.

    A request may exist without a transport -- there is no transport in this
    milestone -- but "persisted" has to mean the payload survives, not only
    that a row exists.
    """
    from muster.core.evidence.requests import read_evidence_request
    from muster.core.wire.codec import decode

    recorded = _dispatched(casework, case, ravi.NOW)
    with database.reading(case.tenant_id) as scope:
        octets = scope.content.get(DigestKind.EVIDENCE_REQUEST, recorded.request_id)
    assert isinstance(octets, Ok), octets
    node = decode(octets.value)
    assert isinstance(node, Ok), node
    request = read_evidence_request(node.value)
    assert request.digest() == recorded.request_id
    assert request.revision_semantic_digest == recorded.revision_digest
    assert request.tenant_id == case.tenant_id
    assert request.case_id == case.case_id


def test_recording_the_same_request_twice_is_a_no_op(
    database: SqlDatabase, casework: Casework, case: RaviCase
) -> None:
    recorded = _dispatched(casework, case, ravi.NOW)
    with database.writing(case.tenant_id) as scope:
        again = scope.requests.record(recorded)
    assert isinstance(again, Ok)
    assert again.value is False


def test_a_request_id_may_not_be_re_registered_against_another_revision(
    database: SqlDatabase, casework: Casework, case: RaviCase
) -> None:
    """The id is the digest of a record containing the revision.

    So a re-registration naming a different revision is a digest claiming to be
    two things, which is corruption and not a legitimate retry.
    """
    from dataclasses import replace

    recorded = _dispatched(casework, case, ravi.NOW)
    with database.writing(case.tenant_id) as scope:
        refused = scope.requests.record(replace(recorded, revision_digest=Digest(b"\x01" * 32)))
    assert isinstance(refused, Err)
    assert refused.error.failure is RequestFailure.REQUEST_IDENTITY_CONFLICT


def test_a_re_registration_cannot_extend_a_deadline_it_did_not_set(
    database: SqlDatabase, casework: Casework, case: RaviCase
) -> None:
    from dataclasses import replace

    recorded = _dispatched(casework, case, ravi.NOW)
    with database.writing(case.tenant_id) as scope:
        again = scope.requests.record(replace(recorded, deadline=recorded.deadline + 10**9))
        assert isinstance(again, Ok)

    with database.reading(case.tenant_id) as scope:
        outstanding = scope.requests.outstanding(case.case_id)
    assert isinstance(outstanding, Ok)
    assert outstanding.value[0].deadline == recorded.deadline


def test_a_request_stops_being_outstanding_when_the_head_moves_past_it(
    database: SqlDatabase, casework: Casework, case: RaviCase
) -> None:
    """Outstandingness is a join, so it changes with the head and never lags.

    There is no status column to update, so there is no window in which a crash
    could leave the head saying one thing and a status column another.
    """
    recorded = _dispatched(casework, case, ravi.NOW)
    with database.reading(case.tenant_id) as scope:
        before = scope.requests.outstanding(case.case_id)
    assert isinstance(before, Ok)
    assert recorded in before.value

    #  Move the head past it by admitting one more entry, from the attested
    #  variant of the same case, and advancing.
    attested = ravi.ravi(case.tenant_id, case.case_id, attested=True)
    extra = next(
        entry for entry in attested.entries if entry_digest(entry) not in _members(database, case)
    )
    appended = append_transcript_entry(
        casework,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=extra,
        now=ravi.NOW,
    )
    assert isinstance(appended, Ok), appended
    assert isinstance(appended.value.advanced, Ok), appended.value.advanced
    assert appended.value.advanced.value.published

    with database.reading(case.tenant_id) as scope:
        after = scope.requests.outstanding(case.case_id)
    assert isinstance(after, Ok)
    #  The old request is gone from the outstanding set, and the row is still
    #  there: nothing was deleted or mutated, the head simply moved.
    assert recorded not in after.value
