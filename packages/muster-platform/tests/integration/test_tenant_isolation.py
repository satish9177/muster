"""The tenant boundary, attacked against a real database.

The claim being tested is narrow and stated honestly: **isolation here is
enforced by the shape of the repository API and by the primary keys, not by
database roles and not by row-level security.**  There is one component and one
database role in this milestone, so there is no second principal to fence off;
a claim of database-level isolation would be a claim nothing enforces.

The structural half of the same rule -- that a query missing its tenant
qualification cannot be written at all -- is in ``architecture/test_tenant_boundary``,
where it belongs and where it runs without a database.
"""

from __future__ import annotations

import pytest

from muster.core.results import Err, Ok
from muster.core.wire.digests import DigestKind
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import case_status
from muster.platform.casework.ports import HeadFailure, StoreFailure, TranscriptFailure
from muster.platform.ingest.admission import AdmissionFailure, admit_entry
from support import ravi
from support.fixtures import append_all, open_ravi

pytestmark = pytest.mark.postgres


def test_two_tenants_hold_the_same_case_id_independently(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(database)
    mine = ravi.ravi(tenant_id, case_id)
    theirs = ravi.ravi(other_tenant_id, case_id)
    open_ravi(casework, mine)
    open_ravi(casework, theirs)

    append_all(casework, mine, now=ravi.NOW)

    with database.reading(tenant_id) as scope:
        my_head = scope.heads.read(case_id)
    with database.reading(other_tenant_id) as scope:
        their_head = scope.heads.read(case_id)
    assert isinstance(my_head, Ok) and isinstance(their_head, Ok)
    assert my_head.value.revision_digest is not None
    assert their_head.value.revision_digest is None
    assert my_head.value.inputs.construction_digest != their_head.value.inputs.construction_digest


def test_one_tenant_cannot_read_another_tenants_head(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(database)
    open_ravi(casework, ravi.ravi(tenant_id, case_id))

    with database.reading(other_tenant_id) as scope:
        read = scope.heads.read(case_id)
    assert isinstance(read, Err)
    assert read.error.failure is HeadFailure.UNKNOWN_CASE


def test_one_tenant_cannot_read_another_tenants_transcript(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(database)
    case = ravi.ravi(tenant_id, case_id)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)

    with database.reading(other_tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Err)
    assert members.error.failure is TranscriptFailure.UNKNOWN_CASE


def test_one_tenant_cannot_append_to_another_tenants_case(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    """Refused twice: the entry's binding, and then the case's own key."""
    casework = ravi.casework(database)
    mine = ravi.ravi(tenant_id, case_id)
    open_ravi(casework, mine)

    with database.writing(other_tenant_id) as scope:
        refused = admit_entry(scope, case_id, mine.entries[0])
    assert isinstance(refused, Err)
    assert refused.error.failure is AdmissionFailure.TENANT_MISMATCH

    #  Even an entry the other tenant *could* admit cannot join a case it does
    #  not have: the membership row is keyed by tenant and the case is not there.
    theirs = ravi.ravi(other_tenant_id, case_id)
    with database.writing(other_tenant_id) as scope:
        admitted = admit_entry(scope, case_id, theirs.entries[0])
        assert isinstance(admitted, Ok), admitted
        added = scope.transcript.add(case_id, admitted.value.entry_digest)
    assert isinstance(added, Err)
    assert added.error.failure is TranscriptFailure.UNKNOWN_CASE


def test_one_tenant_cannot_reference_another_tenants_stored_octets(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    """The content key carries the tenant, so a cross-tenant reference is absent.

    Not "denied" -- absent. There is no row at that key for this tenant, and
    the foreign key that would have to resolve carries the tenant too.
    """
    casework = ravi.casework(database)
    mine = ravi.ravi(tenant_id, case_id)
    open_ravi(casework, mine)
    with database.writing(tenant_id) as scope:
        admitted = admit_entry(scope, case_id, mine.entries[0])
    assert isinstance(admitted, Ok), admitted

    theirs = ravi.ravi(other_tenant_id, case_id)
    open_ravi(casework, theirs)
    with database.writing(other_tenant_id) as scope:
        read = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, admitted.value.entry_digest)
        assert isinstance(read, Err)
        assert read.error.failure is StoreFailure.CONTENT_ABSENT
        borrowed = scope.transcript.add(case_id, admitted.value.entry_digest)
    assert isinstance(borrowed, Err)
    assert borrowed.error.failure is TranscriptFailure.CONTENT_NOT_STORED


def test_one_tenant_cannot_see_another_tenants_evidence_requests(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(database)
    mine = ravi.ravi(tenant_id, case_id)
    theirs = ravi.ravi(other_tenant_id, case_id)
    open_ravi(casework, mine)
    open_ravi(casework, theirs)
    append_all(casework, mine, now=ravi.NOW)

    with database.reading(tenant_id) as scope:
        ours = scope.requests.outstanding(case_id)
    with database.reading(other_tenant_id) as scope:
        others = scope.requests.outstanding(case_id)
    assert isinstance(ours, Ok) and isinstance(others, Ok)
    assert len(ours.value) == 1
    assert others.value == ()


def test_a_status_query_is_answered_only_for_the_calling_tenant(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(database)
    mine = ravi.ravi(tenant_id, case_id)
    open_ravi(casework, mine)
    append_all(casework, mine, now=ravi.NOW)

    theirs = case_status(casework, tenant_id=other_tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(theirs, Err)
    assert theirs.error.failure.value == "UNKNOWN_CASE"


def test_the_same_octets_under_two_tenants_are_two_rows_and_two_lifecycles(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, dsn: str
) -> None:
    """Deduplication across the boundary is refused by design, not missed.

    Sharing a row would make one tenant's retention decision another tenant's
    problem, and would leak the existence of an artifact across the boundary
    that exists to prevent exactly that.
    """
    import psycopg

    octets = b"an artifact two tenants happen to hold"
    digests = []
    for tenant in (tenant_id, other_tenant_id):
        with database.writing(tenant) as scope:
            stored = scope.content.put(DigestKind.TRANSCRIPT_ENTRY, octets)
            assert isinstance(stored, Ok), stored
            digests.append(stored.value)
    #  The same octets under the same domain, so the same key -- twice.
    assert digests[0] == digests[1]
    digest = digests[0]

    with psycopg.connect(dsn) as connection:
        rows = connection.execute(
            "SELECT tenant_id FROM store.content "
            "WHERE digest = %s AND tenant_id = ANY(%s) ORDER BY tenant_id",
            (digest.octets, [tenant_id, other_tenant_id]),
        ).fetchall()
    assert sorted(row[0] for row in rows) == sorted([tenant_id, other_tenant_id])

    #  Deleting one leaves the other untouched.
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "DELETE FROM store.content WHERE tenant_id = %s AND digest = %s",
            (tenant_id, digest.octets),
        )
    with database.reading(other_tenant_id) as scope:
        survived = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, digest)
    assert isinstance(survived, Ok)
    assert survived.value == octets


def test_a_construction_record_cannot_declare_another_tenants_principal_as_a_party(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    """The parties are inside the record, and each of them names a tenant.

    Roles come from the construction record -- signed by an officer, never from
    a party's own assertion about itself -- so a party bound to another tenant
    is an authored role declaration about somebody outside the boundary. The
    outer record's tenant matched, so checking only that let this through, and
    the content store has no delete: it would have been permanent.
    """
    from dataclasses import replace

    from muster.platform.ingest.admission import admit_case_construction

    case = ravi.ravi(tenant_id, case_id)
    smuggled = replace(
        case.construction,
        parties=(
            replace(case.construction.parties[0], tenant_id=other_tenant_id),
            *case.construction.parties[1:],
        ),
    )
    assert smuggled.tenant_id == tenant_id
    assert smuggled.case_id == case_id

    with database.writing(tenant_id) as scope:
        refused = admit_case_construction(scope, case_id, smuggled)
        assert isinstance(refused, Err), refused
        assert refused.error.failure is AdmissionFailure.TENANT_MISMATCH
        assert other_tenant_id in refused.error.detail
        #  And nothing was stored under its digest.
        stored = scope.content.get(DigestKind.CASE_CONSTRUCTION, smuggled.digest())
    assert isinstance(stored, Err)
    assert stored.error.failure is StoreFailure.CONTENT_ABSENT


def test_a_case_is_not_rebuilt_from_a_construction_record_with_a_foreign_party(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    """Re-checked on the way out, because admission is not the only door.

    The other door is an operator with SQL, and this test is that operator.
    A stored record whose party names another tenant makes the case unreadable
    rather than quietly contributing a foreign role to a revision.
    """
    from dataclasses import replace

    from muster.core.wire.codec import encode
    from support.fixtures import insert_content, repoint_construction

    case = ravi.ravi(tenant_id, case_id)
    casework = ravi.casework(database)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)

    smuggled = replace(
        case.construction,
        parties=(
            replace(case.construction.parties[0], tenant_id=other_tenant_id),
            *case.construction.parties[1:],
        ),
    )
    #  Stored under its *own* digest and the head repointed at it, rather than
    #  overwritten beneath the original key. Overwriting would be caught by the
    #  store's hash check before the party check was ever reached, so the test
    #  would pass whether or not the party check existed -- which is no test at
    #  all of the read door.
    insert_content(
        migrated_dsn,
        tenant_id,
        smuggled.digest(),
        "CASE_CONSTRUCTION",
        encode(smuggled.to_node()),
    )
    repoint_construction(migrated_dsn, tenant_id, case_id, smuggled.digest())

    report = case_status(casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(report, Err)
    assert report.error.failure.value == "SNAPSHOT_REFUSED"
    assert "PartyRecord" in report.error.detail
    assert other_tenant_id in report.error.detail
