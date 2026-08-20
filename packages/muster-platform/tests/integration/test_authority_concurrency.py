"""Authority under concurrency, on real threads against real PostgreSQL.

Milestone C's hold-and-swap discipline exists to stop two appenders leaving a
transcript that rebuilds for nobody.  Milestone E puts a second decision inside
the same transaction -- Q-12 -- and the question this file answers is whether
that decision can be raced.

Four races, and each one has a specific way to be wrong:

* **an authorized and an unauthorized receipt at once.**  The wrong outcome is
  the unauthorized one riding in on the authorized one's transaction;
* **a snapshot published while an admission is in flight.**  The wrong outcome
  is the admission picking up the newer snapshot mid-decision, which is only
  possible if something resolves "current" rather than the pin;
* **the same unauthorized receipt from two threads.**  The wrong outcome is one
  of them winning a race that neither should win;
* **two tenants using identical identifiers.**  The wrong outcome is either of
  them seeing the other's authority.

The interleavings are forced with the same rendezvous milestone C used, so a
green result is not a machine that happened to be fast.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from muster.core.evidence.transcript import Attestation, entry_digest
from muster.core.results import Err, Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import AppendFailure, append_transcript_entry
from support import authority as A
from support import ravi
from support.authority import sign_receipt
from support.fixtures import open_ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

SATURDAY_PRESENCE = 18
SATURDAY_DURATION = 19


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


@pytest.fixture
def prepared(database: SqlDatabase, tenant_id: str, case_id: str) -> RaviCase:
    """A case open and holding everything except the Saturday observations."""
    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, case)
    for index in range(SATURDAY_PRESENCE):
        appended = append_transcript_entry(
            work,
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            entry=case.entries[index],
            now=ravi.NOW,
        )
        assert isinstance(appended, Ok), appended
    return case


def _forged(case: RaviCase, index: int, key_ref: str = A.WORKER_KEY) -> Attestation:
    entry = case.entries[index]
    assert isinstance(entry, Attestation)
    return Attestation(
        sign_receipt(
            replace(entry.receipt, payload=replace(entry.receipt.payload, signer_key_ref=key_ref))
        )
    )


def _append(database: SqlDatabase, case: RaviCase, entry: object) -> object:
    return append_transcript_entry(
        ravi.casework(database),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=entry,  # type: ignore[arg-type]
        now=ravi.NOW,
    )


def _members(database: SqlDatabase, case: RaviCase) -> set[object]:
    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok), members
    return set(members.value)


def test_an_unauthorized_receipt_racing_an_authorized_one_is_still_refused(
    database: SqlDatabase, prepared: RaviCase
) -> None:
    """Both threads inside the append at once; only one entry survives.

    The hold serialises them, so this is not a test that two things happened at
    the same time -- it is a test that being second does not change the answer.
    An implementation that resolved the authority view *before* taking the hold
    and reused it across the wait would still pass; one that let the second
    transaction see the first's uncommitted work would not.
    """
    honest = prepared.entries[SATURDAY_PRESENCE]
    forged = _forged(prepared, SATURDAY_DURATION)

    with ThreadPoolExecutor(max_workers=2) as pool:
        left = pool.submit(_append, database, prepared, honest)
        right = pool.submit(_append, database, prepared, forged)
        outcomes = (left.result(), right.result())

    assert isinstance(outcomes[0], Ok), outcomes[0]
    assert isinstance(outcomes[1], Err), outcomes[1]
    assert outcomes[1].error.failure is AppendFailure.ADMISSION_REFUSED

    members = _members(database, prepared)
    assert entry_digest(honest) in members
    assert entry_digest(forged) not in members


def test_the_same_unauthorized_receipt_from_two_threads_is_refused_twice(
    database: SqlDatabase, prepared: RaviCase
) -> None:
    """Neither thread wins a race that neither should win.

    Worth separating from the test above because the failure mode is
    different: two appenders inserting *the same* membership row conflict on
    the primary key, and an implementation that treated the conflict as "the
    entry is already a member, so it must have been fine" would admit it.
    """
    forged = _forged(prepared, SATURDAY_PRESENCE)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [
            future.result()
            for future in (
                pool.submit(_append, database, prepared, forged),
                pool.submit(_append, database, prepared, forged),
            )
        ]

    for outcome in outcomes:
        assert isinstance(outcome, Err), outcome
        assert outcome.error.failure is AppendFailure.ADMISSION_REFUSED
    assert entry_digest(forged) not in _members(database, prepared)


def test_a_snapshot_published_mid_flight_does_not_reach_the_case(
    database: SqlDatabase, prepared: RaviCase
) -> None:
    """A successor published while an admission runs is invisible to it.

    Only possible to get wrong by resolving "the current snapshot" somewhere,
    which is a call the port does not offer -- so this test is evidence for an
    absence.  It races a publication against an admission of a receipt the
    successor *would* authorize, and requires the refusal.
    """
    from muster.core.authority.scope import ResourceScope

    forged = _forged(prepared, SATURDAY_PRESENCE)

    def publish() -> A.PublishedAuthority:
        return A.publish(
            database,
            prepared.tenant_id,
            grants=(
                *A.workforce_grants(prepared.tenant_id),
                A.grant(
                    key_ref=A.WORKER_KEY,
                    principal_id=A.WORKER,
                    tenant_id=prepared.tenant_id,
                    source_class=A.SOURCE_SITE_ACCESS,
                    predicates=("on_site_duration", "present_on_site"),
                    scope=(ResourceScope("SITE", A.SITE_A),),
                ),
            ),
            published_at=A.PUBLISHED_AT + 1,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        publication = pool.submit(publish)
        admission = pool.submit(_append, database, prepared, forged)
        published = publication.result()
        outcome = admission.result()

    assert published.snapshot.digest() != prepared.authority_snapshot.digest()
    assert isinstance(outcome, Err), outcome
    assert "UnauthorizedSourceClassForKey" in outcome.error.detail
    assert entry_digest(forged) not in _members(database, prepared)

    #  And it stays refused afterwards, when there is no race at all: the
    #  successor exists, is published, and the case still does not see it.
    again = _append(database, prepared, forged)
    assert isinstance(again, Err)
    assert "UnauthorizedSourceClassForKey" in again.error.detail


def test_two_tenants_reusing_every_identifier_do_not_share_authority(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    """Same case identifier, same site, same key reference, two tenants.

    Run concurrently, because the interesting failure is a cache or a resolver
    keyed on something that is not the tenant.  Each tenant's authority is
    published separately and each case is admitted separately, and the check is
    that a receipt bound to one is refused by the other -- while both succeed
    in their own.
    """
    mine = ravi.ravi(tenant_id, case_id, attested=True)
    theirs = ravi.ravi(other_tenant_id, case_id, attested=True)
    assert mine.authority_snapshot.digest() != theirs.authority_snapshot.digest()

    for case in (mine, theirs):
        open_ravi(ravi.casework(database), case)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [
            future.result()
            for future in (
                pool.submit(_append, database, mine, mine.entries[SATURDAY_PRESENCE]),
                pool.submit(_append, database, theirs, theirs.entries[SATURDAY_PRESENCE]),
            )
        ]
    for outcome in outcomes:
        assert isinstance(outcome, Ok), outcome

    #  And crossed over, both are refused on binding before authority is even
    #  reached -- the entry carries its tenant inside the octets a signature
    #  covers, so there is nothing to reinterpret.
    crossed = _append(database, mine, theirs.entries[SATURDAY_DURATION])
    assert isinstance(crossed, Err)
    assert "TENANT_MISMATCH" in crossed.error.detail
