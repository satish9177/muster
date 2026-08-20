"""Historical authority: a newer snapshot never rewrites a decided case.

The acceptance milestone E has to reach, stated as the sequence it is:

    1  publish authority snapshot A
    2  admit a valid receipt under A, and let the case advance
    3  publish successor snapshot B, which withdraws what A granted
    4  restart -- a new database handle, sharing nothing with the old
    5  the historical case still identifies A, and replays to the same answer
    6  a case opened now under B obeys B
    7  no substitution occurs anywhere in between

The property underneath all of it is that authority is reached through the pin
a revision carries and never through "what is current".  There is no accessor
for the current authority snapshot -- not in the port, not in either adapter --
so re-deciding a historical case under today's grants is not a check that could
be forgotten; it is a call that cannot be spelled.

**Revocation is therefore not retroactive**, and that is the ratified semantics
rather than a convenience.  A case decided in March under a snapshot that did
not revoke a key replays in December to the same answer, because it replays
against March's pins.  Making it reach backwards would mean a published case
could change its outcome with no new evidence and no new revision.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.core.analysis.outcomes import outcome_class
from muster.core.authority.revocation import RevocationSnapshot
from muster.core.results import Err, Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.authority.resolve import resolve_authority
from muster.platform.casework.commands import AppendFailure, append_transcript_entry, case_status
from support import authority as A
from support import ravi
from support.fixtures import append_all, open_ravi
from support.ravi import RaviCase
from tests.support.semantics import semantic_core

pytestmark = pytest.mark.postgres

SATURDAY_PRESENCE = 18


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


def _revoking_successor(case: RaviCase) -> RevocationSnapshot:
    """Snapshot B: the same grants, with the site key withdrawn.

    A *revocation* successor rather than a narrower registry, because that is
    the change most likely to be expected to reach backwards -- "the key was
    compromised, so nothing it ever said counts" is a reasonable-sounding
    sentence and the wrong semantics.
    """
    return replace(case.revocation_snapshot, revoked_key_refs=(A.SITE_A_KEY,))


def test_a_successor_snapshot_does_not_rewrite_a_decided_case(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """Steps 1 to 7, in order."""
    #  ---- 1 and 2. publish A, decide a case under it -----------------------
    historical = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, historical)
    advanced = append_all(work, historical, now=ravi.NOW)
    assert advanced.published
    pinned_snapshot = historical.authority_snapshot.digest()
    pinned_revocation = historical.revocation_snapshot.digest()
    published_revision = advanced.head.revision_digest
    assert published_revision is not None
    decided = semantic_core(advanced.analysis.revision, advanced.analysis)

    #  ---- 3. publish B, which revokes the key that signed --------------------
    later = A.publish(
        database,
        tenant_id,
        revoked=(A.SITE_A_KEY,),
        published_at=A.PUBLISHED_AT + 1,
    )
    assert later.revocation.revokes(A.SITE_A_KEY)
    assert later.revocation.digest() != pinned_revocation

    #  ---- 4. restart ---------------------------------------------------------
    del work, advanced
    reopened = ravi.casework(SqlDatabase(migrated_dsn_of(database)))

    #  ---- 5. the historical case still identifies A and replays to A's answer
    with database.reading(tenant_id) as scope:
        head = scope.heads.read(case_id)
    assert isinstance(head, Ok), head
    with database.reading(tenant_id) as scope:
        from muster.platform.casework.snapshot import read_case_inputs

        inputs = read_case_inputs(scope, case_id, A.publisher_verifier(), A.officer_verifier())
    assert isinstance(inputs, Ok), inputs
    assert inputs.value.authorization_context.authority_registry_snapshot_digest == (
        pinned_snapshot
    )
    assert inputs.value.authorization_context.revocation_snapshot_digest == pinned_revocation
    assert inputs.value.authority.revocation.digest() == pinned_revocation
    assert not inputs.value.authority.revocation.revokes(A.SITE_A_KEY)

    replayed = case_status(reopened, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(replayed, Ok), replayed
    analysis = replayed.value.analysis
    assert analysis is not None
    assert analysis.revision.digest() == published_revision
    assert semantic_core(analysis.revision, analysis) == decided
    assert outcome_class(analysis.kernel.outcome) == "INVARIANT"


def migrated_dsn_of(database: SqlDatabase) -> str:
    """The DSN behind a handle, so a restart is a genuinely new handle."""
    return database.dsn


def test_a_case_opened_under_the_successor_obeys_it(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """Step 6. The same key, the same receipt, and a case that pins B.

    Which is the other half of the property: not-retroactive must not mean
    not-effective.  A revocation that reached nothing would be as broken as one
    that reached backwards.
    """
    base = ravi.ravi(tenant_id, case_id, attested=True)
    revoked = _revoking_successor(base)
    current = replace(
        base,
        revocation_snapshot=revoked,
        authorization_context=replace(
            base.authorization_context,
            revocation_snapshot_digest=revoked.digest(),
        ),
    )
    work = ravi.casework(database)
    open_ravi(work, current)

    outcome = append_transcript_entry(
        work,
        tenant_id=tenant_id,
        case_id=case_id,
        entry=current.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is AppendFailure.ADMISSION_REFUSED
    assert "KeyRevoked" in outcome.error.detail


def test_the_two_cases_coexist_under_two_snapshots(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """Step 7, stated positively: both answers are live at the same instant.

    One tenant, one key, two cases, two pins, two answers -- and neither one
    reaches the other.  A design that resolved "the current snapshot" could not
    produce this state at all, which is what makes it the evidence rather than
    an illustration.
    """
    historical = ravi.ravi(tenant_id, f"{case_id}-historical", attested=True)
    work = ravi.casework(database)
    open_ravi(work, historical)
    advanced = append_all(work, historical, now=ravi.NOW)
    assert advanced.published

    revoked = _revoking_successor(historical)
    A.publish(database, tenant_id, revoked=(A.SITE_A_KEY,), published_at=A.PUBLISHED_AT + 1)
    current = replace(
        ravi.ravi(tenant_id, f"{case_id}-current", attested=True),
        revocation_snapshot=revoked,
    )
    current = replace(
        current,
        authorization_context=replace(
            current.authorization_context,
            revocation_snapshot_digest=revoked.digest(),
        ),
    )
    open_ravi(work, current)

    #  The historical case: the site key's evidence is admitted and stays.
    with database.reading(tenant_id) as scope:
        members = scope.transcript.members(historical.case_id)
    assert isinstance(members, Ok)
    assert len(members.value) == len(historical.entries)

    #  The current case: the same receipt, refused.
    refused = append_transcript_entry(
        work,
        tenant_id=tenant_id,
        case_id=current.case_id,
        entry=current.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(refused, Err)
    assert "KeyRevoked" in refused.error.detail

    #  And both pins still resolve, to two different snapshots.
    with database.reading(tenant_id) as scope:
        old = resolve_authority(scope, historical.authorization_context, A.publisher_verifier())
        new = resolve_authority(scope, current.authorization_context, A.publisher_verifier())
    assert isinstance(old, Ok) and isinstance(new, Ok)
    assert old.value.revocation.digest() != new.value.revocation.digest()
    assert not old.value.revocation.revokes(A.SITE_A_KEY)
    assert new.value.revocation.revokes(A.SITE_A_KEY)


def test_KEY_ROTATION_DOES_NOT_MAKE_HISTORY_UNREADABLE(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """A rotated key: the successor is granted, the predecessor stays historical.

    The milestone-D principle, applied to authority.  Rotating a site agent's
    key today must not make every observation it ever signed inadmissible --
    a case decided under the snapshot that granted the old key replays exactly
    as it did, because that snapshot is what it pinned.

    What rotation *does* change is which key a new case accepts, and that is
    checked in the same breath so the test is not a statement that rotation
    does nothing.
    """
    from muster.core.authority.scope import ResourceScope
    from muster.core.values.times import HalfOpenInterval

    historical = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, historical)
    advanced = append_all(work, historical, now=ravi.NOW)
    assert advanced.published
    decided = semantic_core(advanced.analysis.revision, advanced.analysis)

    #  The rotation: the predecessor's grant ends, the successor's begins, and
    #  both are in the snapshot -- which is what makes the old case readable
    #  and the new key usable.
    rotated = A.publish(
        database,
        tenant_id,
        grants=(
            A.payroll_grant(tenant_id),
            A.grant(
                key_ref=A.SITE_A_KEY,
                principal_id=A.SITE_A,
                tenant_id=tenant_id,
                source_class=A.SOURCE_SITE_ACCESS,
                predicates=("on_site_duration", "present_on_site"),
                scope=(ResourceScope("SITE", A.SITE_A),),
                validity=HalfOpenInterval(A.GRANT_START, historical.as_of),
            ),
            A.grant(
                key_ref=A.SITE_A_NEXT_KEY,
                principal_id=A.SITE_A,
                tenant_id=tenant_id,
                source_class=A.SOURCE_SITE_ACCESS,
                predicates=("on_site_duration", "present_on_site"),
                scope=(ResourceScope("SITE", A.SITE_A),),
                validity=HalfOpenInterval(historical.as_of, A.GRANT_END),
            ),
        ),
        published_at=A.PUBLISHED_AT + 1,
    )

    #  The historical case is untouched: same revision, same decision.
    replayed = case_status(work, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(replayed, Ok), replayed
    assert replayed.value.analysis is not None
    assert semantic_core(replayed.value.analysis.revision, replayed.value.analysis) == decided

    #  A case pinned to the rotated snapshot: the retired key is refused and the
    #  new one is not.  Its ``as_of`` is the instant the predecessor's window
    #  closes, which is where a half-open interval decides.
    current = replace(
        ravi.ravi(tenant_id, f"{case_id}-rotated", attested=True),
        authority_snapshot=rotated.snapshot,
        revocation_snapshot=rotated.revocation,
        authorization_context=rotated.context,
    )
    open_ravi(work, current)
    retired = append_transcript_entry(
        work,
        tenant_id=tenant_id,
        case_id=current.case_id,
        entry=current.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(retired, Err), retired
    assert "AuthorityExpired" in retired.error.detail
