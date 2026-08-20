"""G7: a new case opens under the authority in force, or it does not open.

The attack this file exists to refuse, as the sequence it is:

    1  snapshot A grants key K a class over a resource
    2  snapshot B is published later and does NOT carry that grant
    3  K is never key-revoked -- there is no revocation snapshot naming it
    4  a caller opens a BRAND NEW case, deliberately naming A in its
       authorization context
    5  the case admits a receipt signed by K

Before milestone E every step succeeded.  Withdrawing a grant is publishing a
successor snapshot, and a successor has no effect on a case that pinned the
predecessor -- which is right for a case that already exists, and was being
applied to cases that did not exist yet.  So "withdraw K's authority" was
something any new case could decline to notice, simply by naming the older
snapshot, and the key never had to be revoked for it to keep attesting.

**What is and is not being changed.**  Nothing about a historical case moves.
It is not reopened, it does not repin, and its rebuild resolves the snapshot its
own authorization context names -- so the revocation-is-not-retroactive
semantics of ``test_authority_replay`` are exactly as they were, and one of the
tests below asserts that both properties hold at once, because a fix that
achieved freshness by making history mutable would be a worse defect than the
one it closed.

**Why equality with the in-force snapshot, rather than an age bound.**  A bound
expressed as a duration has to be measured against some instant, and the only
instant available when a case opens is ``as_of`` -- which the caller supplies.
A freshness rule a caller satisfies by choosing a number is not a freshness
rule.  Equality needs no clock, cannot be argued with, and is the strongest
bound available; the cost is that a case opened during a publication has to be
retried, which is a fail-closed cost.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.core.authority.grants import AuthorityGrant
from muster.core.case.revision import AuthorizationContext
from muster.core.results import Err, Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import (
    OpenFailure,
    append_transcript_entry,
    open_case,
)
from muster.platform.casework.snapshot import read_case_inputs
from support import authority as A
from support import ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

SATURDAY_PRESENCE = 18


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


def _site_key(case: RaviCase) -> str:
    entry = case.entries[SATURDAY_PRESENCE]
    assert hasattr(entry, "receipt")
    return str(entry.receipt.payload.signer_key_ref)


def _without_the_site_grant(case: RaviCase) -> tuple[AuthorityGrant, ...]:
    """Snapshot B's grant set: A's, minus the one the site key holds.

    A *withdrawal by omission*, which is the whole construction.  The key is
    not revoked -- no revocation snapshot names it, and Q-12(f) has nothing to
    say about it -- so if the case resolves snapshot A the receipt is admitted
    on every clause.  The only thing standing between the attacker and a fact
    is which snapshot the new case is allowed to pin.
    """
    signer = _site_key(case)
    dropped = tuple(grant for grant in case.authority_snapshot.grants if grant.key_ref != signer)
    assert len(dropped) < len(case.authority_snapshot.grants), "nothing was withdrawn"
    return dropped


def _open(database: SqlDatabase, case: RaviCase, context: AuthorizationContext) -> object:
    return open_case(
        ravi.casework(database),
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )


def test_OLD_AUTHORITY_SNAPSHOT_CANNOT_BE_RESURRECTED_FOR_NEW_CASE(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The ratified regression, run end to end on the public production path.

    Everything here goes through ``open_case`` and the real publisher.  Nothing
    reaches past a repository, nothing writes a row itself, and the receipt is
    genuinely signed -- so the refusal is the system's and not the fixture's.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)

    #  Snapshot A: the case's own authority, which grants the site key exactly
    #  what the receipt needs.
    first = A.publish(database, tenant_id, grants=case.authority_snapshot.grants)

    #  Snapshot B: the same registry with that grant dropped.  Published second,
    #  so it is what the tenant now has in force.
    A.publish(database, tenant_id, grants=_without_the_site_grant(case))

    #  The attack: a brand-new case naming A.
    stale = replace(
        case.authorization_context,
        authority_registry_snapshot_digest=first.snapshot.digest(),
        revocation_snapshot_digest=first.revocation.digest(),
    )
    opened = _open(database, case, stale)

    assert isinstance(opened, Err), opened
    assert opened.error.failure is OpenFailure.AUTHORITY_NOT_IN_FORCE
    assert "PUBLICATION_SUPERSEDED" in opened.error.detail

    #  And it left nothing behind.  A refused open that still deposited a head
    #  would leave a case an operator could later advance.
    with database.reading(tenant_id) as scope:
        head = scope.heads.read(case_id)
    assert isinstance(head, Err), head


def test_the_resurrected_grant_would_otherwise_have_admitted_the_receipt(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The attack is refused for the right reason, and not by accident.

    A regression that only shows a refusal proves nothing: the receipt might be
    inadmissible for six other reasons, and the test would pass with the gate
    removed.  So this runs the *same* receipt into a case opened under the same
    snapshot A while A is still in force, and admits it.

    Read together with the test above, the pair says exactly one thing: the
    receipt is admissible under A, and what refuses it is that A is no longer
    what a new case may open under.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    first = A.publish(database, tenant_id, grants=case.authority_snapshot.grants)

    work = ravi.casework(database)
    opened = open_case(
        work,
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=first.context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )
    assert isinstance(opened, Ok), opened

    admitted = append_transcript_entry(
        work,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=case.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(admitted, Ok), admitted


def test_a_case_already_open_under_the_old_snapshot_keeps_it(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """Historical and new are separated, and both properties hold together.

    The case opens legitimately under A, a successor B is published that drops
    the grant, and the *already open* case goes on admitting under A.  That is
    not a hole -- it is the pin doing its job, and it is what makes a decided
    case replay to the same answer forever.  A fix for staleness that also made
    this fail would have replaced a freshness defect with an immutability one.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    first = A.publish(database, tenant_id, grants=case.authority_snapshot.grants)

    work = ravi.casework(database)
    opened = open_case(
        work,
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=first.context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )
    assert isinstance(opened, Ok), opened

    #  The successor lands *after* the case is open.
    A.publish(database, tenant_id, grants=_without_the_site_grant(case))

    admitted = append_transcript_entry(
        work,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=case.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(admitted, Ok), admitted

    #  And the head still identifies A.  "Still admits" and "still pinned to A"
    #  are two claims, and only the second rules out the case having quietly
    #  repinned to something that happens to permit the same thing.
    with database.reading(tenant_id) as scope:
        inputs = read_case_inputs(scope, case_id, A.publisher_verifier(), A.officer_verifier())
    assert isinstance(inputs, Ok), inputs
    assert inputs.value.authorization_context.authority_registry_snapshot_digest == (
        first.snapshot.digest()
    )


def test_a_tenant_with_no_authority_in_force_cannot_open_a_case_at_all(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """G7's fail-closed absence, and it is a different finding from staleness.

    Nothing has ever been published for this tenant, so there is no state
    against which "this is the authority in force" could be true.  The refusal
    names the absence rather than reporting it as a superseded pin: an operator
    who has not deployed a publisher and an operator whose pin is stale have
    different problems, and one error for both would hide the first behind the
    second.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    opened = _open(database, case, case.authorization_context)
    assert isinstance(opened, Err), opened
    assert opened.error.failure is OpenFailure.AUTHORITY_NOT_IN_FORCE
    assert "PUBLICATION_STATE_ABSENT" in opened.error.detail


def test_publishing_a_successor_makes_it_the_one_new_cases_must_use(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The other direction: the gate admits what is current, so it is not a wall.

    A gate that refused everything would pass every test above and be useless.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    A.publish(database, tenant_id, grants=case.authority_snapshot.grants)
    second = A.publish(database, tenant_id, grants=_without_the_site_grant(case))

    opened = _open(database, case, second.context)
    assert isinstance(opened, Ok), opened


def test_another_tenants_current_snapshot_is_not_this_tenants(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """Freshness is per tenant, and the row it reads is this tenant's row.

    Two tenants publish independently.  A case in one may not open under the
    other's current snapshot, even though that snapshot is perfectly current
    somewhere -- "in force" is not a global fact.
    """
    mine = ravi.ravi(tenant_id, case_id, attested=True)
    A.publish(database, tenant_id, grants=mine.authority_snapshot.grants)

    theirs = ravi.ravi(f"{tenant_id}-other", case_id, attested=True)
    elsewhere = A.publish(database, theirs.tenant_id, grants=theirs.authority_snapshot.grants)

    borrowed = replace(
        mine.authorization_context,
        authority_registry_snapshot_digest=elsewhere.snapshot.digest(),
    )
    opened = _open(database, mine, borrowed)
    assert isinstance(opened, Err), opened
    assert opened.error.failure is OpenFailure.AUTHORITY_NOT_IN_FORCE


def test_the_freshness_check_is_not_satisfied_by_a_caller_chosen_instant(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """No ``as_of`` a caller can pick makes a superseded snapshot current.

    The rule is equality with a published digest, so there is no number to
    choose.  Asserted rather than assumed, because "freshness" is exactly the
    kind of rule that gets implemented against a timestamp the attacker
    supplies -- and a caller who could open a stale case by claiming an earlier
    ``as_of`` would have the whole attack back.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    first = A.publish(database, tenant_id, grants=case.authority_snapshot.grants)
    A.publish(database, tenant_id, grants=_without_the_site_grant(case))

    stale = replace(
        case.authorization_context,
        authority_registry_snapshot_digest=first.snapshot.digest(),
        revocation_snapshot_digest=first.revocation.digest(),
    )
    work = ravi.casework(database)
    for as_of in (case.as_of, case.as_of - 10_000_000, case.as_of + 10_000_000):
        opened = open_case(
            work,
            tenant_id=case.tenant_id,
            construction=case.construction,
            authorization_context=stale,
            policy_id=case.policy_id,
            as_of=as_of,
        )
        assert isinstance(opened, Err), (as_of, opened)
        assert opened.error.failure is OpenFailure.AUTHORITY_NOT_IN_FORCE
