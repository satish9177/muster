"""Revocation and admission have an order, and the order is forced, not hoped for.

The race this file exists to close, as read-committed permits it:

    T1  admission starts
    T1  reads the revocation state -- key K is not revoked
    T2  publishes revocation(K)
    T2  COMMIT
    T1  continues
    T1  COMMIT -- the receipt is durable

Nothing in that schedule conflicts.  T1 inserts a transcript row and reads the
revocation table; T2 inserts a revocation row.  Two different tables, two
different rows, no lock taken by either, so PostgreSQL is entirely correct to
let both commit -- and the result is an attestation that became durable *after*
its key's revocation became durable.  Calling that "just read-committed" would
be true and would also be the end of the argument, which is why it is not the
answer here.

**The rule, stated once.**

    If revocation publication linearizes before receipt admission, that receipt
    cannot establish a new fact under the revoked key.

Equivalently: concurrent admission and revocation have a single explainable
winner, and which one won is a fact about the schedule rather than about the
weather.

**The mechanism.**  One row per tenant, ``authority.publication_state``.
Admission takes it ``FOR SHARE`` at the top of its transaction; a publisher
takes it exclusively.  Share locks do not conflict with one another, so
concurrent admissions never wait -- the cost is paid only against publication,
which is rare.  There is no global serialization, no advisory lock namespace to
get wrong, and nothing held across a solver: the lock lives exactly as long as
the admission transaction, which is bounded by one rebuild.

**What the tests below actually force.**  Not "start two threads and hope".
The admitting thread is stopped *inside* its transaction at the exact instant
that matters -- after it has read the old revocation state and before it
commits -- by a hook on the repository call that reads it.  The revocation is
then attempted from another thread and observed to **block**, which is the
observable form of the claim: if it did not block, the dangerous schedule would
be available.  Only then is the admission released.

The hook is not a mock.  It wraps the production repository and forwards every
call to it; what it adds is a pause after the read returns.  Every statement
executed here is a statement production executes.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Any

import pytest

from muster.core.authority.revocation import RevocationSnapshot
from muster.core.evidence.transcript import entry_digest
from muster.core.results import Err, Ok
from muster.core.wire.digests import Digest
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.authority.publish import (
    AuthorityPublisher,
    publish_revocation_snapshot,
)
from muster.platform.casework.commands import (
    AppendFailure,
    append_transcript_entry,
    open_case,
)
from muster.platform.casework.ports import (
    AuthorityRepository,
    CaseworkDatabase,
    Publication,
    TenantScope,
)
from support import authority as A
from support import ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

SATURDAY_PRESENCE = 18

#  Long enough that a slow machine is not mistaken for a lock, short enough
#  that a genuine deadlock fails rather than hangs the suite.
BLOCKED_FOR = 1.5
RELEASE_TIMEOUT = 60.0


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


#  ---- the hook ------------------------------------------------------------


@dataclass
class _PausingAuthority:
    """The production repository, plus a pause after the revocation read.

    Every method forwards.  ``revocations`` is the one that matters: it is what
    ``published_revocations`` calls, so returning from it is the exact instant
    at which "the admission has read the old revocation state" becomes true.
    """

    inner: AuthorityRepository
    after_revocations: Any

    def publish_authority(self, publication: Publication) -> Any:
        return self.inner.publish_authority(publication)

    def read_authority(self, snapshot_digest: Digest) -> Any:
        return self.inner.read_authority(snapshot_digest)

    def publish_revocation(self, publication: Publication) -> Any:
        return self.inner.publish_revocation(publication)

    def read_revocation(self, snapshot_digest: Digest) -> Any:
        return self.inner.read_revocation(snapshot_digest)

    def in_force_authority(self) -> Any:
        return self.inner.in_force_authority()

    def hold_publication_state(self) -> Any:
        return self.inner.hold_publication_state()

    def set_in_force_authority(self, snapshot_digest: Digest) -> Any:
        return self.inner.set_in_force_authority(snapshot_digest)

    def set_in_force_revocation(self, snapshot_digest: Digest) -> Any:
        return self.inner.set_in_force_revocation(snapshot_digest)

    def revocations(self) -> Any:
        found = self.inner.revocations()
        self.after_revocations()
        return found


@dataclass
class _PausingScope:
    inner: TenantScope
    after_revocations: Any

    @property
    def tenant_id(self) -> str:
        return self.inner.tenant_id

    @property
    def content(self) -> Any:
        return self.inner.content

    @property
    def transcript(self) -> Any:
        return self.inner.transcript

    @property
    def heads(self) -> Any:
        return self.inner.heads

    @property
    def requests(self) -> Any:
        return self.inner.requests

    @property
    def commitments(self) -> Any:
        return self.inner.commitments

    @property
    def catalog(self) -> Any:
        return self.inner.catalog

    @property
    def authority(self) -> Any:
        return _PausingAuthority(self.inner.authority, self.after_revocations)


@dataclass
class _PausingDatabase:
    """A real database whose write transactions pause where a test says to.

    Only the *first* write transaction pauses.  An admission opens two -- the
    one that admits and the one that publishes the advance -- and pausing both
    would stop the test somewhere it is not asking about.
    """

    inner: CaseworkDatabase
    after_revocations: Any
    writes: int = 0

    def writing(self, tenant_id: str) -> AbstractContextManager[TenantScope]:
        self.writes += 1
        paused = self.writes == 1
        return self._scoped(tenant_id, paused=paused)

    def reading(self, tenant_id: str) -> AbstractContextManager[TenantScope]:
        return self.inner.reading(tenant_id)

    @contextmanager
    def _scoped(self, tenant_id: str, *, paused: bool) -> Iterator[TenantScope]:
        with self.inner.writing(tenant_id) as scope:
            if not paused:
                yield scope
            else:
                yield _PausingScope(scope, self.after_revocations)  # type: ignore[arg-type]


#  ---- fixtures ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Opened:
    case: RaviCase
    publisher: AuthorityPublisher


def _opened(database: SqlDatabase, tenant_id: str, case_id: str) -> Opened:
    case = ravi.ravi(tenant_id, case_id, attested=True)
    published = A.publish(database, tenant_id, grants=case.authority_snapshot.grants)
    bound = _repinned(case, published)
    work = ravi.casework(database)
    head = open_case(
        work,
        tenant_id=bound.tenant_id,
        construction=bound.construction,
        authorization_context=bound.authorization_context,
        policy_id=bound.policy_id,
        as_of=bound.as_of,
    )
    assert isinstance(head, Ok), head
    return Opened(
        bound,
        AuthorityPublisher(
            database=database,
            signer=A.publisher_signer(A.AUTHORITY_PUBLISHER_KEY),
            verifier=A.publisher_verifier(),
        ),
    )


def _repinned(case: RaviCase, published: Any) -> RaviCase:
    from dataclasses import replace

    return replace(
        case,
        authority_snapshot=published.snapshot,
        revocation_snapshot=published.revocation,
        authorization_context=published.context,
    )


def _site_key(case: RaviCase) -> str:
    entry = case.entries[SATURDAY_PRESENCE]
    return str(entry.receipt.payload.signer_key_ref)  # type: ignore[union-attr]


def _revoking(case: RaviCase) -> RevocationSnapshot:
    """A successor revocation snapshot withdrawing the site key."""
    return A.revocation(case.tenant_id, (_site_key(case),), published_at=A.PUBLISHED_AT + 1)


#  ---- the forced interleaving --------------------------------------------


def test_REVOCATION_PUBLICATION_AND_ADMISSION_HAVE_DEFINED_ORDER(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The ratified regression, with the dangerous schedule forced.

    The admitting thread is held *inside* its transaction, after it has read a
    revocation state in which the key is not revoked.  The revocation is then
    published from another thread.

    Two assertions, and the first is the one that makes this a test of the
    mechanism rather than of the outcome:

    1. while the admission is held, the revocation **cannot commit**.  If it
       could, the schedule at the top of this file would be available and the
       receipt would become durable after the revocation did;
    2. once the admission is released, both complete, and the order is the one
       the locks imposed: the admission first, then the revocation.
    """
    opened = _opened(database, tenant_id, case_id)
    case = opened.case

    reached = threading.Event()
    release = threading.Event()

    def pause() -> None:
        reached.set()
        assert release.wait(timeout=RELEASE_TIMEOUT), "the admission was never released"

    paused = _PausingDatabase(database, pause)
    work = ravi.casework(paused)  # type: ignore[arg-type]

    admission: dict[str, Any] = {}

    def admit() -> None:
        admission["outcome"] = append_transcript_entry(
            work,
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            entry=case.entries[SATURDAY_PRESENCE],
            now=ravi.NOW,
        )

    revocation: dict[str, Any] = {}

    def revoke() -> None:
        revocation["outcome"] = publish_revocation_snapshot(
            opened.publisher,
            tenant_id=case.tenant_id,
            snapshot=_revoking(case),
            now=ravi.NOW,
        )

    admitting = threading.Thread(target=admit, name="admitting")
    admitting.start()
    assert reached.wait(timeout=RELEASE_TIMEOUT), "the admission never read revocation state"

    #  The admission is now inside its transaction, holding the publication
    #  state in share mode, having read a revocation state that does not name
    #  the key.  This is the top of the file, exactly.
    revoking = threading.Thread(target=revoke, name="revoking")
    revoking.start()

    #  **The load-bearing assertion.**  The revocation cannot get through while
    #  the admission holds the row.  A test that skipped this and only compared
    #  the end state would pass on a machine where the threads happened not to
    #  overlap, which is the failure mode the whole file is written against.
    revoking.join(timeout=BLOCKED_FOR)
    assert revoking.is_alive(), (
        "the revocation committed while an admission held the publication state: "
        "the two are not linearized"
    )
    assert "outcome" not in revocation

    release.set()
    admitting.join(timeout=RELEASE_TIMEOUT)
    revoking.join(timeout=RELEASE_TIMEOUT)
    assert not admitting.is_alive() and not revoking.is_alive(), "a thread deadlocked"

    #  Both succeeded, and the order is decided: the admission linearized first,
    #  so its receipt stands and the revocation applies to everything after it.
    assert isinstance(admission["outcome"], Ok), admission["outcome"]
    assert isinstance(revocation["outcome"], Ok), revocation["outcome"]

    with database.reading(tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members
    assert entry_digest(case.entries[SATURDAY_PRESENCE]) in set(members.value)


def test_a_revocation_that_linearizes_first_refuses_the_later_admission(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The other order, and the half that carries the security property.

    The rule is not "the admission always wins".  It is that there is one
    winner and it is decided by the order the two linearize in.  Here the
    revocation commits first, and the admission that follows -- the same
    receipt, the same key, the same case -- is refused.
    """
    opened = _opened(database, tenant_id, case_id)
    case = opened.case

    published = publish_revocation_snapshot(
        opened.publisher,
        tenant_id=case.tenant_id,
        snapshot=_revoking(case),
        now=ravi.NOW,
    )
    assert isinstance(published, Ok), published

    outcome = append_transcript_entry(
        ravi.casework(database),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=case.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is AppendFailure.ADMISSION_REFUSED
    assert "KEY_WITHDRAWN" in outcome.error.detail

    with database.reading(tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members
    assert entry_digest(case.entries[SATURDAY_PRESENCE]) not in set(members.value)


def test_the_epoch_records_which_authority_state_each_side_saw(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The ordering is observable, not merely asserted.

    A lock whose effect cannot be seen is a lock nobody can test.  The epoch is
    what makes "this admission was judged against the authority state before
    the revocation" a statement with a number in it.
    """
    opened = _opened(database, tenant_id, case_id)
    case = opened.case

    #  Observed through a *writing* scope, because the hold is a ``SELECT FOR
    #  SHARE`` and PostgreSQL refuses row locks in a read-only transaction.
    #  That refusal is itself worth knowing: the only way to read this state is
    #  to take the lock, so there is no unlocked read of it for a future caller
    #  to reach for.
    with database.writing(tenant_id) as scope:
        before = scope.authority.hold_publication_state()
    assert isinstance(before, Ok), before

    published = publish_revocation_snapshot(
        opened.publisher,
        tenant_id=case.tenant_id,
        snapshot=_revoking(case),
        now=ravi.NOW,
    )
    assert isinstance(published, Ok), published

    with database.writing(tenant_id) as scope:
        after = scope.authority.hold_publication_state()
    assert isinstance(after, Ok), after
    assert after.value.epoch == before.value.epoch + 1
    #  And the registry in force did not move: a revocation withdraws keys, it
    #  does not replace the registry.
    assert after.value.in_force_authority_digest == before.value.in_force_authority_digest


#  ---- the cost of the mechanism, bounded ---------------------------------


def test_two_concurrent_admissions_do_not_wait_for_each_other(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """Share mode, demonstrated: the lock is not a global admission bottleneck.

    Two admissions in two different cases run at once, and the first is held
    inside its transaction while the second runs to completion.  If the hold
    were exclusive the second would block behind it and this would hang.
    """
    first = _opened(database, tenant_id, f"{case_id}-a")
    second_case = ravi.ravi(tenant_id, f"{case_id}-b", attested=True)
    second_case = _repinned(
        second_case,
        _PublishedLike(
            first.case.authority_snapshot,
            first.case.revocation_snapshot,
            first.case.authorization_context,
        ),
    )
    head = open_case(
        ravi.casework(database),
        tenant_id=second_case.tenant_id,
        construction=second_case.construction,
        authorization_context=second_case.authorization_context,
        policy_id=second_case.policy_id,
        as_of=second_case.as_of,
    )
    assert isinstance(head, Ok), head

    reached = threading.Event()
    release = threading.Event()

    def pause() -> None:
        reached.set()
        assert release.wait(timeout=RELEASE_TIMEOUT), "never released"

    held = _PausingDatabase(database, pause)
    outcomes: dict[str, Any] = {}

    def admit_first() -> None:
        outcomes["first"] = append_transcript_entry(
            ravi.casework(held),  # type: ignore[arg-type]
            tenant_id=first.case.tenant_id,
            case_id=first.case.case_id,
            entry=first.case.entries[SATURDAY_PRESENCE],
            now=ravi.NOW,
        )

    holder = threading.Thread(target=admit_first, name="held-admission")
    holder.start()
    assert reached.wait(timeout=RELEASE_TIMEOUT), "the first admission never paused"

    #  The second admission runs while the first holds the row.  No timeout, no
    #  retry: if share locks conflicted this would simply never return.
    outcomes["second"] = append_transcript_entry(
        ravi.casework(database),
        tenant_id=second_case.tenant_id,
        case_id=second_case.case_id,
        entry=second_case.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(outcomes["second"], Ok), outcomes["second"]

    release.set()
    holder.join(timeout=RELEASE_TIMEOUT)
    assert not holder.is_alive(), "the held admission deadlocked"
    assert isinstance(outcomes["first"], Ok), outcomes["first"]


def test_an_unrelated_tenants_revocation_is_not_blocked(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The lock is one tuple wide, and tenants are independent.

    A held admission in tenant A must not delay a revocation in tenant B.  The
    row is keyed by tenant, so this is a statement about the schema rather than
    about the code -- which is exactly why it is worth asserting: a later change
    to a table-level lock or an advisory key that dropped the tenant would pass
    every other test in this file.
    """
    mine = _opened(database, tenant_id, case_id)
    other_tenant = f"{tenant_id}-other"
    theirs = _opened(SqlDatabase(migrated_dsn), other_tenant, case_id)

    reached = threading.Event()
    release = threading.Event()

    def pause() -> None:
        reached.set()
        assert release.wait(timeout=RELEASE_TIMEOUT), "never released"

    held = _PausingDatabase(database, pause)

    def admit() -> None:
        append_transcript_entry(
            ravi.casework(held),  # type: ignore[arg-type]
            tenant_id=mine.case.tenant_id,
            case_id=mine.case.case_id,
            entry=mine.case.entries[SATURDAY_PRESENCE],
            now=ravi.NOW,
        )

    holder = threading.Thread(target=admit, name="held-admission")
    holder.start()
    assert reached.wait(timeout=RELEASE_TIMEOUT), "the admission never paused"

    #  Tenant B's publisher, while tenant A's admission holds tenant A's row.
    published = publish_revocation_snapshot(
        theirs.publisher,
        tenant_id=theirs.case.tenant_id,
        snapshot=_revoking(theirs.case),
        now=ravi.NOW,
    )
    assert isinstance(published, Ok), published

    release.set()
    holder.join(timeout=RELEASE_TIMEOUT)
    assert not holder.is_alive(), "the held admission deadlocked"


@dataclass(frozen=True, slots=True)
class _PublishedLike:
    snapshot: Any
    revocation: Any
    context: Any
