"""The custody protocols, asserted of every adapter that claims to implement them.

Each test here runs twice: once against PostgreSQL and once against the
in-memory records.  That is the whole point of the file.  Two implementations
of one set of protocols will drift the moment nothing is comparing them, and
the drift is always in the same direction -- the fast one grows a semantics
that is easier to implement, the tests that use it start passing for the wrong
reason, and the difference is discovered in production.

**What is in scope here is exactly what both substrates genuinely share.**
Insert-if-absent, digest collision, membership as a set, the ordering the
prefix depends on, compare-and-swap against the whole parent state, which
refusal a rejection is called, commit-or-discard.  Those are properties of the
*port*, and an adapter that gets one of them wrong is wrong.

**What is deliberately not here is anything about concurrency.**  The memory
adapter serialises writers with a lock, so a contended compare-and-swap in this
file would be a test of a mutex.  Contention, isolation, visibility and
recovery are claims about PostgreSQL, they are tested in ``tests/integration``
and ``tests/adversarial`` against a real one, and running them against a
dictionary would produce a green result for a property nobody checked.

Two further divergences are stated rather than asserted, because they belong to
the substrate:

* ``StoreFailure.CONTENT_NOT_VISIBLE`` is an MVCC outcome and is unreachable in
  memory;
* corrupt stored octets can only be produced by going around the port, which is
  raw SQL in one case and ``MemoryDatabase.records`` in the other. Both
  adapters re-derive the digest on every read; each suite produces the state
  its own substrate allows.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, replace

import pytest

from muster.core.case.revision import RebuildInputs, RebuildMode
from muster.core.results import Err, InvariantViolation, Ok
from muster.core.wire.digests import Digest, DigestKind
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.schema import migrate
from muster.platform.casework.ports import (
    CaseHead,
    CaseworkDatabase,
    HeadFailure,
    RecordedRequest,
    RequestFailure,
    StoreFailure,
    TranscriptFailure,
)

#  ---- the two adapters, behind one fixture ---------------------------------

ADAPTERS = ("memory", "postgres")


@dataclass(frozen=True, slots=True)
class Custody:
    """A database and a tenant nothing else in the suite uses."""

    database: CaseworkDatabase
    tenant_id: str
    name: str


@pytest.fixture(params=ADAPTERS, ids=ADAPTERS)
def custody(request: pytest.FixtureRequest, tenant_id: str) -> Iterator[Custody]:
    """One test, run against each adapter that claims to satisfy the protocols.

    The PostgreSQL parameter skips without a DSN, exactly as the rest of the
    suite does; the memory parameter always runs, so a contract violation in
    the shared logic is caught even on a machine with no database.
    """
    if request.param == "memory":
        yield Custody(MemoryDatabase(), tenant_id, "memory")
        return

    dsn = os.environ.get("MUSTER_TEST_DSN")
    if not dsn:
        pytest.skip("needs a real PostgreSQL instance: set MUSTER_TEST_DSN")
    migrate(dsn)
    yield Custody(SqlDatabase(dsn), tenant_id, "postgres")


#  ---- helpers, written against the protocols and nothing below them --------


def _put(custody: Custody, kind: DigestKind, octets: bytes) -> Digest:
    with custody.database.writing(custody.tenant_id) as scope:
        stored = scope.content.put(kind, octets)
    assert isinstance(stored, Ok), stored
    return stored.value


def _inputs(custody: Custody, case_id: str, *, seed: bytes = b"") -> RebuildInputs:
    """Rebuild inputs whose three pinned artifacts really are in the store.

    Arbitrary octets, because no adapter decodes them -- what both enforce is
    that the head cannot name an artifact the store does not hold.
    """
    return RebuildInputs(
        tenant_id=custody.tenant_id,
        case_id=case_id,
        construction_digest=_put(custody, DigestKind.CASE_CONSTRUCTION, b"construction" + seed),
        transcript_prefix_digest=_put(custody, DigestKind.TRANSCRIPT_PREFIX, b"prefix" + seed),
        bundle_manifest_digest=Digest(b"\x11" * 32),
        as_of=1_760_000_000_000_000,
        mode=RebuildMode.OPERATIONAL,
        authorization_context_digest=_put(
            custody, DigestKind.AUTHORIZATION_CONTEXT, b"context" + seed
        ),
    )


def _open(custody: Custody, case_id: str, *, seed: bytes = b"") -> CaseHead:
    #  The artifacts are stored in their own transactions, which commit, before
    #  the one that opens the case begins. Building them inside it would nest a
    #  writing transaction inside another -- which the memory adapter refuses by
    #  name, and which against PostgreSQL would quietly take a second connection.
    inputs = _inputs(custody, case_id, seed=seed)
    with custody.database.writing(custody.tenant_id) as scope:
        opened = scope.heads.open(inputs)
    assert isinstance(opened, Ok), opened
    return opened.value


def _entry(custody: Custody, octets: bytes) -> Digest:
    return _put(custody, DigestKind.TRANSCRIPT_ENTRY, octets)


#  ---- content store --------------------------------------------------------


def test_the_store_derives_the_key_from_the_octets(custody: Custody) -> None:
    """There is no ``put(digest, octets)``, so a wrong key is unrepresentable."""
    digest = _put(custody, DigestKind.TRANSCRIPT_ENTRY, b"an entry")
    with custody.database.reading(custody.tenant_id) as scope:
        read = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, digest)
    assert isinstance(read, Ok), read
    assert read.value == b"an entry"


def test_storing_the_same_octets_twice_is_one_row_and_one_digest(custody: Custody) -> None:
    first = _put(custody, DigestKind.TRANSCRIPT_ENTRY, b"repeated")
    second = _put(custody, DigestKind.TRANSCRIPT_ENTRY, b"repeated")
    assert first == second


def test_reading_an_absent_digest_is_a_typed_absence(custody: Custody) -> None:
    with custody.database.reading(custody.tenant_id) as scope:
        read = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, Digest(b"\x07" * 32))
    assert isinstance(read, Err)
    assert read.error.failure is StoreFailure.CONTENT_ABSENT


def test_reading_stored_octets_under_another_domain_is_refused(custody: Custody) -> None:
    """The domain is part of the key, so the same octets under two kinds are two
    artifacts -- and asking for one under the other's name is not a near miss."""
    digest = _put(custody, DigestKind.TRANSCRIPT_ENTRY, b"domain separated")
    with custody.database.reading(custody.tenant_id) as scope:
        read = scope.content.get(DigestKind.CASE_REVISION, digest)
    assert isinstance(read, Err)
    assert read.error.failure in {StoreFailure.CONTENT_ABSENT, StoreFailure.CONTENT_CORRUPT}


def test_one_tenants_octets_are_not_another_tenants(custody: Custody) -> None:
    digest = _put(custody, DigestKind.TRANSCRIPT_ENTRY, b"mine")
    with custody.database.reading("tenant-somebody-else") as scope:
        read = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, digest)
    assert isinstance(read, Err)
    assert read.error.failure is StoreFailure.CONTENT_ABSENT


#  ---- transcript membership ------------------------------------------------


def test_membership_needs_a_case(custody: Custody, case_id: str) -> None:
    digest = _entry(custody, b"orphan")
    with custody.database.writing(custody.tenant_id) as scope:
        added = scope.transcript.add(case_id, digest)
    assert isinstance(added, Err)
    assert added.error.failure is TranscriptFailure.UNKNOWN_CASE


def test_membership_needs_the_preimage(custody: Custody, case_id: str) -> None:
    """Membership without octets would make the prefix undecodable."""
    _open(custody, case_id)
    with custody.database.writing(custody.tenant_id) as scope:
        added = scope.transcript.add(case_id, Digest(b"\x09" * 32))
    assert isinstance(added, Err)
    assert added.error.failure is TranscriptFailure.CONTENT_NOT_STORED


def test_adding_the_same_entry_twice_is_one_member(custody: Custody, case_id: str) -> None:
    """What makes at-least-once delivery free, in both adapters."""
    _open(custody, case_id)
    digest = _entry(custody, b"delivered twice")

    with custody.database.writing(custody.tenant_id) as scope:
        first = scope.transcript.add(case_id, digest)
        again = scope.transcript.add(case_id, digest)
    assert isinstance(first, Ok) and first.value is True
    assert isinstance(again, Ok) and again.value is False

    with custody.database.reading(custody.tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members
    assert members.value == (digest,)


def test_members_come_back_ascending_by_digest_octets(custody: Custody, case_id: str) -> None:
    """The prefix is a hash of this list, so the order is part of the contract.

    An adapter that returned insertion order would produce a different prefix
    digest for the same set of entries, and every published head would depend
    on the order the entries happened to arrive in.
    """
    _open(custody, case_id)
    digests = [_entry(custody, f"entry-{index}".encode()) for index in range(6)]
    with custody.database.writing(custody.tenant_id) as scope:
        for digest in reversed(digests):
            assert isinstance(scope.transcript.add(case_id, digest), Ok)

    with custody.database.reading(custody.tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members
    assert members.value == tuple(sorted(digests, key=lambda digest: digest.octets))


def test_the_members_of_an_unknown_case_are_a_refusal_and_not_an_empty_set(
    custody: Custody, case_id: str
) -> None:
    with custody.database.reading(custody.tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Err)
    assert members.error.failure is TranscriptFailure.UNKNOWN_CASE


#  ---- case head ------------------------------------------------------------


def test_an_opened_case_is_revision_zero_with_no_revision(custody: Custody, case_id: str) -> None:
    head = _open(custody, case_id)
    assert head.revision_digest is None
    assert head.certificate_digest is None
    assert head.revision_number == 0


def test_opening_twice_with_the_same_inputs_returns_the_same_head(
    custody: Custody, case_id: str
) -> None:
    first = _open(custody, case_id)
    inputs = first.inputs
    with custody.database.writing(custody.tenant_id) as scope:
        again = scope.heads.open(inputs)
    assert isinstance(again, Ok), again
    assert again.value == first


def test_opening_the_same_identifier_under_a_different_pin_is_refused(
    custody: Custody, case_id: str
) -> None:
    """Two officers opening "the same case" under different pins opened two cases."""
    head = _open(custody, case_id)
    repinned = replace(head.inputs, bundle_manifest_digest=Digest(b"\x22" * 32))
    with custody.database.writing(custody.tenant_id) as scope:
        refused = scope.heads.open(repinned)
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.CASE_ALREADY_OPEN


def test_a_counterfactual_case_cannot_be_opened(custody: Custody, case_id: str) -> None:
    """A counterfactual rebuild answers a question; it is not a state."""
    inputs = replace(_inputs(custody, case_id), mode=RebuildMode.COUNTERFACTUAL)
    with custody.database.writing(custody.tenant_id) as scope:
        refused = scope.heads.open(inputs)
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.MODE_NOT_PUBLISHABLE


def test_a_case_cannot_pin_an_artifact_the_store_does_not_hold(
    custody: Custody, case_id: str
) -> None:
    """It would be unreplayable from the instant it existed."""
    inputs = replace(_inputs(custody, case_id), construction_digest=Digest(b"\x33" * 32))
    with custody.database.writing(custody.tenant_id) as scope:
        refused = scope.heads.open(inputs)
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.INPUTS_NOT_STORED


@pytest.mark.parametrize("as_of", [2**63, -(2**63) - 1, 2**70])
def test_a_case_cannot_be_opened_at_an_instant_no_store_could_hold(
    custody: Custody, case_id: str, as_of: int
) -> None:
    """Both adapters refuse the same instant, and that is the point of asserting it here.

    ``Instant`` is an alias for ``int``, and Python integers are unbounded;
    ``case_head.as_of`` is a ``bigint``. Without the check in the contract, a
    dictionary accepts an instant that PostgreSQL answers with an untyped
    ``NumericValueOutOfRange`` from the driver -- so a case that opens in a unit
    test fails in production, which is exactly the divergence one suite over two
    adapters exists to catch.

    The kernel's ``as_of`` stays unbounded and correctly so: a counterfactual
    rebuild has no column. The bound belongs to the head, which does.
    """
    inputs = replace(_inputs(custody, case_id), as_of=as_of)
    with custody.database.writing(custody.tenant_id) as scope:
        refused = scope.heads.open(inputs)
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.INSTANT_NOT_DURABLE
    assert str(as_of) in refused.error.detail


def test_the_largest_durable_instant_is_accepted_by_both(custody: Custody, case_id: str) -> None:
    """The boundary is inclusive at the top of the signed range, in both adapters."""
    inputs = replace(_inputs(custody, case_id), as_of=2**63 - 1)
    with custody.database.writing(custody.tenant_id) as scope:
        opened = scope.heads.open(inputs)
    assert isinstance(opened, Ok), opened
    assert opened.value.inputs.as_of == 2**63 - 1


def test_reading_an_unopened_case_is_a_typed_absence(custody: Custody, case_id: str) -> None:
    with custody.database.reading(custody.tenant_id) as scope:
        read = scope.heads.read(case_id)
    assert isinstance(read, Err)
    assert read.error.failure is HeadFailure.UNKNOWN_CASE


def test_holding_a_case_returns_the_head_it_holds(custody: Custody, case_id: str) -> None:
    """The value is ``read``'s. The guarantee is not, and only one adapter proves it.

    What is shared, and therefore what belongs here, is that ``hold`` answers
    with the same head ``read`` does and refuses an unknown case the same way.
    That it actually excludes a concurrent writer is a claim about PostgreSQL
    row locks -- the memory adapter satisfies it by making every writing
    transaction exclusive, which is coarser than the contract rather than
    evidence for it -- and it is tested against a real instance in
    ``tests/integration/test_admission_rollback.py``.
    """
    opened = _open(custody, case_id)
    with custody.database.writing(custody.tenant_id) as scope:
        held = scope.heads.hold(case_id)
        read = scope.heads.read(case_id)
    assert isinstance(held, Ok), held
    assert isinstance(read, Ok), read
    assert held.value == read.value == opened


def test_holding_an_unknown_case_is_the_same_typed_absence_as_reading_one(
    custody: Custody, case_id: str
) -> None:
    with custody.database.writing(custody.tenant_id) as scope:
        held = scope.heads.hold(case_id)
    assert isinstance(held, Err)
    assert held.error.failure is HeadFailure.UNKNOWN_CASE


def test_holding_a_case_twice_in_one_transaction_is_not_a_deadlock(
    custody: Custody, case_id: str
) -> None:
    """A hold is re-entrant within its own transaction, because a lock it took is its own.

    Worth asserting rather than assuming: an implementation that took a lock a
    second transaction would have to wait for would hang here rather than fail,
    and a hang in a suite is the least useful failure there is.
    """
    _open(custody, case_id)
    with custody.database.writing(custody.tenant_id) as scope:
        first = scope.heads.hold(case_id)
        again = scope.heads.hold(case_id)
    assert isinstance(first, Ok), first
    assert isinstance(again, Ok), again
    assert first.value == again.value


def test_a_swap_moves_the_head_and_only_the_prefix(custody: Custody, case_id: str) -> None:
    """The transcript prefix is the only rebuild input an advance may change."""
    parent = _open(custody, case_id)
    prefix = _put(custody, DigestKind.TRANSCRIPT_PREFIX, b"a published prefix")

    with custody.database.writing(custody.tenant_id) as scope:
        advanced = scope.heads.advance(
            parent=parent,
            prefix_digest=prefix,
            revision_digest=Digest(b"\x44" * 32),
            certificate_digest=Digest(b"\x55" * 32),
        )
    assert isinstance(advanced, Ok), advanced
    head = advanced.value
    assert head.revision_number == parent.revision_number + 1
    assert head.revision_digest == Digest(b"\x44" * 32)
    assert head.inputs == replace(parent.inputs, transcript_prefix_digest=prefix)

    with custody.database.reading(custody.tenant_id) as scope:
        read = scope.heads.read(case_id)
    assert isinstance(read, Ok), read
    assert read.value == head


def test_a_second_swap_from_the_same_parent_is_told_the_head_moved(
    custody: Custody, case_id: str
) -> None:
    """The lost-update guard, exercised without needing two writers at once.

    Contention is not what is being checked -- one thread is enough to show
    that the predicate is over the parent state rather than over the case
    identifier. Whether PostgreSQL evaluates it correctly under a *concurrent*
    writer is a claim about PostgreSQL and lives in the concurrency suite.
    """
    parent = _open(custody, case_id)
    first_prefix = _put(custody, DigestKind.TRANSCRIPT_PREFIX, b"first")
    second_prefix = _put(custody, DigestKind.TRANSCRIPT_PREFIX, b"second")

    with custody.database.writing(custody.tenant_id) as scope:
        won = scope.heads.advance(
            parent=parent,
            prefix_digest=first_prefix,
            revision_digest=Digest(b"\x66" * 32),
            certificate_digest=Digest(b"\x77" * 32),
        )
    assert isinstance(won, Ok), won

    with custody.database.writing(custody.tenant_id) as scope:
        lost = scope.heads.advance(
            parent=parent,
            prefix_digest=second_prefix,
            revision_digest=Digest(b"\x88" * 32),
            certificate_digest=Digest(b"\x99" * 32),
        )
    assert isinstance(lost, Err)
    assert lost.error.failure is HeadFailure.HEAD_MOVED


def test_a_swap_whose_parent_carries_a_different_pin_matches_nothing(
    custody: Custody, case_id: str
) -> None:
    """The predicate is the whole parent state, not the revision digest alone.

    A computation that analysed one policy pin cannot land on a head carrying
    another, even when the head is otherwise exactly where it was.
    """
    parent = _open(custody, case_id)
    prefix = _put(custody, DigestKind.TRANSCRIPT_PREFIX, b"under another pin")
    impostor = replace(
        parent, inputs=replace(parent.inputs, bundle_manifest_digest=Digest(b"\xaa" * 32))
    )

    with custody.database.writing(custody.tenant_id) as scope:
        refused = scope.heads.advance(
            parent=impostor,
            prefix_digest=prefix,
            revision_digest=Digest(b"\xbb" * 32),
            certificate_digest=Digest(b"\xcc" * 32),
        )
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.HEAD_MOVED


def test_a_head_cannot_name_a_prefix_the_store_does_not_hold(
    custody: Custody, case_id: str
) -> None:
    parent = _open(custody, case_id)
    with custody.database.writing(custody.tenant_id) as scope:
        refused = scope.heads.advance(
            parent=parent,
            prefix_digest=Digest(b"\xdd" * 32),
            revision_digest=Digest(b"\xee" * 32),
            certificate_digest=Digest(b"\xff" * 32),
        )
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.PREFIX_NOT_STORED


#  ---- evidence requests ----------------------------------------------------


def _request(custody: Custody, case_id: str, revision: Digest, octets: bytes) -> RecordedRequest:
    return RecordedRequest(
        case_id=case_id,
        request_id=_put(custody, DigestKind.EVIDENCE_REQUEST, octets),
        revision_digest=revision,
        deadline=1_760_003_600_000_000,
    )


def _published(custody: Custody, case_id: str, revision: Digest) -> CaseHead:
    parent = _open(custody, case_id)
    prefix = _put(custody, DigestKind.TRANSCRIPT_PREFIX, b"published " + revision.octets[:4])
    with custody.database.writing(custody.tenant_id) as scope:
        advanced = scope.heads.advance(
            parent=parent,
            prefix_digest=prefix,
            revision_digest=revision,
            certificate_digest=Digest(b"\x01" * 32),
        )
    assert isinstance(advanced, Ok), advanced
    return advanced.value


def test_a_request_needs_a_case(custody: Custody, case_id: str) -> None:
    request = _request(custody, case_id, Digest(b"\x02" * 32), b"request-a")
    with custody.database.writing(custody.tenant_id) as scope:
        refused = scope.requests.record(request)
    assert isinstance(refused, Err)
    assert refused.error.failure is RequestFailure.UNKNOWN_CASE


def test_a_request_needs_its_payload_in_the_store(custody: Custody, case_id: str) -> None:
    _published(custody, case_id, Digest(b"\x03" * 32))
    unstored = RecordedRequest(
        case_id=case_id,
        request_id=Digest(b"\x04" * 32),
        revision_digest=Digest(b"\x03" * 32),
        deadline=1,
    )
    with custody.database.writing(custody.tenant_id) as scope:
        refused = scope.requests.record(unstored)
    assert isinstance(refused, Err)
    assert refused.error.failure is RequestFailure.CONTENT_NOT_STORED


def test_recording_the_same_request_twice_creates_one_row(custody: Custody, case_id: str) -> None:
    revision = Digest(b"\x05" * 32)
    _published(custody, case_id, revision)
    request = _request(custody, case_id, revision, b"request-b")

    with custody.database.writing(custody.tenant_id) as scope:
        first = scope.requests.record(request)
        again = scope.requests.record(request)
    assert isinstance(first, Ok) and first.value is True
    assert isinstance(again, Ok) and again.value is False


def test_a_retry_cannot_move_a_deadline_it_did_not_set(custody: Custody, case_id: str) -> None:
    """The deadline is the one field the identity does not cover."""
    revision = Digest(b"\x06" * 32)
    _published(custody, case_id, revision)
    request = _request(custody, case_id, revision, b"request-c")

    with custody.database.writing(custody.tenant_id) as scope:
        assert isinstance(scope.requests.record(request), Ok)
        extended = scope.requests.record(replace(request, deadline=request.deadline * 2))
    assert isinstance(extended, Ok) and extended.value is False

    with custody.database.reading(custody.tenant_id) as scope:
        outstanding = scope.requests.outstanding(case_id)
    assert isinstance(outstanding, Ok), outstanding
    assert outstanding.value == (request,)


def test_one_request_id_naming_two_revisions_is_refused(custody: Custody, case_id: str) -> None:
    """The id is the digest of a record containing the revision. This is corruption."""
    revision = Digest(b"\x0a" * 32)
    _published(custody, case_id, revision)
    request = _request(custody, case_id, revision, b"request-d")

    with custody.database.writing(custody.tenant_id) as scope:
        assert isinstance(scope.requests.record(request), Ok)
        conflicting = scope.requests.record(replace(request, revision_digest=Digest(b"\x0b" * 32)))
    assert isinstance(conflicting, Err)
    assert conflicting.error.failure is RequestFailure.REQUEST_IDENTITY_CONFLICT


def test_a_request_stops_being_outstanding_when_the_head_moves(
    custody: Custody, case_id: str
) -> None:
    """Outstanding is a join, not a column, so there is no window to disagree in."""
    revision = Digest(b"\x0c" * 32)
    head = _published(custody, case_id, revision)
    request = _request(custody, case_id, revision, b"request-e")
    with custody.database.writing(custody.tenant_id) as scope:
        assert isinstance(scope.requests.record(request), Ok)

    with custody.database.reading(custody.tenant_id) as scope:
        before = scope.requests.outstanding(case_id)
    assert isinstance(before, Ok) and before.value == (request,)

    later = _put(custody, DigestKind.TRANSCRIPT_PREFIX, b"a later prefix")
    with custody.database.writing(custody.tenant_id) as scope:
        moved = scope.heads.advance(
            parent=head,
            prefix_digest=later,
            revision_digest=Digest(b"\x0d" * 32),
            certificate_digest=Digest(b"\x0e" * 32),
        )
    assert isinstance(moved, Ok), moved

    with custody.database.reading(custody.tenant_id) as scope:
        after = scope.requests.outstanding(case_id)
    assert isinstance(after, Ok) and after.value == ()


#  ---- transactions ---------------------------------------------------------


class _Injected(RuntimeError):
    """A failure a test caused on purpose."""


def test_an_exception_discards_everything_the_transaction_wrote(
    custody: Custody, case_id: str
) -> None:
    """Commit-or-discard, which is the property every rejection path depends on.

    ``open_case`` and ``append_transcript_entry`` both leave by exception when
    they refuse, precisely so that a rejection writes nothing -- the content
    store has no delete, so a rejection that wrote would be permanent.
    """
    _open(custody, case_id)
    digest = _put(custody, DigestKind.TRANSCRIPT_ENTRY, b"to be rolled back")

    with pytest.raises(_Injected), custody.database.writing(custody.tenant_id) as scope:
        assert isinstance(scope.transcript.add(case_id, digest), Ok)
        raise _Injected("after the membership, before the commit")

    with custody.database.reading(custody.tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members
    assert members.value == ()


def test_a_committed_write_is_visible_to_the_next_transaction(
    custody: Custody, case_id: str
) -> None:
    _open(custody, case_id)
    digest = _put(custody, DigestKind.TRANSCRIPT_ENTRY, b"committed")
    with custody.database.writing(custody.tenant_id) as scope:
        assert isinstance(scope.transcript.add(case_id, digest), Ok)

    with custody.database.reading(custody.tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members
    assert members.value == (digest,)


def test_a_read_only_scope_refuses_to_write(custody: Custody, case_id: str) -> None:
    """Both substrates raise rather than return: the caller asked for the wrong scope.

    PostgreSQL answers ``cannot execute INSERT in a read-only transaction``; the
    memory adapter answers with an ``InvariantViolation``. A typed rejection
    would invite a caller to carry on after asking a read-only transaction to
    change durable state.
    """
    _open(custody, case_id)
    raised: BaseException | None = None
    try:
        with custody.database.reading(custody.tenant_id) as scope:
            scope.content.put(DigestKind.TRANSCRIPT_ENTRY, b"not from here")
    except Exception as error:
        raised = error

    assert raised is not None, "a read-only scope accepted a write"
    #  Two substrates, two exception types, one contract: it raised rather than
    #  returning a rejection the caller could shrug off.
    assert isinstance(raised, InvariantViolation) or type(raised).__module__.startswith("psycopg")


#  ---- the suite is really running twice ------------------------------------


def test_both_adapters_were_exercised(custody: Custody) -> None:
    """A parametrised fixture that silently collapsed to one adapter proves nothing.

    Named as a test so that a skipped PostgreSQL parameter is *reported* as a
    skip rather than disappearing into a suite that still says it ran a
    contract against both.
    """
    assert custody.name in ADAPTERS
    with custody.database.reading(custody.tenant_id) as scope:
        assert scope.tenant_id == custody.tenant_id
