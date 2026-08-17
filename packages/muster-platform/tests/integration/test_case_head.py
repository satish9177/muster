"""The case head and its compare-and-swap, against real PostgreSQL.

The swap is tested here in isolation from the analysis that normally produces
its arguments, because the two failure modes are different: this file is about
whether the *statement* is correct under contention, and the concurrency file
is about whether the loop around it is.

Arbitrary digests are used for the revision and certificate. Nothing checks
them -- there is deliberately no foreign key, because a revision is a cache and
pruning it must stay possible -- so using real ones here would test the
pipeline a second time and hide which layer failed.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.core.case.revision import RebuildInputs, RebuildMode
from muster.core.results import Err, Ok
from muster.core.wire.digests import Digest, DigestKind
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import Casework
from muster.platform.casework.ports import CaseHead, HeadFailure
from support import ravi
from support.fixtures import open_ravi

pytestmark = pytest.mark.postgres


def _digest(seed: int) -> Digest:
    return Digest(bytes([seed]) * 32)


def _with_digest(inputs: RebuildInputs, field: str, digest: Digest) -> RebuildInputs:
    """One digest-valued rebuild input, replaced by name.

    Spelled out rather than passed through ``**{field: ...}`` so that the type
    checker still sees which field is being written -- a parametrised drift
    test should not cost the guarantee that the drift is well-typed.
    """
    match field:
        case "construction_digest":
            return replace(inputs, construction_digest=digest)
        case "bundle_manifest_digest":
            return replace(inputs, bundle_manifest_digest=digest)
        case "authorization_context_digest":
            return replace(inputs, authorization_context_digest=digest)
        case "transcript_prefix_digest":
            return replace(inputs, transcript_prefix_digest=digest)
        case _:
            raise AssertionError(f"{field} is not a digest-valued rebuild input")


def _stored_prefix(database: SqlDatabase, tenant_id: str, seed: int) -> Digest:
    """A prefix digest the head is allowed to name, because its octets exist.

    The head's foreign key insists on this, and the insistence is the point: a
    head naming a prefix nobody stored is a revision nobody can replay.
    """
    with database.writing(tenant_id) as scope:
        stored = scope.content.put(DigestKind.TRANSCRIPT_PREFIX, b"prefix-" + bytes([seed]))
    assert isinstance(stored, Ok), stored
    return stored.value


@pytest.fixture
def casework(database: SqlDatabase) -> Casework:
    return ravi.casework(database)


@pytest.fixture
def head(casework: Casework, tenant_id: str, case_id: str) -> CaseHead:
    return open_ravi(casework, ravi.ravi(tenant_id, case_id))


def test_an_opened_case_has_no_revision_and_is_revision_zero(head: CaseHead) -> None:
    """ "Opened and never analysed" is a state, not a placeholder for one."""
    assert head.revision_digest is None
    assert head.certificate_digest is None
    assert head.revision_number == 0
    assert head.inputs.mode is RebuildMode.OPERATIONAL


def test_opening_the_same_case_twice_with_the_same_inputs_is_idempotent(
    casework: Casework, tenant_id: str, case_id: str
) -> None:
    case = ravi.ravi(tenant_id, case_id)
    first = open_ravi(casework, case)
    second = open_ravi(casework, case)
    assert first == second


def test_opening_the_same_case_id_with_different_inputs_is_refused(
    casework: Casework, tenant_id: str, case_id: str, database: SqlDatabase
) -> None:
    """Two officers opening "the same case" under different pins are opening two.

    Returning the first silently would answer the second caller's request with
    somebody else's case.
    """
    case = ravi.ravi(tenant_id, case_id)
    open_ravi(casework, case)

    with database.writing(tenant_id) as scope:
        head = scope.heads.read(case_id)
        assert isinstance(head, Ok), head
        moved = scope.heads.open(replace(head.value.inputs, as_of=head.value.inputs.as_of + 1))
    assert isinstance(moved, Err)
    assert moved.error.failure is HeadFailure.CASE_ALREADY_OPEN


def test_a_counterfactual_head_is_refused_by_the_repository(
    tenant_id: str, case_id: str, database: SqlDatabase, head: CaseHead
) -> None:
    """A counterfactual rebuild answers a question; it is not a case state.

    ``open_case`` has no ``mode`` parameter at all, so this is unreachable
    through the command. The repository refuses it anyway, and so does a column
    constraint -- three layers, because "simulate persists nothing" is a rule
    about money.
    """
    with database.writing(tenant_id) as scope:
        refused = scope.heads.open(
            replace(head.inputs, case_id=f"{case_id}-cf", mode=RebuildMode.COUNTERFACTUAL)
        )
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.MODE_NOT_PUBLISHABLE


def test_the_first_swap_moves_the_head_off_none(
    database: SqlDatabase, tenant_id: str, head: CaseHead
) -> None:
    with database.writing(tenant_id) as scope:
        advanced = scope.heads.advance(
            parent=head,
            prefix_digest=head.inputs.transcript_prefix_digest,
            revision_digest=_digest(1),
            certificate_digest=_digest(2),
        )
    assert isinstance(advanced, Ok), advanced
    assert advanced.value.revision_number == 1
    assert advanced.value.revision_digest == _digest(1)

    with database.reading(tenant_id) as scope:
        read = scope.heads.read(head.case_id)
    assert isinstance(read, Ok)
    assert read.value == advanced.value


def test_a_swap_from_a_parent_that_is_no_longer_the_head_matches_nothing(
    database: SqlDatabase, tenant_id: str, head: CaseHead
) -> None:
    """The lost-update guard, stated at its smallest.

    Two computations from one parent. The first publishes; the second is told
    it matched no row rather than silently replacing the winner.
    """
    with database.writing(tenant_id) as scope:
        winner = scope.heads.advance(
            parent=head,
            prefix_digest=head.inputs.transcript_prefix_digest,
            revision_digest=_digest(1),
            certificate_digest=_digest(2),
        )
    assert isinstance(winner, Ok), winner

    with database.writing(tenant_id) as scope:
        loser = scope.heads.advance(
            parent=head,  # the same stale parent
            prefix_digest=head.inputs.transcript_prefix_digest,
            revision_digest=_digest(3),
            certificate_digest=_digest(4),
        )
    assert isinstance(loser, Err)
    assert loser.error.failure is HeadFailure.HEAD_MOVED

    with database.reading(tenant_id) as scope:
        read = scope.heads.read(head.case_id)
    assert isinstance(read, Ok)
    assert read.value.revision_digest == _digest(1)
    assert read.value.revision_number == 1


def test_a_stale_revision_number_alone_defeats_the_swap(
    database: SqlDatabase, tenant_id: str, head: CaseHead
) -> None:
    """The ABA guard.

    The revision digest is in the predicate and so is the monotone revision
    number. A writer holding a parent whose digest happens to match the current
    head, but whose number does not, is a writer whose computation began before
    the head moved -- and it cannot publish.
    """
    with database.writing(tenant_id) as scope:
        first = scope.heads.advance(
            parent=head,
            prefix_digest=head.inputs.transcript_prefix_digest,
            revision_digest=_digest(1),
            certificate_digest=_digest(2),
        )
    assert isinstance(first, Ok), first

    #  Same revision digest, a number one behind: an ABA writer.
    forged = replace(first.value, revision_number=first.value.revision_number - 1)
    with database.writing(tenant_id) as scope:
        refused = scope.heads.advance(
            parent=forged,
            prefix_digest=head.inputs.transcript_prefix_digest,
            revision_digest=_digest(9),
            certificate_digest=_digest(9),
        )
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.HEAD_MOVED


@pytest.mark.parametrize(
    "field",
    [
        "construction_digest",
        "bundle_manifest_digest",
        "authorization_context_digest",
        "transcript_prefix_digest",
    ],
)
def test_a_swap_whose_pinned_inputs_do_not_match_the_head_matches_nothing(
    database: SqlDatabase, tenant_id: str, head: CaseHead, field: str
) -> None:
    """Analysing under one pin cannot publish onto a head carrying another.

    The whole parent state is in the predicate, not only the revision digest,
    so a computation that ran against a different policy pin, a different
    authorization context or a different transcript prefix lands nowhere.
    """
    drifted = replace(head, inputs=_with_digest(head.inputs, field, _digest(0xEE)))
    with database.writing(tenant_id) as scope:
        refused = scope.heads.advance(
            parent=drifted,
            prefix_digest=_digest(5),
            revision_digest=_digest(6),
            certificate_digest=_digest(7),
        )
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.HEAD_MOVED


def test_a_swap_under_a_drifted_as_of_matches_nothing(
    database: SqlDatabase, tenant_id: str, head: CaseHead
) -> None:
    drifted = replace(head, inputs=replace(head.inputs, as_of=head.inputs.as_of + 1))
    with database.writing(tenant_id) as scope:
        refused = scope.heads.advance(
            parent=drifted,
            prefix_digest=_digest(5),
            revision_digest=_digest(6),
            certificate_digest=_digest(7),
        )
    assert isinstance(refused, Err)
    assert refused.error.failure is HeadFailure.HEAD_MOVED


def test_a_swap_changes_the_transcript_prefix_and_nothing_else_pinned(
    database: SqlDatabase, tenant_id: str, head: CaseHead
) -> None:
    """A repin is not something advancing a case can do by accident.

    Every other rebuild input on the returned head is copied from the parent,
    because the statement copies them from the parent rather than taking them
    from the caller.
    """
    prefix = _stored_prefix(database, tenant_id, 0x42)
    with database.writing(tenant_id) as scope:
        advanced = scope.heads.advance(
            parent=head,
            prefix_digest=prefix,
            revision_digest=_digest(1),
            certificate_digest=_digest(2),
        )
    assert isinstance(advanced, Ok), advanced
    after = advanced.value.inputs
    before = head.inputs
    assert after.transcript_prefix_digest == prefix
    assert after.construction_digest == before.construction_digest
    assert after.bundle_manifest_digest == before.bundle_manifest_digest
    assert after.authorization_context_digest == before.authorization_context_digest
    assert after.as_of == before.as_of
    assert after.mode == before.mode


def test_the_revision_number_advances_by_exactly_one_each_time(
    database: SqlDatabase, tenant_id: str, head: CaseHead
) -> None:
    current = head
    for step in range(1, 5):
        prefix = _stored_prefix(database, tenant_id, 0x10 + step)
        with database.writing(tenant_id) as scope:
            advanced = scope.heads.advance(
                parent=current,
                prefix_digest=prefix,
                revision_digest=_digest(0x20 + step),
                certificate_digest=_digest(0x30 + step),
            )
        assert isinstance(advanced, Ok), advanced
        assert advanced.value.revision_number == step
        current = advanced.value


def test_a_head_may_not_name_a_prefix_whose_octets_are_absent(
    database: SqlDatabase, tenant_id: str, head: CaseHead
) -> None:
    """Refused as a value, not as an exception that abandons the transaction.

    A head naming a prefix nobody stored is a revision nobody can replay, so
    the database refuses it -- and the repository turns that refusal into a
    typed failure inside a savepoint, leaving the caller's transaction usable.
    """
    with database.writing(tenant_id) as scope:
        refused = scope.heads.advance(
            parent=head,
            prefix_digest=_digest(0xAB),
            revision_digest=_digest(1),
            certificate_digest=_digest(2),
        )
        assert isinstance(refused, Err)
        assert refused.error.failure is HeadFailure.PREFIX_NOT_STORED
        #  The transaction survived the refusal: this read would fail if the
        #  constraint violation had aborted it.
        still_usable = scope.heads.read(head.case_id)
        assert isinstance(still_usable, Ok)
        assert still_usable.value.revision_digest is None


def test_reading_an_unopened_case_is_a_typed_absence(database: SqlDatabase, tenant_id: str) -> None:
    with database.reading(tenant_id) as scope:
        read = scope.heads.read("no-such-case")
    assert isinstance(read, Err)
    assert read.error.failure is HeadFailure.UNKNOWN_CASE
