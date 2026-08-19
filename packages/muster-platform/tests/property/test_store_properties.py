"""Properties of the durable store, sampled against real PostgreSQL.

Hypothesis *samples*: it does not prove a property over an input space, so
these are evidence rather than proof, and they are stated as the three
properties the rest of the design leans on.

**Injectivity.** Different octets get different keys, and identical octets get
identical ones. Everything content-addressed in the system -- deduplication,
idempotent delivery, the prefix a revision commits to -- is that sentence.

**Idempotency.** Storing the same artifact any number of times is storing it
once, so at-least-once delivery and retry after a lost swap both cost nothing.

**Ordering independence.** Membership is a set. The order entries arrive in
does not reach the prefix, and therefore does not reach any digest downstream
of it -- which is what makes two concurrent appenders safe to reason about
separately.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from muster.application.rebuild import transcript_prefix
from muster.core.evidence.transcript import entry_digest
from muster.core.results import Ok
from muster.core.wire.digests import DigestKind, digest_octets
from muster.platform.adapters.sql.database import SqlDatabase
from support import ravi
from support.fixtures import open_ravi

pytestmark = pytest.mark.postgres

#  A database round trip per example, so the counts are deliberately small.
#  These sample a property; the exhaustive statements live in the unit suites.
_DATABASE_EXAMPLES = 25
_SETTINGS = settings(
    max_examples=_DATABASE_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)

_octets = st.binary(max_size=512)
KIND = DigestKind.TRANSCRIPT_ENTRY


@given(_octets)
@_SETTINGS
def test_storing_and_reading_is_the_identity_on_octets(
    database: SqlDatabase, tenant_id: str, octets: bytes
) -> None:
    with database.writing(tenant_id) as scope:
        stored = scope.content.put(KIND, octets)
    assert isinstance(stored, Ok), stored
    with database.reading(tenant_id) as scope:
        read = scope.content.get(KIND, stored.value)
    assert isinstance(read, Ok), read
    assert read.value == octets


@given(_octets, st.integers(min_value=1, max_value=5))
@_SETTINGS
def test_storing_is_idempotent_however_many_times_it_happens(
    database: SqlDatabase, tenant_id: str, octets: bytes, times: int
) -> None:
    keys = set()
    with database.writing(tenant_id) as scope:
        for _ in range(times):
            stored = scope.content.put(KIND, octets)
            assert isinstance(stored, Ok), stored
            keys.add(stored.value)
    assert len(keys) == 1
    with database.reading(tenant_id) as scope:
        read = scope.content.get(KIND, keys.pop())
    assert isinstance(read, Ok)
    assert read.value == octets


@given(_octets, _octets)
@_SETTINGS
def test_two_artifacts_share_a_key_exactly_when_they_share_their_octets(
    database: SqlDatabase, tenant_id: str, left: bytes, right: bytes
) -> None:
    with database.writing(tenant_id) as scope:
        first = scope.content.put(KIND, left)
        second = scope.content.put(KIND, right)
    assert isinstance(first, Ok) and isinstance(second, Ok)
    assert (first.value == second.value) == (left == right)

    #  And the key is the digest the kernel would compute, not one the store
    #  invented -- so an artifact's address is the same everywhere in the system.
    assert first.value == digest_octets(KIND, left)


@given(st.permutations(range(8)))
@settings(
    max_examples=12, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_arrival_order_does_not_reach_the_transcript_prefix(
    database: SqlDatabase, tenant_id: str, order: list[int]
) -> None:
    """The same entries in any order are the same prefix, and the same digest.

    Checked through the durable path rather than in memory: the membership goes
    into PostgreSQL in the generated order and comes back out as a set.
    """
    case_id = f"case-order-{''.join(str(index) for index in order)}"
    casework = ravi.casework(database)
    built = ravi.ravi(tenant_id, case_id)
    open_ravi(casework, built)

    chosen = [built.entries[index] for index in order]
    with database.writing(tenant_id) as scope:
        for entry in chosen:
            from muster.platform.ingest.admission import admit_entry

            admitted = admit_entry(scope, case_id, entry)
            assert isinstance(admitted, Ok), admitted
            added = scope.transcript.add(case_id, admitted.value.entry_digest)
            assert isinstance(added, Ok), added

    with database.reading(tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members

    #  Ascending by octets, whatever order they went in.
    assert list(members.value) == sorted(members.value, key=lambda digest: digest.octets)
    assert set(members.value) == {entry_digest(entry) for entry in chosen}

    #  And the prefix the kernel would build from the stored set is the prefix
    #  it would build from any ordering of the same entries.
    stored_prefix = transcript_prefix(tenant_id, case_id, tuple(chosen))
    assert stored_prefix.entry_digests == members.value


@given(st.lists(st.integers(min_value=0, max_value=7), min_size=1, max_size=10))
@settings(
    max_examples=12, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
def test_membership_counts_entries_not_deliveries(
    database: SqlDatabase, tenant_id: str, deliveries: list[int]
) -> None:
    """Duplicates collapse, however many times each one arrives.

    The case identifier is derived from the whole delivery sequence, as its
    sibling above derives one from the whole order.  A summary of it -- length,
    sum, first element -- is not injective: ``[0, 1, 2]`` and ``[0, 0, 3]``
    share all three and have different member sets, so two examples in one run
    would land on one case, membership would accumulate across them, and the
    count below would be a count of both.  The tenant is fresh per test and not
    per example, which is what makes that reachable at all.
    """
    case_id = f"case-dup-{'-'.join(str(index) for index in deliveries)}"
    casework = ravi.casework(database)
    built = ravi.ravi(tenant_id, case_id)
    open_ravi(casework, built)

    from muster.platform.ingest.admission import admit_entry

    with database.writing(tenant_id) as scope:
        for index in deliveries:
            admitted = admit_entry(scope, case_id, built.entries[index])
            assert isinstance(admitted, Ok), admitted
            added = scope.transcript.add(case_id, admitted.value.entry_digest)
            assert isinstance(added, Ok), added

    with database.reading(tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members
    assert len(members.value) == len(set(deliveries))
