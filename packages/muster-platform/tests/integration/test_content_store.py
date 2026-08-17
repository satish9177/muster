"""The content store against real PostgreSQL.

Append-only, insert-if-absent, injective, and byte-preserving.  The interesting
tests are the last two: a store that quietly returned different octets than it
was given, or that let two preimages share a key, would make every digest in
the system a claim nobody checks.
"""

from __future__ import annotations

import pytest

from muster.core.results import Err, Ok
from muster.core.wire.digests import DigestKind, digest_octets
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.ports import StoreFailure

pytestmark = pytest.mark.postgres

KIND = DigestKind.TRANSCRIPT_ENTRY


def test_storing_octets_returns_their_own_digest(database: SqlDatabase, tenant_id: str) -> None:
    octets = b"the artifact is the octets"
    with database.writing(tenant_id) as scope:
        stored = scope.content.put(KIND, octets)
    assert isinstance(stored, Ok), stored
    assert stored.value == digest_octets(KIND, octets)


@pytest.mark.parametrize(
    "octets",
    [
        b"",
        b"\x00",
        b"\x00\xff\x00\xff",
        bytes(range(256)),
        b"\xed\xa0\x80",  # a lone surrogate: not valid UTF-8, and not text
        b"x" * 100_000,
    ],
    ids=["empty", "nul", "nul-and-high", "every-octet", "lone-surrogate", "large"],
)
def test_retrieval_returns_exactly_the_octets_that_were_stored(
    database: SqlDatabase, tenant_id: str, octets: bytes
) -> None:
    """Byte preservation, including the shapes a text column would ruin."""
    with database.writing(tenant_id) as scope:
        stored = scope.content.put(KIND, octets)
        assert isinstance(stored, Ok), stored

    with database.reading(tenant_id) as scope:
        read = scope.content.get(KIND, stored.value)
    assert isinstance(read, Ok), read
    assert read.value == octets
    assert type(read.value) is bytes


def test_storing_the_same_octets_twice_is_an_idempotent_success(
    database: SqlDatabase, tenant_id: str
) -> None:
    octets = b"at-least-once delivery costs nothing"
    with database.writing(tenant_id) as scope:
        first = scope.content.put(KIND, octets)
        second = scope.content.put(KIND, octets)
        third = scope.content.put(KIND, octets)
    assert isinstance(first, Ok) and isinstance(second, Ok) and isinstance(third, Ok)
    assert first.value == second.value == third.value


def test_a_second_write_never_replaces_the_first(
    database: SqlDatabase, tenant_id: str, dsn: str
) -> None:
    """Append-only, checked by reading the row rather than trusting the API.

    ``ON CONFLICT DO NOTHING`` means the row PostgreSQL holds is the one the
    first writer put there. If the statement were ever changed to
    ``DO UPDATE``, the digest would still match and only this would notice.
    """
    from support.fixtures import count_content

    octets = b"first"
    with database.writing(tenant_id) as scope:
        stored = scope.content.put(KIND, octets)
        assert isinstance(stored, Ok), stored
    with database.writing(tenant_id) as scope:
        again = scope.content.put(KIND, octets)
        assert isinstance(again, Ok), again

    assert count_content(dsn, tenant_id, KIND.value) == 1
    with database.reading(tenant_id) as scope:
        read = scope.content.get(KIND, stored.value)
    assert isinstance(read, Ok)
    assert read.value == octets


def test_absent_content_is_a_typed_absence_and_not_an_empty_answer(
    database: SqlDatabase, tenant_id: str
) -> None:
    missing = digest_octets(KIND, b"never stored")
    with database.reading(tenant_id) as scope:
        read = scope.content.get(KIND, missing)
    assert isinstance(read, Err)
    assert read.error.failure is StoreFailure.CONTENT_ABSENT
    assert read.error.digest == missing.hex


def test_a_key_holding_different_octets_is_a_hard_integrity_failure(
    database: SqlDatabase, tenant_id: str, dsn: str
) -> None:
    """The one condition that is neither a race nor a retry.

    Reached by writing straight to the table, because the store's own API
    derives the key from the octets and cannot produce this state. Under
    SHA-256 it means corruption or a forged row, so the answer is a refusal --
    never a silent success that hands a caller the wrong preimage.
    """
    from support.fixtures import forge_content

    honest = b"what the digest is of"
    with database.writing(tenant_id) as scope:
        stored = scope.content.put(KIND, honest)
    assert isinstance(stored, Ok), stored

    forge_content(dsn, tenant_id, stored.value, KIND.value, b"something else entirely")

    with database.writing(tenant_id) as scope:
        offered_again = scope.content.put(KIND, honest)
    assert isinstance(offered_again, Err)
    assert offered_again.error.failure is StoreFailure.DIGEST_COLLISION


def test_octets_that_do_not_hash_to_their_key_are_refused_on_read(
    database: SqlDatabase, tenant_id: str, dsn: str
) -> None:
    """Every read re-derives the digest, so corruption cannot be read past."""
    from support.fixtures import forge_content

    with database.writing(tenant_id) as scope:
        stored = scope.content.put(KIND, b"honest octets")
    assert isinstance(stored, Ok), stored

    forge_content(dsn, tenant_id, stored.value, KIND.value, b"tampered octets")

    with database.reading(tenant_id) as scope:
        read = scope.content.get(KIND, stored.value)
    assert isinstance(read, Err)
    assert read.error.failure is StoreFailure.CONTENT_CORRUPT


def test_reading_under_the_wrong_domain_is_refused(database: SqlDatabase, tenant_id: str) -> None:
    """Domain separation is enforced on the way out as well as on the way in.

    Asking for an entry's digest under the certificate domain is answered by
    refusal, not by the octets. The stored domain is compared before the digest
    is recomputed, so the caller is told the artifact is not the kind it asked
    for rather than being handed octets it will then misread.
    """
    octets = b"stored as an entry"
    with database.writing(tenant_id) as scope:
        stored = scope.content.put(DigestKind.TRANSCRIPT_ENTRY, octets)
    assert isinstance(stored, Ok), stored

    with database.reading(tenant_id) as scope:
        read = scope.content.get(DigestKind.ANALYSIS_CERTIFICATE, stored.value)
    assert isinstance(read, Err)
    assert read.error.failure is StoreFailure.CONTENT_CORRUPT
    assert "stored as TRANSCRIPT_ENTRY" in read.error.detail


def test_two_domains_over_identical_octets_are_two_artifacts(
    database: SqlDatabase, tenant_id: str
) -> None:
    octets = b"identical octets, different meanings"
    with database.writing(tenant_id) as scope:
        as_entry = scope.content.put(DigestKind.TRANSCRIPT_ENTRY, octets)
        as_prefix = scope.content.put(DigestKind.TRANSCRIPT_PREFIX, octets)
    assert isinstance(as_entry, Ok) and isinstance(as_prefix, Ok)
    assert as_entry.value != as_prefix.value


def test_a_digest_stored_by_one_tenant_is_absent_for_another(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str
) -> None:
    """Content is not shared across the boundary, deliberately.

    Deduplicating identical octets across tenants would make one tenant's
    retention decision another tenant's problem, and would leak the existence
    of an artifact across the boundary that exists to prevent exactly that.
    """
    octets = b"a receipt both tenants happen to hold"
    with database.writing(tenant_id) as scope:
        mine = scope.content.put(KIND, octets)
    assert isinstance(mine, Ok), mine

    with database.reading(other_tenant_id) as scope:
        theirs = scope.content.get(KIND, mine.value)
    assert isinstance(theirs, Err)
    assert theirs.error.failure is StoreFailure.CONTENT_ABSENT

    #  And storing it independently is allowed, and is a separate row.
    with database.writing(other_tenant_id) as scope:
        stored = scope.content.put(KIND, octets)
    assert isinstance(stored, Ok)
    assert stored.value == mine.value
    with database.reading(other_tenant_id) as scope:
        read = scope.content.get(KIND, mine.value)
    assert isinstance(read, Ok)
    assert read.value == octets


def test_a_rolled_back_transaction_stores_nothing(database: SqlDatabase, tenant_id: str) -> None:
    octets = b"written, then abandoned"
    digest = digest_octets(KIND, octets)
    with pytest.raises(RuntimeError, match="abandon"), database.writing(tenant_id) as scope:
        stored = scope.content.put(KIND, octets)
        assert isinstance(stored, Ok), stored
        raise RuntimeError("abandon this transaction")

    with database.reading(tenant_id) as scope:
        read = scope.content.get(KIND, digest)
    assert isinstance(read, Err)
    assert read.error.failure is StoreFailure.CONTENT_ABSENT
