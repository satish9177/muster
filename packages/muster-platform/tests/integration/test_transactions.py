"""The transaction scopes are what they claim to be, asked of PostgreSQL.

Everything the concurrency suite proves rests on two settings that are applied
in one place and stated in prose everywhere else.  Prose is not a setting.  A
``reading`` scope that had quietly stayed at read-committed would still pass
every concurrency test -- the compare-and-swap would still catch the races --
while the snapshot the revision was derived from silently stopped being one
instant.  So the settings are read back out of the server.
"""

from __future__ import annotations

import pytest

from muster.core.results import Ok
from muster.core.wire.digests import DigestKind
from muster.platform.adapters.sql.database import SqlDatabase, SqlTenantScope

pytestmark = pytest.mark.postgres


def _setting(scope: SqlTenantScope, name: str) -> str:
    row = scope.connection.execute(f"SHOW {name}").fetchone()
    assert row is not None
    value = row[0]
    assert isinstance(value, str)
    return value


def test_a_reading_scope_is_a_read_only_repeatable_read_snapshot(
    database: SqlDatabase, tenant_id: str
) -> None:
    """One instant, so a revision is derived from a state that existed.

    A revision is a function of a head *and* a membership set. Read at
    read-committed those are two instants, and the derivation would describe a
    state the case was never in -- undetectably, because both halves are
    individually valid.
    """
    with database.reading(tenant_id) as scope:
        assert isinstance(scope, SqlTenantScope)
        assert _setting(scope, "transaction_isolation") == "repeatable read"
        assert _setting(scope, "transaction_read_only") == "on"


def test_a_writing_scope_is_read_committed_and_writable(
    database: SqlDatabase, tenant_id: str
) -> None:
    """Read-committed is sufficient here, and it is a choice rather than a default.

    The compare-and-swap is a single-row conditional update. PostgreSQL
    re-evaluates its predicate against the updated row after waiting for a
    concurrent writer, so exactly one of two contending swaps matches and the
    other is told it matched nothing. A stricter level would buy a
    serialization failure to handle and no additional guarantee.
    """
    with database.writing(tenant_id) as scope:
        assert isinstance(scope, SqlTenantScope)
        assert _setting(scope, "transaction_isolation") == "read committed"
        assert _setting(scope, "transaction_read_only") == "off"


def test_a_reading_scope_refuses_to_write(database: SqlDatabase, tenant_id: str) -> None:
    """Enforced by the server, not by which methods the caller happens to call."""
    import psycopg

    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):  # noqa: SIM117
        with database.reading(tenant_id) as scope:
            scope.content.put(DigestKind.TRANSCRIPT_ENTRY, b"not allowed here")


def test_a_writing_scope_commits_on_exit_and_rolls_back_on_error(
    database: SqlDatabase, tenant_id: str
) -> None:
    from muster.core.wire.digests import digest_octets

    kept = b"committed"
    with database.writing(tenant_id) as scope:
        stored = scope.content.put(DigestKind.TRANSCRIPT_ENTRY, kept)
        assert isinstance(stored, Ok), stored

    discarded = b"abandoned"
    with pytest.raises(RuntimeError, match="abandon"):  # noqa: SIM117
        with database.writing(tenant_id) as scope:
            scope.content.put(DigestKind.TRANSCRIPT_ENTRY, discarded)
            raise RuntimeError("abandon")

    with database.reading(tenant_id) as scope:
        assert isinstance(scope.content.get(DigestKind.TRANSCRIPT_ENTRY, stored.value), Ok)
        gone = scope.content.get(
            DigestKind.TRANSCRIPT_ENTRY, digest_octets(DigestKind.TRANSCRIPT_ENTRY, discarded)
        )
    assert not isinstance(gone, Ok)


def test_two_scopes_are_two_connections_and_do_not_share_a_transaction(
    database: SqlDatabase, tenant_id: str
) -> None:
    """A nested scope is a separate session, so an uncommitted write is invisible.

    This is what makes the concurrency tests real: two threads calling into the
    same ``SqlDatabase`` contend against each other through PostgreSQL rather
    than sharing one connection and serialising by accident.
    """
    octets = b"visible only after the commit"
    with database.writing(tenant_id) as outer:
        assert isinstance(outer, SqlTenantScope)
        stored = outer.content.put(DigestKind.TRANSCRIPT_ENTRY, octets)
        assert isinstance(stored, Ok), stored
        with database.reading(tenant_id) as inner:
            assert isinstance(inner, SqlTenantScope)
            assert inner.connection is not outer.connection
            unseen = inner.content.get(DigestKind.TRANSCRIPT_ENTRY, stored.value)
        assert not isinstance(unseen, Ok)

    with database.reading(tenant_id) as after:
        assert isinstance(after.content.get(DigestKind.TRANSCRIPT_ENTRY, stored.value), Ok)
