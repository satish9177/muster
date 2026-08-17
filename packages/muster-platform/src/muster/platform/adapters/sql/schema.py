"""Applying and reverting the schema.

**The lock is around the operation, not around each step.**  One session-level
advisory lock, taken before anything is read or written and released when the
operation ends, so "bring the schema to this version" is what serialises rather
than "apply this one migration".  Per-step locking was not enough for two
reasons, and both are real:

* the *ledger* is created by the runner rather than by a migration -- a
  migration cannot record itself before the table recording it exists -- and
  ``CREATE SCHEMA IF NOT EXISTS`` is not a concurrency primitive.  It checks
  the catalogue and then inserts into it, so two sessions that both pass the
  check both insert, and the loser aborts with a unique violation on
  ``pg_namespace_nspname_index`` that takes its whole migration down with it;
* with the lock released between steps, ``migrate`` and ``revert`` can
  interleave their loops.  With one migration that is harmless and with two it
  is a schema at a version nobody asked for, which is not a bug to introduce
  later along with the second migration.

Inside the lock, **one transaction per step** is kept, and that is a different
property worth having: a migration that fails leaves nothing half-applied, and
PostgreSQL's transactional DDL is what makes that statement true rather than
aspirational.  The session lock spans those transactions rather than living
inside one, which is why the connection is opened in autocommit and each step
opens its own transaction explicitly.

The lock is scoped to migrating.  One identifier, taken by this module and
nowhere else, and no runtime case command takes it -- so serialising migrations
costs a concurrent caseworker nothing.  A process that dies holding it releases
it by disconnecting, because that is what PostgreSQL does with a session lock.

``revert`` exists and is exercised, because a downgrade nobody has ever run is
not a downgrade path.  It is the inverse of ``up`` and it drops tables; it does
not, and must not, rewrite anything.  It creates the ledger for the same reason
``migrate`` does: reverting a database that has never been migrated is a
no-op, and a no-op should answer ``()`` rather than raise ``UndefinedTable``.

**A version number is not an identity on its own.**  Two builds can both carry
"version 1" and mean two different schemas -- a migration edited in place rather
than added to -- and skipping on the number would let the second build start
against tables its repositories were not written for.  The ledger records
``Migration.identity``, which is the name and a digest of the statements, and
both ``_apply`` and ``_revert`` refuse a version whose recorded identity is not
theirs.  ``_revert`` needs it more sharply than ``_apply``: applying the wrong
migration usually fails on DDL that does not fit, while reverting the wrong one
can be valid SQL that drops what the schema in front of it needs.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg

from muster.core.results import InvariantViolation
from muster.platform.adapters.sql.migrations import (
    LEDGER_SCHEMA,
    LEDGER_TABLE,
    MIGRATION_LOCK_ID,
    MIGRATIONS,
    Migration,
)


def applied_versions(connection: psycopg.Connection[tuple[object, ...]]) -> tuple[int, ...]:
    rows = connection.execute(
        "SELECT version FROM platform.schema_migration ORDER BY version"
    ).fetchall()
    return tuple(_version(row[0]) for row in rows)


def _version(value: object) -> int:
    if not isinstance(value, int):
        raise InvariantViolation(f"schema_migration.version is not an integer: {value!r}")
    return value


def migrate(dsn: str) -> tuple[int, ...]:
    """Apply every migration this build knows and the database does not."""
    applied: list[int] = []
    with _migrating(dsn) as connection:
        for migration in MIGRATIONS:
            if _apply(connection, migration):
                applied.append(migration.version)
    return tuple(applied)


def revert(dsn: str, *, to_version: int) -> tuple[int, ...]:
    """Undo every applied migration above ``to_version``, newest first."""
    reverted: list[int] = []
    with _migrating(dsn) as connection:
        for migration in reversed(MIGRATIONS):
            if migration.version > to_version and _revert(connection, migration):
                reverted.append(migration.version)
    return tuple(reverted)


@contextmanager
def _migrating(dsn: str) -> Iterator[psycopg.Connection[tuple[object, ...]]]:
    """Hold the migration lock and guarantee the ledger, for one whole operation.

    Autocommit, so that the lock and each step's transaction are separate.  The
    lock is session-scoped -- ``pg_advisory_lock``, not
    ``pg_advisory_xact_lock`` -- so it survives every commit and rollback on
    this connection and is released by the ``finally`` below or by the session
    ending, whichever comes first.  Autocommit is what makes each step's
    ``connection.transaction()`` an independent top-level transaction rather
    than a savepoint inside one long one, which is how per-step atomicity
    survives an operation-wide lock.

    ``pg_advisory_lock`` waits rather than failing, which is the behaviour a
    second operator wants: their migration runs after the first one finishes
    instead of reporting a conflict they would only resolve by running it
    again.
    """
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK_ID,))
        try:
            _create_ledger(connection)
            yield connection
        finally:
            #  Released here on success and on failure alike. Closing the
            #  connection would release it too -- this says so out loud, and it
            #  is what keeps a pooled or reused connection honest.
            connection.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK_ID,))


def _create_ledger(connection: psycopg.Connection[tuple[object, ...]]) -> None:
    """The ledger, created under the lock the caller is already holding.

    Both operations need it before they can read it, and neither may assume the
    other ran first: a fresh database reverted before it was ever migrated is a
    no-op, not an error, and a fresh database migrated by eight processes at
    once is one schema, not seven aborts.
    """
    with connection.transaction():
        connection.execute(LEDGER_SCHEMA)
        connection.execute(LEDGER_TABLE)


def _apply(connection: psycopg.Connection[tuple[object, ...]], migration: Migration) -> bool:
    with connection.transaction():
        #  Read the ledger under the operation's lock. Reading it outside would
        #  be a check whose answer another process can invalidate between the
        #  check and the DDL.
        recorded = _recorded_identity(connection, migration)
        if recorded is not None:
            _require_same_migration(recorded, migration)
            return False
        for statement in migration.up:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO platform.schema_migration (version, name) VALUES (%s, %s)",
            (migration.version, migration.identity()),
        )
    return True


def _revert(connection: psycopg.Connection[tuple[object, ...]], migration: Migration) -> bool:
    with connection.transaction():
        recorded = _recorded_identity(connection, migration)
        if recorded is None:
            return False
        #  Checked before the ``down`` statements run, and for a sharper reason
        #  than on the way up: applying the wrong migration fails on DDL that
        #  does not fit, but *reverting* the wrong one can be perfectly valid
        #  SQL that drops objects the schema it is actually looking at needs.
        _require_same_migration(recorded, migration)
        for statement in migration.down:
            connection.execute(statement)
        connection.execute(
            "DELETE FROM platform.schema_migration WHERE version = %s", (migration.version,)
        )
    return True


def _recorded_identity(
    connection: psycopg.Connection[tuple[object, ...]], migration: Migration
) -> str | None:
    row = connection.execute(
        "SELECT name FROM platform.schema_migration WHERE version = %s", (migration.version,)
    ).fetchone()
    if row is None:
        return None
    recorded = row[0]
    if not isinstance(recorded, str):
        raise InvariantViolation(f"schema_migration.name is not text: {recorded!r}")
    return recorded


def _require_same_migration(recorded: str, migration: Migration) -> None:
    """Two builds must not disagree about what a version number means."""
    if recorded != migration.identity():
        raise InvariantViolation(
            f"schema version {migration.version} was applied as {recorded!r}, and this "
            f"build calls it {migration.identity()!r}: two builds disagree about what "
            "this version is"
        )
