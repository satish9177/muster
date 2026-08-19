"""Migrations: applied, reverted, idempotent, and unable to touch an octet.

The static guard is the one that matters, and it is three assertions because
the migrations are data rather than a framework's output. **Canonical octets
are never migrated**: a migration that rewrote a stored preimage would
invalidate every digest, signature and commitment that ever referenced it, and
that rule is worth more as something a test enforces than as something a
reviewer remembers.

The rest runs against a database created for the test and dropped after it,
because applying and reverting a schema is not something to do underneath the
rest of the suite.

The concurrency section at the end is about scope.  The lock is around the
whole *operation* -- migrate, or revert -- rather than around each migration,
and the two defects that shape says out loud are both reproducible: the ledger
created outside the lock, which crashed concurrent migrators on a catalogue
unique violation, and ``revert`` reading a ledger it never ensured existed,
which crashed on a fresh database and on one whose first migration was still in
flight.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from unittest.mock import patch

import psycopg
import pytest

from muster.core.results import InvariantViolation, Ok
from muster.platform.adapters.sql import schema
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.migrations import MIGRATION_LOCK_ID, MIGRATIONS, Migration
from muster.platform.adapters.sql.schema import applied_versions, migrate, revert
from support import ravi
from support.fixtures import open_ravi
from support.paths import PACKAGE_ROOT

#  ---- static guards: no database needed, and none should be -----------------

_MUTATION = re.compile(r"\b(INSERT|UPDATE|DELETE|TRUNCATE|COPY)\b", re.IGNORECASE)


def _statements() -> list[tuple[Migration, str]]:
    return [
        (migration, statement)
        for migration in MIGRATIONS
        for statement in (*migration.up, *migration.down)
    ]


def test_no_migration_statement_writes_a_row() -> None:
    """Pure DDL. A migration that can write cannot rewrite what it must not."""
    for migration, statement in _statements():
        found = _MUTATION.search(statement)
        assert found is None, f"migration {migration.version} runs {found.group(0)}: {statement}"


_DECLARES_OCTETS = re.compile(r"^\s*octets\s+bytea\b", re.IGNORECASE | re.MULTILINE)


def test_the_octets_column_is_declared_once_and_never_altered() -> None:
    """The canonical preimages are created and then left completely alone.

    Two assertions, because the word appears legitimately inside constraint
    names and matching it loosely would flag those. What must not exist is a
    second declaration, or any ``ALTER`` that reaches the column -- a change of
    type, a collation, an encoding, anything that rewrites what is stored.
    """
    declaring = [
        statement for _migration, statement in _statements() if _DECLARES_OCTETS.search(statement)
    ]
    assert len(declaring) == 1
    assert "CREATE TABLE store.content" in declaring[0]

    for migration, statement in _statements():
        lowered = statement.lower()
        assert not ("alter" in lowered and "octets" in lowered), (
            f"migration {migration.version} alters the canonical octets"
        )


def test_no_migration_recomputes_or_rewrites_a_digest() -> None:
    forbidden = ("digest(", "sha256", "encode(", "decode(", "convert_")
    for migration, statement in _statements():
        lowered = statement.lower()
        for needle in forbidden:
            assert needle not in lowered, f"migration {migration.version} computes {needle}"


def test_versions_are_unique_and_ascending() -> None:
    versions = [migration.version for migration in MIGRATIONS]
    assert versions == sorted(set(versions))
    assert versions[0] == 1


def test_every_migration_declares_a_downgrade() -> None:
    """A downgrade nobody wrote is not a downgrade path."""
    for migration in MIGRATIONS:
        assert migration.up
        assert migration.down


#  ---- against a database of the test's own ----------------------------------

pytestmark_postgres = pytest.mark.postgres


@pytest.mark.postgres
def test_migrating_twice_applies_each_version_once(scratch_database: str) -> None:
    first = migrate(scratch_database)
    second = migrate(scratch_database)
    assert first == tuple(migration.version for migration in MIGRATIONS)
    assert second == ()

    with psycopg.connect(scratch_database) as connection:
        assert applied_versions(connection) == first


@pytest.mark.postgres
def test_the_schema_is_what_the_repositories_expect(scratch_database: str) -> None:
    migrate(scratch_database)
    with psycopg.connect(scratch_database) as connection:
        tables = {
            (row[0], row[1])
            for row in connection.execute(
                "SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_schema IN ('store', 'casework')"
            ).fetchall()
        }
    assert tables == {
        ("store", "content"),
        ("casework", "case_head"),
        ("casework", "transcript_entry"),
        ("casework", "evidence_request"),
        ("casework", "case_commitment"),
    }


@pytest.mark.postgres
def test_no_gate_settlement_or_agent_table_is_created(scratch_database: str) -> None:
    """Milestone C owns two schemas and builds nothing for a later milestone.

    An authorization table created "ready for the gate" would be a schema whose
    owner does not exist, in a design whose whole point about the gate is that
    it owns its own state.
    """
    migrate(scratch_database)
    with psycopg.connect(scratch_database) as connection:
        schemas = {
            row[0]
            for row in connection.execute(
                "SELECT schema_name FROM information_schema.schemata"
            ).fetchall()
        }
        names = {
            row[0]
            for row in connection.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema NOT IN ('pg_catalog', 'information_schema')"
            ).fetchall()
        }
    assert "gate" not in schemas
    assert "policy" not in schemas
    for forbidden in ("authorization_attempt", "settlement", "execution_receipt", "agent"):
        assert not any(forbidden in name for name in names), forbidden


@pytest.mark.postgres
def test_reverting_removes_the_schema_and_the_ledger_entry(scratch_database: str) -> None:
    migrate(scratch_database)
    reverted = revert(scratch_database, to_version=0)
    assert reverted == tuple(migration.version for migration in reversed(MIGRATIONS))

    with psycopg.connect(scratch_database) as connection:
        assert applied_versions(connection) == ()
        remaining = connection.execute(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name IN ('store', 'casework')"
        ).fetchall()
    assert remaining == []


@pytest.mark.postgres
def test_reverting_twice_is_a_no_op(scratch_database: str) -> None:
    migrate(scratch_database)
    revert(scratch_database, to_version=0)
    assert revert(scratch_database, to_version=0) == ()


@pytest.mark.postgres
def test_migrating_after_a_revert_rebuilds_the_schema(scratch_database: str) -> None:
    """Down and up again, so the downgrade is a path and not a decoration."""
    migrate(scratch_database)
    revert(scratch_database, to_version=0)
    reapplied = migrate(scratch_database)
    assert reapplied == tuple(migration.version for migration in MIGRATIONS)


#  ---- concurrent migration --------------------------------------------------

CONCURRENT_MIGRATORS = 8


def _migrate_together(dsn: str, workers: int) -> list[tuple[int, ...] | BaseException]:
    """Run ``migrate`` from ``workers`` threads released at the same instant."""
    started = threading.Barrier(workers)
    results: list[tuple[int, ...] | BaseException] = [()] * workers

    def run(slot: int) -> None:
        started.wait(timeout=30.0)
        try:
            results[slot] = migrate(dsn)
        except BaseException as error:  # the failure is the finding, not an escape
            results[slot] = error

    threads = [threading.Thread(target=run, args=(slot,)) for slot in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120.0)
        assert not thread.is_alive(), "a migrating thread did not finish: the lock deadlocked"
    return results


@pytest.mark.postgres
def test_concurrent_migrations_serialise_instead_of_racing(scratch_database: str) -> None:
    """Eight processes starting at once produce one schema and no failure.

    This fails on an implementation that creates the migration ledger outside
    the advisory lock.  ``CREATE SCHEMA IF NOT EXISTS`` is not atomic against a
    concurrent session: both check the catalogue, both insert, and the loser
    aborts with a unique violation on ``pg_namespace_nspname_index`` -- which
    takes down the caller's whole migration, not just the redundant statement.
    Measured at 34 failures in 48 concurrent calls before the lock moved.

    Exactly one caller reports having applied the migration.  That is the
    serialisation being real rather than merely quiet: if two callers each
    believed they applied version 1, the DDL ran twice.
    """
    results = _migrate_together(scratch_database, CONCURRENT_MIGRATORS)

    failures = [result for result in results if isinstance(result, BaseException)]
    assert not failures, f"{len(failures)} of {CONCURRENT_MIGRATORS} raced: {failures[0]!r}"

    expected = tuple(migration.version for migration in MIGRATIONS)
    applied_by = [result for result in results if result == expected]
    assert len(applied_by) == 1, f"{len(applied_by)} callers each applied {expected}"
    assert all(result in ((), expected) for result in results)

    with psycopg.connect(scratch_database) as connection:
        assert applied_versions(connection) == expected


def _held_locks(dsn: str) -> int:
    with psycopg.connect(dsn) as connection:
        held = connection.execute(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
            "AND ((classid::bigint << 32) | objid::bigint) = %s",
            (MIGRATION_LOCK_ID,),
        ).fetchone()
    assert held is not None
    count = held[0]
    assert isinstance(count, int)
    return count


@pytest.mark.postgres
def test_a_concurrent_migration_holds_no_lock_after_it_returns(scratch_database: str) -> None:
    """The lock is released on success and on failure alike.

    Asserted against ``pg_locks`` rather than by inference, and asserted after
    a *failure* as well as after a success: the lock is now session-scoped so
    that it can span the per-migration transactions, which means releasing it
    is something the code has to do rather than something a commit does for it.
    A migration lock that outlived its operation would serialise the next one
    behind a caller that has already gone home.
    """
    _migrate_together(scratch_database, CONCURRENT_MIGRATORS)
    assert _held_locks(scratch_database) == 0

    #  And after an operation that raised part-way through. ``revert`` to a
    #  version below zero is not the failure; the injected one is.
    class _Injected(RuntimeError):
        pass

    broken = list(MIGRATIONS)
    broken.append(Migration(999, "cannot apply", ("CREATE TABLE nowhere.nothing (x int)",), ()))
    with pytest.raises(psycopg.Error), patch.object(schema, "MIGRATIONS", tuple(broken)):
        migrate(scratch_database)

    assert _held_locks(scratch_database) == 0
    #  And the failure left nothing behind, which is the other half of it.
    with psycopg.connect(scratch_database) as connection:
        assert applied_versions(connection) == tuple(m.version for m in MIGRATIONS)


@pytest.mark.postgres
def test_reverting_a_database_that_was_never_migrated_is_a_no_op(scratch_database: str) -> None:
    """It answers ``()``. It used to raise ``UndefinedTable``.

    ``revert`` read the ledger without ensuring it existed, so reverting a
    fresh database -- or reverting one *while* its first ``migrate`` was still
    holding the lock -- crashed on ``relation "platform.schema_migration" does
    not exist``. A downgrade of nothing is nothing, and saying so is the whole
    correction.
    """
    assert revert(scratch_database, to_version=0) == ()
    assert revert(scratch_database, to_version=0) == ()

    #  The ledger it created is empty, not populated with versions nobody ran.
    with psycopg.connect(scratch_database) as connection:
        assert applied_versions(connection) == ()

    #  And migrating afterwards still applies everything.
    assert migrate(scratch_database) == tuple(migration.version for migration in MIGRATIONS)


@pytest.mark.postgres
def test_migrate_and_revert_racing_on_a_fresh_database_both_survive(
    scratch_database: str,
) -> None:
    """The operation is what serialises, so the loser is a no-op and not a crash.

    Four migrators and four reverters released together against a database
    that has never been touched. Every caller has to return: one of the two
    operations goes first, the other sees a consistent ledger, and the final
    state is one of exactly two states -- fully applied or fully reverted.
    Neither is an error, and *that* is the property. A per-step lock let the
    reverter read a ledger the migrator had not created yet.
    """
    workers = 4
    started = threading.Barrier(workers * 2)
    results: list[object] = [None] * (workers * 2)

    def run(slot: int) -> None:
        operation: Callable[[], tuple[int, ...]] = (
            (lambda: migrate(scratch_database))
            if slot < workers
            else (lambda: revert(scratch_database, to_version=0))
        )
        started.wait(timeout=60.0)
        try:
            results[slot] = operation()
        except BaseException as error:  # the failure is the finding, not an escape
            results[slot] = error

    threads = [threading.Thread(target=run, args=(slot,)) for slot in range(workers * 2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=180.0)
        assert not thread.is_alive(), "a thread did not finish: the migration lock deadlocked"

    failures = [result for result in results if isinstance(result, BaseException)]
    assert not failures, f"{len(failures)} of {workers * 2} raced: {failures[0]!r}"

    with psycopg.connect(scratch_database) as connection:
        final = applied_versions(connection)
    assert final in ((), tuple(migration.version for migration in MIGRATIONS))
    assert _held_locks(scratch_database) == 0


@pytest.mark.postgres
def test_the_lock_spans_the_whole_operation_and_not_one_step(scratch_database: str) -> None:
    """Held across the per-migration transactions, not taken inside each one.

    Checked by holding it from outside and watching a migration wait: with a
    per-step transaction lock the runner would still have created the ledger
    outside it, and with no operation-wide lock a second operator's ``revert``
    could interleave between two of this one's migrations. Both are the same
    mistake at different scopes, and this is the assertion that closes it.
    """
    with psycopg.connect(scratch_database, autocommit=True) as holder:
        holder.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK_ID,))
        finished = threading.Event()

        def run() -> None:
            migrate(scratch_database)
            finished.set()

        migrating = threading.Thread(target=run)
        migrating.start()
        #  It cannot get past the lock, so nothing exists yet.
        assert not finished.wait(timeout=2.0)
        with psycopg.connect(scratch_database) as observer:
            schemas = observer.execute(
                "SELECT count(*) FROM information_schema.schemata "
                "WHERE schema_name IN ('platform', 'store', 'casework')"
            ).fetchone()
        assert schemas is not None
        assert schemas[0] == 0, "the runner wrote the catalogue without holding the lock"

        holder.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK_ID,))
        assert finished.wait(timeout=120.0), "the migration never acquired the released lock"
        migrating.join(timeout=10.0)

    with psycopg.connect(scratch_database) as connection:
        assert applied_versions(connection) == tuple(m.version for m in MIGRATIONS)


@pytest.mark.postgres
def test_the_runtime_path_does_not_take_the_migration_lock(scratch_database: str) -> None:
    """A case command must never queue behind a migration, or the reverse.

    The lock is named once in the schema runner and nowhere else; this asserts
    it from the other side, by holding it and then doing ordinary durable work
    on another connection while it is held.
    """
    migrate(scratch_database)
    database = SqlDatabase(scratch_database)
    case = ravi.ravi("tenant-lockcheck", "case-lockcheck")

    with psycopg.connect(scratch_database) as holder:
        holder.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK_ID,))
        try:
            head = open_ravi(ravi.casework(database), case)
            assert head.case_id == case.case_id
            with database.reading(case.tenant_id) as scope:
                read = scope.heads.read(case.case_id)
            assert isinstance(read, Ok), read
        finally:
            holder.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK_ID,))


def test_the_migration_lock_is_named_only_by_the_schema_runner() -> None:
    """One identifier, one caller. A second taker would be a second policy."""
    source = PACKAGE_ROOT / "src" / "muster" / "platform"
    naming = {
        path.relative_to(source).as_posix()
        for path in source.rglob("*.py")
        if "MIGRATION_LOCK_ID" in path.read_text(encoding="utf-8")
    }
    assert naming == {"adapters/sql/migrations.py", "adapters/sql/schema.py"}

    advisory = {
        path.relative_to(source).as_posix()
        for path in source.rglob("*.py")
        if "pg_advisory" in path.read_text(encoding="utf-8")
    }
    assert advisory == {"adapters/sql/schema.py"}


def test_a_migrations_identity_covers_its_statements_and_not_only_its_name() -> None:
    """The digest is what makes "version 1" mean one thing.

    An in-place edit usually keeps the migration's human name, so comparing
    names alone would miss the common case rather than the edge one. The
    identity is a string because it goes in the existing ``name`` column: a new
    column would mean migrating the table that records migrations, and this
    runner deliberately cannot do that.
    """
    original = MIGRATIONS[0]
    assert original.identity().startswith(f"{original.name}@")
    assert original.identity() == original.identity()

    renamed = Migration(original.version, "something else", original.up, original.down)
    edited_up = Migration(
        original.version,
        original.name,
        (*original.up, "CREATE INDEX later ON store.content (kind)"),
        original.down,
    )
    edited_down = Migration(original.version, original.name, original.up, ("DROP SCHEMA store",))
    for changed in (renamed, edited_up, edited_down):
        assert changed.identity() != original.identity()


@pytest.mark.postgres
@pytest.mark.parametrize("field", ["name", "up", "down"])
def test_a_version_that_two_builds_disagree_about_is_refused(
    scratch_database: str, field: str
) -> None:
    """A version number is not an identity, and skipping on it alone is unsafe.

    Two builds both carrying "version 1" and meaning two different schemas is
    what happens when a migration is edited in place rather than added to. The
    second build would otherwise see the version recorded, skip its own DDL,
    and start against tables its repositories were not written for. It refuses
    instead, and says which two identities disagree.

    Parametrised over all three things that can change, because a guard that
    only caught a rename would miss the way this actually happens.
    """
    original = MIGRATIONS[0]
    assert migrate(scratch_database) == tuple(m.version for m in MIGRATIONS)

    impostors = {
        "name": Migration(
            original.version, "a different schema entirely", original.up, original.down
        ),
        "up": Migration(
            original.version,
            original.name,
            (*original.up, "CREATE TABLE store.extra (x int)"),
            original.down,
        ),
        "down": Migration(original.version, original.name, original.up, ("DROP SCHEMA store",)),
    }
    impostor = impostors[field]

    with (
        pytest.raises(InvariantViolation) as raised,
        patch.object(schema, "MIGRATIONS", (impostor,)),
    ):
        migrate(scratch_database)
    assert impostor.identity() in str(raised.value)
    assert original.identity() in str(raised.value)

    #  It refused rather than half-applying, and the lock is not left behind.
    with psycopg.connect(scratch_database) as connection:
        assert applied_versions(connection) == tuple(m.version for m in MIGRATIONS)
    assert _held_locks(scratch_database) == 0

    #  The build that owns the schema still migrates cleanly afterwards.
    assert migrate(scratch_database) == ()


@pytest.mark.postgres
def test_a_downgrade_from_a_build_that_owns_a_different_schema_is_refused(
    scratch_database: str,
) -> None:
    """The sharper half of the same guard, and the reason it is in ``revert`` too.

    Applying the wrong migration usually fails on DDL that does not fit the
    schema in front of it. *Reverting* the wrong one can be perfectly valid SQL
    that drops exactly what the real schema needs -- so the identity is checked
    before a single ``down`` statement runs, not after one of them has taken a
    table with it.
    """
    original = MIGRATIONS[0]
    migrate(scratch_database)

    impostor = (
        Migration(original.version, original.name, original.up, ("DROP SCHEMA store CASCADE",)),
    )
    with pytest.raises(InvariantViolation), patch.object(schema, "MIGRATIONS", impostor):
        revert(scratch_database, to_version=0)

    #  Nothing was dropped, and the ledger still says what it said.
    with psycopg.connect(scratch_database) as connection:
        assert applied_versions(connection) == tuple(m.version for m in MIGRATIONS)
        remaining = connection.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'store'"
        ).fetchone()
    assert remaining is not None
    assert remaining[0] == 1
    assert _held_locks(scratch_database) == 0

    #  And the build that owns the schema can still revert it.  Reverting runs
    #  newest-first, which is the only order that can work: a later migration's
    #  tables may reference an earlier one's.
    assert revert(scratch_database, to_version=0) == tuple(m.version for m in reversed(MIGRATIONS))


def test_the_identity_does_not_depend_on_a_separator_no_statement_contains() -> None:
    """Length-prefixed, so two different migrations cannot share a digest by luck.

    A separator-joined encoding is only unambiguous while no field contains the
    separator, which is an assumption about SQL text that nothing checks. These
    two migrations would collide under any such encoding and do not here.
    """
    left = Migration(1, "m", ("a", "bc"), ())
    right = Migration(1, "m", ("ab", "c"), ())
    assert left.identity() != right.identity()

    #  And a statement containing the old separator does not collide either.
    weird = Migration(1, "m", ("a\x1fbc",), ())
    assert weird.identity() != left.identity()


def test_the_identity_digest_is_not_truncated() -> None:
    """The column is ``text``. A short digest would be a collision argument to make."""
    identity = MIGRATIONS[0].identity()
    name, _, digest = identity.partition("@")
    assert name == MIGRATIONS[0].name
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")
