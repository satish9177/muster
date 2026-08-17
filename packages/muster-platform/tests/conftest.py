"""Fixtures for the control-plane suite.

**PostgreSQL is not simulated.**  Everything this milestone claims about
transactions, compare-and-swap, insert-if-absent and concurrent writers is a
claim about PostgreSQL, and a claim about PostgreSQL checked against SQLite is
not evidence -- SQLite has different isolation, different locking and no
``IS NOT DISTINCT FROM`` semantics under concurrency worth testing.  So the
tests that matter are gated on a real instance and are *skipped*, loudly, when
there is not one.  A suite that quietly substituted a different database would
report a green result for a property nobody checked.

    MUSTER_TEST_DSN=postgresql://user:password@host:port/database

Isolation between tests is by tenant.  Every test gets a tenant identifier
nothing else uses, which is faster than truncating, keeps parallel tests
independent, and has the pleasant side effect that the tenant boundary is
exercised by every test in the suite rather than only by the ones about it.

**One exception, and it is a constraint on how the suite is run.**  The
acceptance and failure-injection suites use the fixture's *own* tenant and
clear it first, because the frozen milestone-B digests are digests of that
tenant and no other one reproduces them.  Two copies of the suite running
against one database at the same time will therefore erase each other's state.
Run one at a time, or point them at separate databases.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.schema import migrate

DSN_VARIABLE = "MUSTER_TEST_DSN"

_SKIP = (
    f"needs a real PostgreSQL instance: set {DSN_VARIABLE}. "
    "These tests are about PostgreSQL transaction semantics and are not "
    "meaningful against another engine."
)


@pytest.fixture(scope="session")
def dsn() -> str:
    configured = os.environ.get(DSN_VARIABLE)
    if not configured:
        pytest.skip(_SKIP, allow_module_level=True)
    return configured


@pytest.fixture(scope="session")
def migrated_dsn(dsn: str) -> str:
    """The schema, applied once for the session. Applying it twice is a no-op."""
    migrate(dsn)
    return dsn


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


@pytest.fixture
def tenant_id() -> str:
    """A tenant nothing else in the suite uses."""
    return f"tenant-{uuid.uuid4().hex[:16]}"


@pytest.fixture
def other_tenant_id() -> str:
    return f"tenant-{uuid.uuid4().hex[:16]}"


@pytest.fixture
def case_id() -> str:
    return f"case-{uuid.uuid4().hex[:12]}"


@pytest.fixture
def scratch_database(dsn: str) -> Iterator[str]:
    """A database of this test's own, created and dropped around it.

    Only the migration tests need one: applying and reverting a schema is not
    something to do underneath the rest of the suite.
    """
    import psycopg

    name = f"muster_migration_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    try:
        yield _with_database(dsn, name)
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def _with_database(dsn: str, name: str) -> str:
    """The same connection string, pointed at a different database."""
    import psycopg

    return psycopg.conninfo.make_conninfo(dsn, dbname=name)
