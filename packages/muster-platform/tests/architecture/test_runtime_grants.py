"""A migration that adds a table must not leave the runtime role locked out.

This suite exists because of a specific failure.  Migration 7 added the
``sandbox_rail`` schema; the runtime grant block lived in ``infra/README.md`` as
a step an operator re-runs by hand; nobody re-ran it.  The first statement
``DurableSandboxPaymentExecutor`` issues then failed with SQLSTATE ``42501``,
the Gate turned the exception into ``UnknownOutcome("EXECUTOR_EXCEPTION", ...)``
and recorded UNCERTAIN, and reconciliation's ``inspect`` failed the same way and
correctly refused to guess.  Every one of those behaviours is right, and
together they hid a permission bug behind a fail-closed lifecycle.

So the grant list is data in ``adapters.sql.runtime_grants``, and these tests
tie it to two things that can change under it:

* the *schema* -- every table any migration creates has to be named there;
* the *statements* -- the privileges the SQL in the durable adapters actually
  needs have to be the privileges granted, no fewer and, where the scan can see
  the whole of a module, no more.

The statement scan is textual, and it says so.  Two adapters build a table name
by interpolation (``authority.py``), so a scan cannot enumerate their tables and
this suite only requires *sufficiency* there.  For ``sandbox_rail`` and
``executions`` -- the two modules the Action Gate's durability rests on -- every
statement names its table literally, so those are held to exactness.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from muster.platform.adapters.sql import runtime_grants
from muster.platform.adapters.sql.migrations import LEDGER_TABLE, MIGRATIONS
from muster.platform.adapters.sql.runtime_grants import (
    FORBIDDEN_DATABASE_PRIVILEGES,
    FORBIDDEN_PRIVILEGES,
    OWNERSHIP,
    RUNTIME_SCHEMAS,
    RUNTIME_TABLE_GRANTS,
    SCHEMA_PRIVILEGES,
    TABLE_PRIVILEGES,
    PrivilegeFinding,
    PrivilegeReport,
    RuntimeGrantError,
    TableGrant,
    grant_statements,
    schema_expectations,
)

pytestmark = pytest.mark.architecture

_ADAPTERS = Path(runtime_grants.__file__).resolve().parent

#: Modules whose SQL the *runtime* role executes.  ``migrations``, ``schema``
#: and ``bootstrap`` are the migrator's, and ``runtime_grants`` is this list.
_RUNTIME_MODULES: tuple[str, ...] = (
    "authority.py",
    "commitments.py",
    "content.py",
    "database.py",
    "executions.py",
    "head.py",
    "requests.py",
    "sandbox_rail.py",
    "transcript.py",
)

#: The two the Gate's durability rests on, and the two whose every statement
#: names its table literally, so a textual scan sees all of them.
_EXACTLY_SCANNED: tuple[str, ...] = ("executions.py", "sandbox_rail.py")

_CREATE_TABLE = re.compile(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)\.(\w+)")
_STATEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bINSERT\s+INTO\s+(\w+)\.(\w+)"), "INSERT"),
    (re.compile(r"\bUPDATE\s+(\w+)\.(\w+)"), "UPDATE"),
    (re.compile(r"\bFROM\s+(\w+)\.(\w+)"), "SELECT"),
    (re.compile(r"\bJOIN\s+(\w+)\.(\w+)"), "SELECT"),
)
_DELETE = re.compile(r"\bDELETE\s+FROM\s+(\w+)\.(\w+)")


def _granted() -> dict[str, frozenset[str]]:
    return {grant.qualified(): frozenset(grant.privileges) for grant in RUNTIME_TABLE_GRANTS}


def _created_tables() -> set[str]:
    """Every table the schema creates: the migrations, and the ledger."""
    statements = [statement for migration in MIGRATIONS for statement in migration.up]
    statements.append(LEDGER_TABLE)
    return {
        f"{schema}.{table}"
        for statement in statements
        for schema, table in _CREATE_TABLE.findall(statement)
    }


def _required(module: str) -> dict[str, set[str]]:
    source = (_ADAPTERS / module).read_text(encoding="utf-8")
    required: dict[str, set[str]] = {}
    for pattern, privilege in _STATEMENTS:
        for schema, table in pattern.findall(source):
            required.setdefault(f"{schema}.{table}", set()).add(privilege)
    #  DELETE is deliberately not one of the patterns above.  A runtime DELETE
    #  would be read as a SELECT by the ``FROM`` pattern and quietly satisfied;
    #  ``test_no_runtime_adapter_deletes`` asserts separately that there is not
    #  one, which is the stronger statement and the one the role rests on.
    return required


def test_every_created_table_is_granted_on() -> None:
    """The migration-7 regression, stated directly.

    A migration that adds a table and no grant is exactly what happened, and it
    is invisible until a fail-closed lifecycle records an unknown outcome over
    a permission error.  This fails at import time instead.
    """
    missing = sorted(_created_tables() - set(_granted()))
    assert not missing, (
        "these tables are created by a migration and the runtime role is granted "
        f"nothing on them: {missing}"
    )


def test_no_grant_names_a_table_the_schema_does_not_create() -> None:
    stale = sorted(set(_granted()) - _created_tables())
    assert not stale, f"these grants name tables no migration creates: {stale}"


def test_sandbox_rail_is_granted_exactly_what_its_statements_need() -> None:
    """The schema this failure was actually about, held to the executor's SQL."""
    granted = _granted()
    required = _required("sandbox_rail.py")
    assert set(required) == {"sandbox_rail.attempt", "sandbox_rail.transfer"}
    assert required["sandbox_rail.attempt"] == {"SELECT", "INSERT", "UPDATE"}
    assert required["sandbox_rail.transfer"] == {"SELECT", "INSERT"}
    for qualified, privileges in required.items():
        assert granted[qualified] == privileges


@pytest.mark.parametrize("module", _RUNTIME_MODULES)
def test_runtime_statements_have_the_privileges_they_need(module: str) -> None:
    granted = _granted()
    for qualified, privileges in _required(module).items():
        assert qualified in granted, f"{module} names {qualified} and nothing grants on it"
        unmet = sorted(privileges - granted[qualified])
        assert not unmet, f"{module} needs {unmet} on {qualified} and does not hold it"


@pytest.mark.parametrize("module", _EXACTLY_SCANNED)
def test_the_gate_adapters_are_granted_nothing_beyond_their_statements(module: str) -> None:
    granted = _granted()
    required = _required(module)
    for qualified, privileges in required.items():
        excess = sorted(granted[qualified] - privileges)
        assert not excess, f"{qualified} is granted {excess}, which {module} never issues"


@pytest.mark.parametrize("module", _RUNTIME_MODULES)
def test_no_runtime_adapter_deletes(module: str) -> None:
    """No runtime statement deletes, so no runtime grant may include DELETE."""
    source = (_ADAPTERS / module).read_text(encoding="utf-8")
    assert not _DELETE.findall(source), f"{module} issues a DELETE"


def test_no_forbidden_privilege_is_enumerated() -> None:
    for grant in RUNTIME_TABLE_GRANTS:
        overlap = sorted(set(grant.privileges) & set(FORBIDDEN_PRIVILEGES))
        assert not overlap, f"{grant.qualified()} enumerates {overlap}"


def test_the_grants_are_enumerated_rather_than_defaulted() -> None:
    """No ``ALL``, no ``ALL TABLES``, no ``CREATE``, no ownership."""
    composed = " ".join(
        statement.as_string(None) for statement in grant_statements("muster_runtime")
    )
    for widening in ("ALL TABLES", "ALL PRIVILEGES", " CREATE", "WITH GRANT OPTION", "OWNER"):
        assert widening not in composed.upper(), f"a grant statement contains {widening!r}"
    assert composed.count("GRANT") == len(RUNTIME_SCHEMAS) + len(RUNTIME_TABLE_GRANTS)


def test_every_granted_schema_gets_usage_and_nothing_else() -> None:
    usage = [
        statement
        for statement in grant_statements("muster_runtime")
        if "USAGE ON SCHEMA" in statement.as_string(None)
    ]
    assert len(usage) == len(RUNTIME_SCHEMAS)
    assert set(RUNTIME_SCHEMAS) == {grant.schema for grant in RUNTIME_TABLE_GRANTS}


@pytest.mark.parametrize("role", ["", "1runtime", "muster runtime", 'runtime";--', "run-time"])
def test_a_role_name_that_is_not_a_plain_identifier_is_refused(role: str) -> None:
    with pytest.raises(RuntimeGrantError):
        grant_statements(role)


def test_the_role_name_is_quoted_rather_than_interpolated() -> None:
    composed = grant_statements("muster_runtime")[0].as_string(None)
    assert '"muster_runtime"' in composed


def test_the_grants_never_revoke() -> None:
    """Additive and idempotent: bootstrap widens reach, it does not repair it.

    A privilege the role holds and the list does not name fails the report, and
    is left in the database for somebody to decide about.  A ``REVOKE`` here
    would make a deploy job the thing that removes a deliberate grant.
    """
    composed = " ".join(
        statement.as_string(None) for statement in grant_statements("muster_runtime")
    )
    assert "REVOKE" not in composed.upper()


#  ---- what the report asks, as opposed to what the list enumerates ---------
#
#  The gap these close: a report that asks only about the privileges the grant
#  list names, plus a fixed forbidden four, cannot see a privilege from the
#  vocabulary that is neither -- ``UPDATE`` on ``sandbox_rail.transfer`` being
#  exactly that, since ``UPDATE`` is grantable in general and forbidden there.


def test_the_vocabulary_is_the_whole_of_the_postgresql_table_privilege_set() -> None:
    assert set(TABLE_PRIVILEGES) == {
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
    }


def test_the_forbidden_set_is_the_vocabulary_minus_what_may_be_granted() -> None:
    """Derived, so a privilege added to the vocabulary is refused by default."""
    grantable = {privilege for grant in RUNTIME_TABLE_GRANTS for privilege in grant.privileges}
    assert set(FORBIDDEN_PRIVILEGES) == set(TABLE_PRIVILEGES) - grantable


@pytest.mark.parametrize("grant", RUNTIME_TABLE_GRANTS, ids=lambda g: g.qualified())
def test_every_table_is_asked_about_every_privilege(grant: TableGrant) -> None:
    expectations = dict(grant.expectations())
    assert set(expectations) == set(TABLE_PRIVILEGES), (
        f"{grant.qualified()} is not asked about the whole vocabulary, so a "
        "privilege outside its list would never be measured"
    )
    for privilege, forbidden in expectations.items():
        assert forbidden is not (privilege in grant.privileges)


def test_update_on_the_transfer_table_is_a_question_the_report_puts() -> None:
    """The exact hole: ``UPDATE`` is grantable, and forbidden on this table.

    ``sandbox_rail.transfer`` holds a synthetic acceptance that is written once
    and read forever.  A hand-issued ``GRANT UPDATE`` on it is a widening no
    "required present, DELETE/TRUNCATE absent" check would have noticed.
    """
    transfer = next(
        grant for grant in RUNTIME_TABLE_GRANTS if grant.qualified() == "sandbox_rail.transfer"
    )
    expectations = dict(transfer.expectations())
    assert expectations["UPDATE"] is True
    assert expectations["SELECT"] is False
    assert expectations["INSERT"] is False


def test_every_schema_is_asked_for_usage_and_against_create() -> None:
    assert set(SCHEMA_PRIVILEGES) == {"USAGE", "CREATE"}
    assert dict(schema_expectations()) == {"USAGE": False, "CREATE": True}


def test_the_database_level_question_is_create_and_only_create() -> None:
    """CONNECT is what the role needs; TEMPORARY is not this deployment's claim.

    ``infra/README.md`` step 3 revokes everything on the database from PUBLIC
    and grants the runtime role CONNECT alone, so CREATE -- which is
    ``CREATE SCHEMA``, a path to persistent objects that narrow table grants say
    nothing about -- is the one this promises is absent.
    """
    assert FORBIDDEN_DATABASE_PRIVILEGES == ("CREATE",)


def _finding(privilege: str, held: bool, forbidden: bool) -> PrivilegeFinding:
    return PrivilegeFinding("sandbox_rail.transfer", privilege, held, forbidden=forbidden)


def test_a_held_forbidden_privilege_makes_the_report_incomplete() -> None:
    """``complete()`` is false for a privilege that is present and unenumerated."""
    report = PrivilegeReport(
        "muster_runtime",
        True,
        (
            _finding("SELECT", True, False),
            _finding("INSERT", True, False),
            _finding("UPDATE", True, True),
        ),
    )
    assert not report.complete()
    assert [finding.privilege for finding in report.wrong()] == ["UPDATE"]
    assert "WRONG" in report.wrong()[0].line()


def test_ownership_is_reported_as_something_that_must_be_absent() -> None:
    assert OWNERSHIP == "OWNER"
    owned = PrivilegeFinding("casework.case_head", OWNERSHIP, True, forbidden=True)
    assert not owned.satisfied()
    assert PrivilegeFinding("casework.case_head", OWNERSHIP, False, forbidden=True).satisfied()
