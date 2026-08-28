"""The exact privileges the runtime role needs, enumerated beside the schema.

**A migration that adds a table does not grant on it.**  That sentence was true
of ``infra/README.md`` and it was written there as an instruction to an
operator, which is a place a step gets forgotten: migration 7 added
``sandbox_rail`` and the runtime role was never granted anything on it, so the
durable sandbox executor's first statement failed with SQLSTATE ``42501``.  The
Gate turned that into ``UnknownOutcome("EXECUTOR_EXCEPTION", ...)`` -- correct,
fail-closed behaviour over a cause that had nothing to do with an external
world.

So the grant list lives here, next to ``migrations``, as data:

* it is enumerated rather than defaulted.  ``GRANT ... ON ALL TABLES`` and
  ``ALTER DEFAULT PRIVILEGES`` both widen silently with the schema, and the
  point of this role is that what it may do is a list somebody read;
* every privilege below is one a statement in ``adapters.sql`` actually issues,
  and no other.  ``UPDATE`` appears on exactly the four tables that
  compare-and-set or seal;
* :func:`privilege_report` asks the database about the *whole* privilege
  vocabulary for every runtime object, not only about the privileges this file
  enumerates.  Presence of a listed privilege and **absence of every unlisted
  one** are both measurements, so a hand-issued ``GRANT UPDATE ON
  sandbox_rail.transfer`` is a finding rather than a question the report never
  put.  Schema ``CREATE``, ownership of a runtime schema or table, and
  ``CREATE`` on the database are measured the same way;
* a test walks ``MIGRATIONS`` and refuses a table this file does not mention,
  so the next migration cannot repeat migration 7's omission.

Applying it is :func:`apply_runtime_grants`, called by the schema bootstrap --
the one identity in the deployment that performs DDL and the only one that owns
these tables.  It only ever grants: a privilege the report finds and this file
does not list is *reported*, never revoked, because bootstrap is not the thing
that decides a privilege somebody granted deliberately was a mistake.  Nothing
in the request path imports this module.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg
from psycopg import sql

#: The PostgreSQL login role the control plane connects as.  Not a secret: it
#: is a role name, and the password that goes with it lives in Secret Manager.
RUNTIME_ROLE = "muster_runtime"

#: Every privilege PostgreSQL can grant on a table.  :func:`privilege_report`
#: asks about all of them for every runtime table, which is the difference
#: between "the privileges we listed are held" and "the privileges held are the
#: ones we listed".  Only the second one notices a widening nobody enumerated.
TABLE_PRIVILEGES: tuple[str, ...] = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)

#: The only privileges this role may be granted at all.  A wider one in the
#: table below is a mistake caught when the module is imported.
_GRANTABLE: frozenset[str] = frozenset({"SELECT", "INSERT", "UPDATE"})

#: Privileges the runtime role must never hold on any table it can reach --
#: derived from the vocabulary rather than typed a second time, so a privilege
#: added to :data:`TABLE_PRIVILEGES` is forbidden by default rather than
#: unasked.  Read back by :func:`privilege_report`, so "no DELETE, no TRUNCATE"
#: is a measurement against the live database rather than an assertion about a
#: script that was supposed to have run.
FORBIDDEN_PRIVILEGES: tuple[str, ...] = tuple(
    privilege for privilege in TABLE_PRIVILEGES if privilege not in _GRANTABLE
)

#: Every privilege PostgreSQL can grant on a schema.  ``USAGE`` is required and
#: ``CREATE`` is refused: a role that may create in a schema it does not own can
#: put a table beside the ones the grant list enumerates.
SCHEMA_PRIVILEGES: tuple[str, ...] = ("USAGE", "CREATE")
_REQUIRED_SCHEMA_PRIVILEGES: frozenset[str] = frozenset({"USAGE"})

#: Database-level privileges the runtime role must not hold.  ``CREATE`` on the
#: database is ``CREATE SCHEMA``, which is a path to persistent objects that
#: narrow table grants do nothing about -- ``infra/README.md`` step 3 revokes
#: everything from ``PUBLIC`` and grants the runtime role ``CONNECT`` alone, and
#: this is that promise measured.  ``CONNECT`` and ``TEMPORARY`` are
#: deliberately not here: the first is what the role needs to work at all, and
#: the second is a session-lifetime object this deployment takes no position on.
FORBIDDEN_DATABASE_PRIVILEGES: tuple[str, ...] = ("CREATE",)

#: How ownership is named in a report line.  Not a privilege PostgreSQL grants:
#: an owner holds every privilege on the object implicitly and may ``DROP`` it,
#: so a runtime role that owns a runtime table has all of the above regardless
#: of what any ``GRANT`` says.
OWNERSHIP = "OWNER"

#: Privileges PostgreSQL can also grant on a single column.  The absence checks
#: use ``has_any_column_privilege`` for these, because a column-level
#: ``GRANT UPDATE (external_reference)`` is a widening that
#: ``has_table_privilege`` answers ``false`` to.
_COLUMN_CAPABLE: frozenset[str] = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})


class RuntimeGrantError(RuntimeError):
    """The runtime role or its schema is not in a state grants may be applied to."""


@dataclass(frozen=True, slots=True)
class TableGrant:
    """One table, and the exact privileges the adapters' statements need on it."""

    schema: str
    table: str
    privileges: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.privileges:
            raise ValueError("a table grant names at least one privilege")
        if not set(self.privileges) <= _GRANTABLE:
            raise ValueError(f"{self.qualified()} names a privilege outside the runtime set")

    def qualified(self) -> str:
        return f"{self.schema}.{self.table}"

    def expectations(self) -> tuple[tuple[str, bool], ...]:
        """Every table privilege, and whether *holding* it is the defect.

        The whole vocabulary rather than this grant's own privileges, so the
        report puts a question about ``UPDATE`` to ``sandbox_rail.transfer`` --
        a table that must not have it -- instead of asking only about the two
        privileges it is supposed to have and finding them both present.
        """
        required = set(self.privileges)
        return tuple((privilege, privilege not in required) for privilege in TABLE_PRIVILEGES)


#  Every entry is justified by a statement in this package:
#
#    store.content                INSERT ... ON CONFLICT DO NOTHING, and SELECT
#    casework.case_head           SELECT ... FOR UPDATE and a compare-and-set
#    casework.transcript_entry    append-only
#    casework.evidence_request    append-only
#    casework.case_commitment     append-only
#    authority.registry_snapshot  append-only
#    authority.revocation_snapshot append-only
#    authority.publication_state  ON CONFLICT ... DO UPDATE
#    catalog.agent_snapshot       append-only
#    action_gate.execution        reserve, begin_dispatch, finalize, reconcile
#    sandbox_rail.attempt         INSERT the marker, UPDATE it to sealed, SELECT
#    sandbox_rail.transfer        INSERT the acceptance, SELECT and count it
#    platform.schema_migration    the runtime reads the ledger and never writes
RUNTIME_TABLE_GRANTS: tuple[TableGrant, ...] = (
    TableGrant("store", "content", ("SELECT", "INSERT")),
    TableGrant("casework", "case_head", ("SELECT", "INSERT", "UPDATE")),
    TableGrant("casework", "transcript_entry", ("SELECT", "INSERT")),
    TableGrant("casework", "evidence_request", ("SELECT", "INSERT")),
    TableGrant("casework", "case_commitment", ("SELECT", "INSERT")),
    TableGrant("authority", "registry_snapshot", ("SELECT", "INSERT")),
    TableGrant("authority", "revocation_snapshot", ("SELECT", "INSERT")),
    TableGrant("authority", "publication_state", ("SELECT", "INSERT", "UPDATE")),
    TableGrant("catalog", "agent_snapshot", ("SELECT", "INSERT")),
    TableGrant("action_gate", "execution", ("SELECT", "INSERT", "UPDATE")),
    #  Outside MUSTER custody, and reached only by the durable sandbox executor.
    #  Granted for the same reason as everything else here -- the executor's SQL
    #  needs it -- and no wider: no DELETE, because durable external evidence is
    #  never withdrawn, and no UPDATE on ``transfer``, because an acceptance is
    #  written once and read forever.
    TableGrant("sandbox_rail", "attempt", ("SELECT", "INSERT", "UPDATE")),
    TableGrant("sandbox_rail", "transfer", ("SELECT", "INSERT")),
    TableGrant("platform", "schema_migration", ("SELECT",)),
)

#: USAGE, in the order the tables above first name each schema.  Never CREATE.
RUNTIME_SCHEMAS: tuple[str, ...] = tuple(
    dict.fromkeys(grant.schema for grant in RUNTIME_TABLE_GRANTS)
)


def schema_expectations() -> tuple[tuple[str, bool], ...]:
    """Every schema privilege, and whether *holding* it is the defect."""
    return tuple(
        (privilege, privilege not in _REQUIRED_SCHEMA_PRIVILEGES)
        for privilege in SCHEMA_PRIVILEGES
    )


@dataclass(frozen=True, slots=True)
class PrivilegeFinding:
    """One privilege that was asked about, and what the database answered."""

    subject: str
    privilege: str
    held: bool
    #: ``True`` when *holding* it is the defect: every privilege outside this
    #: object's enumerated set, schema ``CREATE``, ownership, database ``CREATE``.
    forbidden: bool = False

    def satisfied(self) -> bool:
        return self.held is not self.forbidden

    def line(self) -> str:
        expected = "absent" if self.forbidden else "present"
        actual = "present" if self.held else "absent"
        verdict = "ok" if self.satisfied() else "WRONG"
        return f"{self.subject:<30} {self.privilege:<10} {expected:<8} {actual:<8} {verdict}"


@dataclass(frozen=True, slots=True)
class PrivilegeReport:
    """What the live database says the runtime role may, and may not, do."""

    role: str
    role_exists: bool
    findings: tuple[PrivilegeFinding, ...]

    def wrong(self) -> tuple[PrivilegeFinding, ...]:
        return tuple(finding for finding in self.findings if not finding.satisfied())

    def complete(self) -> bool:
        return self.role_exists and bool(self.findings) and not self.wrong()

    def lines(self) -> tuple[str, ...]:
        header = (
            f"runtime role           {self.role}",
            f"role exists            {'yes' if self.role_exists else 'no'}",
            f"privileges asked       {len(self.findings)}",
            f"privileges wrong       {len(self.wrong())}",
            "",
            f"{'SUBJECT':<30} {'PRIVILEGE':<10} {'EXPECTED':<8} {'ACTUAL':<8} VERDICT",
        )
        return header + tuple(finding.line() for finding in self.findings)


def grant_statements(role: str = RUNTIME_ROLE) -> tuple[sql.Composed, ...]:
    """The enumerated GRANTs, composed with quoted identifiers and no values.

    Repeatable: PostgreSQL treats a grant already held as a no-op, so running
    this after every migration is the same operation every time.  Additive by
    construction -- there is no ``REVOKE`` here, and see
    :func:`apply_runtime_grants` for why not.
    """
    _require_role_name(role)
    principal = sql.Identifier(role)
    statements: list[sql.Composed] = [
        sql.SQL("GRANT USAGE ON SCHEMA {schema} TO {role}").format(
            schema=sql.Identifier(schema), role=principal
        )
        for schema in RUNTIME_SCHEMAS
    ]
    statements.extend(
        sql.SQL("GRANT {privileges} ON TABLE {table} TO {role}").format(
            #  Closed vocabulary: ``TableGrant`` refuses anything outside
            #  ``_GRANTABLE``, so these three tokens are the only ones that can
            #  ever reach ``sql.SQL`` here.
            privileges=sql.SQL(", ").join(
                sql.SQL(privilege) for privilege in grant.privileges
            ),
            table=sql.Identifier(grant.schema, grant.table),
            role=principal,
        )
        for grant in RUNTIME_TABLE_GRANTS
    )
    return tuple(statements)


def apply_runtime_grants(dsn: str, *, role: str = RUNTIME_ROLE) -> int:
    """Grant exactly :data:`RUNTIME_TABLE_GRANTS`, as the owner, in one transaction.

    Refuses before writing anything when the role does not exist: a grant to an
    absent role is an error PostgreSQL reports per statement, and half an
    applied list is the state this exists to make impossible.

    **Additive only.**  A privilege the role holds and this file does not list
    is left alone here and reported as WRONG by :func:`privilege_report`, which
    fails the bootstrap.  Revoking it would make bootstrap a repair for a
    widening nobody has read yet, and a ``REVOKE`` issued by a job is exactly
    how a deliberate grant disappears without anyone deciding it should.
    """
    statements = grant_statements(role)
    with psycopg.connect(dsn) as connection:
        if not _role_exists(connection, role):
            raise RuntimeGrantError(
                f"the runtime role {role!r} does not exist; create it before granting"
            )
        with connection.transaction():
            for statement in statements:
                connection.execute(statement)
    return len(statements)


def privilege_report(dsn: str, *, role: str = RUNTIME_ROLE) -> PrivilegeReport:
    """Read back, read-only, what the role may and may not do.  Writes nothing.

    Every answer is an *effective* one.  ``has_*_privilege`` and ``pg_has_role``
    resolve role membership and ``PUBLIC`` the way the executor does, so a
    privilege reached through a role the runtime role is a member of is held
    here too -- which reading ``relacl`` strings would have missed.
    """
    _require_role_name(role)
    findings: list[PrivilegeFinding] = []
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        if not _role_exists(connection, role):
            return PrivilegeReport(role, False, ())
        for schema in RUNTIME_SCHEMAS:
            for privilege, forbidden in schema_expectations():
                findings.append(
                    PrivilegeFinding(
                        schema,
                        privilege,
                        _has_schema_privilege(connection, role, schema, privilege),
                        forbidden=forbidden,
                    )
                )
            findings.append(
                PrivilegeFinding(
                    schema, OWNERSHIP, _owns_schema(connection, role, schema), forbidden=True
                )
            )
        for grant in RUNTIME_TABLE_GRANTS:
            qualified = grant.qualified()
            for privilege, forbidden in grant.expectations():
                findings.append(
                    PrivilegeFinding(
                        qualified,
                        privilege,
                        _has_table_privilege(
                            connection, role, qualified, privilege, any_column=forbidden
                        ),
                        forbidden=forbidden,
                    )
                )
            findings.append(
                PrivilegeFinding(
                    qualified,
                    OWNERSHIP,
                    _owns_table(connection, role, qualified),
                    forbidden=True,
                )
            )
        database = connection.info.dbname
        for privilege in FORBIDDEN_DATABASE_PRIVILEGES:
            findings.append(
                PrivilegeFinding(
                    f"database {database}",
                    privilege,
                    _has_database_privilege(connection, role, privilege),
                    forbidden=True,
                )
            )
    return PrivilegeReport(role, True, tuple(findings))


def _role_exists(connection: psycopg.Connection[tuple[object, ...]], role: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s", (role,)
    ).fetchone()
    return row is not None


def _has_schema_privilege(
    connection: psycopg.Connection[tuple[object, ...]],
    role: str,
    schema: str,
    privilege: str,
) -> bool:
    row = connection.execute(
        "SELECT pg_catalog.has_schema_privilege(%s, %s, %s)", (role, schema, privilege)
    ).fetchone()
    return bool(row and row[0])


def _has_table_privilege(
    connection: psycopg.Connection[tuple[object, ...]],
    role: str,
    qualified: str,
    privilege: str,
    *,
    any_column: bool,
) -> bool:
    """Whether the role effectively holds ``privilege`` on ``qualified``.

    ``any_column`` widens the question to column-level grants, and the caller
    passes it for exactly the privileges that must be *absent*: a table without
    ``UPDATE`` but with ``UPDATE (one_column)`` can still write that column, and
    ``has_table_privilege`` says ``false`` about it.  The requirement side keeps
    the table-level question, because a column grant would not be enough for the
    statements the adapters actually issue.
    """
    #  Two literal names from a closed set, chosen here and never from input.
    function = (
        "has_any_column_privilege"
        if any_column and privilege in _COLUMN_CAPABLE
        else "has_table_privilege"
    )
    row = connection.execute(
        f"SELECT pg_catalog.{function}(%s, %s, %s)", (role, qualified, privilege)
    ).fetchone()
    return bool(row and row[0])


def _has_database_privilege(
    connection: psycopg.Connection[tuple[object, ...]], role: str, privilege: str
) -> bool:
    row = connection.execute(
        "SELECT pg_catalog.has_database_privilege(%s, pg_catalog.current_database(), %s)",
        (role, privilege),
    ).fetchone()
    return bool(row and row[0])


def _owns_schema(
    connection: psycopg.Connection[tuple[object, ...]], role: str, schema: str
) -> bool:
    row = connection.execute(
        "SELECT pg_catalog.pg_has_role(%s, n.nspowner, 'USAGE')"
        " FROM pg_catalog.pg_namespace n WHERE n.nspname = %s",
        (role, schema),
    ).fetchone()
    return bool(row and row[0])


def _owns_table(
    connection: psycopg.Connection[tuple[object, ...]], role: str, qualified: str
) -> bool:
    """Ownership, effectively: membership of the owning role is ownership.

    ``pg_has_role(..., 'USAGE')`` is the question PostgreSQL asks itself before
    allowing ``DROP``, so this covers a runtime role made a member of
    ``muster_migrator`` as well as one made the owner outright.
    """
    row = connection.execute(
        "SELECT pg_catalog.pg_has_role(%s, c.relowner, 'USAGE')"
        " FROM pg_catalog.pg_class c WHERE c.oid = %s::regclass",
        (role, qualified),
    ).fetchone()
    return bool(row and row[0])


def _require_role_name(role: str) -> None:
    """A role name is an identifier this deployment chose, never caller input.

    Composed with :class:`psycopg.sql.Identifier` regardless, so this is about
    catching a misconfiguration early rather than about quoting.
    """
    if not role or role[0].isdigit() or not role.replace("_", "").isalnum():
        raise RuntimeGrantError(
            "the runtime role name must be a plain unquoted PostgreSQL identifier"
        )
