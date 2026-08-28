"""The whole reconciliation sequence, run as the least-privileged runtime role.

Every other PostgreSQL suite here connects as the owner, because what those
suites are about is transaction semantics.  That is exactly how the live failure
got through: the deployed control plane does *not* connect as the owner, it
connects as ``muster_runtime``, and migration 7 created ``sandbox_rail`` without
granting that role anything on it.  ``ActionGate`` then behaved perfectly --
``UnknownOutcome("EXECUTOR_EXCEPTION", ...)``, a durable UNCERTAIN row, no
redispatch, and an inspection that refused to guess -- and the permission bug
was invisible behind it.

So this suite connects as a role that holds exactly
``runtime_grants.RUNTIME_TABLE_GRANTS`` and nothing else, and runs the sequence
end to end: a committed synthetic acceptance, a lost answer, a durable
UNCERTAIN, an observational reconciliation to CONFIRMED, and one transfer
throughout.  It also runs the *negative*: a role granted everything except
``sandbox_rail`` reproduces the live symptom exactly, which is what makes the
diagnosis a reproduction rather than a story.

**And it runs the other negative, which is a widening rather than a gap.**  A
report that asks only whether the enumerated privileges are present, and whether
a fixed forbidden four are absent, says ``complete()`` about a database in which
somebody has granted ``UPDATE`` on ``sandbox_rail.transfer`` -- because
``UPDATE`` is a privilege the role legitimately holds on four other tables, so
it is in neither list.  So each widening below is applied to a live database, one
privilege at a time, and the report must name that exact subject as WRONG:
unenumerated table privileges (including one granted on a single column), schema
``CREATE``, ``CREATE`` on the database, and ownership reached through role
membership.

It needs a test DSN whose role may ``CREATE ROLE``; it skips, by name, when it
does not.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from demo.cloud_hero import (
    CLOUD_ACTION_KIND,
    CLOUD_EXECUTOR_ID,
    CLOUD_GATE_ID,
    CloudFleet,
    HeroMode,
    cloud_executor,
)
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from muster.core.results import Ok
from muster.platform.adapters.sql.config import DatabaseDeployment
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.runtime_grants import (
    RUNTIME_SCHEMAS,
    RUNTIME_TABLE_GRANTS,
    PrivilegeReport,
    apply_runtime_grants,
    privilege_report,
)
from muster.platform.adapters.sql.sandbox_rail import (
    DurableSandboxPaymentExecutor,
    external_effect_evidence,
)
from muster.platform.casework.advance import Casework
from muster.platform.gate.authority import (
    ExecutionGrant,
    GateCaller,
    LocalExecutionAuthority,
)
from muster.platform.gate.model import ExecuteProposal, ExecutionLookup, ExecutionState
from muster.platform.gate.service import ActionGate
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

pytestmark = pytest.mark.postgres

PRINCIPAL = "muster-control-plane@muster-project.iam.gserviceaccount.com"

#  A local container's throwaway login.  Never a deployed credential: the
#  deployment's runtime password lives in Secret Manager and is not read by the
#  thing that grants, which needs the role's *name* and nothing else.
_PASSWORD = "runtime-role-suite"  # noqa: S105


def _runtime_dsn(owner_dsn: str, role: str) -> str:
    """The suite's own DSN, pointed at the same database as another role."""
    return make_conninfo(owner_dsn, user=role, password=_PASSWORD)


def _create_login_role(owner_dsn: str, role: str) -> None:
    with psycopg.connect(owner_dsn, autocommit=True) as connection:
        connection.execute(
            sql.SQL("CREATE ROLE {role} LOGIN PASSWORD {password}").format(
                role=sql.Identifier(role), password=sql.Literal(_PASSWORD)
            )
        )
        database = conninfo_to_dict(owner_dsn).get("dbname")
        assert isinstance(database, str)
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {database} TO {role}").format(
                database=sql.Identifier(database), role=sql.Identifier(role)
            )
        )


def _drop_login_role(owner_dsn: str, role: str) -> None:
    with psycopg.connect(owner_dsn, autocommit=True) as connection:
        for statement in (
            sql.SQL("DROP OWNED BY {role}").format(role=sql.Identifier(role)),
            sql.SQL("DROP ROLE IF EXISTS {role}").format(role=sql.Identifier(role)),
        ):
            connection.execute(statement)


def _as_owner(owner_dsn: str, statement: str) -> None:
    """One privilege statement, issued by the identity that owns these tables.

    The literal SQL is written in the test rather than composed, because what
    each of these tests is *about* is a statement a human could type against the
    deployed database by hand.  Nothing here reaches production code.
    """
    with psycopg.connect(owner_dsn, autocommit=True) as connection:
        connection.execute(statement)


def _held(report: PrivilegeReport) -> dict[str, set[str]]:
    """Subject -> the privileges the catalogue says the role actually holds."""
    holdings: dict[str, set[str]] = {}
    for finding in report.findings:
        holdings.setdefault(finding.subject, set())
        if finding.held:
            holdings[finding.subject].add(finding.privilege)
    return holdings


@pytest.fixture
def runtime_role(migrated_dsn: str) -> object:
    """A role holding exactly the enumerated runtime grants, and nothing else."""
    role = f"muster_runtime_{uuid.uuid4().hex[:12]}"
    try:
        _create_login_role(migrated_dsn, role)
    except psycopg.errors.InsufficientPrivilege:
        pytest.skip(f"the test DSN's role may not CREATE ROLE, so {role} cannot exist")
    try:
        apply_runtime_grants(migrated_dsn, role=role)
        yield role
    finally:
        _drop_login_role(migrated_dsn, role)


@pytest.fixture
def role_without_sandbox_rail(migrated_dsn: str) -> object:
    """The live deployment's state before the fix: every grant except sandbox_rail."""
    role = f"muster_nosandbox_{uuid.uuid4().hex[:12]}"
    try:
        _create_login_role(migrated_dsn, role)
    except psycopg.errors.InsufficientPrivilege:
        pytest.skip(f"the test DSN's role may not CREATE ROLE, so {role} cannot exist")
    try:
        with psycopg.connect(migrated_dsn) as connection, connection.transaction():
            for schema in RUNTIME_SCHEMAS:
                if schema == "sandbox_rail":
                    continue
                connection.execute(
                    sql.SQL("GRANT USAGE ON SCHEMA {schema} TO {role}").format(
                        schema=sql.Identifier(schema), role=sql.Identifier(role)
                    )
                )
            for grant in RUNTIME_TABLE_GRANTS:
                if grant.schema == "sandbox_rail":
                    continue
                connection.execute(
                    sql.SQL("GRANT {privileges} ON TABLE {table} TO {role}").format(
                        privileges=sql.SQL(", ").join(
                            sql.SQL(privilege) for privilege in grant.privileges
                        ),
                        table=sql.Identifier(grant.schema, grant.table),
                        role=sql.Identifier(role),
                    )
                )
        yield role
    finally:
        _drop_login_role(migrated_dsn, role)


def _fleet(dsn: str, tenant_id: str, case_id: str, **overrides: object) -> CloudFleet:
    settings: dict[str, object] = {
        "tenant_id": tenant_id,
        "case_id": case_id,
        "site_endpoint": "https://site.example.invalid",
        "employer_endpoint": "https://employer.example.invalid",
        "site_key_ref": "site-key/test",
        "employer_key_ref": "employer-key/test",
        "site_public_key": b"",
        "employer_public_key": b"",
        "timeout_seconds": None,
        "raw_object": None,
        "postgres": dsn,
        "deployment": DatabaseDeployment.CLOUD_SQL,
        "gate_mode": HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX,
        "gate_principal": PRINCIPAL,
    }
    settings.update(overrides)
    return CloudFleet(**settings)  # type: ignore[arg-type]


def _gate(casework: Casework, tenant_id: str, executor: object) -> ActionGate:
    return ActionGate(
        casework=casework,
        executor=executor,  # type: ignore[arg-type]
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=PRINCIPAL,
                    tenant_id=tenant_id,
                    action_kind=CLOUD_ACTION_KIND,
                    gate_id=CLOUD_GATE_ID,
                    executor_id=CLOUD_EXECUTOR_ID,
                ),
            )
        ),
        gate_id=CLOUD_GATE_ID,
    )


def _analysed_proposal(dsn: str, tenant_id: str, case_id: str) -> tuple[Casework, ExecuteProposal]:
    casework = ravi.casework(SqlDatabase(dsn))
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    _report, request = proposal(casework, case)
    return casework, request


#  ---- what the grants establish -------------------------------------------


def test_the_enumerated_grants_satisfy_the_privilege_report(
    migrated_dsn: str, runtime_role: str
) -> None:
    report = privilege_report(migrated_dsn, role=runtime_role)
    assert report.role_exists
    assert report.wrong() == (), [finding.line() for finding in report.wrong()]
    assert report.complete()


def test_the_runtime_role_still_cannot_write_schema_or_remove_rows(
    migrated_dsn: str, runtime_role: str
) -> None:
    """The grants widened the role's reach and not its powers.

    Three refusals, the same three ``infra/README.md`` asks an operator for,
    plus the two the sandbox schema introduced.  If any of these succeeded the
    fix would have traded a permission bug for a boundary.
    """
    refused = (
        "CREATE TABLE casework.should_be_refused (x int)",
        "DROP TABLE casework.transcript_entry",
        "TRUNCATE casework.case_head",
        "DELETE FROM sandbox_rail.transfer",
        "CREATE TABLE sandbox_rail.should_be_refused (x int)",
        "UPDATE sandbox_rail.transfer SET external_reference = 'x'",
    )
    for statement in refused:
        with psycopg.connect(_runtime_dsn(migrated_dsn, runtime_role)) as connection:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                connection.execute(statement)
            connection.rollback()


def test_the_report_asks_about_the_sandbox_privileges_it_requires(
    migrated_dsn: str, runtime_role: str
) -> None:
    """The positive half, named: the two sandbox tables, exactly their grants.

    ``attempt`` writes a marker and seals it; ``transfer`` writes an acceptance
    once and reads it forever.  Both must be present, and ``UPDATE`` on
    ``transfer`` must not be.
    """
    held = _held(privilege_report(migrated_dsn, role=runtime_role))
    assert held["sandbox_rail.attempt"] >= {"SELECT", "INSERT", "UPDATE"}
    assert held["sandbox_rail.transfer"] >= {"SELECT", "INSERT"}
    assert "UPDATE" not in held["sandbox_rail.transfer"]
    assert "DELETE" not in held["sandbox_rail.transfer"]
    assert "USAGE" in held["sandbox_rail"]
    assert "CREATE" not in held["sandbox_rail"]


#  ---- a widening the report must refuse ------------------------------------
#
#  Each of these grants one privilege the enumerated list does not name, and
#  asserts the report says WRONG about that exact subject.  The one that pays
#  for the suite is ``UPDATE`` on ``sandbox_rail.transfer``: it is a privilege
#  the role legitimately holds on four *other* tables, so a report that checks
#  "required present, DELETE/TRUNCATE/REFERENCES/TRIGGER absent" answers
#  ``complete()`` for a database in which an acceptance can be rewritten.


@pytest.mark.parametrize(
    ("widening", "subject", "privilege"),
    [
        pytest.param(
            "GRANT UPDATE ON sandbox_rail.transfer TO {role}",
            "sandbox_rail.transfer",
            "UPDATE",
            id="update-on-transfer",
        ),
        pytest.param(
            "GRANT UPDATE (external_reference) ON sandbox_rail.transfer TO {role}",
            "sandbox_rail.transfer",
            "UPDATE",
            id="update-on-one-column-of-transfer",
        ),
        pytest.param(
            "GRANT INSERT ON platform.schema_migration TO {role}",
            "platform.schema_migration",
            "INSERT",
            id="insert-on-the-ledger",
        ),
        pytest.param(
            "GRANT UPDATE ON platform.schema_migration TO {role}",
            "platform.schema_migration",
            "UPDATE",
            id="update-on-the-ledger",
        ),
        pytest.param(
            "GRANT DELETE ON casework.transcript_entry TO {role}",
            "casework.transcript_entry",
            "DELETE",
            id="delete-on-the-transcript",
        ),
        pytest.param(
            "GRANT TRUNCATE ON casework.case_head TO {role}",
            "casework.case_head",
            "TRUNCATE",
            id="truncate-on-the-case-head",
        ),
        pytest.param(
            "GRANT REFERENCES ON store.content TO {role}",
            "store.content",
            "REFERENCES",
            id="references-on-the-store",
        ),
        pytest.param(
            "GRANT TRIGGER ON action_gate.execution TO {role}",
            "action_gate.execution",
            "TRIGGER",
            id="trigger-on-the-execution-table",
        ),
        pytest.param(
            "GRANT CREATE ON SCHEMA sandbox_rail TO {role}",
            "sandbox_rail",
            "CREATE",
            id="create-on-a-runtime-schema",
        ),
    ],
)
def test_one_unenumerated_privilege_makes_the_report_wrong(
    migrated_dsn: str, runtime_role: str, widening: str, subject: str, privilege: str
) -> None:
    assert privilege_report(migrated_dsn, role=runtime_role).complete()

    _as_owner(migrated_dsn, widening.format(role=f'"{runtime_role}"'))

    report = privilege_report(migrated_dsn, role=runtime_role)
    assert not report.complete(), (
        f"{widening} left the report saying the privileges are exactly the set"
    )
    wrong = {(finding.subject, finding.privilege) for finding in report.wrong()}
    assert (subject, privilege) in wrong, sorted(wrong)


def test_create_on_the_database_makes_the_report_wrong(
    migrated_dsn: str, runtime_role: str
) -> None:
    """Narrow table grants say nothing about ``CREATE SCHEMA``.

    ``infra/README.md`` step 3 revokes everything on the database from PUBLIC
    and grants the runtime role ``CONNECT`` alone, so this is that promise with
    a measurement behind it: a role that may create a schema may put persistent
    objects beside the enumerated ones and own them.
    """
    database = conninfo_to_dict(migrated_dsn).get("dbname")
    assert isinstance(database, str)
    assert privilege_report(migrated_dsn, role=runtime_role).complete()

    _as_owner(migrated_dsn, f'GRANT CREATE ON DATABASE "{database}" TO "{runtime_role}"')
    try:
        report = privilege_report(migrated_dsn, role=runtime_role)
        assert not report.complete()
        assert {(finding.subject, finding.privilege) for finding in report.wrong()} == {
            (f"database {database}", "CREATE")
        }
    finally:
        _as_owner(migrated_dsn, f'REVOKE CREATE ON DATABASE "{database}" FROM "{runtime_role}"')


def test_ownership_reached_through_role_membership_makes_the_report_wrong(
    migrated_dsn: str, runtime_role: str
) -> None:
    """An owner holds everything implicitly, and may DROP.

    Measured with ``pg_has_role``, so membership of the owning role counts --
    which is how a role acquires ownership without any ``ALTER TABLE ... OWNER``
    ever naming it, and is invisible to anything that reads ``relacl``.
    """
    owner = conninfo_to_dict(migrated_dsn).get("user")
    assert isinstance(owner, str)
    assert privilege_report(migrated_dsn, role=runtime_role).complete()

    _as_owner(migrated_dsn, f'GRANT "{owner}" TO "{runtime_role}"')
    try:
        report = privilege_report(migrated_dsn, role=runtime_role)
        assert not report.complete()
        owned = {finding.subject for finding in report.wrong() if finding.privilege == "OWNER"}
        assert "sandbox_rail" in owned
        assert "sandbox_rail.transfer" in owned
    finally:
        _as_owner(migrated_dsn, f'REVOKE "{owner}" FROM "{runtime_role}"')


#  ---- the sequence, as the role the deployment actually connects as --------


def test_the_runtime_role_completes_unknown_then_reconciliation(
    migrated_dsn: str, runtime_role: str, tenant_id: str, case_id: str
) -> None:
    """Setup, reconciliation and repeat, all over one least-privileged connection."""
    dsn = _runtime_dsn(migrated_dsn, runtime_role)

    setup_fleet = _fleet(dsn, tenant_id, case_id, gate_simulate_unknown=True)
    casework, request = _analysed_proposal(dsn, tenant_id, case_id)
    setup_executor = cloud_executor(setup_fleet)
    caller = GateCaller(PRINCIPAL)
    performed = _gate(casework, tenant_id, setup_executor).execute(
        caller=caller, tenant_id=tenant_id, request=request, now=ravi.NOW
    )
    assert isinstance(performed, Ok), performed
    key = performed.value.execution_key.hex

    #  The external effect committed, and the answer was lost after it.
    assert performed.value.state is ExecutionState.UNCERTAIN
    assert performed.value.outcome_code == "EXECUTOR_EXCEPTION"
    assert performed.value.external_reference is None
    assert setup_executor.dispatch_count == 1
    evidence = external_effect_evidence(dsn, key)
    assert evidence.attempt is not None
    assert evidence.attempt.outcome == "ATTEMPTED"
    assert evidence.transfer is not None
    assert evidence.transfer.external_reference == f"sandbox-pay-{key}"
    assert evidence.transfer_count == 1

    #  A second process, no simulation, and the reconciliation entry point.
    reconciling_executor = cloud_executor(_fleet(dsn, tenant_id, case_id))
    assert isinstance(reconciling_executor, DurableSandboxPaymentExecutor)
    reconciled = _gate(
        ravi.casework(SqlDatabase(dsn)), tenant_id, reconciling_executor
    ).reconcile_execution(
        caller=caller,
        tenant_id=tenant_id,
        lookup=ExecutionLookup(
            execution_key=performed.value.execution_key, expected_case_id=case_id
        ),
        now=ravi.NOW,
    )
    assert isinstance(reconciled, Ok), reconciled
    assert reconciled.value.state is ExecutionState.CONFIRMED
    assert reconciled.value.reconciled_from is ExecutionState.UNCERTAIN
    assert reconciled.value.reconciled_at is not None
    assert reconciled.value.external_reference == f"sandbox-pay-{key}"
    assert reconciling_executor.dispatch_count == 0
    assert reconciling_executor.inspection_count == 1
    assert external_effect_evidence(dsn, key).transfer_count == 1


def test_a_role_without_sandbox_rail_reproduces_the_live_failure(
    migrated_dsn: str, role_without_sandbox_rail: str, tenant_id: str, case_id: str
) -> None:
    """The diagnosis, reproduced: no grant, no external effect, UNCERTAIN.

    This is the exact live symptom -- ``EXECUTOR_EXCEPTION``, no external
    reference, one dispatch, and *no* transfer -- which is also why the historic
    execution it produced could not honestly be reconciled: there was nothing
    outside MUSTER for an observation to find.
    """
    dsn = _runtime_dsn(migrated_dsn, role_without_sandbox_rail)
    fleet = _fleet(dsn, tenant_id, case_id, gate_simulate_unknown=True)
    casework, request = _analysed_proposal(dsn, tenant_id, case_id)
    executor = cloud_executor(fleet)
    caller = GateCaller(PRINCIPAL)

    performed = _gate(casework, tenant_id, executor).execute(
        caller=caller, tenant_id=tenant_id, request=request, now=ravi.NOW
    )

    assert isinstance(performed, Ok), performed
    record = performed.value
    assert record.state is ExecutionState.UNCERTAIN
    assert record.outcome_code == "EXECUTOR_EXCEPTION"
    assert record.external_reference is None
    assert record.detail == "InsufficientPrivilege"
    assert executor.dispatch_count == 1
    #  Read as the owner: the role under test cannot see the schema at all.
    assert external_effect_evidence(migrated_dsn, record.execution_key.hex).transfer is None
    assert external_effect_evidence(migrated_dsn, record.execution_key.hex).transfer_count == 0
