"""Which custody the deployed run opens, and what it does instead of guessing.

The one property this file exists for: **a control plane told to be durable
never quietly becomes ephemeral.** Every way Cloud SQL can be unavailable --
absent configuration, an unmigrated database, a stale ledger, an unreachable
instance -- ends the run. None of them reaches the in-memory branch.

The converse matters too, and is why the in-memory branch still exists at all.
The verified Stage-90 run kept nothing and said so; that run must stay runnable
after this milestone, as something a deployment *names* rather than something
it falls back to.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from demo.cloud_hero import (
    CASE,
    EMPLOYER_ENDPOINT,
    EMPLOYER_KEY_REF,
    EMPLOYER_PUBLIC_KEY,
    SITE_ENDPOINT,
    SITE_KEY_REF,
    SITE_PUBLIC_KEY,
    TENANT,
    CloudFleet,
    DurableCase,
    _configuration_lines,
    build_transport,
    from_environment,
    main,
    open_database,
    read_durable_case,
)

from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.adapters.sql.config import (
    DATABASE_DEPLOYMENT,
    DATABASE_URL,
    DatabaseDeployment,
)
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.schema import SchemaNotCurrent

SERVER_CA = "/var/run/muster/cloud-sql/server-ca.pem"
#: TEST-NET-1 (RFC 5737), with a one-second bound.  Reserved for documentation,
#: routed nowhere, so this cannot reach a real database by accident.
UNREACHABLE_DSN = (
    "postgresql://muster-runtime:not-a-real-secret@192.0.2.1:5432/muster"
    f"?sslmode=verify-ca&sslrootcert={SERVER_CA}"
    "&connect_timeout=1&application_name=muster-control-plane"
)
SENTINEL = "sentinel-password-must-never-appear"


def _fleet_environment(**overrides: str) -> dict[str, str]:
    keys = base64.b64encode(b"-----BEGIN PUBLIC KEY-----\n").decode("ascii")
    environment = {
        TENANT: "TENANT-1",
        CASE: "CASE-RAVI-SAT-CLOUD",
        SITE_ENDPOINT: "https://site.example.run.app",
        EMPLOYER_ENDPOINT: "https://employer.example.run.app",
        SITE_KEY_REF: "site-key/1",
        EMPLOYER_KEY_REF: "employer-key/1",
        SITE_PUBLIC_KEY: keys,
        EMPLOYER_PUBLIC_KEY: keys,
    }
    environment.update(overrides)
    return environment


def _ephemeral() -> CloudFleet:
    return from_environment(
        _fleet_environment(**{DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value})
    )


def _cloud(dsn: str = UNREACHABLE_DSN) -> CloudFleet:
    return from_environment(
        _fleet_environment(
            **{
                DATABASE_DEPLOYMENT: DatabaseDeployment.CLOUD_SQL.value,
                DATABASE_URL: dsn,
            }
        )
    )


#  ---- the deployment names its custody ------------------------------------


def test_a_deployed_run_without_a_named_custody_does_not_start() -> None:
    with pytest.raises(SystemExit, match="DATABASE CONFIGURATION REFUSED"):
        from_environment(_fleet_environment())


def test_ephemeral_is_a_choice_a_deployment_makes() -> None:
    fleet = _ephemeral()

    assert fleet.deployment is DatabaseDeployment.EPHEMERAL
    assert fleet.postgres is None


def test_cloud_sql_carries_its_connection_string() -> None:
    fleet = _cloud()

    assert fleet.deployment is DatabaseDeployment.CLOUD_SQL
    assert fleet.postgres == UNREACHABLE_DSN


def test_a_fleet_cannot_claim_durability_it_has_no_database_for() -> None:
    """The other door: a fleet built directly rather than from an environment."""
    environment = _fleet_environment(
        **{DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value}
    )
    fields: dict[str, Any] = {
        "tenant_id": environment[TENANT],
        "case_id": environment[CASE],
        "site_endpoint": environment[SITE_ENDPOINT],
        "employer_endpoint": environment[EMPLOYER_ENDPOINT],
        "site_key_ref": environment[SITE_KEY_REF],
        "employer_key_ref": environment[EMPLOYER_KEY_REF],
        "site_public_key": b"",
        "employer_public_key": b"",
        "timeout_seconds": None,
        "raw_object": None,
    }

    with pytest.raises(ValueError, match="names no database"):
        CloudFleet(**fields, postgres=None, deployment=DatabaseDeployment.CLOUD_SQL)
    with pytest.raises(ValueError, match="carries no database"):
        CloudFleet(
            **fields,
            postgres=UNREACHABLE_DSN,
            deployment=DatabaseDeployment.EPHEMERAL,
        )


#  ---- and then opens exactly that -----------------------------------------


def test_ephemeral_custody_opens_the_in_memory_database() -> None:
    assert isinstance(open_database(_ephemeral()), MemoryDatabase)


def test_cloud_sql_that_cannot_be_reached_ends_the_run() -> None:
    """An unreachable instance is a refusal, and refusals do not return."""
    with pytest.raises(SystemExit) as raised:
        open_database(_cloud())

    #  The failure *class*, never the driver's message: libpq quotes connection
    #  fields, and Cloud Run logs are read by more people than the database is.
    assert "DATABASE CONNECTION REFUSED" in str(raised.value)
    assert SENTINEL not in str(raised.value)
    assert "not-a-real-secret" not in str(raised.value)
    assert "192.0.2.1" not in str(raised.value)


@pytest.mark.parametrize(
    "failure",
    (
        SchemaNotCurrent("the migration ledger is absent"),
        SchemaNotCurrent("migration identity disagrees with this build at version 4"),
        RuntimeError("some driver failure nobody anticipated"),
        OSError("the network went away"),
    ),
)
def test_no_cloud_sql_failure_reaches_the_in_memory_database(
    failure: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every branch, not only the one a live database happens to produce."""
    def refuse(_: str) -> tuple[int, ...]:
        raise failure

    monkeypatch.setattr("demo.cloud_hero.require_current_schema", refuse)

    with pytest.raises(SystemExit) as raised:
        open_database(_cloud())
    assert "REFUSED" in str(raised.value)


def test_a_current_schema_opens_the_durable_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("demo.cloud_hero.require_current_schema", lambda _: (1,))

    database = open_database(_cloud())

    assert isinstance(database, SqlDatabase)
    assert database.dsn == UNREACHABLE_DSN


#  ---- and reports which it opened -----------------------------------------


def test_the_configuration_report_names_the_custody_and_no_credential() -> None:
    for fleet, expected in ((_ephemeral(), "EPHEMERAL MEMORY"), (_cloud(), "CLOUD SQL")):
        lines = _configuration_lines(fleet, build_transport(fleet))
        store = next(line for line in lines if line.startswith("store"))
        assert expected in store
        #  A configuration report is printed by ``--print-configuration`` into a
        #  job log.  It says what this run is pointed at, and never with what.
        rendered = "\n".join(lines)
        assert "not-a-real-secret" not in rendered
        assert "postgresql://" not in rendered


def test_the_ephemeral_report_says_what_is_lost_rather_than_naming_a_store() -> None:
    """"in-memory" reads like a store.  It is the absence of one."""
    lines = _configuration_lines(_ephemeral(), build_transport(_ephemeral()))
    store = next(line for line in lines if line.startswith("store"))

    assert "not durable" in store


#  ---- reading a case a previous execution left behind ---------------------
#
#  The second half of the durability proof.  ``run_cloud_hero`` cannot be the
#  second half itself: it opens the case as its first act, and the fixture
#  re-signs its construction record in every process, so a second execution is
#  correctly refused as a different authored case.  These assert the read-only
#  path that does not have that problem because it does not open anything.


def test_reading_a_durable_case_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The property the whole proof rests on: it is a reader.

    A verification step that created what it went looking for would establish
    nothing at all, so the write scope is made to fail rather than trusted.
    """
    from muster.platform.adapters.memory import MemoryDatabase

    database = MemoryDatabase()

    def refuse(*_: object, **__: object) -> None:
        raise AssertionError("the durable read opened a write transaction")

    monkeypatch.setattr(type(database), "writing", refuse)

    with pytest.raises(SystemExit, match="DURABLE CASE ABSENT"):
        read_durable_case(database, tenant_id="ALPHA", case_id="CASE-RAVI-SAT-CLOUD")


def test_an_absent_case_is_a_refusal_and_not_an_empty_answer() -> None:
    from muster.platform.adapters.memory import MemoryDatabase

    with pytest.raises(SystemExit) as raised:
        read_durable_case(MemoryDatabase(), tenant_id="ALPHA", case_id="NO-SUCH-CASE")

    assert "DURABLE CASE ABSENT" in str(raised.value)


def test_ephemeral_custody_cannot_be_asked_what_it_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing survives one execution, so the question is a configuration error."""
    for name, value in _fleet_environment(
        **{DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value}
    ).items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(DATABASE_URL, raising=False)

    with pytest.raises(SystemExit, match="EPHEMERAL custody keeps nothing"):
        main(["--verify-durable-case"])


def test_the_durable_report_prints_identity_and_never_content() -> None:
    """Digests, counts and enum values.  The same closed vocabulary as the run."""
    durable = DurableCase(
        tenant_id="ALPHA",
        case_id="CASE-RAVI-SAT-CLOUD",
        revision_number=4,
        revision_digest="ab" * 32,
        certificate_digest="cd" * 32,
        construction_digest="12" * 32,
        authorization_context_digest="34" * 32,
        transcript_entries=9,
        transcript_digest="ef" * 32,
    )
    rendered = "\n".join(durable.lines())

    assert "CASE-RAVI-SAT-CLOUD" in rendered
    assert "ab" * 32 in rendered
    assert "cd" * 32 in rendered
    #  Nothing a source authored, and nothing that could carry a value.
    for forbidden in ("postgresql://", "detail", "Ravi", "hours", "shift"):
        assert forbidden not in rendered, forbidden
