"""Database deployment configuration fails closed without exposing credentials."""

from __future__ import annotations

import traceback

import pytest
from demo.database_bootstrap import main

from muster.platform.adapters.sql.config import (
    DATABASE_DEPLOYMENT,
    DATABASE_URL,
    MIGRATION_DATABASE_URL,
    DatabaseConfigurationError,
    DatabaseDeployment,
    configuration_from_environment,
)

LOCAL_DSN = "postgresql://muster:muster@127.0.0.1:55432/muster"
SERVER_CA = "/var/run/muster/cloud-sql/server-ca.pem"
CLOUD_DSN = (
    "postgresql://muster-runtime:not-a-real-secret@10.20.0.3:5432/muster"
    f"?sslmode=verify-ca&sslrootcert={SERVER_CA}"
    "&connect_timeout=10&application_name=muster-control-plane"
)

#: A password that exists only to be looked for.  Every assertion about leakage
#: below searches for this exact string, so a test that passes is a test that
#: went looking rather than one that trusted a redaction.
SENTINEL = "sentinel-password-must-never-appear"


def _cloud_environment(dsn: str = CLOUD_DSN) -> dict[str, str]:
    return {
        DATABASE_DEPLOYMENT: DatabaseDeployment.CLOUD_SQL.value,
        DATABASE_URL: dsn,
    }


#  ---- the three custodies -------------------------------------------------


def test_the_existing_local_postgresql_configuration_still_reads() -> None:
    """No label, one DSN: the convention every local command already uses."""
    configuration = configuration_from_environment({DATABASE_URL: LOCAL_DSN})

    assert configuration.deployment is DatabaseDeployment.LOCAL
    assert configuration.dsn == LOCAL_DSN


def test_ephemeral_custody_is_named_and_carries_no_database() -> None:
    """In-memory custody a deployment *chose*, not one it fell back to."""
    configuration = configuration_from_environment(
        {DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value},
        require_deployed=True,
    )

    assert configuration.deployment is DatabaseDeployment.EPHEMERAL
    assert configuration.dsn is None


def test_ephemeral_custody_refuses_a_database_rather_than_choosing_between_them() -> None:
    """Naming both is not a precedence question; it is an undecided deployment."""
    with pytest.raises(DatabaseConfigurationError, match="takes no"):
        configuration_from_environment(
            {
                DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value,
                DATABASE_URL: CLOUD_DSN,
            },
            require_deployed=True,
        )


def test_a_deployed_control_plane_must_name_its_custody() -> None:
    with pytest.raises(DatabaseConfigurationError, match=DATABASE_DEPLOYMENT):
        configuration_from_environment({DATABASE_URL: CLOUD_DSN}, require_deployed=True)


def test_a_deployed_control_plane_may_not_inherit_the_local_convention() -> None:
    """``LOCAL`` is a developer's database.  A deployment names one of two kinds."""
    with pytest.raises(DatabaseConfigurationError, match="EPHEMERAL or CLOUD_SQL"):
        configuration_from_environment(
            {
                DATABASE_DEPLOYMENT: DatabaseDeployment.LOCAL.value,
                DATABASE_URL: LOCAL_DSN,
            },
            require_deployed=True,
        )


def test_an_unknown_custody_is_refused_by_name() -> None:
    with pytest.raises(DatabaseConfigurationError, match="malformed"):
        configuration_from_environment(
            {DATABASE_DEPLOYMENT: "FIRESTORE"}, require_deployed=True
        )


def test_cloud_sql_requires_its_connection_string() -> None:
    with pytest.raises(DatabaseConfigurationError, match=DATABASE_URL):
        configuration_from_environment(
            {DATABASE_DEPLOYMENT: DatabaseDeployment.CLOUD_SQL.value},
            require_deployed=True,
        )


def test_a_valid_cloud_sql_dsn_is_ordinary_postgresql_configuration() -> None:
    configuration = configuration_from_environment(
        _cloud_environment(), require_deployed=True
    )

    assert configuration.deployment is DatabaseDeployment.CLOUD_SQL
    assert configuration.dsn == CLOUD_DSN


#  ---- a password and a server CA, and nothing else ------------------------


@pytest.mark.parametrize("parameter", ("sslcert", "sslkey"))
def test_a_client_certificate_is_refused_rather_than_merely_unrequired(
    parameter: str,
) -> None:
    """The deployment mounts one file, so a DSN may not name a second.

    Cloud SQL client certificates are an optional instance feature.  On a
    private address, behind this project's own VPC, against a server already
    verified by its CA, they buy little and cost a second private key to mint,
    mount at a mode libpq accepts, and rotate.  Accepting one here would let a
    DSN name a path Stage 90 does not mount, which fails later and opaquely.
    """
    dsn = f"{CLOUD_DSN}&{parameter}=/var/run/muster/cloud-sql/client.pem"

    with pytest.raises(DatabaseConfigurationError, match=parameter):
        configuration_from_environment(_cloud_environment(dsn), require_deployed=True)


def test_verify_ca_is_enough_and_verify_full_is_permitted() -> None:
    """``verify-ca`` is the U1 configuration; ``verify-full`` is not forbidden.

    Both authenticate the server.  ``verify-full`` additionally requires that
    the instance's certificate actually carry the name being connected to,
    which on Cloud SQL is true only under a CA mode that issues one -- an
    operator decision, not something this validator can establish.
    """
    for mode in ("verify-ca", "verify-full"):
        dsn = CLOUD_DSN.replace("sslmode=verify-ca", f"sslmode={mode}")
        assert configuration_from_environment(
            _cloud_environment(dsn), require_deployed=True
        ).dsn == dsn


@pytest.mark.parametrize(
    "dsn",
    (
        "not a postgresql dsn",
        #  loopback, in each of the three ways it can be written
        f"postgresql://u:p@localhost/muster?sslmode=verify-ca&sslrootcert={SERVER_CA}"
        "&connect_timeout=10&application_name=muster",
        f"postgresql://u:p@127.0.0.1/muster?sslmode=verify-ca&sslrootcert={SERVER_CA}"
        "&connect_timeout=10&application_name=muster",
        CLOUD_DSN + "&hostaddr=127.0.0.1",
        #  an unverified server is indistinguishable from a redirected one
        CLOUD_DSN.replace("sslmode=verify-ca", "sslmode=require"),
        CLOUD_DSN.replace("sslmode=verify-ca", "sslmode=disable"),
        #  the server CA, absent or not a container path
        CLOUD_DSN.replace(f"&sslrootcert={SERVER_CA}", ""),
        CLOUD_DSN.replace(SERVER_CA, "server-ca.pem"),
        #  no password, no application name, no bounded connect timeout
        CLOUD_DSN.replace(":not-a-real-secret", ""),
        CLOUD_DSN.replace("&application_name=muster-control-plane", ""),
        CLOUD_DSN.replace("&connect_timeout=10", ""),
        CLOUD_DSN.replace("connect_timeout=10", "connect_timeout=0"),
        CLOUD_DSN.replace("connect_timeout=10", "connect_timeout=600"),
        CLOUD_DSN.replace("connect_timeout=10", "connect_timeout=ten"),
        #  more than one host is more than one instance
        CLOUD_DSN.replace("@10.20.0.3:5432", "@10.20.0.3,10.20.0.4:5432"),
    ),
)
def test_malformed_cloud_sql_configuration_is_refused(dsn: str) -> None:
    with pytest.raises(DatabaseConfigurationError):
        configuration_from_environment(_cloud_environment(dsn), require_deployed=True)


#  ---- what a refusal is allowed to say ------------------------------------


@pytest.mark.parametrize(
    "dsn",
    (
        #  libpq quotes the token it choked on, and the token can be part of a
        #  password: ``password=P@ss word9`` fails with ``missing "=" after
        #  "word9"``.  Each of these puts the sentinel in that position.
        f"host=10.20.0.3 dbname=muster user=u password=P@ss {SENTINEL}",
        f"host=10.20.0.3 password={SENTINEL} dbname",
        f"postgresql://u:{SENTINEL}@10.20.0.3/muster?sslmode",
        f"postgresql://u:{SENTINEL}@10.20.0.3/db extra='unterminated",
    ),
)
def test_a_malformed_dsn_keeps_nothing_of_the_dsn(dsn: str) -> None:
    """Not just unprinted: not retained.

    A redacted message is not enough on its own.  ``raise ... from error`` would
    keep libpq's diagnostic on ``__cause__``, where it is one ``format_exc()``
    away from a log line, so the parse error is suppressed rather than chained.
    """
    with pytest.raises(DatabaseConfigurationError) as raised:
        configuration_from_environment(_cloud_environment(dsn), require_deployed=True)

    error = raised.value
    chain = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    for exposed in (str(error), repr(error), repr(error.__cause__), repr(error.args), chain):
        assert SENTINEL not in exposed, exposed
    assert error.__cause__ is None
    assert error.__suppress_context__


def test_a_malformed_deployment_label_keeps_nothing_of_the_environment() -> None:
    with pytest.raises(DatabaseConfigurationError) as raised:
        configuration_from_environment(
            {DATABASE_DEPLOYMENT: SENTINEL, DATABASE_URL: CLOUD_DSN},
            require_deployed=True,
        )

    error = raised.value
    chain = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    assert SENTINEL not in chain
    assert error.__cause__ is None


def test_bootstrap_refusal_never_prints_the_database_secret(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = main(
        ["--cloud-sql"],
        environment={
            DATABASE_DEPLOYMENT: DatabaseDeployment.CLOUD_SQL.value,
            MIGRATION_DATABASE_URL: f"postgresql://user:{SENTINEL}@localhost/muster",
        },
    )

    output = capsys.readouterr()
    assert result == 2
    assert SENTINEL not in output.out
    assert SENTINEL not in output.err


def test_bootstrap_refuses_a_custody_that_has_no_schema(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """There is nothing to migrate in memory, and saying so beats connecting."""
    result = main(
        ["--cloud-sql"],
        environment={DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value},
    )

    assert result == 2
    assert "CLOUD_SQL" in capsys.readouterr().err
