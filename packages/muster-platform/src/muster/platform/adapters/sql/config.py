"""PostgreSQL deployment configuration, kept at the SQL adapter boundary.

Local callers may keep passing a PostgreSQL DSN directly to :class:`SqlDatabase`
exactly as before. Deployed composition roots use this module instead: it
requires an explicit deployment kind, validates the libpq connection string
without connecting, and never substitutes one kind of custody for another.

Three kinds, and a deployed root must name one of the last two:

``LOCAL``
    The existing developer convention. A DSN in ``MUSTER_DATABASE_URL`` and no
    label at all, which is what the local Action Gate demo and the PostgreSQL
    suites already do.
``EPHEMERAL``
    Deliberate in-memory custody for the length of one execution. It carries no
    DSN, and asking for one alongside it is a refusal rather than a precedence
    rule: a deployment that names both has not decided anything.
``CLOUD_SQL``
    Durable custody in Cloud SQL for PostgreSQL. Mandatory DSN, mandatory
    server-certificate verification.

Cloud SQL is reached as ordinary PostgreSQL over the deployment's private VPC
route. No Google client or connector belongs here; TLS, timeouts and the
application name are libpq settings carried by the secret-backed DSN.

**Authentication is a password, and the server is authenticated by its CA.**
Not a client certificate. Cloud SQL client certificates are an optional
instance feature, and on a private address, with no public IP, reached only
through the deployment's own VPC, they add a second private key to mint, mount,
protect and rotate in exchange for very little. ``sslcert`` and ``sslkey`` are
therefore refused rather than merely unrequired: the deployment mounts one
secret file, the server CA, so a DSN naming a client certificate would name a
path that is not there and fail later, opaquely, at connect time.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address
from pathlib import PurePosixPath

import psycopg
from psycopg.conninfo import conninfo_to_dict

DATABASE_DEPLOYMENT = "MUSTER_DATABASE_DEPLOYMENT"
DATABASE_URL = "MUSTER_DATABASE_URL"
MIGRATION_DATABASE_URL = "MUSTER_MIGRATION_DATABASE_URL"

#: What a Cloud SQL DSN must carry, and what it must not.
_REQUIRED_CLOUD_SQL_PARAMETERS = (
    "host",
    "dbname",
    "user",
    "password",
    "application_name",
    "sslrootcert",
)
_REFUSED_CLOUD_SQL_PARAMETERS = ("sslcert", "sslkey")

#: ``verify-ca`` is the normal U1 configuration and the one this milestone is
#: provisioned with. ``verify-full`` is accepted, but it is only *reachable* on
#: Cloud SQL under conditions the operator has to have arranged deliberately --
#: see the note in ``infra/README.md``. Anything weaker is refused: an
#: unverified server is indistinguishable from a redirected one.
_VERIFYING_SSL_MODES = frozenset({"verify-ca", "verify-full"})


class DatabaseDeployment(Enum):
    LOCAL = "LOCAL"
    EPHEMERAL = "EPHEMERAL"
    CLOUD_SQL = "CLOUD_SQL"


class DatabaseConfigurationError(RuntimeError):
    """A database deployment is absent or malformed, without echoing its DSN."""


@dataclass(frozen=True, slots=True)
class DatabaseConfiguration:
    deployment: DatabaseDeployment
    #: ``None`` for EPHEMERAL, and only for EPHEMERAL.  A caller that has to
    #: narrow this is a caller that has to have decided what to do without one.
    dsn: str | None = None


def configuration_from_environment(
    environment: Mapping[str, str],
    *,
    dsn_variable: str = DATABASE_URL,
    require_deployed: bool = False,
) -> DatabaseConfiguration:
    """Read and validate one PostgreSQL configuration without connecting.

    ``require_deployed`` is for a deployed composition root. It makes the
    deployment label mandatory and confines it to the two kinds a deployment
    may name, so an omitted secret cannot quietly turn durable custody into a
    process-local proof -- and, equally, so an in-memory run is something a
    deployment *chose* rather than something it fell back to. Local commands
    accept the existing ``MUSTER_DATABASE_URL`` convention with no new label.
    """
    deployment = _deployment(environment, require_deployed=require_deployed)
    if deployment is DatabaseDeployment.EPHEMERAL:
        if (environment.get(dsn_variable) or "").strip():
            raise DatabaseConfigurationError(
                f"{DATABASE_DEPLOYMENT}=EPHEMERAL takes no {dsn_variable};"
                " in-memory custody and a database are different decisions"
            )
        return DatabaseConfiguration(deployment)

    dsn = (environment.get(dsn_variable) or "").strip()
    if not dsn:
        raise DatabaseConfigurationError(f"missing {dsn_variable}")
    parameters = _parse(dsn, dsn_variable)
    if deployment is DatabaseDeployment.CLOUD_SQL:
        _require_cloud_sql_parameters(parameters, dsn_variable)
    return DatabaseConfiguration(deployment, dsn)


def _deployment(
    environment: Mapping[str, str], *, require_deployed: bool
) -> DatabaseDeployment:
    raw = (environment.get(DATABASE_DEPLOYMENT) or "").strip()
    deployed = (DatabaseDeployment.EPHEMERAL, DatabaseDeployment.CLOUD_SQL)
    if not raw:
        if require_deployed:
            choices = " or ".join(member.value for member in deployed)
            raise DatabaseConfigurationError(
                f"missing {DATABASE_DEPLOYMENT}; a deployed control plane names"
                f" {choices} rather than inheriting one"
            )
        return DatabaseDeployment.LOCAL
    try:
        deployment = DatabaseDeployment(raw)
    except ValueError:
        choices = " or ".join(member.value for member in DatabaseDeployment)
        raise DatabaseConfigurationError(
            f"malformed {DATABASE_DEPLOYMENT}; expected {choices}"
        ) from None
    if require_deployed and deployment not in deployed:
        choices = " or ".join(member.value for member in deployed)
        raise DatabaseConfigurationError(
            f"{DATABASE_DEPLOYMENT} must be {choices} for a deployed control plane"
        )
    return deployment


def _parse(dsn: str, variable: str) -> dict[str, str | int | None]:
    """Parse without connecting, and without keeping what failed to parse.

    ``from None`` rather than ``from error``: libpq's parse diagnostics quote
    the offending token, and the offending token can be part of a password --
    ``password=P@ss word9`` fails with ``missing "=" after "word9"``. Nothing
    on the current paths prints a chained traceback, but a retained ``__cause__``
    is one ``format_exc`` away from a log line, and the cause says nothing the
    operator can act on that the variable's name does not.
    """
    try:
        return conninfo_to_dict(dsn)
    except (psycopg.Error, ValueError):
        raise DatabaseConfigurationError(
            f"malformed {variable}; expected a PostgreSQL libpq connection string"
        ) from None


def _require_cloud_sql_parameters(
    parameters: Mapping[str, str | int | None], variable: str
) -> None:
    for name in _REQUIRED_CLOUD_SQL_PARAMETERS:
        if not _text(parameters.get(name)):
            raise DatabaseConfigurationError(f"malformed {variable}; Cloud SQL requires {name}")

    for name in _REFUSED_CLOUD_SQL_PARAMETERS:
        if _text(parameters.get(name)):
            raise DatabaseConfigurationError(
                f"malformed {variable}; Cloud SQL authenticates with a password and"
                f" verifies the server CA, so {name} names a file this deployment"
                " does not mount"
            )

    hosts = [part.strip().lower() for part in _text(parameters.get("host")).split(",")]
    if len(hosts) != 1 or not hosts[0] or hosts[0] == "localhost" or hosts[0].startswith("/"):
        raise DatabaseConfigurationError(
            f"malformed {variable}; Cloud SQL requires one non-loopback host"
        )
    try:
        loopback = ip_address(hosts[0]).is_loopback
    except ValueError:
        loopback = False
    if loopback or _text(parameters.get("hostaddr")):
        raise DatabaseConfigurationError(
            f"malformed {variable}; Cloud SQL host must not be overridden or loopback"
        )

    if not PurePosixPath(_text(parameters.get("sslrootcert"))).is_absolute():
        raise DatabaseConfigurationError(
            f"malformed {variable}; Cloud SQL sslrootcert must be an absolute container path"
        )

    timeout = _text(parameters.get("connect_timeout"))
    try:
        seconds = int(timeout)
    except ValueError:
        raise DatabaseConfigurationError(
            f"malformed {variable}; Cloud SQL requires an integer connect_timeout"
        ) from None
    if not 1 <= seconds <= 60:
        raise DatabaseConfigurationError(
            f"malformed {variable}; Cloud SQL connect_timeout must be between 1 and 60"
        )

    if _text(parameters.get("sslmode")) not in _VERIFYING_SSL_MODES:
        raise DatabaseConfigurationError(
            f"malformed {variable}; Cloud SQL sslmode must verify server identity"
        )


def _text(value: str | int | None) -> str:
    return value.strip() if isinstance(value, str) else ""
