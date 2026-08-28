"""Explicit, repeatable PostgreSQL migration command for local and Cloud SQL.

The DSN is read from an environment variable rather than a command-line value,
so a database password does not enter shell history or process arguments.
Normal cloud execution only checks schema readiness; it never invokes this.

It also grants the runtime role exactly what the schema it just applied
requires, from ``adapters.sql.runtime_grants``, and reads the result back.  The
role *name* is configuration -- ``MUSTER_RUNTIME_ROLE``, a plain identifier and
not a secret -- and the runtime password is never read here at all: granting is
something the owner does to a role, not something it needs the role's
credential for.

    --report-runtime-grants   read the privileges back and change nothing

is the read-only half, for establishing what a database's state *was* before
anything repaired it.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
for _entry in (
    REPOSITORY,
    REPOSITORY / "packages" / "muster-kernel" / "src",
    REPOSITORY / "packages" / "muster-platform" / "src",
):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from muster.core.results import InvariantViolation  # noqa: E402
from muster.platform.adapters.sql.bootstrap import BootstrapResult, bootstrap  # noqa: E402
from muster.platform.adapters.sql.config import (  # noqa: E402
    DATABASE_DEPLOYMENT,
    DATABASE_URL,
    MIGRATION_DATABASE_URL,
    DatabaseConfigurationError,
    DatabaseDeployment,
    configuration_from_environment,
)
from muster.platform.adapters.sql.runtime_grants import (  # noqa: E402
    PrivilegeReport,
    RuntimeGrantError,
    privilege_report,
)
from muster.platform.adapters.sql.schema import SchemaNotCurrent  # noqa: E402

#: The PostgreSQL login role the control plane connects as.  A role name, not a
#: credential: it is printed, and the password it belongs to is never read here.
RUNTIME_ROLE_VARIABLE = "MUSTER_RUNTIME_ROLE"


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument(
        "--cloud-sql",
        action="store_true",
        help=(f"require an explicit Cloud SQL deployment and read {MIGRATION_DATABASE_URL}"),
    )
    parser.add_argument(
        "--report-runtime-grants",
        action="store_true",
        help=(
            "read back what the runtime role may and may not do, and change nothing:"
            " no migration is applied and no grant is issued"
        ),
    )
    arguments = parser.parse_args(argv)
    source = dict(os.environ) if environment is None else dict(environment)
    variable = MIGRATION_DATABASE_URL if arguments.cloud_sql else DATABASE_URL
    if not arguments.cloud_sql and not source.get(DATABASE_URL):
        variable = MIGRATION_DATABASE_URL
    runtime_role = (source.get(RUNTIME_ROLE_VARIABLE) or "").strip() or None
    try:
        configuration = configuration_from_environment(
            source,
            dsn_variable=variable,
            require_deployed=arguments.cloud_sql,
        )
        if arguments.cloud_sql and configuration.deployment is not DatabaseDeployment.CLOUD_SQL:
            raise DatabaseConfigurationError(
                f"{DATABASE_DEPLOYMENT} must be CLOUD_SQL to bootstrap a Cloud SQL database"
            )
        if configuration.dsn is None:
            #  EPHEMERAL custody has no schema, and no ledger to bring current.
            raise DatabaseConfigurationError(
                f"{configuration.deployment.value} custody has no schema to bootstrap"
            )
        if arguments.report_runtime_grants:
            if runtime_role is None:
                raise DatabaseConfigurationError(
                    f"missing {RUNTIME_ROLE_VARIABLE}; there is no role to report on"
                )
            return _report(privilege_report(configuration.dsn, role=runtime_role))
        result = bootstrap(configuration.dsn, runtime_role=runtime_role)
    except DatabaseConfigurationError as error:
        print(f"muster-database-bootstrap: CONFIGURATION REFUSED: {error}", file=sys.stderr)
        return 2
    except RuntimeGrantError as error:
        print(f"muster-database-bootstrap: GRANT REFUSED: {error}", file=sys.stderr)
        return 1
    except (InvariantViolation, SchemaNotCurrent) as error:
        print(f"muster-database-bootstrap: SCHEMA REFUSED: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # Driver errors can quote connection fields. The failure class is enough
        # for operator routing and does not risk copying credentials to logs.
        print(
            f"muster-database-bootstrap: DATABASE REFUSED: {type(error).__name__}",
            file=sys.stderr,
        )
        return 1

    return _bootstrapped(result, runtime_role)


def _bootstrapped(result: BootstrapResult, runtime_role: str | None) -> int:
    applied = ",".join(str(version) for version in result.applied) or "none"
    current = ",".join(str(version) for version in result.current)
    print(f"muster-database-bootstrap: applied={applied} current={current}")
    if runtime_role is None:
        #  Said out loud rather than left as silence: a deployment that names no
        #  role has not granted one, and the next migration's tables will be
        #  unreachable to whatever role it does connect as.
        print(
            f"muster-database-bootstrap: no {RUNTIME_ROLE_VARIABLE};"
            " no runtime grant was applied or checked"
        )
        return 0
    print(f"muster-database-bootstrap: granted={result.granted} role={runtime_role}")
    if result.runtime is None:
        return 1
    return _report(result.runtime)


def _report(report: PrivilegeReport) -> int:
    """Print the privilege report and make its verdict the exit status.

    Every line is a role name, a schema or table name, a privilege keyword and
    a verdict.  No DSN, no password, no row.
    """
    print("")
    for line in report.lines():
        print(f"  {line}")
    print("")
    if not report.role_exists:
        print(
            f"muster-database-bootstrap: RUNTIME ROLE ABSENT: {report.role}",
            file=sys.stderr,
        )
        return 1
    if not report.complete():
        print(
            "muster-database-bootstrap: RUNTIME PRIVILEGES WRONG:"
            f" {len(report.wrong())} of {len(report.findings)}",
            file=sys.stderr,
        )
        return 1
    print("muster-database-bootstrap: runtime privileges are exactly the enumerated set")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
