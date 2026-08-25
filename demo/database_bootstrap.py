"""Explicit, repeatable PostgreSQL migration command for local and Cloud SQL.

The DSN is read from an environment variable rather than a command-line value,
so a database password does not enter shell history or process arguments.
Normal cloud execution only checks schema readiness; it never invokes this.
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
from muster.platform.adapters.sql.bootstrap import bootstrap  # noqa: E402
from muster.platform.adapters.sql.config import (  # noqa: E402
    DATABASE_DEPLOYMENT,
    DATABASE_URL,
    MIGRATION_DATABASE_URL,
    DatabaseConfigurationError,
    DatabaseDeployment,
    configuration_from_environment,
)
from muster.platform.adapters.sql.schema import SchemaNotCurrent  # noqa: E402


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
    arguments = parser.parse_args(argv)
    source = dict(os.environ) if environment is None else dict(environment)
    variable = MIGRATION_DATABASE_URL if arguments.cloud_sql else DATABASE_URL
    if not arguments.cloud_sql and not source.get(DATABASE_URL):
        variable = MIGRATION_DATABASE_URL
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
        result = bootstrap(configuration.dsn)
    except DatabaseConfigurationError as error:
        print(f"muster-database-bootstrap: CONFIGURATION REFUSED: {error}", file=sys.stderr)
        return 2
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

    applied = ",".join(str(version) for version in result.applied) or "none"
    current = ",".join(str(version) for version in result.current)
    print(f"muster-database-bootstrap: applied={applied} current={current}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
