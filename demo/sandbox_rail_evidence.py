"""Read the simulated external world for one execution key.  Writes nothing.

The reconciliation proof rests on a claim about something *outside* MUSTER: a
synthetic acceptance that committed before the process lost its answer.  A Gate
row that says CONFIRMED after reconciliation is not evidence of that -- the
reconciliation is what wrote it.  The evidence is the ``sandbox_rail`` rows, and
this reads them, on a read-only connection, before and after.

    MUSTER_MIGRATION_DATABASE_URL=... \\
      python demo/sandbox_rail_evidence.py --cloud-sql --key <execution-id>

It touches ``sandbox_rail`` and nothing else.  No case, no transcript, no
execution row, no tenant: those are MUSTER custody and are read through the Gate
or not at all.  ``sandbox_rail`` is the simulated external system, has no tenant
and no foreign key into custody, and moves no real funds.

    0   every named key was read
    1   the database refused, or a key is not 64 hex characters
    2   the configuration was not usable
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
from muster.platform.adapters.sql.config import (  # noqa: E402
    DATABASE_DEPLOYMENT,
    DATABASE_URL,
    MIGRATION_DATABASE_URL,
    DatabaseConfigurationError,
    DatabaseDeployment,
    configuration_from_environment,
)
from muster.platform.adapters.sql.sandbox_rail import external_effect_evidence  # noqa: E402

_KEY_LENGTH = 64


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument(
        "--cloud-sql",
        action="store_true",
        help=f"require an explicit Cloud SQL deployment and read {MIGRATION_DATABASE_URL}",
    )
    parser.add_argument(
        "--key",
        action="append",
        default=[],
        metavar="EXECUTION_ID",
        help="an execution id, which is the executor's idempotency key; repeatable",
    )
    arguments = parser.parse_args(argv)
    source = dict(os.environ) if environment is None else dict(environment)
    variable = MIGRATION_DATABASE_URL if arguments.cloud_sql else DATABASE_URL
    if not arguments.cloud_sql and not source.get(DATABASE_URL):
        variable = MIGRATION_DATABASE_URL

    keys = tuple(str(key).strip() for key in arguments.key)
    if not keys:
        print("muster-sandbox-evidence: CONFIGURATION REFUSED: no --key", file=sys.stderr)
        return 2
    for key in keys:
        if len(key) != _KEY_LENGTH or any(character not in "0123456789abcdef" for character in key):
            print(
                "muster-sandbox-evidence: REFUSED: an execution id is 64 lowercase hex "
                "characters",
                file=sys.stderr,
            )
            return 1

    try:
        configuration = configuration_from_environment(
            source, dsn_variable=variable, require_deployed=arguments.cloud_sql
        )
        if arguments.cloud_sql and configuration.deployment is not DatabaseDeployment.CLOUD_SQL:
            raise DatabaseConfigurationError(
                f"{DATABASE_DEPLOYMENT} must be CLOUD_SQL to read a Cloud SQL database"
            )
        if configuration.dsn is None:
            raise DatabaseConfigurationError(
                f"{configuration.deployment.value} custody has no simulated external world"
            )
        evidence = tuple(external_effect_evidence(configuration.dsn, key) for key in keys)
    except DatabaseConfigurationError as error:
        print(f"muster-sandbox-evidence: CONFIGURATION REFUSED: {error}", file=sys.stderr)
        return 2
    except InvariantViolation as error:
        print(f"muster-sandbox-evidence: REFUSED: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        #  The failure class only: a driver message can quote connection fields.
        print(
            f"muster-sandbox-evidence: DATABASE REFUSED: {type(error).__name__}",
            file=sys.stderr,
        )
        return 1

    print("")
    print("  SANDBOX: NO REAL FUNDS TRANSFERRED")
    for one in evidence:
        print("")
        for line in one.lines():
            print(f"  {line}")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
