"""Reset only the synthetic local Ravi Action Gate execution before a demo."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

import psycopg

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from demo.action_gate_api import (  # noqa: E402
    DEMO_CASE,
    DEMO_TENANT,
    DemoStartupError,
    resolve_dsn,
)

DEMO_CONFIRMATION = f"{DEMO_TENANT}/{DEMO_CASE}"


class DemoResetRefused(RuntimeError):
    """The explicit demo-only reset confirmation was absent or incorrect."""


def reset_demo_execution(
    *,
    dsn: str | None = None,
    confirmation: str,
) -> int:
    """Delete only the configured synthetic demo case's Action Gate row."""
    if confirmation != DEMO_CONFIRMATION:
        raise DemoResetRefused(
            "refusing reset: confirmation must exactly match " f"{DEMO_CONFIRMATION}"
        )

    configured_dsn = resolve_dsn(dsn)
    with psycopg.connect(configured_dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            DELETE FROM action_gate.execution
            WHERE tenant_id = %s AND case_id = %s
            """,
            (DEMO_TENANT, DEMO_CASE),
        )
        return cursor.rowcount


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument(
        "--confirm-demo-only-reset",
        required=True,
        metavar=DEMO_CONFIRMATION,
        help="required literal confirming the one synthetic tenant/case target",
    )
    parser.add_argument(
        "--dsn",
        help=(
            "PostgreSQL DSN; otherwise MUSTER_DATABASE_URL then "
            "MUSTER_TEST_DSN is required"
        ),
    )
    arguments = parser.parse_args(argv)
    try:
        deleted = reset_demo_execution(
            dsn=arguments.dsn,
            confirmation=arguments.confirm_demo_only_reset,
        )
    except (DemoResetRefused, DemoStartupError, psycopg.Error) as error:
        print(f"MUSTER demo-only reset refused: {error}", file=sys.stderr)
        return 2

    print(
        f"MUSTER demo-only reset complete: {DEMO_CONFIRMATION}; "
        f"execution rows removed={deleted}"
    )
    print("Presentation state: PROPOSED / NOT_EXECUTED. No real funds transferred.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
