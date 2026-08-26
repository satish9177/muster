"""The local hero converges on the same durable Action Gate lifecycle."""

from __future__ import annotations

import psycopg
import pytest
from demo.hero import execute_local_gate, main

from muster.core.results import Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import case_status
from muster.platform.gate.model import ExecutionState
from support import ravi

pytestmark = pytest.mark.postgres


def test_gate_flag_requires_postgresql() -> None:
    with pytest.raises(SystemExit, match="--gate requires --postgres"):
        main(["--gate"])


def test_local_hero_confirms_and_a_fresh_executor_repeats_without_dispatch(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = main(
        [
            "--postgres",
            migrated_dsn,
            "--gate",
            "--tenant",
            tenant_id,
            "--case",
            case_id,
        ]
    )
    printed = capsys.readouterr().out

    assert result == 0
    assert "state                  CONFIRMED" in printed
    assert "dispatches this run    1" in printed
    assert "principal source       CONFIGURED" in printed
    assert "OBSERVED" not in printed

    fresh_casework = ravi.casework(SqlDatabase(migrated_dsn))
    reported = case_status(
        fresh_casework,
        tenant_id=tenant_id,
        case_id=case_id,
        now=ravi.NOW,
    )
    assert isinstance(reported, Ok), reported
    repeated = execute_local_gate(
        fresh_casework,
        tenant_id=tenant_id,
        report=reported.value,
    )

    assert repeated.record.state is ExecutionState.CONFIRMED
    assert repeated.dispatch_count == 0
    assert repeated.execution_count == 0
    with psycopg.connect(migrated_dsn) as connection:
        rows = connection.execute(
            "SELECT execution_id, state, external_reference, dispatched_at, finalized_at "
            "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchall()
    assert len(rows) == 1
    assert bytes(rows[0][0]) == repeated.record.execution_key.octets
    assert rows[0][1] == "CONFIRMED"
    assert rows[0][2] == repeated.record.external_reference
    assert rows[0][3] == repeated.record.dispatched_at
    assert rows[0][4] == repeated.record.finalized_at
