"""Real-process acceptance proof for the PostgreSQL reconciliation Ravi demo."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
from demo.reconcile_ravi import (
    DIED_AFTER_EXTERNAL_EFFECT,
    DIED_BEFORE_EXTERNAL_EFFECT,
    validate_artifact,
)

pytestmark = pytest.mark.postgres

REPOSITORY = Path(__file__).resolve().parents[4]
SCRIPT = REPOSITORY / "demo/reconcile_ravi.py"

EXPECTED_CLAIMS = {
    "distinct_processes": True,
    "gate_row_was_dispatched_after_the_crash": True,
    "external_transfer_committed_before_the_crash": True,
    "gate_was_not_finalized_before_reconciliation": True,
    "finality_was_unknown_after_restart": True,
    "reconciled_from_dispatched": True,
    "recovered_state_confirmed": True,
    "same_external_reference": True,
    "redispatches_during_reconciliation": 0,
    "external_transfers_after_reconciliation": 1,
    "repeat_dispatched_nothing": True,
    "repeat_same_execution": True,
    "repeat_same_external_reference": True,
}


def test_prove_generates_the_complete_machine_readable_artifact(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    proof = _phase(
        migrated_dsn,
        tenant_id,
        case_id,
        "prove",
        "--confirm-demo-only-reset",
        f"{tenant_id}/{case_id}",
        "--json",
    )

    validate_artifact(proof)
    assert proof["claims"] == EXPECTED_CLAIMS


def test_real_crash_reconciles_once_and_the_exact_repeat_never_redispatches(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    _reset(migrated_dsn, tenant_id, case_id)
    record_path = tmp_path / "after-external.json"
    crashed = _invoke(
        migrated_dsn,
        tenant_id,
        case_id,
        "crash",
        "--window",
        "after-external",
        "--record",
        str(record_path),
    )

    assert crashed.returncode == DIED_AFTER_EXTERNAL_EFFECT, crashed.stderr
    crash_record = _json_record(record_path.read_text(encoding="utf-8"))
    execution_key = cast(str, crash_record["execution_key"])
    external_reference = cast(str, crash_record["external_reference"])
    assert execution_key
    assert external_reference

    # This query is deliberately independent of the demo projection.  The
    # killed child cannot have printed a convenient final state, and the test
    # refuses to accept its rendezvous file as evidence that the Gate commit or
    # the simulated external commit actually happened.
    gate_row = _execution_row(migrated_dsn, tenant_id, execution_key)
    assert gate_row is not None
    assert gate_row[0] == "DISPATCHED"
    assert gate_row[1] is None
    transfers = _transfer_rows(migrated_dsn, execution_key)
    assert transfers == [(external_reference,)]

    observed = _phase(
        migrated_dsn,
        tenant_id,
        case_id,
        "observe",
        "--execution",
        execution_key,
    )
    reconciled = _phase(
        migrated_dsn,
        tenant_id,
        case_id,
        "reconcile",
        "--execution",
        execution_key,
    )
    repeated = _phase(migrated_dsn, tenant_id, case_id, "repeat")

    assert len(
        {observed["process_id"], reconciled["process_id"], repeated["process_id"]}
    ) == 3
    assert observed["state"] == "DISPATCHED"
    assert observed["finality"] == "OUTCOME_UNKNOWN"
    assert reconciled["before"] == {
        "state": "DISPATCHED",
        "finality": "OUTCOME_UNKNOWN",
    }
    assert reconciled["after"]["state"] == "CONFIRMED"
    assert reconciled["after"]["reconciled_from"] == "DISPATCHED"
    assert reconciled["after"]["external_reference"] == external_reference
    assert reconciled["dispatches"] == 0
    assert reconciled["inspections"] == 1
    assert reconciled["external"]["transfer_count"] == 1

    reconciled_row = _execution_row(migrated_dsn, tenant_id, execution_key)
    assert reconciled_row is not None
    assert reconciled_row[0] == "CONFIRMED"
    assert reconciled_row[2] == external_reference
    assert _transfer_rows(migrated_dsn, execution_key) == [(external_reference,)]

    assert repeated["execution_key"] == execution_key
    assert repeated["external_reference"] == external_reference
    assert repeated["dispatches"] == 0
    assert repeated["external"]["transfer_count"] == 1
    assert _transfer_rows(migrated_dsn, execution_key) == [(external_reference,)]


def test_death_after_attempt_remains_conservatively_uncertain(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    conservative_case = f"{case_id}-CONSERVATIVE"
    _reset(migrated_dsn, tenant_id, conservative_case)
    record_path = tmp_path / "before-external.json"
    crashed = _invoke(
        migrated_dsn,
        tenant_id,
        conservative_case,
        "crash",
        "--window",
        "before-external",
        "--record",
        str(record_path),
    )

    assert crashed.returncode == DIED_BEFORE_EXTERNAL_EFFECT, crashed.stderr
    crash_record = _json_record(record_path.read_text(encoding="utf-8"))
    execution_key = cast(str, crash_record["execution_key"])
    assert _attempt_outcome(migrated_dsn, execution_key) == "ATTEMPTED"
    assert _transfer_rows(migrated_dsn, execution_key) == []

    reconciled = _phase(
        migrated_dsn,
        tenant_id,
        conservative_case,
        "reconcile",
        "--execution",
        execution_key,
    )

    assert reconciled["before"]["state"] == "DISPATCHED"
    assert reconciled["after"]["state"] == "UNCERTAIN"
    assert reconciled["after"]["finality"] == "OUTCOME_UNKNOWN"
    assert reconciled["executor_inspection"] == "STILL_UNKNOWN"
    assert reconciled["dispatches"] == 0
    assert reconciled["inspections"] == 1
    assert reconciled["external"]["attempt"] == "ATTEMPTED"
    assert reconciled["external"]["transfer_count"] == 0


def test_reset_refuses_the_wrong_case_and_removes_gate_and_external_rows(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    _reset(migrated_dsn, tenant_id, case_id)
    record_path = tmp_path / "reset-scope.json"
    crashed = _invoke(
        migrated_dsn,
        tenant_id,
        case_id,
        "crash",
        "--window",
        "after-external",
        "--record",
        str(record_path),
    )
    assert crashed.returncode == DIED_AFTER_EXTERNAL_EFFECT, crashed.stderr
    execution_key = cast(
        str,
        _json_record(record_path.read_text(encoding="utf-8"))["execution_key"],
    )

    refused = _invoke(
        migrated_dsn,
        tenant_id,
        case_id,
        "reset",
        "--confirm-demo-only-reset",
        f"{tenant_id}/wrong-case",
    )
    assert refused.returncode != 0
    assert _execution_row(migrated_dsn, tenant_id, execution_key) is not None
    assert _attempt_outcome(migrated_dsn, execution_key) == "ATTEMPTED"
    assert len(_transfer_rows(migrated_dsn, execution_key)) == 1

    reset = _reset(migrated_dsn, tenant_id, case_id)
    assert reset["deleted"]["sandbox_rail_transfer"] == 1
    assert reset["deleted"]["sandbox_rail_attempt"] == 1
    assert reset["deleted"]["action_gate_execution"] == 1
    assert _execution_row(migrated_dsn, tenant_id, execution_key) is None
    assert _attempt_outcome(migrated_dsn, execution_key) is None
    assert _transfer_rows(migrated_dsn, execution_key) == []


def test_prove_prints_the_measured_human_narrative(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    completed = _invoke(
        migrated_dsn,
        tenant_id,
        case_id,
        "prove",
        "--confirm-demo-only-reset",
        f"{tenant_id}/{case_id}",
    )

    assert completed.returncode == 0, completed.stderr
    assert "MUSTER -- DURABLE RECONCILIATION AFTER PROCESS DEATH" in completed.stdout
    assert "BEFORE CRASH" in completed.stdout
    assert "AFTER RESTART" in completed.stdout
    assert "RECONCILIATION" in completed.stdout
    assert "EXACT REPEAT" in completed.stdout
    assert "  Redispatches              0" in completed.stdout
    assert "  External transfers        1" in completed.stdout
    assert "  Additional dispatches     0" in completed.stdout


def _reset(dsn: str, tenant_id: str, case_id: str) -> dict[str, Any]:
    return _phase(
        dsn,
        tenant_id,
        case_id,
        "reset",
        "--confirm-demo-only-reset",
        f"{tenant_id}/{case_id}",
    )


def _execution_row(
    dsn: str, tenant_id: str, execution_key: str
) -> tuple[object, ...] | None:
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        return connection.execute(
            "SELECT state, finalized_at, external_reference "
            "FROM action_gate.execution "
            "WHERE tenant_id = %s AND execution_id = %s",
            (tenant_id, bytes.fromhex(execution_key)),
        ).fetchone()


def _attempt_outcome(dsn: str, execution_key: str) -> str | None:
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        row = connection.execute(
            "SELECT outcome FROM sandbox_rail.attempt WHERE idempotency_key = %s",
            (execution_key,),
        ).fetchone()
    if row is None:
        return None
    assert isinstance(row[0], str)
    return row[0]


def _transfer_rows(dsn: str, execution_key: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        return connection.execute(
            "SELECT external_reference FROM sandbox_rail.transfer "
            "WHERE idempotency_key = %s",
            (execution_key,),
        ).fetchall()


def _json_record(serialized: str) -> dict[str, Any]:
    parsed: object = json.loads(serialized)
    assert isinstance(parsed, dict)
    return parsed


def _phase(
    dsn: str, tenant_id: str, case_id: str, phase: str, *arguments: str
) -> dict[str, Any]:
    completed = _invoke(dsn, tenant_id, case_id, phase, *arguments)
    assert completed.returncode == 0, completed.stderr
    return _json_record(completed.stdout)


def _invoke(
    dsn: str, tenant_id: str, case_id: str, phase: str, *arguments: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - exact interpreter and local script are controlled
        [
            sys.executable,
            str(SCRIPT),
            "--dsn",
            dsn,
            "--tenant",
            tenant_id,
            "--case",
            case_id,
            phase,
            *arguments,
        ],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
    )
