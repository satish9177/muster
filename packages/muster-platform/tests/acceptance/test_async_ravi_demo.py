"""Real-process acceptance proof for the local PostgreSQL async Ravi utility."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from demo.async_ravi import validate_artifact

pytestmark = pytest.mark.postgres

REPOSITORY = Path(__file__).resolve().parents[4]
SCRIPT = REPOSITORY / "demo/async_ravi.py"


def test_separate_process_retry_and_resume_preserve_the_same_case(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    first = _phase(migrated_dsn, tenant_id, case_id, "employer")
    retry = _phase(migrated_dsn, tenant_id, case_id, "employer")
    resumed = _phase(migrated_dsn, tenant_id, case_id, "resume-site")

    assert len({first["process_id"], retry["process_id"], resumed["process_id"]}) == 3
    assert first["authored_entries_created"] > 0
    assert retry["authored_entries_created"] == 0
    assert retry["state"]["head"] == first["state"]["head"]
    assert resumed["loaded_state"] == first["state"]
    assert resumed["prior_employer_entry_preserved"] is True
    assert resumed["state"]["head"]["revision_number"] > first["state"]["head"][
        "revision_number"
    ]
    assert resumed["result"]["outcome"] == "INVARIANT"
    assert resumed["result"]["exact_duration_status"] == "UNRESOLVED"
    assert resumed["result"]["action"]["amount"]["display"] == "INR 5,100.00"
    assert resumed["delivered"][1]["relation"]["display"] == ">= 508 minutes"


def test_prove_generates_a_valid_machine_readable_artifact(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    proof = _phase(
        migrated_dsn,
        tenant_id,
        case_id,
        "prove",
        "--confirm-demo-only-reset",
        f"{tenant_id}/{case_id}",
    )
    validate_artifact(proof)
    assert proof["continuity"] == {
        "same_tenant_case": True,
        "different_processes": True,
        "loaded_phase_one_head": True,
        "loaded_phase_one_transcript": True,
        "prior_employer_evidence_preserved": True,
        "revision_progressed": True,
    }


def test_reset_is_confirmed_scoped_and_tenant_bound(
    migrated_dsn: str, tenant_id: str, other_tenant_id: str, case_id: str
) -> None:
    sibling = f"{case_id}-sibling"
    _phase(migrated_dsn, tenant_id, case_id, "employer")
    _phase(migrated_dsn, tenant_id, sibling, "employer")

    refused = _invoke(
        migrated_dsn,
        tenant_id,
        case_id,
        "reset",
        "--confirm-demo-only-reset",
        f"{tenant_id}/wrong-case",
    )
    assert refused.returncode == 1
    assert _invoke(migrated_dsn, tenant_id, case_id, "inspect").returncode == 0
    assert _invoke(migrated_dsn, other_tenant_id, case_id, "inspect").returncode == 1

    _phase(
        migrated_dsn,
        tenant_id,
        case_id,
        "reset",
        "--confirm-demo-only-reset",
        f"{tenant_id}/{case_id}",
    )
    assert _invoke(migrated_dsn, tenant_id, case_id, "inspect").returncode == 1
    assert _invoke(migrated_dsn, tenant_id, sibling, "inspect").returncode == 0


def _phase(
    dsn: str, tenant_id: str, case_id: str, phase: str, *arguments: str
) -> dict[str, Any]:
    completed = _invoke(dsn, tenant_id, case_id, phase, *arguments)
    assert completed.returncode == 0, completed.stderr
    parsed: object = json.loads(completed.stdout)
    assert isinstance(parsed, dict)
    return parsed


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
