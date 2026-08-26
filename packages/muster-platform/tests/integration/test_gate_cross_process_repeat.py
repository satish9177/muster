"""An exact repeat survives process loss with PostgreSQL as the only shared state."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest

from support import ravi

pytestmark = pytest.mark.postgres

REPOSITORY = Path(__file__).resolve().parents[4]

_CHILD = r"""
import json
import os
import sys
from pathlib import Path

from demo.durable_ravi import durable_case, durable_casework, open_durable_case
from muster.core.results import Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import case_status, open_case
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.executor import SandboxPaymentExecutor
from muster.platform.gate.service import ActionGate
from support import ravi
from support.fixtures import append_all
from support.gate import proposal

dsn, tenant_id, case_id, output_name = sys.argv[1:]
casework = durable_casework(SqlDatabase(dsn))
case = durable_case(tenant_id, case_id)
open_durable_case(casework, case)
reopened = open_case(
    casework,
    tenant_id=tenant_id,
    construction=case.construction,
    authorization_context=case.authorization_context,
    policy_id=case.policy_id,
    as_of=case.as_of,
)
assert isinstance(reopened, Ok), reopened
append_all(casework, case, now=ravi.NOW)
reported = case_status(casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
assert isinstance(reported, Ok), reported
assert reported.value.head.certificate_digest is not None
_report, request = proposal(casework, case)

caller = GateCaller("cross-process-repeat-operator")
executor = SandboxPaymentExecutor()
gate = ActionGate(
    casework=casework,
    executor=executor,
    authority=LocalExecutionAuthority((ExecutionGrant(
        principal_id=caller.principal_id,
        tenant_id=tenant_id,
        action_kind="PAY",
        gate_id=executor.trusted_gate_id,
        executor_id=executor.executor_id,
    ),)),
)
executed = gate.execute(caller=caller, tenant_id=tenant_id, request=request, now=ravi.NOW)
assert isinstance(executed, Ok), executed
assert executed.value.external_reference is not None
Path(output_name).write_text(json.dumps({
    "dispatch_count": executor.dispatch_count,
    "execution_key": executed.value.execution_key.hex,
    "external_reference": executed.value.external_reference,
    "state": executed.value.state.value,
    "reopened_revision": reopened.value.revision_number,
    "certificate_digest": reported.value.head.certificate_digest.hex,
    "certificate_reproduced": reported.value.certificate_reproduced,
    "execution_id_environment": (
        "MUSTER_HERO_GATE_EXECUTION_ID" in os.environ
        or "HERO_GATE_EXECUTION_ID" in os.environ
    ),
}), encoding="utf-8")
"""


def _run_child(
    dsn: str,
    tenant_id: str,
    case_id: str,
    output: Path,
) -> dict[str, Any]:
    environment = os.environ.copy()
    environment.pop("MUSTER_HERO_GATE_EXECUTION_ID", None)
    environment.pop("HERO_GATE_EXECUTION_ID", None)
    pythonpath = [
        REPOSITORY,
        REPOSITORY / "packages" / "muster-kernel" / "src",
        REPOSITORY / "packages" / "muster-kernel",
        REPOSITORY / "packages" / "muster-platform" / "src",
        REPOSITORY / "packages" / "muster-platform" / "tests",
        REPOSITORY / "packages" / "muster-agents" / "src",
        REPOSITORY / "packages" / "muster-agents",
    ]
    environment["PYTHONPATH"] = os.pathsep.join(map(str, pythonpath))
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and local test program
        [sys.executable, "-c", _CHILD, dsn, tenant_id, case_id, str(output)],
        cwd=REPOSITORY,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    loaded: object = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, Any], loaded)


def test_exact_repeat_reopens_and_replays_across_two_os_processes(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    first = _run_child(migrated_dsn, tenant_id, case_id, tmp_path / "first.json")
    repeat = _run_child(migrated_dsn, tenant_id, case_id, tmp_path / "repeat.json")

    assert first["dispatch_count"] == 1
    assert repeat["dispatch_count"] == 0
    assert repeat["execution_key"] == first["execution_key"]
    assert repeat["external_reference"] == first["external_reference"]
    assert first["state"] == repeat["state"] == "CONFIRMED"
    assert repeat["reopened_revision"] >= first["reopened_revision"]
    assert first["certificate_reproduced"] is True
    assert repeat["certificate_reproduced"] is True
    assert repeat["certificate_digest"] == first["certificate_digest"]
    assert repeat["execution_id_environment"] is False

    with psycopg.connect(migrated_dsn) as connection:
        rows = connection.execute(
            "SELECT execution_id, state, external_reference, dispatched_at, finalized_at "
            "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchall()
    assert len(rows) == 1
    assert bytes(rows[0][0]).hex() == first["execution_key"]
    assert rows[0][1:] == (
        "CONFIRMED",
        first["external_reference"],
        ravi.NOW,
        ravi.NOW,
    )
