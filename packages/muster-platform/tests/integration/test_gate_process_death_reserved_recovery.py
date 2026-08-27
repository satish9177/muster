"""Real process-death proof for recovery of durable RESERVED work."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest

from muster.core.authority.signing import PublisherRole
from muster.core.results import Err, Ok
from muster.platform.adapters.crypto import (
    LocalEcdsaOfficerVerifier,
    LocalEcdsaPublisherVerifier,
    LocalEcdsaSourceVerifier,
)
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.sandbox_rail import DurableSandboxPaymentExecutor
from muster.platform.casework.advance import Casework
from muster.platform.gate.authority import (
    ExecutionGrant,
    GateCaller,
    LocalExecutionAuthority,
)
from muster.platform.gate.executor import ActionExecutor
from muster.platform.gate.model import ExecutionKey, ExecutionLookup, ExecutionState
from muster.platform.gate.service import ActionGate, GateFailure
from support import ravi
from support.gate import proposal

pytestmark = pytest.mark.postgres

REPOSITORY = Path(__file__).resolve().parents[4]
CALLER = GateCaller("reserved-recovery-operator")

_CHILD = r"""
import json
import os
import sys
from pathlib import Path

from muster.core.results import Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.sandbox_rail import DurableSandboxPaymentExecutor
from muster.platform.casework.commands import case_status
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority
from muster.platform.gate.eligibility import current_action_intent
from muster.platform.gate.service import ActionGate
from support import ravi
from support.fixtures import append_all, open_ravi
from support.gate import proposal

dsn, tenant_id, case_id, output_name = sys.argv[1:]
database = SqlDatabase(dsn)
casework = ravi.casework(database)
case = ravi.ravi(tenant_id, case_id, attested=True)
open_ravi(casework, case)
append_all(casework, case, now=ravi.NOW)
_report, request = proposal(casework, case)
caller = GateCaller("reserved-recovery-operator")
executor = DurableSandboxPaymentExecutor(dsn, accepted_at=ravi.NOW)
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
reported = case_status(casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
assert isinstance(reported, Ok), reported
eligible = current_action_intent(
    reported.value,
    request,
    tenant_id=tenant_id,
    gate_id=gate.gate_id,
    executor_id=executor.executor_id,
)
assert isinstance(eligible, Ok), eligible
intent = eligible.value
assert gate.authority.may_invoke(
    caller,
    tenant_id=tenant_id,
    gate_id=gate.gate_id,
    executor_id=executor.executor_id,
)
assert gate.authority.permits(
    caller,
    tenant_id=tenant_id,
    action_kind=intent.action.kind,
    gate_id=gate.gate_id,
    executor_id=executor.executor_id,
)
with database.writing(tenant_id) as scope:
    reserved = scope.executions.reserve(
        intent, requested_by=caller.principal_id, now=ravi.NOW
    )
assert isinstance(reserved, Ok) and reserved.value.acquired, reserved

# The reservation transaction is committed and no dispatch CAS has been
# attempted. Closing this file is the deterministic signal; death is immediate.
Path(output_name).write_text(json.dumps({
    "execution_key": intent.execution_key().hex,
    "state": reserved.value.record.state.value,
    "source_keys": {
        key: value.decode("ascii")
        for key, value in casework.source_verifier.public_keys.items()
    },
    "officer_keys": {
        key: value.decode("ascii")
        for key, value in casework.officer_verifier.public_keys.items()
    },
    "publisher_keys": {
        role.value: {
            key: value.decode("ascii") for key, value in keys.items()
        }
        for role, keys in casework.publisher_verifier.public_keys.items()
    },
}), encoding="utf-8")
os._exit(73)
"""


def _run_crashing_child(
    dsn: str,
    tenant_id: str,
    case_id: str,
    output: Path,
) -> dict[str, Any]:
    environment = os.environ.copy()
    pythonpath = [
        REPOSITORY,
        REPOSITORY / "packages" / "muster-kernel" / "src",
        REPOSITORY / "packages" / "muster-kernel",
        REPOSITORY / "packages" / "muster-platform" / "src",
        REPOSITORY / "packages" / "muster-platform" / "tests",
    ]
    environment["PYTHONPATH"] = os.pathsep.join(map(str, pythonpath))
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and local test program
        [
            sys.executable,
            "-c",
            _CHILD,
            dsn,
            tenant_id,
            case_id,
            str(output),
        ],
        cwd=REPOSITORY,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 73, completed.stderr
    loaded: object = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, Any], loaded)


def _gate(
    dsn: str,
    tenant_id: str,
    caller: GateCaller,
    executor: ActionExecutor,
    *,
    casework: Casework | None = None,
) -> ActionGate:
    return ActionGate(
        casework=ravi.casework(SqlDatabase(dsn)) if casework is None else casework,
        executor=executor,
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=caller.principal_id,
                    tenant_id=tenant_id,
                    action_kind="PAY",
                    gate_id=executor.trusted_gate_id,
                    executor_id=executor.executor_id,
                ),
            )
        ),
    )


def _public_keys(raw: object) -> dict[str, bytes]:
    assert isinstance(raw, dict)
    decoded: dict[str, bytes] = {}
    for key, value in raw.items():
        assert isinstance(key, str) and isinstance(value, str)
        decoded[key] = value.encode("ascii")
    return decoded


def _publisher_keys(raw: object) -> dict[PublisherRole, dict[str, bytes]]:
    assert isinstance(raw, dict)
    decoded: dict[PublisherRole, dict[str, bytes]] = {}
    for role, keys in raw.items():
        assert isinstance(role, str)
        decoded[PublisherRole(role)] = _public_keys(keys)
    return decoded


def _trusted_casework(dsn: str, child: dict[str, Any]) -> Casework:
    """A fresh deployment trusting only the child's exported public halves."""
    return replace(
        ravi.casework(SqlDatabase(dsn)),
        source_verifier=LocalEcdsaSourceVerifier(_public_keys(child["source_keys"])),
        officer_verifier=LocalEcdsaOfficerVerifier(_public_keys(child["officer_keys"])),
        publisher_verifier=LocalEcdsaPublisherVerifier(_publisher_keys(child["publisher_keys"])),
    )


def _lookup(execution_key: str, case_id: str) -> ExecutionLookup:
    return ExecutionLookup(ExecutionKey(bytes.fromhex(execution_key)), expected_case_id=case_id)


def _external_rows(dsn: str, execution_key: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT idempotency_key, external_reference, accepted_at "
            "FROM sandbox_rail.transfer WHERE idempotency_key = %s",
            (execution_key,),
        ).fetchall()


def _gate_state(dsn: str, tenant_id: str, execution_key: str) -> str:
    with psycopg.connect(dsn) as connection:
        row = connection.execute(
            "SELECT state FROM action_gate.execution WHERE tenant_id = %s AND execution_id = %s",
            (tenant_id, bytes.fromhex(execution_key)),
        ).fetchone()
    assert row is not None and isinstance(row[0], str)
    return row[0]


def _gate_rows(dsn: str, tenant_id: str, case_id: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT execution_id, state, external_reference "
            "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchall()


def test_reserved_work_survives_process_death_and_is_recovered_once(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    child = _run_crashing_child(
        migrated_dsn,
        tenant_id,
        case_id,
        tmp_path / "reserved.json",
    )
    execution_key = cast(str, child["execution_key"])
    assert child["state"] == "RESERVED"
    assert _gate_state(migrated_dsn, tenant_id, execution_key) == "RESERVED"
    assert _external_rows(migrated_dsn, execution_key) == []

    # A reservation is visible to authorized reads, but it is neither a
    # resumable read-side grant nor an outcome the executor may inspect.
    read_executor = DurableSandboxPaymentExecutor(migrated_dsn, accepted_at=ravi.NOW + 1)
    read_gate = _gate(migrated_dsn, tenant_id, CALLER, read_executor)
    lookup = _lookup(execution_key, case_id)
    read = read_gate.read_authorized_execution(caller=CALLER, tenant_id=tenant_id, lookup=lookup)
    assert isinstance(read, Err), read
    assert read.error.failure is GateFailure.RESERVED_WITHOUT_DISPATCH
    reconciled = read_gate.reconcile_execution(
        caller=CALLER,
        tenant_id=tenant_id,
        lookup=lookup,
        now=ravi.NOW + 1,
    )
    assert isinstance(reconciled, Err), reconciled
    assert reconciled.error.failure is GateFailure.NOTHING_TO_RECONCILE
    assert read_executor.dispatch_count == 0
    assert read_executor.inspection_count == 0
    assert _gate_state(migrated_dsn, tenant_id, execution_key) == "RESERVED"
    assert _external_rows(migrated_dsn, execution_key) == []

    # This deployment shares no Python object with the child or the read-only
    # deployment. It must recover the existing row through the dispatch CAS.
    executor = DurableSandboxPaymentExecutor(migrated_dsn, accepted_at=ravi.NOW + 1)
    casework = _trusted_casework(migrated_dsn, child)
    gate = _gate(
        migrated_dsn,
        tenant_id,
        CALLER,
        executor,
        casework=casework,
    )
    case = ravi.ravi(tenant_id, case_id, attested=True)
    _report, request = proposal(gate.casework, case)
    recovered = gate.execute(
        caller=CALLER,
        tenant_id=tenant_id,
        request=request,
        now=ravi.NOW + 1,
    )

    assert isinstance(recovered, Ok), recovered
    record = recovered.value
    assert record.state is ExecutionState.CONFIRMED
    assert record.execution_key.hex == execution_key
    assert executor.dispatch_count == 1

    rows = _gate_rows(migrated_dsn, tenant_id, case_id)
    assert len(rows) == 1
    assert rows[0][0] == bytes.fromhex(execution_key)
    assert rows[0][1] == "CONFIRMED"
    assert rows[0][2] == record.external_reference

    external = _external_rows(migrated_dsn, execution_key)
    assert len(external) == 1
    assert external[0][0] == execution_key
    assert external[0][1] == record.external_reference
