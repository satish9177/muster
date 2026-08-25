"""The local UI API is a thin, fail-closed PostgreSQL Action Gate composition."""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Any, cast

import psycopg
import pytest
from demo import action_gate_api
from demo.action_gate_api import DemoActionGate, DemoStartupError, create_server

from muster.core.results import Ok
from muster.core.values.scalars import VEnum, VScaled
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.adapters.sql.executions import SqlExecutionRepository
from muster.platform.gate.authority import GateCaller
from muster.platform.gate.executor import SandboxMode
from muster.platform.gate.model import ExecutionState

pytestmark = pytest.mark.postgres

_PROCESS_EXECUTE = """
import json
import sys

from demo.action_gate_api import DemoActionGate
from muster.platform.gate.executor import SandboxMode

tenant_id, case_id, mode = sys.argv[1:]
application = DemoActionGate.create(
    tenant_id=tenant_id,
    case_id=case_id,
    mode=SandboxMode(mode),
)
proposal = application.read_proposal(case_id)
executed = application.execute(case_id, str(proposal["proposal_id"]))
print(json.dumps({
    "proposal_id": proposal["proposal_id"],
    "execution": executed["execution"],
    "process_dispatch_count": application.executor.dispatch_count,
}))
"""


@pytest.fixture
def application(migrated_dsn: str, tenant_id: str, case_id: str) -> DemoActionGate:
    return DemoActionGate.create(
        dsn=migrated_dsn,
        tenant_id=tenant_id,
        case_id=case_id,
    )


@contextmanager
def _running(application: DemoActionGate) -> Iterator[str]:
    server = create_server(application, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    if isinstance(host, bytes):
        host = host.decode("ascii")
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _get(url: str) -> tuple[int, dict[str, Any]]:
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - loopback only
        return response.status, json.load(response)


def _post(url: str, body: bytes | None = None) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, data=body, method="POST")  # noqa: S310
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        return response.status, json.load(response)


def _proposal(base: str, case_id: str) -> dict[str, Any]:
    status, payload = _get(f"{base}/api/demo/cases/{case_id}/proposal")
    assert status == 200
    return payload


def _execute_url(base: str, case_id: str, proposal_id: str) -> str:
    return f"{base}/api/demo/cases/{case_id}/proposals/{proposal_id}/execute"


def _execution_url(base: str, case_id: str, proposal_id: str) -> str:
    return f"{base}/api/demo/cases/{case_id}/proposals/{proposal_id}/execution"


def _execute_in_fresh_process(
    dsn: str,
    tenant_id: str,
    case_id: str,
    mode: SandboxMode,
) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["MUSTER_DATABASE_URL"] = dsn
    environment.pop("MUSTER_TEST_DSN", None)
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and local test program
        [sys.executable, "-c", _PROCESS_EXECUTE, tenant_id, case_id, mode.value],
        cwd=action_gate_api.REPOSITORY,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    loaded: object = json.loads(completed.stdout)
    assert isinstance(loaded, dict)
    return cast(dict[str, Any], loaded)


def test_api_fails_closed_without_a_configured_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MUSTER_DATABASE_URL", raising=False)
    monkeypatch.delenv("MUSTER_TEST_DSN", raising=False)

    with pytest.raises(DemoStartupError, match="PostgreSQL is required"):
        DemoActionGate.create()


def test_api_fails_closed_when_postgresql_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_dsn: str) -> tuple[int, ...]:
        raise psycopg.OperationalError("database unavailable")

    monkeypatch.setattr(action_gate_api, "migrate", unavailable)

    with pytest.raises(DemoStartupError, match="database unavailable"):
        DemoActionGate.create(dsn="postgresql://configured-but-unavailable/muster")


def test_demo_api_contains_no_memory_database_fallback() -> None:
    source = inspect.getsource(action_gate_api)

    assert "MemoryDatabase" not in source
    assert "adapters.memory" not in source
    assert "SqlDatabase" in source


def test_demo_dsn_prefers_database_url_and_accepts_the_existing_test_convention() -> None:
    assert action_gate_api.resolve_dsn(
        environment={
            "MUSTER_DATABASE_URL": "postgresql://demo",
            "MUSTER_TEST_DSN": "postgresql://test",
        }
    ) == "postgresql://demo"
    assert action_gate_api.resolve_dsn(
        environment={"MUSTER_TEST_DSN": "postgresql://test"}
    ) == "postgresql://test"


def test_the_local_demo_refuses_the_deployed_control_planes_database() -> None:
    """A local tool that migrates on startup, one export away from production.

    This module and the cloud hero read the same ``MUSTER_DATABASE_URL``, and
    this one calls ``migrate`` and writes Ravi's rows before it serves anything.
    An operator with the deployed DSN exported would point it at Cloud SQL.
    PostgreSQL would refuse the DDL -- the runtime role holds no ``CREATE`` --
    but that is a grant saving us, and it would still have opened a connection
    and attempted it.  The label is checked first, before the DSN is resolved.
    """
    environment = {
        "MUSTER_DATABASE_DEPLOYMENT": "CLOUD_SQL",
        "MUSTER_DATABASE_URL": "postgresql://runtime@10.20.0.3/muster",
    }

    with pytest.raises(DemoStartupError, match="CLOUD_SQL"):
        action_gate_api.resolve_dsn(environment=environment)
    #  Including when a DSN is passed explicitly rather than read.
    with pytest.raises(DemoStartupError, match="CLOUD_SQL"):
        action_gate_api.resolve_dsn("postgresql://local", environment=environment)


def test_the_local_demo_is_unaffected_by_an_ephemeral_or_absent_label() -> None:
    """The deployed run's other custody says nothing about a developer's database."""
    for label in ({}, {"MUSTER_DATABASE_DEPLOYMENT": "EPHEMERAL"}):
        assert action_gate_api.resolve_dsn(
            environment={**label, "MUSTER_DATABASE_URL": "postgresql://demo"}
        ) == "postgresql://demo"


def test_real_postgresql_repository_is_composed(application: DemoActionGate) -> None:
    database = application.gate.casework.database
    assert isinstance(database, SqlDatabase)

    with database.reading(application.tenant_id) as scope:
        assert isinstance(scope.executions, SqlExecutionRepository)


def test_api_accepts_only_proposal_identity_and_gate_reloads_the_exact_action(
    application: DemoActionGate,
) -> None:
    with _running(application) as base:
        proposal = _proposal(base, application.case_id)
        assert "recipient" not in json.dumps(proposal)
        assert "amount" not in json.dumps(proposal)
        assert "currency" not in json.dumps(proposal)
        assert "action_kind" not in json.dumps(proposal)
        _status, executed = _post(
            _execute_url(base, application.case_id, proposal["proposal_id"])
        )

    assert executed["execution"]["phase"] == "EXECUTED"
    with application.gate.casework.database.reading(application.tenant_id) as scope:
        stored = scope.executions.read_for_case(application.case_id)
    assert isinstance(stored, Ok), stored
    assert stored.value.intent.action.kind == "PAY"
    fields = {
        field.name: field.value for field in stored.value.intent.action.consequential_fields
    }
    assert fields == {
        "amount": VScaled("INR", 2, 510_000),
        "recipient": VEnum("party_id", "RAVI"),
    }


def test_execution_status_route_reads_the_same_proposal_lifecycle(
    application: DemoActionGate,
) -> None:
    with _running(application) as base:
        proposal = _proposal(base, application.case_id)
        url = _execution_url(base, application.case_id, proposal["proposal_id"])
        _initial_status, initial = _get(url)
        _executed_status, executed = _post(
            _execute_url(base, application.case_id, proposal["proposal_id"])
        )
        _read_status, reread = _get(url)

    assert initial["execution"]["phase"] == "AUTHORIZED"
    assert executed["execution"]["phase"] == "EXECUTED"
    assert reread["execution"]["phase"] == "EXECUTED"
    assert reread["execution"]["execution_id"] == executed["execution"]["execution_id"]
    assert reread["execution"]["dispatch_count"] == 1


def test_repeated_http_request_returns_one_confirmation_and_no_second_dispatch(
    application: DemoActionGate,
) -> None:
    with _running(application) as base:
        proposal = _proposal(base, application.case_id)
        url = _execute_url(base, application.case_id, proposal["proposal_id"])
        _first_status, first = _post(url)
        _second_status, second = _post(url)

    assert first["execution"]["execution_id"] == second["execution"]["execution_id"]
    assert first["execution"]["external_reference"] == second["execution"][
        "external_reference"
    ]
    assert second["execution"]["existing_confirmation_returned"] is True
    assert second["execution"]["dispatch_count"] == 1
    assert application.executor.dispatch_count == 1


def test_api_restart_returns_the_same_confirmation_without_redispatch(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    first_application = DemoActionGate.create(
        dsn=migrated_dsn,
        tenant_id=tenant_id,
        case_id=case_id,
    )
    with _running(first_application) as base:
        proposal = _proposal(base, case_id)
        _status, first = _post(_execute_url(base, case_id, proposal["proposal_id"]))

    restarted = DemoActionGate.create(
        dsn=migrated_dsn,
        tenant_id=tenant_id,
        case_id=case_id,
    )
    with _running(restarted) as base:
        reloaded = _proposal(base, case_id)
        _status, second = _post(_execute_url(base, case_id, reloaded["proposal_id"]))

    assert reloaded["proposal_id"] == proposal["proposal_id"]
    assert second["execution"]["execution_id"] == first["execution"]["execution_id"]
    assert second["execution"]["external_reference"] == first["execution"][
        "external_reference"
    ]
    assert second["execution"]["existing_confirmation_returned"] is True
    assert first_application.executor.dispatch_count == 1
    assert restarted.executor.dispatch_count == 0


def test_process_restart_returns_the_same_confirmation_without_redispatch(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    first = _execute_in_fresh_process(
        migrated_dsn,
        tenant_id,
        case_id,
        SandboxMode.SUCCESS,
    )
    restarted = _execute_in_fresh_process(
        migrated_dsn,
        tenant_id,
        case_id,
        SandboxMode.SUCCESS,
    )

    assert restarted["proposal_id"] == first["proposal_id"]
    assert restarted["execution"]["execution_id"] == first["execution"]["execution_id"]
    assert restarted["execution"]["external_reference"] == first["execution"][
        "external_reference"
    ]
    assert restarted["execution"]["existing_confirmation_returned"] is True
    assert first["process_dispatch_count"] == 1
    assert restarted["process_dispatch_count"] == 0


def test_concurrent_duplicate_http_requests_dispatch_once(
    application: DemoActionGate,
) -> None:
    with _running(application) as base:
        proposal = _proposal(base, application.case_id)
        url = _execute_url(base, application.case_id, proposal["proposal_id"])
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(_post, url) for _ in range(2)]
            results = [future.result() for future in futures]

    payloads = [payload for _status, payload in results]
    assert len({payload["execution"]["execution_id"] for payload in payloads}) == 1
    assert application.executor.dispatch_count == 1
    assert application.executor.execution_count == 1


def test_malformed_and_stale_proposals_are_rejected(
    application: DemoActionGate,
) -> None:
    with _running(application) as base:
        proposal = _proposal(base, application.case_id)
        refused = ("not-a-digest", "00" * 32)
        assert proposal["proposal_id"] not in refused
        for proposal_id in refused:
            with pytest.raises(urllib.error.HTTPError) as raised:
                _post(_execute_url(base, application.case_id, proposal_id))
            response = json.load(raised.value)
            assert raised.value.code == 409
            assert response["error"]["code"] == "PROPOSAL_NOT_CURRENT"

    assert application.executor.dispatch_count == 0


def test_http_body_cannot_substitute_payment_authority(
    application: DemoActionGate,
) -> None:
    with _running(application) as base:
        proposal = _proposal(base, application.case_id)
        body = json.dumps(
            {"recipient": "ATTACKER", "amount": 1, "currency": "USD", "kind": "PAY"}
        ).encode()
        with pytest.raises(urllib.error.HTTPError) as raised:
            _post(
                _execute_url(base, application.case_id, proposal["proposal_id"]),
                body,
            )
        response = json.load(raised.value)

    assert raised.value.code == 400
    assert response["error"]["code"] == "BODY_NOT_ALLOWED"
    assert application.executor.dispatch_count == 0


def test_unauthorized_configured_execution_principal_is_rejected(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    application = DemoActionGate.create(
        dsn=migrated_dsn,
        tenant_id=tenant_id,
        case_id=case_id,
        caller=GateCaller("agent-site-a"),
    )
    with _running(application) as base:
        proposal = _proposal(base, application.case_id)
        with pytest.raises(urllib.error.HTTPError) as raised:
            _post(_execute_url(base, application.case_id, proposal["proposal_id"]))
        response = json.load(raised.value)

    assert raised.value.code == 403
    assert response["error"]["code"] == "EXECUTION_AUTHORITY_REFUSED"
    assert application.executor.dispatch_count == 0


@pytest.mark.parametrize(
    ("mode", "phase", "durable_state", "finality"),
    [
        (
            SandboxMode.UNKNOWN_AFTER_DISPATCH,
            "UNCERTAIN",
            ExecutionState.UNCERTAIN.value,
            "OUTCOME_UNKNOWN",
        ),
        (
            SandboxMode.DEFINITE_PRE_DISPATCH_FAILURE,
            "FAILED",
            ExecutionState.FAILED.value,
            "DEFINITELY_NOT_EXECUTED",
        ),
    ],
)
def test_uncertain_and_failed_are_distinct_api_states(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    mode: SandboxMode,
    phase: str,
    durable_state: str,
    finality: str,
) -> None:
    application = DemoActionGate.create(
        dsn=migrated_dsn,
        tenant_id=tenant_id,
        case_id=case_id,
        mode=mode,
    )
    with _running(application) as base:
        proposal = _proposal(base, application.case_id)
        _status, response = _post(
            _execute_url(base, application.case_id, proposal["proposal_id"])
        )

    execution = response["execution"]
    assert execution["phase"] == phase
    assert execution["durable_state"] == durable_state
    assert execution["finality"] == finality
    assert execution["automatic_retry"] is False
    assert application.executor.dispatch_count == 1


def test_uncertain_remains_uncertain_across_restart(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
) -> None:
    first = _execute_in_fresh_process(
        migrated_dsn,
        tenant_id,
        case_id,
        SandboxMode.UNKNOWN_AFTER_DISPATCH,
    )
    restarted = _execute_in_fresh_process(
        migrated_dsn,
        tenant_id,
        case_id,
        SandboxMode.SUCCESS,
    )

    assert first["execution"]["phase"] == "UNCERTAIN"
    assert restarted["execution"]["phase"] == "UNCERTAIN"
    assert restarted["execution"]["execution_id"] == first["execution"]["execution_id"]
    assert restarted["execution"]["finality"] == "OUTCOME_UNKNOWN"
    assert restarted["process_dispatch_count"] == 0
