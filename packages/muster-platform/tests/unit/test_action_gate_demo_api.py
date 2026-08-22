"""The local UI API is a thin, fail-closed composition over ActionGate."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Any

import pytest
from demo.action_gate_api import DEMO_CASE, DemoActionGate, create_server

from muster.core.results import Ok
from muster.core.values.scalars import VEnum, VScaled
from muster.platform.gate.authority import GateCaller
from muster.platform.gate.executor import SandboxMode
from muster.platform.gate.model import ExecutionState


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
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - local test server
        return response.status, json.load(response)


def _post(url: str, body: bytes | None = None) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, data=body, method="POST")  # noqa: S310
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        return response.status, json.load(response)


def _proposal(base: str) -> dict[str, Any]:
    status, payload = _get(f"{base}/api/demo/cases/{DEMO_CASE}/proposal")
    assert status == 200
    return payload


def _execute_url(base: str, proposal_id: str) -> str:
    return f"{base}/api/demo/cases/{DEMO_CASE}/proposals/{proposal_id}/execute"


def _execution_url(base: str, proposal_id: str) -> str:
    return f"{base}/api/demo/cases/{DEMO_CASE}/proposals/{proposal_id}/execution"


def test_api_accepts_only_proposal_identity_and_gate_reloads_the_exact_action() -> None:
    application = DemoActionGate.create()
    with _running(application) as base:
        proposal = _proposal(base)
        assert "recipient" not in json.dumps(proposal)
        assert "amount" not in json.dumps(proposal)
        assert "currency" not in json.dumps(proposal)
        assert "action_kind" not in json.dumps(proposal)
        _status, executed = _post(_execute_url(base, proposal["proposal_id"]))

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


def test_execution_status_route_reads_the_same_proposal_lifecycle() -> None:
    application = DemoActionGate.create()
    with _running(application) as base:
        proposal = _proposal(base)
        _initial_status, initial = _get(_execution_url(base, proposal["proposal_id"]))
        _executed_status, executed = _post(_execute_url(base, proposal["proposal_id"]))
        _read_status, reread = _get(_execution_url(base, proposal["proposal_id"]))

    assert initial["execution"]["phase"] == "AUTHORIZED"
    assert executed["execution"]["phase"] == "EXECUTED"
    assert reread["execution"]["phase"] == "EXECUTED"
    assert reread["execution"]["execution_id"] == executed["execution"]["execution_id"]
    assert reread["execution"]["dispatch_count"] == 1


def test_repeated_http_request_returns_one_confirmation_and_no_second_dispatch() -> None:
    application = DemoActionGate.create()
    with _running(application) as base:
        proposal = _proposal(base)
        url = _execute_url(base, proposal["proposal_id"])
        _first_status, first = _post(url)
        _second_status, second = _post(url)

    assert first["execution"]["execution_id"] == second["execution"]["execution_id"]
    assert first["execution"]["external_reference"] == second["execution"][
        "external_reference"
    ]
    assert second["execution"]["existing_confirmation_returned"] is True
    assert second["execution"]["dispatch_count"] == 1
    assert application.executor.dispatch_count == 1


def test_concurrent_duplicate_http_requests_dispatch_once() -> None:
    application = DemoActionGate.create()
    with _running(application) as base:
        proposal = _proposal(base)
        url = _execute_url(base, proposal["proposal_id"])
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [future.result() for future in (pool.submit(_post, url) for _ in range(2))]

    payloads = [payload for _status, payload in results]
    assert len({payload["execution"]["execution_id"] for payload in payloads}) == 1
    assert application.executor.dispatch_count == 1
    assert application.executor.execution_count == 1


def test_http_body_cannot_substitute_payment_authority() -> None:
    application = DemoActionGate.create()
    with _running(application) as base:
        proposal = _proposal(base)
        body = json.dumps(
            {"recipient": "ATTACKER", "amount": 1, "currency": "USD", "kind": "PAY"}
        ).encode()
        with pytest.raises(urllib.error.HTTPError) as raised:
            _post(_execute_url(base, proposal["proposal_id"]), body)
        response = json.load(raised.value)

    assert raised.value.code == 400
    assert response["error"]["code"] == "BODY_NOT_ALLOWED"
    assert application.executor.dispatch_count == 0


def test_unauthorized_configured_execution_principal_is_rejected() -> None:
    application = DemoActionGate.create(caller=GateCaller("agent-site-a"))
    with _running(application) as base:
        proposal = _proposal(base)
        with pytest.raises(urllib.error.HTTPError) as raised:
            _post(_execute_url(base, proposal["proposal_id"]))
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
    mode: SandboxMode,
    phase: str,
    durable_state: str,
    finality: str,
) -> None:
    application = DemoActionGate.create(mode=mode)
    with _running(application) as base:
        proposal = _proposal(base)
        _status, response = _post(_execute_url(base, proposal["proposal_id"]))

    execution = response["execution"]
    assert execution["phase"] == phase
    assert execution["durable_state"] == durable_state
    assert execution["finality"] == finality
    assert execution["automatic_retry"] is False
    assert application.executor.dispatch_count == 1
