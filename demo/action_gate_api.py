"""Local demo HTTP surface over the real deterministic Action Gate.

This process composes a local Ravi case, the Milestone-G Gate, and the
synthetic sandbox executor. It is deliberately not a production service and
does not claim cloud identity: the only execution principal is configured in
this process, never supplied by the browser.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

REPOSITORY = Path(__file__).resolve().parent.parent
for _entry in (
    REPOSITORY / "packages" / "muster-kernel" / "src",
    REPOSITORY / "packages" / "muster-platform" / "src",
    REPOSITORY / "packages" / "muster-platform" / "tests",
):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from muster.core.analysis.outcomes import Invariant  # noqa: E402
from muster.core.results import Err  # noqa: E402
from muster.platform.adapters.memory import MemoryDatabase  # noqa: E402
from muster.platform.casework.commands import case_status  # noqa: E402
from muster.platform.gate.authority import (  # noqa: E402
    ExecutionGrant,
    GateCaller,
    LocalExecutionAuthority,
)
from muster.platform.gate.executor import (  # noqa: E402
    SandboxMode,
    SandboxPaymentExecutor,
)
from muster.platform.gate.model import (  # noqa: E402
    ExecuteProposal,
    ExecutionState,
    Finality,
    GateReadModel,
    GateReadState,
    read_model,
)
from muster.platform.gate.ports import ExecutionStoreFailure  # noqa: E402
from muster.platform.gate.service import ActionGate, GateFailure  # noqa: E402
from support import ravi  # noqa: E402
from support.fixtures import append_all, open_ravi  # noqa: E402

SCHEMA_VERSION = "muster.action-gate-demo/v1"
DEMO_TENANT = "ALPHA"
DEMO_CASE = "CASE-RAVI-SAT-CLOUD"
AUTHORIZED_PRINCIPAL = "local-ui-sandbox-operator"


@dataclass(frozen=True, slots=True)
class DemoApiError(Exception):
    status: HTTPStatus
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class DemoActionGate:
    """The local trust boundary used by the browser-facing demo API."""

    gate: ActionGate
    executor: SandboxPaymentExecutor
    tenant_id: str
    case_id: str
    caller: GateCaller

    @classmethod
    def create(
        cls,
        *,
        mode: SandboxMode = SandboxMode.SUCCESS,
        caller: GateCaller | None = None,
    ) -> DemoActionGate:
        database = MemoryDatabase()
        casework = ravi.casework(database)
        case = ravi.ravi(DEMO_TENANT, DEMO_CASE, attested=True)
        open_ravi(casework, case)
        append_all(casework, case, now=ravi.NOW)
        executor = SandboxPaymentExecutor(mode=mode)
        authority = LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=AUTHORIZED_PRINCIPAL,
                    tenant_id=DEMO_TENANT,
                    action_kind="PAY",
                    gate_id=executor.trusted_gate_id,
                    executor_id=executor.executor_id,
                ),
            )
        )
        return cls(
            gate=ActionGate(casework=casework, authority=authority, executor=executor),
            executor=executor,
            tenant_id=DEMO_TENANT,
            case_id=DEMO_CASE,
            caller=caller or GateCaller(AUTHORIZED_PRINCIPAL),
        )

    def read_proposal(self, case_id: str) -> dict[str, object]:
        request = self._current_proposal(case_id)
        return self._response(request, self._status(request), existing_confirmation=False)

    def read_execution(self, case_id: str, proposal_id: str) -> dict[str, object]:
        request = self._require_proposal(case_id, proposal_id)
        return self._response(request, self._status(request), existing_confirmation=False)

    def execute(self, case_id: str, proposal_id: str) -> dict[str, object]:
        request = self._require_proposal(case_id, proposal_id)
        before = self._status(request)
        executed = self.gate.execute(
            caller=self.caller,
            tenant_id=self.tenant_id,
            request=request,
            now=ravi.NOW,
        )
        if isinstance(executed, Err):
            status = (
                HTTPStatus.FORBIDDEN
                if executed.error.failure is GateFailure.EXECUTION_AUTHORITY_REFUSED
                else HTTPStatus.CONFLICT
            )
            raise DemoApiError(status, executed.error.failure.value, executed.error.detail)
        existing = (
            before is not None
            and before.state is GateReadState.EXECUTED
            and before.execution_id == executed.value.execution_key.hex
        )
        return self._response(
            request,
            read_model(executed.value),
            existing_confirmation=existing,
        )

    def _current_proposal(self, case_id: str) -> ExecuteProposal:
        if case_id != self.case_id:
            raise DemoApiError(HTTPStatus.NOT_FOUND, "CASE_ABSENT", case_id)
        reported = case_status(
            self.gate.casework,
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            now=ravi.NOW,
        )
        if isinstance(reported, Err):
            raise DemoApiError(
                HTTPStatus.CONFLICT,
                "CASE_NOT_EXECUTABLE",
                reported.error.detail,
            )
        report = reported.value
        if (
            report.analysis is None
            or report.head.revision_digest is None
            or report.head.certificate_digest is None
            or not isinstance(report.analysis.kernel.outcome, Invariant)
        ):
            raise DemoApiError(
                HTTPStatus.CONFLICT,
                "PROPOSAL_ABSENT",
                "the local hero case has no current invariant proposal",
            )
        return ExecuteProposal(
            case_id=self.case_id,
            revision_digest=report.head.revision_digest,
            certificate_digest=report.head.certificate_digest,
            action_digest=report.analysis.kernel.outcome.action.digest(),
        )

    def _require_proposal(self, case_id: str, proposal_id: str) -> ExecuteProposal:
        request = self._current_proposal(case_id)
        if proposal_id != request.certificate_digest.hex:
            raise DemoApiError(
                HTTPStatus.CONFLICT,
                "PROPOSAL_NOT_CURRENT",
                "the opaque proposal reference is not the current reproduced certificate",
            )
        return request

    def _status(self, request: ExecuteProposal) -> GateReadModel | None:
        with self.gate.casework.database.reading(self.tenant_id) as scope:
            found = scope.executions.read_for_case(self.case_id)
        if isinstance(found, Err):
            if found.error.failure is ExecutionStoreFailure.ABSENT:
                return None
            raise DemoApiError(
                HTTPStatus.CONFLICT,
                found.error.failure.value,
                found.error.detail,
            )
        intent = found.value.intent
        if (
            intent.revision_digest != request.revision_digest
            or intent.certificate_digest != request.certificate_digest
            or intent.action_digest != request.action_digest
        ):
            # A confirmed older revision is not the execution status of a new
            # current proposal. The browser must see the new proposal as
            # eligible and unexecuted, never inherit the prior lifecycle.
            return None
        return read_model(found.value)

    def _response(
        self,
        request: ExecuteProposal,
        status: GateReadModel | None,
        *,
        existing_confirmation: bool,
    ) -> dict[str, object]:
        execution = _execution_response(status, self.executor.dispatch_count)
        execution["existing_confirmation_returned"] = existing_confirmation
        return {
            "schema_version": SCHEMA_VERSION,
            "case_id": self.case_id,
            "proposal_id": request.certificate_digest.hex,
            "proposal": {"status": "PROPOSED", "outcome": "INVARIANT"},
            "execution": execution,
            "provenance": {
                "evidence_agent_path": "VERIFIED GOOGLE CLOUD EXECUTION REPLAY",
                "action_execution": "LOCAL DETERMINISTIC SANDBOX EXECUTION",
                "execution_principal": self.caller.principal_id,
                "sandbox": True,
                "real_funds_transferred": False,
            },
        }


def _execution_response(status: GateReadModel | None, dispatch_count: int) -> dict[str, object]:
    if status is None:
        return {
            "phase": "AUTHORIZED",
            "durable_state": None,
            "finality": Finality.DEFINITELY_NOT_EXECUTED.value,
            "execution_id": None,
            "external_reference": None,
            "lifecycle": ["AUTHORIZED"],
            "dispatch_count": dispatch_count,
            "automatic_retry": False,
        }
    lifecycle = ["AUTHORIZED", "RESERVED"]
    if status.durable_state is not ExecutionState.RESERVED:
        lifecycle.append("DISPATCHED")
    phase = {
        ExecutionState.RESERVED: "RESERVED",
        ExecutionState.DISPATCHED: "DISPATCHED",
        ExecutionState.CONFIRMED: "EXECUTED",
        ExecutionState.UNCERTAIN: "UNCERTAIN",
        ExecutionState.FAILED: "FAILED",
    }[status.durable_state]
    if status.durable_state is ExecutionState.CONFIRMED:
        lifecycle.extend(("CONFIRMED", "EXECUTED"))
    elif status.durable_state in {ExecutionState.UNCERTAIN, ExecutionState.FAILED}:
        lifecycle.append(status.durable_state.value)
    return {
        "phase": phase,
        "durable_state": status.durable_state.value,
        "finality": status.finality.value,
        "execution_id": status.execution_id,
        "external_reference": status.external_reference,
        "lifecycle": lifecycle,
        "dispatch_count": dispatch_count,
        "automatic_retry": False,
    }


class ActionGateRequestHandler(BaseHTTPRequestHandler):
    """Three JSON routes; every other method or shape is refused."""

    server_version = "MUSTER-Demo-Action-Gate/1"

    def __init__(
        self,
        *args: Any,
        application: DemoActionGate,
        **kwargs: Any,
    ) -> None:
        self.application = application
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def _handle(self, method: str) -> None:
        try:
            if method == "POST" and self._content_length() != 0:
                raise DemoApiError(
                    HTTPStatus.BAD_REQUEST,
                    "BODY_NOT_ALLOWED",
                    "execution accepts only the opaque proposal reference in the URL",
                )
            segments = [unquote(part) for part in urlsplit(self.path).path.split("/") if part]
            response = self._route(method, segments)
            self._send(HTTPStatus.OK, response)
        except DemoApiError as error:
            self._send(
                error.status,
                {"error": {"code": error.code, "detail": error.detail}},
            )

    def _route(self, method: str, segments: list[str]) -> dict[str, object]:
        if (
            len(segments) == 5
            and segments[:3] == ["api", "demo", "cases"]
            and method == "GET"
            and segments[4] == "proposal"
        ):
            return self.application.read_proposal(segments[3])
        if len(segments) == 7 and segments[:3] == ["api", "demo", "cases"]:
            case_id, collection, proposal_id, operation = segments[3:]
            if collection == "proposals" and method == "GET" and operation == "execution":
                return self.application.read_execution(case_id, proposal_id)
            if collection == "proposals" and method == "POST" and operation == "execute":
                return self.application.execute(case_id, proposal_id)
        raise DemoApiError(HTTPStatus.NOT_FOUND, "ROUTE_ABSENT", self.path)

    def _content_length(self) -> int:
        transfer_encoding = self.headers.get("Transfer-Encoding")
        if transfer_encoding is not None:
            raise DemoApiError(
                HTTPStatus.BAD_REQUEST,
                "TRANSFER_ENCODING_NOT_ALLOWED",
                transfer_encoding,
            )
        raw = self.headers.get("Content-Length")
        if raw is None:
            return 0
        try:
            length = int(raw)
        except ValueError as error:
            raise DemoApiError(
                HTTPStatus.BAD_REQUEST, "INVALID_CONTENT_LENGTH", raw
            ) from error
        if length < 0:
            raise DemoApiError(HTTPStatus.BAD_REQUEST, "INVALID_CONTENT_LENGTH", raw)
        return length

    def _send(self, status: HTTPStatus, body: dict[str, object]) -> None:
        octets = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(octets)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(octets)

    def log_message(self, format: str, *args: object) -> None:
        print(f"action-gate-api {self.address_string()} {format % args}")


def create_server(
    application: DemoActionGate,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> ThreadingHTTPServer:
    handler: Callable[..., ActionGateRequestHandler] = partial(
        ActionGateRequestHandler,
        application=application,
    )
    return ThreadingHTTPServer((host, port), handler)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    arguments = parser.parse_args(argv)
    application = DemoActionGate.create()
    with create_server(application, host=arguments.host, port=arguments.port) as server:
        print(f"MUSTER local sandbox Action Gate: http://{arguments.host}:{arguments.port}")
        print("No real funds transferred.")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
