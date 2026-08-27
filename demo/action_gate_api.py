"""Local demo HTTP surface over the durable deterministic Action Gate.

This process composes PostgreSQL, the authoritative Ravi fixture, the
Milestone-G Gate, and the synthetic sandbox executor. It is deliberately not a
production service and does not claim cloud identity: the only execution
principal is configured in this process, never supplied by the browser.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import psycopg

REPOSITORY = Path(__file__).resolve().parent.parent
for _entry in (
    REPOSITORY,
    REPOSITORY / "packages" / "muster-kernel" / "src",
    REPOSITORY / "packages" / "muster-platform" / "src",
    REPOSITORY / "packages" / "muster-platform" / "tests",
):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from demo.durable_ravi import (  # noqa: E402
    durable_case,
    durable_casework,
    open_durable_case,
)

from muster.application.rebuild import transcript_prefix  # noqa: E402
from muster.core.analysis.outcomes import Invariant  # noqa: E402
from muster.core.evidence.transcript import entry_digest  # noqa: E402
from muster.core.results import Err, InvariantViolation  # noqa: E402
from muster.platform.adapters.sql.config import (  # noqa: E402
    DATABASE_DEPLOYMENT,
    DatabaseDeployment,
)
from muster.platform.adapters.sql.database import SqlDatabase  # noqa: E402
from muster.platform.adapters.sql.schema import migrate  # noqa: E402
from muster.platform.casework.advance import Casework  # noqa: E402
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
from support.fixtures import append_all  # noqa: E402
from support.ravi import RaviCase  # noqa: E402

SCHEMA_VERSION = "muster.action-gate-demo/v1"
# Keep the local durable demo outside the fixture tenant that PostgreSQL test
# suites intentionally reset and corrupt during failure-injection coverage.
DEMO_TENANT = "MUSTER-DEMO-LOCAL-V1"
DEMO_CASE = "CASE-RAVI-SAT-CLOUD"
AUTHORIZED_PRINCIPAL = "local-ui-sandbox-operator"
DSN_ENVIRONMENT_VARIABLES = ("MUSTER_DATABASE_URL", "MUSTER_TEST_DSN")


class DemoStartupError(RuntimeError):
    """The durable demo could not establish its required PostgreSQL state."""


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
        dsn: str | None = None,
        mode: SandboxMode = SandboxMode.SUCCESS,
        caller: GateCaller | None = None,
        tenant_id: str = DEMO_TENANT,
        case_id: str = DEMO_CASE,
    ) -> DemoActionGate:
        configured_dsn = resolve_dsn(dsn)
        try:
            migrate(configured_dsn)
            database = SqlDatabase(configured_dsn)
            casework = durable_casework(database)
            case = durable_case(tenant_id, case_id)
            _prepare_ravi(casework, case)
        except DemoStartupError:
            raise
        except (AssertionError, InvariantViolation, psycopg.Error) as error:
            raise DemoStartupError(
                "PostgreSQL startup, migration, or Ravi preparation failed: "
                f"{type(error).__name__}: {error}"
            ) from error
        executor = SandboxPaymentExecutor(mode=mode)
        authority = LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=AUTHORIZED_PRINCIPAL,
                    tenant_id=tenant_id,
                    action_kind="PAY",
                    gate_id=executor.trusted_gate_id,
                    executor_id=executor.executor_id,
                ),
            )
        )
        return cls(
            gate=ActionGate(casework=casework, authority=authority, executor=executor),
            executor=executor,
            tenant_id=tenant_id,
            case_id=case_id,
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


def resolve_dsn(
    configured: str | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> str:
    """Resolve one explicit PostgreSQL DSN, with no implicit local default.

    **A CLOUD_SQL label stops this before it resolves anything.**  This module
    is a local composition root: it migrates on startup, and it prepares Ravi by
    writing rows.  Both are right for a database a developer owns and neither is
    right for the control plane's.  The two now share a variable name --
    ``MUSTER_DATABASE_URL`` -- so an exported cloud DSN on a workstation would
    otherwise point this at production and have it run DDL there.  The runtime
    role holds no CREATE, so PostgreSQL would refuse it; that is a grant saving
    us, and a grant is not where this decision belongs.
    """
    source = os.environ if environment is None else environment
    deployment = (source.get(DATABASE_DEPLOYMENT) or "").strip()
    if deployment == DatabaseDeployment.CLOUD_SQL.value:
        raise DemoStartupError(
            f"{DATABASE_DEPLOYMENT}={deployment} names the deployed control plane's"
            " database; this local demo migrates on startup and will not do that"
            " to it.  Unset it, or point it at a local PostgreSQL."
        )

    if configured is not None:
        explicit = configured.strip()
        if explicit:
            return explicit
        raise DemoStartupError("the explicit PostgreSQL DSN is empty")

    for variable in DSN_ENVIRONMENT_VARIABLES:
        value = source.get(variable, "").strip()
        if value:
            return value
    names = " or ".join(DSN_ENVIRONMENT_VARIABLES)
    raise DemoStartupError(f"PostgreSQL is required; set {names}")


def _prepare_ravi(casework: Casework, case: RaviCase) -> None:
    """Idempotently restore Ravi through casework without touching executions."""
    # Publishing and opening are both idempotent by their authoritative
    # identities. A different case under this identifier is refused rather
    # than overwritten.
    open_durable_case(casework, case)

    expected_members = frozenset(entry_digest(entry) for entry in case.entries)
    with casework.database.reading(case.tenant_id) as scope:
        stored = scope.transcript.members(case.case_id)
    if isinstance(stored, Err):
        raise DemoStartupError(
            f"Ravi transcript could not be read: {stored.error.failure.value}: "
            f"{stored.error.detail}"
        )
    stored_members = frozenset(stored.value)
    unexpected = stored_members - expected_members
    if unexpected:
        raise DemoStartupError(
            "the durable Ravi demo case contains transcript entries outside "
            "the authoritative fixture"
        )

    reported = case_status(
        casework,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        now=ravi.NOW,
    )
    expected_prefix = transcript_prefix(
        case.tenant_id,
        case.case_id,
        case.entries,
    ).digest()
    needs_restore = stored_members != expected_members
    if (
        isinstance(reported, Err)
        or reported.value.head.inputs.transcript_prefix_digest != expected_prefix
    ):
        needs_restore = True
    if not needs_restore and not isinstance(reported, Err):
        report = reported.value
    else:
        # Duplicate fixture deliveries are successes in casework. They repair a
        # crash after membership committed but before the derived head did.
        append_all(casework, case, now=ravi.NOW)
        restored = case_status(
            casework,
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            now=ravi.NOW,
        )
        if isinstance(restored, Err):
            raise DemoStartupError(
                f"Ravi case did not replay: {restored.error.failure.value}: "
                f"{restored.error.detail}"
            )
        report = restored.value
    if (
        report.head.inputs.transcript_prefix_digest != expected_prefix
        or report.head.revision_digest is None
        or report.head.certificate_digest is None
        or report.analysis is None
        or not report.certificate_reproduced
        or not isinstance(report.analysis.kernel.outcome, Invariant)
    ):
        raise DemoStartupError(
            "the durable Ravi case does not reproduce the authoritative invariant proposal"
        )


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
            "reconciled_at": None,
            "reconciled_from": None,
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
        # Durable reconciliation provenance, projected verbatim. A null pair is
        # an outcome the dispatching process established itself.
        "reconciled_at": status.reconciled_at,
        "reconciled_from": (
            None if status.reconciled_from is None else status.reconciled_from.value
        ),
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
    parser.add_argument(
        "--dsn",
        help=(
            "PostgreSQL DSN; otherwise MUSTER_DATABASE_URL then "
            "MUSTER_TEST_DSN is required"
        ),
    )
    arguments = parser.parse_args(argv)
    try:
        application = DemoActionGate.create(dsn=arguments.dsn)
    except DemoStartupError as error:
        print(f"MUSTER durable Action Gate refused to start: {error}", file=sys.stderr)
        return 2
    with create_server(application, host=arguments.host, port=arguments.port) as server:
        print(
            "MUSTER local PostgreSQL-backed sandbox Action Gate: "
            f"http://{arguments.host}:{arguments.port}"
        )
        print("No real funds transferred.")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
