"""The agent's network face, driven directly rather than over a socket.

An ASGI application is a callable over three arguments, so it can be exercised
exactly as a server would exercise it and with none of the apparatus one needs.
What is checked is the whole of what the handler decides: which route, which
method, whether the caller is authenticated, whether the body is an assignment
-- and, on every refusal, that the answer says nothing about the case.
"""

from __future__ import annotations

import asyncio
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_tests.support import assignments, fleet
from muster.agents.transport.identity import (
    CallerIdentity,
    IdentityError,
    IdentityFailure,
    UncheckedCaller,
)
from muster.agents.transport.service import MAX_ASSIGNMENT_OCTETS, AcquisitionService
from muster.core.evidence.acquisition import AcquiredEvidence, read_acquisition_response
from muster.core.results import Err, Ok, Result
from muster.core.wire.codec import decode, encode

TENANT = "ALPHA"
CASE = "CASE-SERVICE"


@dataclass(slots=True)
class _Exchange:
    """One request and the response it produced, as an ASGI server sees them."""

    status: int = 0
    headers: dict[bytes, bytes] = field(default_factory=dict)
    body: bytes = b""


def _call(
    service: AcquisitionService,
    *,
    path: str = "/acquire",
    method: str = "POST",
    body: bytes = b"",
    bearer: str | None = "a-token",
) -> _Exchange:
    exchange = _Exchange()
    headers: list[tuple[bytes, bytes]] = []
    if bearer is not None:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    scope: MutableMapping[str, Any] = {
        "type": "http",
        "path": path,
        "method": method,
        "headers": headers,
    }

    async def receive() -> MutableMapping[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: MutableMapping[str, Any]) -> None:
        if message["type"] == "http.response.start":
            exchange.status = int(message["status"])
            exchange.headers = dict(message["headers"])
        else:
            exchange.body += bytes(message.get("body", b""))

    asyncio.run(service(scope, receive, send))
    return exchange


def _service(identity: CallerIdentity | None = None) -> AcquisitionService:
    return AcquisitionService(
        agent=fleet.site(TENANT),
        identity=identity if identity is not None else UncheckedCaller(),
    )


def _assignment_octets() -> bytes:
    return encode(
        assignments.site_assignment(
            tenant_id=TENANT, case_id=CASE, agent_id=fleet.SITE_AGENT_ID
        ).to_node()
    )


@dataclass(frozen=True, slots=True)
class _Refusing(CallerIdentity):
    failure: IdentityFailure

    def verify(self, bearer: str | None) -> Result[str, IdentityError]:  # noqa: ARG002
        return Err(IdentityError(self.failure, "refused"))


#  ---- the route it serves -------------------------------------------------


def test_a_well_formed_assignment_is_answered_with_signed_receipts() -> None:
    exchange = _call(_service(), body=_assignment_octets())
    assert exchange.status == 200
    assert exchange.headers[b"content-type"] == b"application/octet-stream"

    node = decode(exchange.body)
    assert isinstance(node, Ok), node
    response = read_acquisition_response(node.value)
    assert isinstance(response.outcome, AcquiredEvidence), response.outcome
    assert len(response.outcome.receipts) == 2


def test_health_reports_liveness_and_touches_no_source() -> None:
    """A readiness probe that read the evidence store would make an
    availability check into a per-minute access of private material."""
    exchange = _call(_service(), path="/healthz", method="GET", bearer=None)
    assert exchange.status == 200
    assert exchange.body == b"ok"


@pytest.mark.parametrize(
    ("path", "method", "status"),
    [
        ("/", "GET", 404),
        ("/acquire", "GET", 405),
        ("/admin", "POST", 404),
        ("/healthz", "POST", 404),
    ],
)
def test_there_is_one_route_and_one_probe(path: str, method: str, status: int) -> None:
    assert _call(_service(), path=path, method=method).status == status


#  ---- who may call it -----------------------------------------------------


def test_an_unauthenticated_caller_is_refused_before_anything_is_decoded() -> None:
    exchange = _call(
        _service(_Refusing(IdentityFailure.ABSENT)), body=_assignment_octets(), bearer=None
    )
    assert exchange.status == 401


def test_a_caller_this_agent_does_not_serve_is_refused() -> None:
    exchange = _call(_service(_Refusing(IdentityFailure.NOT_PERMITTED)), body=_assignment_octets())
    assert exchange.status == 403


def test_a_refused_caller_learns_nothing_about_the_case() -> None:
    """The body is a status word.

    A handler that echoed which tenant or case had been asked about would
    answer, for anybody who can reach the port, the question of whether a case
    exists.
    """
    exchange = _call(
        _service(_Refusing(IdentityFailure.ABSENT)), body=_assignment_octets(), bearer=None
    )
    assert TENANT.encode() not in exchange.body
    assert CASE.encode() not in exchange.body
    assert exchange.body == b"absent"


#  ---- what it will read ---------------------------------------------------


@pytest.mark.parametrize("body", [b"", b"not canonical at all", b"\x00\x01\x02"])
def test_a_body_that_is_not_an_assignment_is_refused(body: bytes) -> None:
    """Reachable, authenticated, and the octets are not an assignment.

    This is the 400 the deployment smoke check expects: it distinguishes "the
    agent is up and the identity chain works" from "something else answered".
    """
    assert _call(_service(), body=body).status == 400


def test_a_canonical_value_of_the_wrong_type_is_refused() -> None:
    """Decoding is two steps and both refuse: canonical octets, then this type."""
    something_else = encode(
        assignments.site_assignment(tenant_id=TENANT, case_id=CASE, agent_id=fleet.SITE_AGENT_ID)
        .targets[0]
        .to_node()
    )
    assert _call(_service(), body=something_else).status == 400


def test_an_oversized_body_is_refused_as_it_arrives() -> None:
    """The cap is checked while reading, not from a header a caller wrote."""
    assert _call(_service(), body=b"x" * (MAX_ASSIGNMENT_OCTETS + 1)).status == 413


def test_a_non_http_scope_is_answered_with_nothing() -> None:
    """Lifespan and websocket scopes both arrive here; neither is offered."""
    exchange = _Exchange()

    async def receive() -> MutableMapping[str, Any]:  # pragma: no cover - never called
        return {"type": "lifespan.startup"}

    async def send(
        message: MutableMapping[str, Any],  # noqa: ARG001 - the ASGI contract
    ) -> None:  # pragma: no cover - nothing is sent for a lifespan scope
        exchange.status = 1

    asyncio.run(_service()({"type": "lifespan"}, receive, send))
    assert exchange.status == 0
