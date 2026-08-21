"""The network face of one agent: one route, octets in, octets out.

An ASGI application of about a hundred lines, with no web framework behind it,
and the smallness is the point.  A source agent is not a web service that
happens to attest; it answers exactly one question, from exactly one caller,
and every additional route is another thing an operator has to reason about in
a process that reads private material.

    POST /acquire   assignment octets  ->  response octets
    GET  /healthz   liveness, and nothing else

**Nothing semantic lives here.**  The handler authenticates the caller, decodes
the octets, calls the agent, and encodes the answer.  It does not interpret, it
does not decide what may be attested, and it does not know what an assignment
means.  Every refusal it can produce is about the request being unreadable or
the caller being unauthenticated -- and an unauthenticated caller gets a status
code, never an abstention, because an abstention is a *source's answer* and this
one never reached the source.

**A refused caller learns nothing about the case.**  The response body is a
status word.  A handler that echoed which tenant or which case had been asked
about would answer, for anybody who can reach the port, the question of whether
a case exists.

**Health does not touch the source.**  It reports that the process is up. A
readiness probe that read the evidence store would make an availability check
into a per-minute access of private material, and would make a storage outage
look like a dead container.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from typing import Any

from muster.agents.runtime.agent import AcquisitionAgent
from muster.agents.transport.identity import CallerIdentity, IdentityFailure
from muster.core.evidence.acquisition import decode_acquisition_assignment
from muster.core.results import Err
from muster.core.wire.codec import decode, encode

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]

OCTETS = b"application/octet-stream"
TEXT = b"text/plain; charset=utf-8"

#: Assignments are small -- a handful of targets, each a few hundred octets.
#: A cap keeps an unauthenticated caller from making the process allocate, and
#: is checked before anything is decoded.
MAX_ASSIGNMENT_OCTETS = 256 * 1024


@dataclass(frozen=True, slots=True)
class AcquisitionService:
    """One agent, behind one authenticated route."""

    agent: AcquisitionAgent
    identity: CallerIdentity

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            #  Lifespan and websocket scopes both arrive here.  Answering
            #  nothing is correct for the first and the second is not offered.
            return
        path = scope.get("path", "")
        method = scope.get("method", "")
        if path == "/healthz" and method == "GET":
            await _respond(send, 200, TEXT, b"ok")
            return
        if path != "/acquire":
            await _respond(send, 404, TEXT, b"not found")
            return
        if method != "POST":
            await _respond(send, 405, TEXT, b"method not allowed")
            return

        caller = self.identity.verify(_bearer(scope))
        if isinstance(caller, Err):
            status = 401 if caller.error.failure is not IdentityFailure.NOT_PERMITTED else 403
            await _respond(send, status, TEXT, caller.error.failure.value.lower().encode())
            return

        body = await _body(receive)
        if body is None:
            await _respond(send, 413, TEXT, b"assignment too large")
            return

        node = decode(body)
        if isinstance(node, Err):
            await _respond(send, 400, TEXT, b"not canonical")
            return
        assignment = decode_acquisition_assignment(node.value)
        if isinstance(assignment, Err):
            await _respond(send, 400, TEXT, b"not an acquisition assignment")
            return

        response = await self.agent.acquire(assignment.value)
        await _respond(send, 200, OCTETS, encode(response.to_node()))


def _bearer(scope: Scope) -> str | None:
    headers: list[tuple[bytes, bytes]] = list(scope.get("headers", ()))
    for name, value in headers:
        if name.lower() != b"authorization":
            continue
        text = value.decode("latin-1")
        prefix, _, token = text.partition(" ")
        if prefix.lower() == "bearer" and token:
            return token
    return None


async def _body(receive: Receive) -> bytes | None:
    """The request body, or ``None`` if it exceeds the cap.

    Accumulated with the cap checked *as it accumulates*, rather than after:
    a content-length header is something a caller writes, and trusting it to
    decide whether to read is trusting the caller about how much to allocate.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            break
        chunk = message.get("body", b"")
        if isinstance(chunk, bytes) and chunk:
            total += len(chunk)
            if total > MAX_ASSIGNMENT_OCTETS:
                return None
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


async def _respond(send: Send, status: int, content_type: bytes, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type),
                (b"content-length", str(len(body)).encode()),
                #  A source agent serves one machine caller and no browser.
                #  Saying so removes a whole class of question about what a
                #  page could do with this endpoint.
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
