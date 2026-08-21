"""An agent in the same interpreter, reached through the same octets.

Used by the local end-to-end path and by the deterministic suite.  It is a real
implementation of the delivery port rather than a shortcut past it: the
assignment is encoded, decoded, answered and re-encoded exactly as it would be
across a network, so every envelope check, every decode refusal and every
binding comparison on the control plane's side is exercised by a run that never
opens a socket.

**What it deliberately does not do is skip anything.**  There is no path here
that hands an ``AcquisitionAssignment`` object straight to an agent, because a
transport that could do that would make the local run a weaker test than the
deployed one -- and the local run is the one that gates every commit.

**An endpoint reference is an address and is resolved by exact match.**  A
reference this registry does not hold is refused, which is what a mis-published
catalog should produce: a routing fault, reported, with the case unchanged.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass

from muster.agents.runtime.agent import AcquisitionAgent
from muster.core.evidence.acquisition import (
    decode_acquisition_assignment,
)
from muster.core.evidence.delivery import TransportError, TransportFailure
from muster.core.results import Err, Ok, Result
from muster.core.wire.codec import decode, encode


@dataclass(frozen=True, slots=True)
class InProcessAcquisitionTransport:
    """A registry from cataloged endpoint reference to a co-located agent."""

    agents: Mapping[str, AcquisitionAgent]

    def deliver(self, *, endpoint_ref: str, assignment: bytes) -> Result[bytes, TransportError]:
        agent = self.agents.get(endpoint_ref)
        if agent is None:
            return Err(
                TransportError(
                    TransportFailure.ENDPOINT_UNKNOWN,
                    f"{endpoint_ref!r} is not a co-located agent",
                )
            )
        node = decode(assignment)
        if isinstance(node, Err):
            #  Reported as the *endpoint* refusing, because that is what a
            #  deployed agent would do with octets it could not read: this
            #  implementation stands where the service would stand, and its
            #  failures have to be the failures a caller would see there.
            return Err(TransportError(TransportFailure.ENDPOINT_REFUSED, str(node.error)))
        read = decode_acquisition_assignment(node.value)
        if isinstance(read, Err):
            return Err(TransportError(TransportFailure.ENDPOINT_REFUSED, str(read.error)))
        try:
            response = asyncio.run(agent.acquire(read.value))
        except Exception as failure:
            #  A deployed agent that raised would return a 5xx, and a 5xx is a
            #  refused endpoint rather than an exception in the caller's stack.
            #  Matching that here keeps the two transports interchangeable in
            #  every path, not only the happy one.
            return Err(
                TransportError(
                    TransportFailure.ENDPOINT_REFUSED, f"{type(failure).__name__}: {failure}"[:200]
                )
            )
        return Ok(encode(response.to_node()))
