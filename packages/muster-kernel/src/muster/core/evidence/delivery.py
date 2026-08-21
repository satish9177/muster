"""How an assignment reaches a source, declared where both sides can see it.

The acquisition protocol has two halves.  The artifacts are next door; this is
the *edge* -- one method, taking canonical octets and returning canonical
octets, over which a control plane hands a source an assignment and receives
its answer.

It is declared here, in the shared wire seam, rather than on either side of the
boundary, because both sides have to agree on it and neither may depend on the
other.  A control plane that imported an agent runtime would have a model
client in the process holding the case record; an agent that imported the
control plane would have a database driver in a process a source operates.  The
contract they share is a contract, so it lives with the contracts.

**Octets rather than values, deliberately.**  An edge that took an
``AcquisitionAssignment`` and returned an ``AcquisitionResponse`` would be an
edge that could *construct* one, and a mistaken or hostile implementation could
then hand back a response nobody ever checked the encoding of.  Octets keep the
decode -- and therefore every well-formedness refusal -- on the reader's own
side, where it is the same decode a stored artifact gets.

**Nothing here performs I/O.**  This is a protocol and a failure vocabulary.
The implementations live in adapters: one carries octets to a co-located
process, one carries them over an authenticated network call, and this module
neither names nor could reach either.

**A delivery failure is never evidence.**  A timeout, a refused identity, an
unreachable host and a malformed reply are four operational facts and one
semantic one: the case is exactly as it was, its request is still outstanding,
and its deadline is still running.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from muster.core.results import Result


class TransportFailure(Enum):
    """Why an assignment did not produce a response.

    Distinct members because the operational responses differ completely: an
    unreachable endpoint is a deployment fault, a refused identity is an access
    fault, a timeout is a capacity or interpretation-latency fault, and an
    unaddressable reference is a catalog fault.  None of them says anything
    about evidence, and no reader may treat any of them as an answer.
    """

    #: The cataloged ``endpoint_ref`` names nothing this implementation can
    #: reach -- an unknown scheme, a host outside the deployment.
    ENDPOINT_UNKNOWN = "ENDPOINT_UNKNOWN"
    #: Addressable, and it did not answer within the caller's bound.
    TIMED_OUT = "TIMED_OUT"
    #: The caller's network identity was refused.  A *different* question from
    #: source authorization, asked at a different layer, and neither answer
    #: implies the other: an identity permitted to call an agent has no
    #: authority to attest anything, and a key authorized to attest cannot
    #: thereby invoke a service.
    IDENTITY_REFUSED = "IDENTITY_REFUSED"
    #: The endpoint answered with a failure of its own.
    ENDPOINT_REFUSED = "ENDPOINT_REFUSED"
    #: Connection refused, name resolution failed, transport-level failure.
    UNREACHABLE = "UNREACHABLE"


@dataclass(frozen=True, slots=True)
class TransportError:
    failure: TransportFailure
    detail: str


class AcquisitionTransport(Protocol):
    """Carry assignment octets to one endpoint and bring response octets back.

    ``endpoint_ref`` comes from the cataloged profile and is an **address**.
    An implementation may refuse to resolve it, and refusing is the safe
    answer: an assignment that is not delivered leaves the case unchanged.

    Synchronous, because the commands either side of it are.  An assignment
    that has been sent and forgotten is a request whose deadline is the only
    thing that will ever notice it; a source that needs longer than the caller
    will wait answers with an abstention naming the reason, which is a durable,
    typed fact rather than a dropped call.
    """

    def deliver(self, *, endpoint_ref: str, assignment: bytes) -> Result[bytes, TransportError]:
        """Deliver one assignment; return the source's encoded response."""
        ...
