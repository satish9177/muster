"""The two ambient values an attestation needs, behind ports so a test can pin them.

A signed payload carries an issue instant and a nonce.  Both are ambient -- one
comes from a clock, the other from an entropy source -- and both are therefore
supplied rather than read, for the reason the control plane supplies ``now``
rather than reading it: a value nothing can fix is a value no regression can
pin, and an acquisition nobody can reproduce is one nobody can attack.

The nonce is what stops two observations of the same proposition, by the same
key, at the same instant, from being the same octets.  It is *not* a security
boundary on its own -- the payload already carries the request it answers and
the case it belongs to -- so a sequence source is a legitimate implementation
for a test, and the deployed agent uses the system source.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Protocol

from muster.core.evidence.transcript import NONCE_OCTETS
from muster.core.results import InvariantViolation
from muster.core.values.times import Instant

#: Microseconds per second.  The wire instant is microseconds since the epoch.
MICROSECONDS = 1_000_000


class SourceClock(Protocol):
    """What instant this source believes it is."""

    def now(self) -> Instant: ...


class NonceSource(Protocol):
    """Fresh octets for one payload."""

    def nonce(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class SystemClock:
    """The deployed agent's clock.  Never reached from a test."""

    def now(self) -> Instant:
        return int(time.time() * MICROSECONDS)


@dataclass(frozen=True, slots=True)
class FixedClock:
    """One instant, forever.

    Used by the demo as well as by tests, and deliberately so: the worked case
    is pinned to an ``as_of`` that is not today, and a receipt is admissible
    only inside a validity window containing the revision's instant.  A demo
    that read the wall clock would produce receipts that verify, admit, and do
    nothing -- which is the most confusing possible failure.
    """

    instant: Instant

    def now(self) -> Instant:
        return self.instant


@dataclass(frozen=True, slots=True)
class SystemNonce:
    """Cryptographic entropy, from the operating system."""

    def nonce(self) -> bytes:
        return secrets.token_bytes(NONCE_OCTETS)


@dataclass(slots=True)
class SequenceNonce:
    """Counting nonces, for a test that needs two receipts to differ predictably.

    Mutable on purpose and the only mutable value in this package: a counter
    that did not advance would produce two payloads with one identity, and a
    test that could not tell them apart would be testing nothing.
    """

    counter: int = field(default=0)

    def nonce(self) -> bytes:
        if self.counter < 0:
            raise InvariantViolation("a nonce counter does not run backwards")
        issued = self.counter
        self.counter += 1
        return issued.to_bytes(NONCE_OCTETS, "big")
