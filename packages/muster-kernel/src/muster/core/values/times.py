"""Instants, durations and validity intervals.

An instant is an integer count of microseconds since the Unix epoch.  The
kernel never reads a clock: ``as_of`` is an input to the case revision, so
replaying a revision a year later reproduces it exactly.

A ``Duration`` is *not* an instant, and it is a class rather than a second
alias for ``int`` precisely so that the type checker can say so.  Both were
spelled ``Instant`` here once, which made ``request_ttl: Instant`` -- "answer
within an hour" -- indistinguishable in a signature from ``now: Instant`` --
"the moment it is".  Passing one where the other belonged typechecked, and the
two mistakes it permits are a deadline an hour after the epoch and a deadline
fifty-six years after now.  The only arithmetic between them is
``Duration.after``, which names its own direction, so a deadline is always
computed rather than assembled.

**Why it lives here when only the control plane calls it.**  The distinction is
between ``Duration`` and ``Instant``, and ``Instant`` is here -- so a
``Duration`` declared anywhere else would put the two halves of one vocabulary
on opposite sides of a package boundary, and the kernel would be free to grow a
second one with different rules.  This is a value type in the package that owns
value types, and the control plane consuming it is the same relationship it
already has with ``Instant`` itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.results import InvariantViolation
from muster.core.wire.nodes import NInt, Node, NRec
from muster.core.wire.shape import option_node, read_int, read_option, read_rec

type Instant = int

TAG_HALF_OPEN = "HalfOpen/v1"


@dataclass(frozen=True, slots=True)
class Duration:
    """A length of time in microseconds. Never a point in time.

    Non-negative, because a duration is a magnitude and the direction belongs
    to the operation that applies it.  There is no ``before``: nothing in this
    system dates anything backwards, and an operation nobody needs is an
    operation nobody has checked.

    Deliberately not serialisable.  No durable contract holds one -- an
    evidence request stores the ``Instant`` its deadline resolved to, not the
    policy that produced it -- and a wire tag for a value nothing persists
    would be a format to keep compatible forever for no reader.
    """

    microseconds: int

    def __post_init__(self) -> None:
        if self.microseconds < 0:
            raise InvariantViolation(f"a duration is not negative: {self.microseconds}")

    def after(self, instant: Instant) -> Instant:
        """The instant this long after ``instant``. The only mixed arithmetic there is."""
        return instant + self.microseconds

    def is_positive(self) -> bool:
        """``False`` for the zero duration, which is a value and rarely a deadline."""
        return self.microseconds > 0


@dataclass(frozen=True, slots=True)
class HalfOpenInterval:
    """``[start, end)``. An open end means "no declared expiry"."""

    start: Instant
    end: Instant | None = None

    def __post_init__(self) -> None:
        if self.end is not None and self.end <= self.start:
            raise InvariantViolation(f"empty validity interval [{self.start}, {self.end})")

    def contains(self, moment: Instant) -> bool:
        return self.start <= moment and (self.end is None or moment < self.end)

    def to_node(self) -> NRec:
        return NRec(
            TAG_HALF_OPEN,
            (NInt(self.start), option_node(None if self.end is None else NInt(self.end))),
        )


def read_half_open(node: Node) -> HalfOpenInterval:
    start, end = read_rec(node, TAG_HALF_OPEN, 2)
    return HalfOpenInterval(read_int(start), read_option(end, read_int))
