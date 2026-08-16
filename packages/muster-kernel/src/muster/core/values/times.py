"""Instants and validity intervals.

An instant is an integer count of microseconds.  The kernel never reads a
clock: ``as_of`` is an input to the case revision, so replaying a revision a
year later reproduces it exactly.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.results import InvariantViolation
from muster.core.wire.nodes import NInt, Node, NRec
from muster.core.wire.shape import option_node, read_int, read_option, read_rec

type Instant = int

TAG_HALF_OPEN = "HalfOpen/v1"


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
