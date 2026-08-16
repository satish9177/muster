"""Total result values.

Errors that a caller is expected to handle travel as values, never as
exceptions, across every public boundary in the kernel.  ``InvariantViolation``
is reserved for programmer error -- a state the type system could not exclude
and no input can produce.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Ok[T]:
    """A successful outcome carrying its value."""

    value: T


@dataclass(frozen=True, slots=True)
class Err[E]:
    """A failed outcome carrying a typed, inspectable error."""

    error: E


type Result[T, E] = Ok[T] | Err[E]


class InvariantViolation(Exception):
    """A kernel invariant was broken by kernel code.

    Never raised in response to untrusted input: input failures are typed
    rejections.  Raised only where a defect in this package would otherwise
    produce a silently wrong deterministic artifact.
    """
