"""Worlds: total assignments over the unresolved variables.

A world is only ever produced by decoding a solver model, and it is validated
before anything reads it: total over the declared universe, in domain, extending
what is already established, and satisfying every constraint.  A partial world
is not a weaker world, it is a defect, and it is reported as indeterminate
rather than used.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.results import InvariantViolation
from muster.core.values.scalars import Value
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import canonical_order, is_canonically_ordered
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NRec, NSeq

TAG_BINDING = "Binding/v1"
TAG_WORLD = "World/v1"


@dataclass(frozen=True, slots=True)
class Binding:
    ref: SymbolRef
    value: Value

    def to_node(self) -> NRec:
        return NRec(TAG_BINDING, (self.ref.to_node(), self.value.to_node()))


@dataclass(frozen=True, slots=True)
class World:
    bindings: tuple[Binding, ...]

    def __post_init__(self) -> None:
        refs = [binding.ref for binding in self.bindings]
        if len(set(refs)) != len(refs):
            raise InvariantViolation("a world binds each reference once")
        if not is_canonically_ordered(self.bindings, lambda binding: binding.to_node()):
            raise InvariantViolation("world bindings are not in canonical order")

    def to_node(self) -> NRec:
        return NRec(TAG_WORLD, (NSeq(tuple(binding.to_node() for binding in self.bindings)),))

    def digest(self) -> Digest:
        return digest_node(DigestKind.WORLD, self.to_node())

    def assignment(self) -> dict[SymbolRef, Value]:
        return {binding.ref: binding.value for binding in self.bindings}


def world_of(assignment: dict[SymbolRef, Value]) -> World:
    """Build a world in canonical order from an assignment."""
    bindings = tuple(Binding(ref, value) for ref, value in assignment.items())
    return World(canonical_order(bindings, lambda binding: binding.to_node()))
