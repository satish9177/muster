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
from muster.core.values.scalars import Value, read_value
from muster.core.values.symbols import SymbolRef, read_symbol_ref
from muster.core.wire.codec import canonical_order, is_canonically_ordered
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import Node, NRec, NSeq
from muster.core.wire.shape import WireFailure, fail, read_rec, read_seq

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


def read_binding(node: Node) -> Binding:
    ref, value = read_rec(node, TAG_BINDING, 2)
    return Binding(read_symbol_ref(ref), read_value(value))


def read_world(node: Node) -> World:
    """The inverse of :meth:`World.to_node`, refusing what the constructor would.

    ``World`` enforces uniqueness and canonical order by raising, which is right
    for a value the system builds: producing an unordered world is a defect.  It
    is the wrong answer for octets that arrived from a store, where a violation
    is a *finding about the octets* and has to reach the caller as one.  So both
    invariants are checked here first and reported as wire failures; the
    constructor then never raises, and no decode of a stored artifact turns a
    corrupt row into an exception on a reading path.
    """
    (bindings,) = read_rec(node, TAG_WORLD, 1)
    read = read_seq(bindings, read_binding)
    refs = [binding.ref for binding in read]
    if len(set(refs)) != len(refs):
        raise fail(WireFailure.NOT_CANONICAL, "a world binding each reference once", "a repeat")
    if not is_canonically_ordered(read, lambda binding: binding.to_node()):
        raise fail(WireFailure.NOT_CANONICAL, "world bindings in canonical order", "out of order")
    return World(read)


def world_of(assignment: dict[SymbolRef, Value]) -> World:
    """Build a world in canonical order from an assignment."""
    bindings = tuple(Binding(ref, value) for ref, value in assignment.items())
    return World(canonical_order(bindings, lambda binding: binding.to_node()))
