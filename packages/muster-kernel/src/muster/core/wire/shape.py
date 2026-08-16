"""Helpers shared by every typed encoder and decoder.

Encoding is a total function, so it needs only constructors.  Decoding is
fallible at every field, and threading a ``Result`` through a recursive
grammar makes the grammar unreadable.  So decoders raise :class:`WireDecodeError`
internally and :func:`decoded` converts it to a value at the public boundary.
The exception never crosses that boundary; callers see ``Result`` only.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum

from muster.core.results import Err, Ok, Result
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import (
    NAtom,
    NBool,
    NBytes,
    NDigest,
    NInt,
    Node,
    NRec,
    NSeq,
    NSet,
    NTagged,
    NUnit,
)

NONE_NODE = NTagged("None", NUnit())


class WireFailure(Enum):
    """Why a canonical node is not a value of the expected type."""

    UNEXPECTED_NODE = "UNEXPECTED_NODE"
    UNKNOWN_TYPE_TAG = "UNKNOWN_TYPE_TAG"
    UNKNOWN_VARIANT = "UNKNOWN_VARIANT"
    ARITY_MISMATCH = "ARITY_MISMATCH"
    OUT_OF_RANGE = "OUT_OF_RANGE"
    NOT_CANONICAL = "NOT_CANONICAL"


@dataclass(frozen=True, slots=True)
class WireError:
    failure: WireFailure
    expected: str
    found: str = ""


class WireDecodeError(Exception):
    """Internal control flow for typed decoding. Never crosses a public boundary."""

    def __init__(self, error: WireError) -> None:
        super().__init__(f"{error.failure.value}: expected {error.expected}, found {error.found}")
        self.error = error


def fail(failure: WireFailure, expected: str, found: object = "") -> WireDecodeError:
    return WireDecodeError(WireError(failure, expected, str(found)))


def decoded[T](decode: Callable[[], T]) -> Result[T, WireError]:
    """Run a typed decoder, converting its internal failure into a value."""
    try:
        return Ok(decode())
    except WireDecodeError as failure:
        return Err(failure.error)


#  ---- constructors -------------------------------------------------------


def option_node(node: Node | None) -> Node:
    """``Some(x)`` or ``None``.

    Takes an already-encoded node rather than a value and an encoder.  The
    generic form cannot be typed usefully: given a union-typed optional field
    the element type widens to ``object`` and no encoder matches it.  Encoding
    at the call site costs one conditional and keeps the helper honest.
    """
    return NONE_NODE if node is None else NTagged("Some", node)


def atom_or_none(text: str | None) -> NAtom | None:
    """An optional atom, ready for :func:`option_node`."""
    return None if text is None else NAtom(text)


def atoms(values: Iterable[str]) -> NSeq:
    return NSeq(tuple(NAtom(value) for value in values))


def digests(values: Iterable[Digest]) -> NSeq:
    return NSeq(tuple(value.to_node() for value in values))


#  ---- readers ------------------------------------------------------------


def read_rec(node: Node, tag: str, arity: int) -> tuple[Node, ...]:
    if not isinstance(node, NRec):
        raise fail(WireFailure.UNEXPECTED_NODE, f"record {tag}", type(node).__name__)
    if node.tag != tag:
        raise fail(WireFailure.UNKNOWN_TYPE_TAG, tag, node.tag)
    if len(node.fields) != arity:
        raise fail(WireFailure.ARITY_MISMATCH, f"{tag} arity {arity}", len(node.fields))
    return node.fields


def read_tagged(node: Node, of: str) -> tuple[str, Node]:
    if not isinstance(node, NTagged):
        raise fail(WireFailure.UNEXPECTED_NODE, f"variant of {of}", type(node).__name__)
    return node.tag, node.payload


def read_atom(node: Node) -> str:
    if not isinstance(node, NAtom):
        raise fail(WireFailure.UNEXPECTED_NODE, "atom", type(node).__name__)
    return node.text


def read_member(node: Node, permitted: frozenset[str], of: str) -> str:
    text = read_atom(node)
    if text not in permitted:
        raise fail(WireFailure.OUT_OF_RANGE, f"{of} in {sorted(permitted)}", text)
    return text


def read_int(node: Node) -> int:
    if not isinstance(node, NInt):
        raise fail(WireFailure.UNEXPECTED_NODE, "integer", type(node).__name__)
    return node.value


def read_bool(node: Node) -> bool:
    if not isinstance(node, NBool):
        raise fail(WireFailure.UNEXPECTED_NODE, "boolean", type(node).__name__)
    return node.value


def read_bytes(node: Node, width: int | None = None) -> bytes:
    if not isinstance(node, NBytes):
        raise fail(WireFailure.UNEXPECTED_NODE, "bytes", type(node).__name__)
    if width is not None and len(node.value) != width:
        raise fail(WireFailure.OUT_OF_RANGE, f"{width} octets", len(node.value))
    return node.value


def read_digest(node: Node) -> Digest:
    if not isinstance(node, NDigest):
        raise fail(WireFailure.UNEXPECTED_NODE, "digest", type(node).__name__)
    return Digest(node.value)


def read_seq[T](node: Node, read_item: Callable[[Node], T], minimum: int = 0) -> tuple[T, ...]:
    if not isinstance(node, NSeq):
        raise fail(WireFailure.UNEXPECTED_NODE, "sequence", type(node).__name__)
    if len(node.items) < minimum:
        raise fail(WireFailure.OUT_OF_RANGE, f"at least {minimum} items", len(node.items))
    return tuple(read_item(item) for item in node.items)


def read_set[T](node: Node, read_item: Callable[[Node], T], minimum: int = 0) -> tuple[T, ...]:
    if not isinstance(node, NSet):
        raise fail(WireFailure.UNEXPECTED_NODE, "set", type(node).__name__)
    if len(node.members) < minimum:
        raise fail(WireFailure.OUT_OF_RANGE, f"at least {minimum} members", len(node.members))
    return tuple(read_item(member) for member in node.members)


def read_option[T](node: Node, read_inner: Callable[[Node], T]) -> T | None:
    tag, payload = read_tagged(node, "Option")
    match tag:
        case "None":
            if not isinstance(payload, NUnit):
                raise fail(WireFailure.UNEXPECTED_NODE, "unit", type(payload).__name__)
            return None
        case "Some":
            return read_inner(payload)
        case _:
            raise fail(WireFailure.UNKNOWN_VARIANT, "Some | None", tag)
