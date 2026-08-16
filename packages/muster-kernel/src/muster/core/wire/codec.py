"""The canonical codec: exactly one octet string per value, and back.

The grammar below is the frozen Phase-0.8 wire format.  Two properties are
load-bearing and are tested rather than asserted in prose:

* **Canonical.**  ``decode`` rejects every non-canonical encoding of a value it
  could otherwise accept -- a non-minimal integer, an unordered set, a
  duplicated set member.  So ``encode(decode(octets)) == octets`` holds for
  everything ``decode`` admits, and a digest identifies a value rather than a
  spelling of one.
* **Fail-closed.**  An unknown tag octet, an unknown length, a truncated stream
  or a trailing octet is a typed rejection.  Nothing is skipped, defaulted or
  repaired.

The codec is schema-free.  It never consults a type registry, so it decodes
artifacts written by a newer producer far enough to reject them precisely.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from itertools import pairwise

from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.nodes import (
    DIGEST_ALG_SHA256,
    DIGEST_OCTETS,
    MAX_ATOM_OCTETS,
    MAX_INT_OCTETS,
    MAX_RECORD_ARITY,
    TAG_ATOM,
    TAG_BOOL_FALSE,
    TAG_BOOL_TRUE,
    TAG_BYTES,
    TAG_DIGEST,
    TAG_INT,
    TAG_REC,
    TAG_SEQ,
    TAG_SET,
    TAG_TAGGED,
    TAG_UNIT,
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

_U32_LIMIT = 1 << 32


class DecodeFailure(Enum):
    """Why an octet string is not a canonical MUSTER value."""

    TRUNCATED = "TRUNCATED"
    TRAILING_OCTETS = "TRAILING_OCTETS"
    UNKNOWN_TAG_OCTET = "UNKNOWN_TAG_OCTET"
    NON_MINIMAL_INT = "NON_MINIMAL_INT"
    INT_OUT_OF_RANGE = "INT_OUT_OF_RANGE"
    ATOM_TOO_LONG = "ATOM_TOO_LONG"
    ATOM_NOT_UTF8 = "ATOM_NOT_UTF8"
    LENGTH_EXCEEDS_INPUT = "LENGTH_EXCEEDS_INPUT"
    SET_NOT_CANONICAL = "SET_NOT_CANONICAL"
    RECORD_SEPARATOR_MISSING = "RECORD_SEPARATOR_MISSING"
    ARITY_OUT_OF_RANGE = "ARITY_OUT_OF_RANGE"
    UNSUPPORTED_DIGEST_ALGORITHM = "UNSUPPORTED_DIGEST_ALGORITHM"


@dataclass(frozen=True, slots=True)
class DecodeError:
    failure: DecodeFailure
    offset: int
    detail: str = ""


def canonical_set(items: Iterable[Node]) -> NSet:
    """Build a set node in canonical order.

    Equal members collapse -- a set containing a value twice is the same set --
    and the result is strictly ascending by member octets, so the order a caller
    happened to discover the members in cannot reach the wire.
    """
    unique: dict[bytes, Node] = {}
    for item in items:
        unique.setdefault(encode(item), item)
    return NSet(tuple(unique[key] for key in sorted(unique)))


def canonical_order[T](items: Iterable[T], as_node: Callable[[T], Node]) -> tuple[T, ...]:
    """Order a derived collection ascending by its members' canonical octets.

    Applied to collections whose membership is semantic and whose order is not:
    established facts, constraints, recorded non-effects, declared instances.
    Authored sequences -- program rules, enum members, term operands -- keep the
    order they were written in, because there the order *is* the meaning.
    """
    return tuple(sorted(items, key=lambda item: encode(as_node(item))))


def is_canonically_ordered[T](items: Iterable[T], as_node: Callable[[T], Node]) -> bool:
    encoded = [encode(as_node(item)) for item in items]
    return all(a < b for a, b in pairwise(encoded))


def encode(node: Node) -> bytes:
    """Serialize a node to its unique canonical octet string."""
    out = bytearray()
    _encode_into(node, out)
    return bytes(out)


def decode(octets: bytes) -> Result[Node, DecodeError]:
    """Decode a complete canonical octet string.

    Trailing octets are a failure: an artifact is exactly its encoding, and a
    decoder that ignores a suffix accepts two artifacts under one digest.
    """
    reader = _Reader(octets)
    node = _decode_node(reader)
    if isinstance(node, Err):
        return node
    if reader.offset != len(octets):
        return Err(DecodeError(DecodeFailure.TRAILING_OCTETS, reader.offset))
    return node


def _encode_into(node: Node, out: bytearray) -> None:
    match node:
        case NUnit():
            out.append(TAG_UNIT)
        case NBool(value):
            out.append(TAG_BOOL_TRUE if value else TAG_BOOL_FALSE)
        case NInt(value):
            body = _int_octets(value)
            out.append(TAG_INT)
            out.append(len(body))
            out += body
        case NAtom(text):
            body = text.encode("utf-8")
            if len(body) > MAX_ATOM_OCTETS:
                raise InvariantViolation(f"atom exceeds {MAX_ATOM_OCTETS} octets: {len(body)}")
            out.append(TAG_ATOM)
            out.append(len(body))
            out += body
        case NBytes(value):
            _encode_prefixed(TAG_BYTES, len(value), out)
            out += value
        case NSeq(items):
            _encode_prefixed(TAG_SEQ, len(items), out)
            for item in items:
                _encode_into(item, out)
        case NSet(members):
            _check_set_canonical(members)
            _encode_prefixed(TAG_SET, len(members), out)
            for member in members:
                _encode_into(member, out)
        case NTagged(tag, payload):
            out.append(TAG_TAGGED)
            _encode_into(NAtom(tag), out)
            _encode_into(payload, out)
        case NRec(tag, fields):
            if len(fields) > MAX_RECORD_ARITY:
                raise InvariantViolation(f"record arity exceeds {MAX_RECORD_ARITY}")
            out.append(TAG_REC)
            _encode_into(NAtom(tag), out)
            out.append(0x00)
            out.append(len(fields))
            for field in fields:
                _encode_into(field, out)
        case NDigest(value):
            if len(value) != DIGEST_OCTETS:
                raise InvariantViolation(f"digest is not {DIGEST_OCTETS} octets: {len(value)}")
            out.append(TAG_DIGEST)
            out.append(DIGEST_ALG_SHA256)
            out += value


def _encode_prefixed(tag: int, count: int, out: bytearray) -> None:
    if count >= _U32_LIMIT:
        raise InvariantViolation(f"length {count} exceeds the declared 32-bit prefix")
    out.append(tag)
    out += count.to_bytes(4, "big")


def _check_set_canonical(members: tuple[Node, ...]) -> None:
    previous: bytes | None = None
    for member in members:
        current = encode(member)
        if previous is not None and current <= previous:
            raise InvariantViolation("set members are not strictly ascending; use canonical_set")
        previous = current


def _int_octets(value: int) -> bytes:
    """Minimal two's-complement big-endian octets; one octet for zero."""
    width = 1
    while True:
        try:
            return value.to_bytes(width, "big", signed=True)
        except OverflowError:
            width += 1
            if width > MAX_INT_OCTETS:
                raise InvariantViolation(
                    f"integer exceeds the declared {MAX_INT_OCTETS}-octet range"
                ) from None


class _Reader:
    __slots__ = ("octets", "offset")

    def __init__(self, octets: bytes) -> None:
        self.octets = octets
        self.offset = 0

    def take(self, count: int) -> bytes | None:
        end = self.offset + count
        if end > len(self.octets):
            return None
        chunk = self.octets[self.offset : end]
        self.offset = end
        return chunk


def _decode_node(reader: _Reader) -> Result[Node, DecodeError]:
    start = reader.offset
    head = reader.take(1)
    if head is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, start, "tag octet"))
    tag = head[0]
    match tag:
        case _ if tag == TAG_UNIT:
            return Ok(NUnit())
        case _ if tag == TAG_BOOL_FALSE:
            return Ok(NBool(False))
        case _ if tag == TAG_BOOL_TRUE:
            return Ok(NBool(True))
        case _ if tag == TAG_INT:
            return _decode_int(reader)
        case _ if tag == TAG_ATOM:
            return _decode_atom(reader)
        case _ if tag == TAG_BYTES:
            return _decode_bytes(reader)
        case _ if tag == TAG_SEQ:
            return _decode_seq(reader)
        case _ if tag == TAG_SET:
            return _decode_set(reader)
        case _ if tag == TAG_TAGGED:
            return _decode_tagged(reader)
        case _ if tag == TAG_REC:
            return _decode_rec(reader)
        case _ if tag == TAG_DIGEST:
            return _decode_digest(reader)
        case _:
            return Err(DecodeError(DecodeFailure.UNKNOWN_TAG_OCTET, start, f"0x{tag:02x}"))


def _decode_int(reader: _Reader) -> Result[Node, DecodeError]:
    at = reader.offset
    length = reader.take(1)
    if length is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, at, "integer length"))
    width = length[0]
    if width == 0:
        return Err(DecodeError(DecodeFailure.NON_MINIMAL_INT, at, "zero-width integer"))
    if width > MAX_INT_OCTETS:
        return Err(DecodeError(DecodeFailure.INT_OUT_OF_RANGE, at, f"{width} octets"))
    body = reader.take(width)
    if body is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, at, "integer body"))
    value = int.from_bytes(body, "big", signed=True)
    if _int_octets(value) != body:
        return Err(DecodeError(DecodeFailure.NON_MINIMAL_INT, at, body.hex()))
    return Ok(NInt(value))


def _decode_atom(reader: _Reader) -> Result[Node, DecodeError]:
    at = reader.offset
    length = reader.take(1)
    if length is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, at, "atom length"))
    body = reader.take(length[0])
    if body is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, at, "atom body"))
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return Err(DecodeError(DecodeFailure.ATOM_NOT_UTF8, at, body.hex()))
    return Ok(NAtom(text))


def _decode_count(reader: _Reader, what: str) -> Result[int, DecodeError]:
    at = reader.offset
    raw = reader.take(4)
    if raw is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, at, f"{what} length"))
    count = int.from_bytes(raw, "big")
    if count > len(reader.octets) - reader.offset:
        #  A declared length larger than the remaining input can only be a
        #  truncated or hostile stream; refuse before allocating for it.
        return Err(DecodeError(DecodeFailure.LENGTH_EXCEEDS_INPUT, at, f"{what}={count}"))
    return Ok(count)


def _decode_bytes(reader: _Reader) -> Result[Node, DecodeError]:
    count = _decode_count(reader, "bytes")
    if isinstance(count, Err):
        return count
    body = reader.take(count.value)
    if body is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, reader.offset, "bytes body"))
    return Ok(NBytes(body))


def _decode_items(reader: _Reader, what: str) -> Result[tuple[Node, ...], DecodeError]:
    count = _decode_count(reader, what)
    if isinstance(count, Err):
        return count
    items: list[Node] = []
    for _ in range(count.value):
        item = _decode_node(reader)
        if isinstance(item, Err):
            return item
        items.append(item.value)
    return Ok(tuple(items))


def _decode_seq(reader: _Reader) -> Result[Node, DecodeError]:
    items = _decode_items(reader, "seq")
    if isinstance(items, Err):
        return items
    return Ok(NSeq(items.value))


def _decode_set(reader: _Reader) -> Result[Node, DecodeError]:
    at = reader.offset
    items = _decode_items(reader, "set")
    if isinstance(items, Err):
        return items
    previous: bytes | None = None
    for member in items.value:
        current = encode(member)
        if previous is not None and current <= previous:
            return Err(DecodeError(DecodeFailure.SET_NOT_CANONICAL, at, current.hex()))
        previous = current
    return Ok(NSet(items.value))


def _decode_tagged(reader: _Reader) -> Result[Node, DecodeError]:
    at = reader.offset
    tag = _decode_node(reader)
    if isinstance(tag, Err):
        return tag
    if not isinstance(tag.value, NAtom):
        return Err(DecodeError(DecodeFailure.UNKNOWN_TAG_OCTET, at, "variant tag is not an atom"))
    payload = _decode_node(reader)
    if isinstance(payload, Err):
        return payload
    return Ok(NTagged(tag.value.text, payload.value))


def _decode_rec(reader: _Reader) -> Result[Node, DecodeError]:
    at = reader.offset
    tag = _decode_node(reader)
    if isinstance(tag, Err):
        return tag
    if not isinstance(tag.value, NAtom):
        return Err(DecodeError(DecodeFailure.UNKNOWN_TAG_OCTET, at, "record tag is not an atom"))
    header = reader.take(2)
    if header is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, reader.offset, "record header"))
    if header[0] != 0x00:
        return Err(DecodeError(DecodeFailure.RECORD_SEPARATOR_MISSING, reader.offset - 2))
    arity = header[1]
    if arity > len(reader.octets) - reader.offset:
        return Err(DecodeError(DecodeFailure.ARITY_OUT_OF_RANGE, reader.offset - 1, str(arity)))
    fields: list[Node] = []
    for _ in range(arity):
        field = _decode_node(reader)
        if isinstance(field, Err):
            return field
        fields.append(field.value)
    return Ok(NRec(tag.value.text, tuple(fields)))


def _decode_digest(reader: _Reader) -> Result[Node, DecodeError]:
    at = reader.offset
    algorithm = reader.take(1)
    if algorithm is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, at, "digest algorithm"))
    if algorithm[0] != DIGEST_ALG_SHA256:
        return Err(
            DecodeError(DecodeFailure.UNSUPPORTED_DIGEST_ALGORITHM, at, f"0x{algorithm[0]:02x}")
        )
    body = reader.take(DIGEST_OCTETS)
    if body is None:
        return Err(DecodeError(DecodeFailure.TRUNCATED, at, "digest body"))
    return Ok(NDigest(body))
