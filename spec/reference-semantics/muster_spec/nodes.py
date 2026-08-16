"""Canonical value model and reference codec for the MUSTER Phase-1 wire contract.

NON-PRODUCTION SPECIFICATION MATERIAL.  See ../README.md.

This module defines the value universe (`Node`) and the *only* normative mapping
between values and octets.  Nothing else in the specification is permitted to
serialise anything.

Primitive tags (frozen):

    0x01 UNIT    0x02 FALSE   0x03 TRUE    0x04 INT     0x05 ATOM    0x06 BYTES
    0x07 SEQ     0x08 SET     0x09 TAGGED  0x0A REC     0x0B DIGEST
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

# --------------------------------------------------------------------------
# tags
# --------------------------------------------------------------------------

T_UNIT = 0x01
T_FALSE = 0x02
T_TRUE = 0x03
T_INT = 0x04
T_ATOM = 0x05
T_BYTES = 0x06
T_SEQ = 0x07
T_SET = 0x08
T_TAGGED = 0x09
T_REC = 0x0A
T_DIGEST = 0x0B

ALGO_SHA256 = 0x01

ATOM_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")

INT_MIN = -(2 ** 127)
INT_MAX = 2 ** 127 - 1


class CodecError(Exception):
    """Raised for any non-canonical or malformed octet string / value."""


# --------------------------------------------------------------------------
# node model
# --------------------------------------------------------------------------


class Node:
    """Base of the canonical value universe."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class Unit(Node):
    pass


@dataclass(frozen=True, slots=True)
class Bool(Node):
    value: bool


@dataclass(frozen=True, slots=True)
class Int(Node):
    value: int

    def __post_init__(self) -> None:
        if not (INT_MIN <= self.value <= INT_MAX):
            raise CodecError(f"integer out of range: {self.value}")


@dataclass(frozen=True, slots=True)
class Atom(Node):
    value: str

    def __post_init__(self) -> None:
        if not ATOM_RE.match(self.value):
            raise CodecError(f"atom violates alphabet or length: {self.value!r}")


@dataclass(frozen=True, slots=True)
class Bytes(Node):
    value: bytes


@dataclass(frozen=True, slots=True)
class Digest(Node):
    raw: bytes
    algo: int = ALGO_SHA256

    def __post_init__(self) -> None:
        if self.algo != ALGO_SHA256:
            raise CodecError(f"unknown digest algorithm {self.algo:#x}")
        if len(self.raw) != 32:
            raise CodecError(f"digest must be 32 octets, got {len(self.raw)}")

    def hex(self) -> str:
        return self.raw.hex()


@dataclass(frozen=True, slots=True)
class Seq(Node):
    items: tuple[Node, ...]

    def __init__(self, items: Sequence[Node]) -> None:
        object.__setattr__(self, "items", tuple(items))


@dataclass(frozen=True, slots=True)
class SetV(Node):
    """Semantic set.  Construction sorts by full encoding and rejects duplicates."""

    items: tuple[Node, ...]

    def __init__(self, items: Sequence[Node]) -> None:
        encoded = [(encode(i), i) for i in items]
        encoded.sort(key=lambda p: p[0])
        for a, b in zip(encoded, encoded[1:]):
            if a[0] == b[0]:
                raise CodecError("duplicate element in SET")
        object.__setattr__(self, "items", tuple(i for _, i in encoded))


@dataclass(frozen=True, slots=True)
class Tagged(Node):
    variant: str
    value: Node

    def __post_init__(self) -> None:
        if not ATOM_RE.match(self.variant):
            raise CodecError(f"variant name violates atom alphabet: {self.variant!r}")


@dataclass(frozen=True, slots=True)
class Rec(Node):
    tag: str
    fields: tuple[Node, ...]

    def __init__(self, tag: str, fields: Sequence[Node]) -> None:
        if not ATOM_RE.match(tag):
            raise CodecError(f"record tag violates atom alphabet: {tag!r}")
        object.__setattr__(self, "tag", tag)
        object.__setattr__(self, "fields", tuple(fields))
        if len(self.fields) > 0xFFFF:
            raise CodecError("record arity exceeds u16")


# --------------------------------------------------------------------------
# integer helpers -- exactly one encoding per integer (R-5)
# --------------------------------------------------------------------------


def int_to_minimal(value: int) -> bytes:
    if not (INT_MIN <= value <= INT_MAX):
        raise CodecError(f"integer out of range: {value}")
    length = 1
    while True:
        try:
            candidate = value.to_bytes(length, "big", signed=True)
        except OverflowError:
            length += 1
            continue
        return candidate


def int_from_minimal(raw: bytes) -> int:
    if len(raw) == 0:
        raise CodecError("INT payload must be at least one octet")
    value = int.from_bytes(raw, "big", signed=True)
    if int_to_minimal(value) != raw:
        raise CodecError(f"non-minimal INT encoding: {raw.hex()}")
    return value


# --------------------------------------------------------------------------
# encoder
# --------------------------------------------------------------------------


def encode(node: Node) -> bytes:
    out = bytearray()
    _encode(node, out)
    return bytes(out)


def _encode(node: Node, out: bytearray) -> None:
    if isinstance(node, Unit):
        out.append(T_UNIT)
    elif isinstance(node, Bool):
        out.append(T_TRUE if node.value else T_FALSE)
    elif isinstance(node, Int):
        raw = int_to_minimal(node.value)
        out.append(T_INT)
        out.append(len(raw))
        out += raw
    elif isinstance(node, Atom):
        raw = node.value.encode("ascii")
        out.append(T_ATOM)
        out.append(len(raw))
        out += raw
    elif isinstance(node, Bytes):
        out.append(T_BYTES)
        out += len(node.value).to_bytes(4, "big")
        out += node.value
    elif isinstance(node, Digest):
        out.append(T_DIGEST)
        out.append(node.algo)
        out += node.raw
    elif isinstance(node, Seq):
        out.append(T_SEQ)
        out += len(node.items).to_bytes(4, "big")
        for item in node.items:
            _encode(item, out)
    elif isinstance(node, SetV):
        out.append(T_SET)
        out += len(node.items).to_bytes(4, "big")
        for item in node.items:
            _encode(item, out)
    elif isinstance(node, Tagged):
        out.append(T_TAGGED)
        _encode(Atom(node.variant), out)
        _encode(node.value, out)
    elif isinstance(node, Rec):
        out.append(T_REC)
        _encode(Atom(node.tag), out)
        out += len(node.fields).to_bytes(2, "big")
        for item in node.fields:
            _encode(item, out)
    else:  # pragma: no cover - exhaustive over the sealed union
        raise CodecError(f"unencodable node {type(node).__name__}")


# --------------------------------------------------------------------------
# decoder -- rejects every non-canonical accepting path
# --------------------------------------------------------------------------


class _Reader:
    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise CodecError("truncated input")
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")


def decode(raw: bytes) -> Node:
    reader = _Reader(raw)
    node = _decode(reader)
    if reader.pos != len(raw):
        raise CodecError(f"trailing octets after value: {len(raw) - reader.pos}")
    return node


def _decode_atom_payload(reader: _Reader) -> str:
    tag = reader.u8()
    if tag != T_ATOM:
        raise CodecError(f"expected ATOM tag, got {tag:#04x}")
    length = reader.u8()
    if length == 0:
        raise CodecError("ATOM length must be >= 1")
    raw = reader.take(length)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CodecError("ATOM payload is not ASCII") from exc
    if not ATOM_RE.match(text):
        raise CodecError(f"ATOM violates alphabet: {text!r}")
    return text


def _decode(reader: _Reader) -> Node:
    tag = reader.u8()
    if tag == T_UNIT:
        return Unit()
    if tag == T_FALSE:
        return Bool(False)
    if tag == T_TRUE:
        return Bool(True)
    if tag == T_INT:
        length = reader.u8()
        if length == 0:
            raise CodecError("INT length must be >= 1")
        return Int(int_from_minimal(reader.take(length)))
    if tag == T_ATOM:
        reader.pos -= 1
        return Atom(_decode_atom_payload(reader))
    if tag == T_BYTES:
        return Bytes(reader.take(reader.u32()))
    if tag == T_DIGEST:
        algo = reader.u8()
        if algo != ALGO_SHA256:
            raise CodecError(f"unknown digest algorithm {algo:#x}")
        return Digest(reader.take(32), algo)
    if tag == T_SEQ:
        count = reader.u32()
        return Seq([_decode(reader) for _ in range(count)])
    if tag == T_SET:
        count = reader.u32()
        items: list[Node] = []
        encodings: list[bytes] = []
        for _ in range(count):
            start = reader.pos
            items.append(_decode(reader))
            encodings.append(reader.buf[start : reader.pos])
        for a, b in zip(encodings, encodings[1:]):
            if a == b:
                raise CodecError("duplicate element in SET")
            if a > b:
                raise CodecError("SET elements are not in ascending encoding order")
        return SetV(items)
    if tag == T_TAGGED:
        variant = _decode_atom_payload(reader)
        return Tagged(variant, _decode(reader))
    if tag == T_REC:
        rec_tag = _decode_atom_payload(reader)
        count = reader.u16()
        return Rec(rec_tag, [_decode(reader) for _ in range(count)])
    raise CodecError(f"unknown primitive tag {tag:#04x}")


# --------------------------------------------------------------------------
# convenience constructors shared by the whole specification
# --------------------------------------------------------------------------


def none() -> Tagged:
    return Tagged("None", Unit())


def some(node: Node) -> Tagged:
    return Tagged("Some", node)


def hexdump(raw: bytes) -> str:
    return " ".join(f"{b:02X}" for b in raw)
