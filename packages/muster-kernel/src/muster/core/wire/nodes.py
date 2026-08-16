"""The canonical value model.

Every MUSTER wire type encodes to a tree of these ten node kinds, and the octet
grammar is defined over the tree rather than over any particular type.  The
split is deliberate: the codec is total and schema-free, so a decoder can read
an artifact it has no type for, and typed decoding is a separate, fallible step
that runs afterwards.

Nodes are immutable values.  ``NSet`` additionally carries a canonical-order
invariant that only :func:`muster.core.wire.codec.canonical_set` establishes.
"""

from __future__ import annotations

from dataclasses import dataclass

#  Grammar octets.  These are the specification, not implementation choices.
TAG_UNIT: int = 0x01
TAG_BOOL_FALSE: int = 0x02
TAG_BOOL_TRUE: int = 0x03
TAG_INT: int = 0x04
TAG_ATOM: int = 0x05
TAG_BYTES: int = 0x06
TAG_SEQ: int = 0x07
TAG_SET: int = 0x08
TAG_TAGGED: int = 0x09
TAG_REC: int = 0x0A
TAG_DIGEST: int = 0x0B

#  Digest values are SHA-256 today; the algorithm octet exists so a future
#  primitive is a new value rather than a reinterpreted length.
DIGEST_ALG_SHA256: int = 0x01
DIGEST_OCTETS: int = 32

#  Declared serialization bounds.  Both are enforced on encode and on decode, so
#  an artifact outside them is unrepresentable rather than merely unusual.
MAX_ATOM_OCTETS: int = 0xFF
MAX_INT_OCTETS: int = 0x20
MAX_RECORD_ARITY: int = 0xFF


@dataclass(frozen=True, slots=True)
class NUnit:
    """The single inhabitant of the unit type; the payload of a nullary variant."""


@dataclass(frozen=True, slots=True)
class NBool:
    value: bool


@dataclass(frozen=True, slots=True)
class NInt:
    """An arbitrary-precision integer. There are no floats anywhere in MUSTER."""

    value: int


@dataclass(frozen=True, slots=True)
class NAtom:
    """A short interned symbol: an identifier, a label, a variant tag."""

    text: str


@dataclass(frozen=True, slots=True)
class NBytes:
    value: bytes


@dataclass(frozen=True, slots=True)
class NSeq:
    """An ordered sequence. Order is semantic and is never rewritten."""

    items: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class NSet:
    """A set, held in canonical order: strictly ascending by member octets.

    Only :func:`muster.core.wire.codec.canonical_set` may build one, because
    the ordering invariant is what makes set-valued fields independent of the
    order a caller happened to discover the members in.
    """

    members: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class NTagged:
    """A sum-type variant: the variant name and its payload."""

    tag: str
    payload: Node


@dataclass(frozen=True, slots=True)
class NRec:
    """A record: a versioned type tag and a fixed number of positional fields."""

    tag: str
    fields: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class NDigest:
    """A SHA-256 digest over a domain-separated preimage."""

    value: bytes


type Node = NUnit | NBool | NInt | NAtom | NBytes | NSeq | NSet | NTagged | NRec | NDigest
