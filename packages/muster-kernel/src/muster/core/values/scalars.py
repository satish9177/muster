"""Concrete values, and their relationship to sorts and declared domains."""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.results import InvariantViolation, Result
from muster.core.values.sorts import (
    BoolDomain,
    BoolSort,
    Domain,
    EnumDomain,
    EnumSort,
    IntRange,
    IntSort,
    ScaledRange,
    ScaledSort,
    Sort,
)
from muster.core.wire.nodes import NAtom, NBool, NInt, Node, NRec, NSeq, NTagged
from muster.core.wire.shape import (
    WireError,
    WireFailure,
    decoded,
    fail,
    read_atom,
    read_bool,
    read_int,
    read_rec,
    read_tagged,
)

TAG_VSCALED = "VScaled/v1"
TAG_VENUM = "VEnum/v1"


@dataclass(frozen=True, slots=True)
class VBool:
    value: bool

    def to_node(self) -> NTagged:
        return NTagged("VBool", NBool(self.value))


@dataclass(frozen=True, slots=True)
class VInt:
    value: int

    def to_node(self) -> NTagged:
        return NTagged("VInt", NInt(self.value))


@dataclass(frozen=True, slots=True)
class VScaled:
    unit_tag: str
    scale: int
    minor: int

    def to_node(self) -> NTagged:
        return NTagged(
            "VScaled",
            NRec(TAG_VSCALED, (NAtom(self.unit_tag), NInt(self.scale), NInt(self.minor))),
        )

    def render(self) -> str:
        if self.scale == 0:
            return f"{self.unit_tag} {self.minor}"
        divisor = 10**self.scale
        sign = "-" if self.minor < 0 else ""
        whole, fraction = divmod(abs(self.minor), divisor)
        return f"{self.unit_tag} {sign}{whole:,}.{fraction:0{self.scale}d}"


@dataclass(frozen=True, slots=True)
class VEnum:
    enum_id: str
    member: str

    def to_node(self) -> NTagged:
        return NTagged("VEnum", NRec(TAG_VENUM, (NAtom(self.enum_id), NAtom(self.member))))


type Value = VBool | VInt | VScaled | VEnum


def sort_of(value: Value) -> Sort:
    match value:
        case VBool():
            return BoolSort()
        case VInt():
            return IntSort()
        case VScaled(unit_tag, scale, _):
            return ScaledSort(unit_tag, scale)
        case VEnum(enum_id, _):
            return EnumSort(enum_id)


def value_in_domain(value: Value, domain: Domain) -> bool:
    match value, domain:
        case VBool(), BoolDomain():
            return True
        case VInt(number), IntRange(lo, hi):
            return lo <= number <= hi
        case VScaled(_, _, minor), ScaledRange(lo, hi):
            return lo <= minor <= hi
        case VEnum(_, member), EnumDomain(members):
            return member in members
        case _:
            return False


def enumerate_domain(sort: Sort, domain: Domain) -> tuple[Value, ...]:
    """Every value of a declared finite domain, in canonical declaration order.

    Used only by the bounded reference backend and by explanation-time
    enumeration.  It is never consulted to decide invariance.
    """
    match sort, domain:
        case BoolSort(), BoolDomain():
            return (VBool(False), VBool(True))
        case IntSort(), IntRange(lo, hi):
            return tuple(VInt(number) for number in range(lo, hi + 1))
        case ScaledSort(unit_tag, scale), ScaledRange(lo, hi):
            return tuple(VScaled(unit_tag, scale, minor) for minor in range(lo, hi + 1))
        case EnumSort(enum_id), EnumDomain(members):
            return tuple(VEnum(enum_id, member) for member in members)
        case _:
            return ()


def derived_filler(sort: Sort, domain: Domain) -> Value:
    """The canonical in-domain filler for a declared field.

    Only ever appears on a branch that an action-kind guard excludes, so it is
    never read; it exists so that every branch of a field selector has one sort.
    It is taken from the declared domain rather than invented, so it is a legal
    value of the field even where it is unreachable.
    """
    match sort, domain:
        case BoolSort(), BoolDomain():
            return VBool(False)
        case IntSort(), IntRange(lo, hi):
            return VInt(lo if lo > 0 else min(hi, 0))
        case ScaledSort(unit_tag, scale), ScaledRange(lo, hi):
            return VScaled(unit_tag, scale, lo if lo > 0 else min(hi, 0))
        case EnumSort(enum_id), EnumDomain(members):
            return VEnum(enum_id, members[0])
        case _:
            raise InvariantViolation(f"domain {domain} does not match sort {sort}")


def render(value: Value) -> str:
    match value:
        case VBool(flag):
            return "true" if flag else "false"
        case VInt(number):
            return str(number)
        case VScaled():
            return value.render()
        case VEnum(_, member):
            return member


def read_value(node: Node) -> Value:
    tag, payload = read_tagged(node, "Value")
    match tag:
        case "VBool":
            return VBool(read_bool(payload))
        case "VInt":
            return VInt(read_int(payload))
        case "VScaled":
            unit_tag, scale, minor = read_rec(payload, TAG_VSCALED, 3)
            return VScaled(read_atom(unit_tag), read_int(scale), read_int(minor))
        case "VEnum":
            enum_id, member = read_rec(payload, TAG_VENUM, 2)
            return VEnum(read_atom(enum_id), read_atom(member))
        case _:
            raise fail(WireFailure.UNKNOWN_VARIANT, "Value", tag)


def decode_value(node: Node) -> Result[Value, WireError]:
    return decoded(lambda: read_value(node))


def value_node(value: Value) -> NTagged:
    """Encode a value. A named function rather than a lambda over a union."""
    return value.to_node()


def value_seq(values: tuple[Value, ...]) -> NSeq:
    return NSeq(tuple(value_node(value) for value in values))
