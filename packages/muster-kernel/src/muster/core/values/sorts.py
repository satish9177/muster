"""Sorts and declared domains.

The unit tag and scale are part of the *sort*, not a label beside it, so
``ScaledSort("INR", 2)`` and ``ScaledSort("USD", 2)`` are different types and
adding them is a type error the expression checker reports rather than a
rounding surprise in a payment.  There are no floats: a scaled quantity is an
integer count of minor units.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.results import InvariantViolation, Result
from muster.core.wire.nodes import NAtom, NInt, Node, NRec, NSeq, NTagged, NUnit
from muster.core.wire.shape import (
    WireError,
    WireFailure,
    atoms,
    decoded,
    fail,
    read_atom,
    read_int,
    read_rec,
    read_seq,
    read_tagged,
)

TAG_SCALED_SORT = "ScaledSort/v1"
TAG_ENUM_SORT = "EnumSort/v1"
TAG_INT_RANGE = "IntRange/v1"
TAG_SCALED_RANGE = "ScaledRange/v1"
TAG_ENUM_DOMAIN = "EnumDomain/v1"


@dataclass(frozen=True, slots=True)
class BoolSort:
    def to_node(self) -> NTagged:
        return NTagged("Bool", NUnit())


@dataclass(frozen=True, slots=True)
class IntSort:
    def to_node(self) -> NTagged:
        return NTagged("Int", NUnit())


@dataclass(frozen=True, slots=True)
class ScaledSort:
    """A tagged integer quantity: ``minor`` units of ``unit_tag`` at ``scale``."""

    unit_tag: str
    scale: int

    def __post_init__(self) -> None:
        if self.scale < 0:
            raise InvariantViolation(f"scale must be non-negative: {self.scale}")

    def to_node(self) -> NTagged:
        return NTagged("Scaled", NRec(TAG_SCALED_SORT, (NAtom(self.unit_tag), NInt(self.scale))))


@dataclass(frozen=True, slots=True)
class EnumSort:
    enum_id: str

    def to_node(self) -> NTagged:
        return NTagged("Enum", NRec(TAG_ENUM_SORT, (NAtom(self.enum_id),)))


type Sort = BoolSort | IntSort | ScaledSort | EnumSort


@dataclass(frozen=True, slots=True)
class BoolDomain:
    def to_node(self) -> NTagged:
        return NTagged("BoolDomain", NUnit())


@dataclass(frozen=True, slots=True)
class IntRange:
    lo: int
    hi: int

    def to_node(self) -> NTagged:
        return NTagged("IntRange", NRec(TAG_INT_RANGE, (NInt(self.lo), NInt(self.hi))))


@dataclass(frozen=True, slots=True)
class ScaledRange:
    """Bounds in minor units of the declared scaled sort."""

    lo: int
    hi: int

    def to_node(self) -> NTagged:
        return NTagged("ScaledRange", NRec(TAG_SCALED_RANGE, (NInt(self.lo), NInt(self.hi))))


@dataclass(frozen=True, slots=True)
class EnumDomain:
    members: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.members:
            raise InvariantViolation("an enum domain has at least one member")
        if len(set(self.members)) != len(self.members):
            raise InvariantViolation(f"duplicate enum member in {self.members}")

    def to_node(self) -> NTagged:
        return NTagged("EnumDomain", NRec(TAG_ENUM_DOMAIN, (atoms(self.members),)))


type Domain = BoolDomain | IntRange | ScaledRange | EnumDomain


def domain_matches_sort(domain: Domain, sort: Sort) -> bool:
    """A domain is meaningful only against the sort it was declared with.

    ``ScaledRange`` carries no unit tag by design -- its bounds are minor units
    of the sort beside it -- so this pairing is checked wherever a declaration
    is admitted rather than inferred later.
    """
    match domain, sort:
        case BoolDomain(), BoolSort():
            return True
        case IntRange(), IntSort():
            return True
        case ScaledRange(), ScaledSort():
            return True
        case EnumDomain(), EnumSort():
            return True
        case _:
            return False


def domain_is_finite(domain: Domain) -> bool:
    """Every declared domain in the Phase-1 fragment is finite by construction."""
    match domain:
        case BoolDomain() | EnumDomain():
            return True
        case IntRange(lo, hi) | ScaledRange(lo, hi):
            return hi >= lo


def domain_cardinality(domain: Domain) -> int:
    match domain:
        case BoolDomain():
            return 2
        case EnumDomain(members):
            return len(members)
        case IntRange(lo, hi) | ScaledRange(lo, hi):
            return max(0, hi - lo + 1)


#  ---- decoding -----------------------------------------------------------


def read_sort(node: Node) -> Sort:
    tag, payload = read_tagged(node, "Sort")
    match tag:
        case "Bool":
            return BoolSort()
        case "Int":
            return IntSort()
        case "Scaled":
            unit_tag, scale = read_rec(payload, TAG_SCALED_SORT, 2)
            return ScaledSort(read_atom(unit_tag), read_int(scale))
        case "Enum":
            (enum_id,) = read_rec(payload, TAG_ENUM_SORT, 1)
            return EnumSort(read_atom(enum_id))
        case _:
            raise fail(WireFailure.UNKNOWN_VARIANT, "Sort", tag)


def decode_sort(node: Node) -> Result[Sort, WireError]:
    return decoded(lambda: read_sort(node))


def read_domain(node: Node) -> Domain:
    tag, payload = read_tagged(node, "Domain")
    match tag:
        case "BoolDomain":
            return BoolDomain()
        case "IntRange":
            lo, hi = read_rec(payload, TAG_INT_RANGE, 2)
            return IntRange(read_int(lo), read_int(hi))
        case "ScaledRange":
            lo, hi = read_rec(payload, TAG_SCALED_RANGE, 2)
            return ScaledRange(read_int(lo), read_int(hi))
        case "EnumDomain":
            (members,) = read_rec(payload, TAG_ENUM_DOMAIN, 1)
            return EnumDomain(read_seq(members, read_atom, minimum=1))
        case _:
            raise fail(WireFailure.UNKNOWN_VARIANT, "Domain", tag)


def decode_domain(node: Node) -> Result[Domain, WireError]:
    return decoded(lambda: read_domain(node))


def sort_seq(sorts: tuple[Sort, ...]) -> NSeq:
    return NSeq(tuple(sort.to_node() for sort in sorts))
