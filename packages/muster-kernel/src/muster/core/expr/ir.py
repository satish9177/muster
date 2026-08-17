"""The expression IR.

One expression family, parameterized by its leaf.  Policy and case expressions
use ``SymbolRef`` leaves; solver-query expressions use world-qualified leaves.
The Phase-0.8 contract requires that the two are distinguishable at the octet
level and that neither can appear where the other belongs: a bare variable in a
query assertion, or a world-qualified variable in a policy term, is a schema
violation rather than a lint.

Both halves of that requirement are met here without writing the grammar twice.
The octet distinction comes from :class:`ExprFamily`, which carries the leaf tag
and the record-tag prefix (``Bin/v1`` against ``QBin/v1``).  The placement
distinction is the type parameter: ``Expr[SymbolRef]`` and ``Expr[QueryVar]``
are different types, so the confusion is a static error rather than a runtime
check that somebody has to remember to call.

The fragment is deliberately narrow -- quantifier-free, linear, integer-only,
total.  There are no floats and no variable denominators.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from muster.core.results import InvariantViolation
from muster.core.values.scalars import VEnum, VScaled
from muster.core.values.sorts import EnumSort, Sort, read_sort
from muster.core.wire.nodes import NAtom, NBool, NInt, Node, NRec, NSeq, NTagged
from muster.core.wire.shape import (
    WireFailure,
    fail,
    read_atom,
    read_bool,
    read_int,
    read_rec,
    read_seq,
    read_tagged,
)


class NAryOp(Enum):
    AND = "And"
    OR = "Or"
    ADD = "Add"


class BinaryOp(Enum):
    IMPLIES = "Implies"
    IFF = "Iff"
    SUB = "Sub"
    EQ = "Eq"
    NE = "Ne"
    LT = "Lt"
    LE = "Le"
    GT = "Gt"
    GE = "Ge"


@dataclass(frozen=True, slots=True)
class Leaf[L]:
    """A variable reference. The only place a family differs."""

    ref: L


@dataclass(frozen=True, slots=True)
class LitBool:
    value: bool


@dataclass(frozen=True, slots=True)
class LitInt:
    value: int


@dataclass(frozen=True, slots=True)
class LitScaled:
    value: VScaled


@dataclass(frozen=True, slots=True)
class LitEnum:
    value: VEnum


@dataclass(frozen=True, slots=True)
class Not[L]:
    operand: Expr[L]


@dataclass(frozen=True, slots=True)
class Neg[L]:
    operand: Expr[L]


@dataclass(frozen=True, slots=True)
class NAry[L]:
    """``And`` / ``Or`` / ``Add`` over at least two operands.

    Operand order is preserved, never normalized: an expression is authored
    structure, and rewriting it would make two authors of the same policy
    produce different octets for the same rule.
    """

    op: NAryOp
    operands: tuple[Expr[L], ...]

    def __post_init__(self) -> None:
        if len(self.operands) < 2:
            raise InvariantViolation(f"{self.op.value} needs at least two operands")


@dataclass(frozen=True, slots=True)
class Binary[L]:
    op: BinaryOp
    left: Expr[L]
    right: Expr[L]


@dataclass(frozen=True, slots=True)
class MulConst[L]:
    """Constant times term. The linearity restriction lives in this shape."""

    k: int
    operand: Expr[L]


@dataclass(frozen=True, slots=True)
class Scale[L]:
    """Introduce a unit: an integer term times a constant, typed as ``to``."""

    operand: Expr[L]
    k: int
    to: Sort


@dataclass(frozen=True, slots=True)
class Rescale[L]:
    """Widen a scaled term's scale. Narrowing is rejected -- see the type rules."""

    operand: Expr[L]
    to_scale: int


@dataclass(frozen=True, slots=True)
class Ite[L]:
    cond: Expr[L]
    if_true: Expr[L]
    if_false: Expr[L]


@dataclass(frozen=True, slots=True)
class Arm[L]:
    member: str
    term: Expr[L]


@dataclass(frozen=True, slots=True)
class EnumTable[L]:
    """An exhaustive table over an enum sort. Exhaustiveness is checked where
    the enum's declared members are known, which is program compilation."""

    scrutinee: Expr[L]
    arms: tuple[Arm[L], ...]

    def __post_init__(self) -> None:
        if not self.arms:
            raise InvariantViolation("an enum table needs at least one arm")


type Expr[L] = (
    Leaf[L]
    | LitBool
    | LitInt
    | LitScaled
    | LitEnum
    | Not[L]
    | Neg[L]
    | NAry[L]
    | Binary[L]
    | MulConst[L]
    | Scale[L]
    | Rescale[L]
    | Ite[L]
    | EnumTable[L]
)


@dataclass(frozen=True, slots=True)
class ExprFamily[L]:
    """How one expression family reaches the wire.

    ``prefix`` is what makes the two grammars distinguishable at the octet
    level: the composite records of the query family are tagged ``QBin/v1``,
    ``QIte/v1`` and so on, so a query assertion and a policy term can never be
    mistaken for one another by a decoder.
    """

    leaf_tag: str
    prefix: str
    encode_leaf: Callable[[L], Node]
    decode_leaf: Callable[[Node], L]

    def rec_tag(self, name: str) -> str:
        return f"{self.prefix}{name}/v1"


def freevars[L](expr: Expr[L]) -> frozenset[L]:
    """Every leaf reference occurring in the expression."""
    match expr:
        case Leaf(ref):
            return frozenset({ref})
        case LitBool() | LitInt() | LitScaled() | LitEnum():
            return frozenset()
        case Not(operand) | Neg(operand) | MulConst(_, operand) | Rescale(operand, _):
            return freevars(operand)
        case Scale(operand, _, _):
            return freevars(operand)
        case NAry(_, operands):
            return frozenset().union(*(freevars(operand) for operand in operands))
        case Binary(_, left, right):
            return freevars(left) | freevars(right)
        case Ite(cond, if_true, if_false):
            return freevars(cond) | freevars(if_true) | freevars(if_false)
        case EnumTable(scrutinee, arms):
            return freevars(scrutinee).union(*(freevars(arm.term) for arm in arms))


def enum_ids[L](expr: Expr[L]) -> frozenset[str]:
    """Every enum the expression mentions, by whatever route it mentions it.

    Not the same question as :func:`freevars`.  An enum reaches an expression
    through a *literal* as readily as through a variable -- the recipient of a
    payment is a constant of an enum no case variable carries -- and a caller
    that asked only which variables occur would never learn that the enum was
    there.  The leaf type is irrelevant to the answer, so this reads a policy
    term and a query assertion alike.
    """
    match expr:
        case Leaf() | LitBool() | LitInt() | LitScaled():
            return frozenset()
        case LitEnum(value):
            return frozenset({value.enum_id})
        case Not(operand) | Neg(operand) | MulConst(_, operand) | Rescale(operand, _):
            return enum_ids(operand)
        case Scale(operand, _, to):
            #  The target sort is part of the term's octets, so an enum named
            #  only there is still an enum the term mentions.
            named = frozenset({to.enum_id}) if isinstance(to, EnumSort) else frozenset[str]()
            return enum_ids(operand) | named
        case NAry(_, operands):
            return frozenset[str]().union(*(enum_ids(operand) for operand in operands))
        case Binary(_, left, right):
            return enum_ids(left) | enum_ids(right)
        case Ite(cond, if_true, if_false):
            return enum_ids(cond) | enum_ids(if_true) | enum_ids(if_false)
        case EnumTable(scrutinee, arms):
            #  An arm's member is a member name, not an enum id: which enum the
            #  table is over is decided by its scrutinee and nothing else.
            return enum_ids(scrutinee).union(*(enum_ids(arm.term) for arm in arms))


def map_leaves[L, M](expr: Expr[L], rewrite: Callable[[L], M]) -> Expr[M]:
    """Rewrite every leaf, preserving structure exactly.

    This is the whole of the query lowering: shared knowledge across the two
    worlds of a self-composed query is structural, because a symbol that is
    already established maps to one variable from both sides rather than to two
    variables tied together by an assertion somebody could forget to emit.
    """
    match expr:
        case Leaf(ref):
            return Leaf(rewrite(ref))
        case LitBool() | LitInt() | LitScaled() | LitEnum():
            return expr
        case Not(operand):
            return Not(map_leaves(operand, rewrite))
        case Neg(operand):
            return Neg(map_leaves(operand, rewrite))
        case MulConst(k, operand):
            return MulConst(k, map_leaves(operand, rewrite))
        case Rescale(operand, to_scale):
            return Rescale(map_leaves(operand, rewrite), to_scale)
        case Scale(operand, k, to):
            return Scale(map_leaves(operand, rewrite), k, to)
        case NAry(op, operands):
            return NAry(op, tuple(map_leaves(operand, rewrite) for operand in operands))
        case Binary(op, left, right):
            return Binary(op, map_leaves(left, rewrite), map_leaves(right, rewrite))
        case Ite(cond, if_true, if_false):
            return Ite(
                map_leaves(cond, rewrite),
                map_leaves(if_true, rewrite),
                map_leaves(if_false, rewrite),
            )
        case EnumTable(scrutinee, arms):
            return EnumTable(
                map_leaves(scrutinee, rewrite),
                tuple(Arm(arm.member, map_leaves(arm.term, rewrite)) for arm in arms),
            )


def expr_node[L](expr: Expr[L], family: ExprFamily[L]) -> Node:
    """Encode an expression in its family's grammar."""
    match expr:
        case Leaf(ref):
            return NTagged(family.leaf_tag, family.encode_leaf(ref))
        case LitBool(value):
            return NTagged("LitBool", NBool(value))
        case LitInt(value):
            return NTagged("LitInt", NInt(value))
        case LitScaled(value):
            return NTagged("LitScaled", _payload(value.to_node()))
        case LitEnum(value):
            return NTagged("LitEnum", _payload(value.to_node()))
        case Not(operand):
            return NTagged("Not", expr_node(operand, family))
        case Neg(operand):
            return NTagged("Neg", expr_node(operand, family))
        case NAry(op, operands):
            return NTagged(
                op.value, NSeq(tuple(expr_node(operand, family) for operand in operands))
            )
        case Binary(op, left, right):
            return NTagged(
                op.value,
                NRec(family.rec_tag("Bin"), (expr_node(left, family), expr_node(right, family))),
            )
        case MulConst(k, operand):
            return NTagged(
                "MulConst", NRec(family.rec_tag("MulConst"), (NInt(k), expr_node(operand, family)))
            )
        case Scale(operand, k, to):
            return NTagged(
                "Scale",
                NRec(family.rec_tag("Scale"), (expr_node(operand, family), NInt(k), to.to_node())),
            )
        case Rescale(operand, to_scale):
            return NTagged(
                "Rescale",
                NRec(family.rec_tag("Rescale"), (expr_node(operand, family), NInt(to_scale))),
            )
        case Ite(cond, if_true, if_false):
            return NTagged(
                "Ite",
                NRec(
                    family.rec_tag("Ite"),
                    (
                        expr_node(cond, family),
                        expr_node(if_true, family),
                        expr_node(if_false, family),
                    ),
                ),
            )
        case EnumTable(scrutinee, arms):
            return NTagged(
                "EnumTable",
                NRec(
                    family.rec_tag("EnumTable"),
                    (
                        expr_node(scrutinee, family),
                        NSeq(
                            tuple(
                                NRec(
                                    family.rec_tag("Arm"),
                                    (NAtom(arm.member), expr_node(arm.term, family)),
                                )
                                for arm in arms
                            )
                        ),
                    ),
                ),
            )


def _payload(tagged: NTagged) -> Node:
    """A literal carries the value's record, not the value's own variant tag."""
    return tagged.payload


def read_expr[L](node: Node, family: ExprFamily[L]) -> Expr[L]:
    tag, payload = read_tagged(node, "Term")
    if tag == family.leaf_tag:
        return Leaf(family.decode_leaf(payload))
    match tag:
        case "LitBool":
            return LitBool(read_bool(payload))
        case "LitInt":
            return LitInt(read_int(payload))
        case "LitScaled":
            return LitScaled(_read_scaled(payload))
        case "LitEnum":
            return LitEnum(_read_enum(payload))
        case "Not":
            return Not(read_expr(payload, family))
        case "Neg":
            return Neg(read_expr(payload, family))
        case "And" | "Or" | "Add":
            operands = read_seq(payload, lambda item: read_expr(item, family), minimum=2)
            return NAry(NAryOp(tag), operands)
        case "Implies" | "Iff" | "Sub" | "Eq" | "Ne" | "Lt" | "Le" | "Gt" | "Ge":
            left, right = read_rec(payload, family.rec_tag("Bin"), 2)
            return Binary(BinaryOp(tag), read_expr(left, family), read_expr(right, family))
        case "MulConst":
            k, operand = read_rec(payload, family.rec_tag("MulConst"), 2)
            return MulConst(read_int(k), read_expr(operand, family))
        case "Scale":
            operand, k, to = read_rec(payload, family.rec_tag("Scale"), 3)
            return Scale(read_expr(operand, family), read_int(k), read_sort(to))
        case "Rescale":
            operand, to_scale = read_rec(payload, family.rec_tag("Rescale"), 2)
            return Rescale(read_expr(operand, family), read_int(to_scale))
        case "Ite":
            cond, if_true, if_false = read_rec(payload, family.rec_tag("Ite"), 3)
            return Ite(
                read_expr(cond, family), read_expr(if_true, family), read_expr(if_false, family)
            )
        case "EnumTable":
            scrutinee, arms = read_rec(payload, family.rec_tag("EnumTable"), 2)
            return EnumTable(
                read_expr(scrutinee, family),
                read_seq(arms, lambda item: _read_arm(item, family), minimum=1),
            )
        case _:
            raise fail(WireFailure.UNKNOWN_VARIANT, "Term", tag)


def _read_arm[L](node: Node, family: ExprFamily[L]) -> Arm[L]:
    member, term = read_rec(node, family.rec_tag("Arm"), 2)
    return Arm(read_atom(member), read_expr(term, family))


def _read_scaled(node: Node) -> VScaled:
    unit_tag, scale, minor = read_rec(node, "VScaled/v1", 3)
    return VScaled(read_atom(unit_tag), read_int(scale), read_int(minor))


def _read_enum(node: Node) -> VEnum:
    enum_id, member = read_rec(node, "VEnum/v1", 2)
    return VEnum(read_atom(enum_id), read_atom(member))
