"""``Term`` -- the expression family whose leaves are proposition references.

This is the expression type that policy programs, entailment rules and case
constraints are written in.  Its leaves are plain ``SymbolRef``s: a term in this
family cannot mention a world, which is what makes a world-qualified leaf in a
policy or case structure a type error rather than a convention.
"""

from __future__ import annotations

from muster.core.expr.ir import (
    Expr,
    ExprFamily,
    LitBool,
    LitEnum,
    LitInt,
    LitScaled,
    expr_node,
    read_expr,
)
from muster.core.results import Result
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled
from muster.core.values.symbols import SymbolRef, read_symbol_ref
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import Node, NSeq
from muster.core.wire.shape import WireError, decoded

type Term = Expr[SymbolRef]

TERM_FAMILY: ExprFamily[SymbolRef] = ExprFamily(
    leaf_tag="Var",
    prefix="",
    encode_leaf=lambda ref: ref.to_node(),
    decode_leaf=read_symbol_ref,
)


def literal[L](value: Value) -> Expr[L]:
    """Lift a concrete value into the matching literal term."""
    match value:
        case VBool(flag):
            return LitBool(flag)
        case VInt(number):
            return LitInt(number)
        case VScaled():
            return LitScaled(value)
        case VEnum():
            return LitEnum(value)


def term_node(term: Term) -> Node:
    return expr_node(term, TERM_FAMILY)


def term_digest(term: Term) -> Digest:
    return digest_node(DigestKind.TERM, term_node(term))


def term_seq(terms: tuple[Term, ...]) -> NSeq:
    return NSeq(tuple(term_node(term) for term in terms))


def read_term(node: Node) -> Term:
    return read_expr(node, TERM_FAMILY)


def decode_term(node: Node) -> Result[Term, WireError]:
    return decoded(lambda: read_term(node))
