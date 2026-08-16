"""A declared domain, restated as an expression.

Written once, for both expression families.  The case record needs it over
proposition references and the solver query needs it over world-qualified
leaves; the two would otherwise be the same six lines twice, drifting apart the
first time a sort is added.
"""

from __future__ import annotations

from muster.core.expr.ir import Binary, BinaryOp, Expr, NAry, NAryOp, Not
from muster.core.expr.terms import literal
from muster.core.results import InvariantViolation
from muster.core.values.scalars import VEnum, VInt, VScaled
from muster.core.values.sorts import (
    BoolDomain,
    Domain,
    EnumDomain,
    EnumSort,
    IntRange,
    ScaledRange,
    ScaledSort,
    Sort,
)


def domain_formula[L](leaf: Expr[L], sort: Sort, domain: Domain) -> Expr[L]:
    """``lo <= v <= hi``, ``v in members``, or a boolean tautology.

    The bound literals take their unit and scale from the *sort*: a scaled range
    carries magnitudes in minor units and nothing else, which is exactly why it
    is only meaningful beside the sort it was declared with.
    """
    match domain:
        case BoolDomain():
            #  A boolean is in its domain by construction. The assertion is kept
            #  so that "one domain formula per declared variable" stays total,
            #  rather than having a branch that silently emits nothing.
            return NAry(NAryOp.OR, (leaf, Not(leaf)))
        case IntRange(lo, hi):
            return NAry(
                NAryOp.AND,
                (
                    Binary(BinaryOp.GE, leaf, literal(VInt(lo))),
                    Binary(BinaryOp.LE, leaf, literal(VInt(hi))),
                ),
            )
        case ScaledRange(lo, hi):
            if not isinstance(sort, ScaledSort):
                raise InvariantViolation(f"scaled range against sort {sort}")
            return NAry(
                NAryOp.AND,
                (
                    Binary(BinaryOp.GE, leaf, literal(VScaled(sort.unit_tag, sort.scale, lo))),
                    Binary(BinaryOp.LE, leaf, literal(VScaled(sort.unit_tag, sort.scale, hi))),
                ),
            )
        case EnumDomain(members):
            if not isinstance(sort, EnumSort):
                raise InvariantViolation(f"enum domain against sort {sort}")
            equalities = tuple(
                Binary(BinaryOp.EQ, leaf, literal(VEnum(sort.enum_id, member)))
                for member in members
            )
            return equalities[0] if len(equalities) == 1 else NAry(NAryOp.OR, equalities)
