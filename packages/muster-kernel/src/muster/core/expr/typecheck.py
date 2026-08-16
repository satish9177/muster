"""The expression type checker.

Ill-typed terms are rejected before they can be built into a validated program,
so the evaluator and the query encoder both receive terms whose sorts already
agree.  Mixing units is the case worth naming: ``INR`` at scale 2 and ``USD`` at
scale 2 are different sorts, and adding them fails here rather than producing a
plausible number.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from muster.core.expr.ir import (
    Arm,
    Binary,
    BinaryOp,
    EnumTable,
    Expr,
    Ite,
    Leaf,
    LitBool,
    LitEnum,
    LitInt,
    LitScaled,
    MulConst,
    NAry,
    NAryOp,
    Neg,
    Not,
    Rescale,
    Scale,
)
from muster.core.results import Err, Ok, Result
from muster.core.values.sorts import BoolSort, EnumSort, IntSort, ScaledSort, Sort

_COMPARISONS = frozenset({BinaryOp.LT, BinaryOp.LE, BinaryOp.GT, BinaryOp.GE})
_BOOLEAN_BINARY = frozenset({BinaryOp.IMPLIES, BinaryOp.IFF})
_EQUALITY = frozenset({BinaryOp.EQ, BinaryOp.NE})


class SortFailure(Enum):
    UNBOUND_SYMBOL = "UNBOUND_SYMBOL"
    EXPECTED_BOOLEAN = "EXPECTED_BOOLEAN"
    EXPECTED_NUMERIC = "EXPECTED_NUMERIC"
    EXPECTED_INTEGER = "EXPECTED_INTEGER"
    EXPECTED_SCALED = "EXPECTED_SCALED"
    EXPECTED_ENUM = "EXPECTED_ENUM"
    SORT_MISMATCH = "SORT_MISMATCH"
    UNIT_MISMATCH = "UNIT_MISMATCH"
    NARROWING_RESCALE = "NARROWING_RESCALE"
    DUPLICATE_ARM = "DUPLICATE_ARM"


@dataclass(frozen=True, slots=True)
class SortError:
    failure: SortFailure
    detail: str


class _Rejected(Exception):
    def __init__(self, error: SortError) -> None:
        super().__init__(f"{error.failure.value}: {error.detail}")
        self.error = error


def _reject(failure: SortFailure, detail: object) -> _Rejected:
    return _Rejected(SortError(failure, str(detail)))


def check[L](expr: Expr[L], env: Mapping[L, Sort]) -> Result[Sort, SortError]:
    """Infer the sort of an expression, or say precisely why it has none."""
    try:
        return Ok(_check(expr, env))
    except _Rejected as rejection:
        return Err(rejection.error)


def _check[L](expr: Expr[L], env: Mapping[L, Sort]) -> Sort:
    match expr:
        case Leaf(ref):
            sort = env.get(ref)
            if sort is None:
                raise _reject(SortFailure.UNBOUND_SYMBOL, ref)
            return sort
        case LitBool():
            return BoolSort()
        case LitInt():
            return IntSort()
        case LitScaled(value):
            return ScaledSort(value.unit_tag, value.scale)
        case LitEnum(value):
            return EnumSort(value.enum_id)
        case Not(operand):
            return _expect_boolean(_check(operand, env))
        case Neg(operand):
            return _expect_numeric(_check(operand, env))
        case NAry(op, operands):
            sorts = [_check(operand, env) for operand in operands]
            if op is NAryOp.ADD:
                return _same(_expect_numeric(sorts[0]), sorts)
            for sort in sorts:
                _expect_boolean(sort)
            return BoolSort()
        case Binary(op, left, right):
            return _check_binary(op, _check(left, env), _check(right, env))
        case MulConst(_, operand):
            return _expect_numeric(_check(operand, env))
        case Scale(operand, _, to):
            if not isinstance(_check(operand, env), IntSort):
                raise _reject(SortFailure.EXPECTED_INTEGER, "scale operand")
            if not isinstance(to, ScaledSort):
                raise _reject(SortFailure.EXPECTED_SCALED, to)
            return to
        case Rescale(operand, to_scale):
            sort = _check(operand, env)
            if not isinstance(sort, ScaledSort):
                raise _reject(SortFailure.EXPECTED_SCALED, sort)
            if to_scale < sort.scale:
                #  Narrowing needs a rounding mode, and the frozen wire type
                #  carries none.  Refuse rather than choose one silently.
                raise _reject(SortFailure.NARROWING_RESCALE, f"{sort.scale} -> {to_scale}")
            return ScaledSort(sort.unit_tag, to_scale)
        case Ite(cond, if_true, if_false):
            _expect_boolean(_check(cond, env))
            branch = _check(if_true, env)
            return _same(branch, [branch, _check(if_false, env)])
        case EnumTable(scrutinee, arms):
            if not isinstance(_check(scrutinee, env), EnumSort):
                raise _reject(SortFailure.EXPECTED_ENUM, "enum table scrutinee")
            _check_unique_arms(arms)
            sorts = [_check(arm.term, env) for arm in arms]
            return _same(sorts[0], sorts)


def _check_binary(op: BinaryOp, left: Sort, right: Sort) -> Sort:
    if op in _BOOLEAN_BINARY:
        _expect_boolean(left)
        _expect_boolean(right)
        return BoolSort()
    if op is BinaryOp.SUB:
        return _same(_expect_numeric(left), [left, right])
    if op in _COMPARISONS:
        _expect_numeric(left)
        _same(left, [left, right])
        return BoolSort()
    if op in _EQUALITY:
        _same(left, [left, right])
        return BoolSort()
    raise _reject(SortFailure.SORT_MISMATCH, op)  # pragma: no cover - total over BinaryOp


def _check_unique_arms[L](arms: tuple[Arm[L], ...]) -> None:
    seen: set[str] = set()
    for arm in arms:
        if arm.member in seen:
            raise _reject(SortFailure.DUPLICATE_ARM, arm.member)
        seen.add(arm.member)


def _expect_boolean(sort: Sort) -> Sort:
    if not isinstance(sort, BoolSort):
        raise _reject(SortFailure.EXPECTED_BOOLEAN, sort)
    return sort


def _expect_numeric(sort: Sort) -> Sort:
    if not isinstance(sort, IntSort | ScaledSort):
        raise _reject(SortFailure.EXPECTED_NUMERIC, sort)
    return sort


def _same(expected: Sort, sorts: list[Sort]) -> Sort:
    for sort in sorts:
        if sort == expected:
            continue
        if isinstance(sort, ScaledSort) and isinstance(expected, ScaledSort):
            raise _reject(SortFailure.UNIT_MISMATCH, f"{expected} vs {sort}")
        raise _reject(SortFailure.SORT_MISMATCH, f"{expected} vs {sort}")
    return expected
