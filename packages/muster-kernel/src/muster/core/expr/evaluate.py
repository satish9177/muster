"""The concrete evaluator.

Pure, total for well-typed terms over a total assignment, and the only
evaluation path in production: replay, entailment materialisation, the bounded
reference backend and the witness validation in every solver adapter all call
this one function, so nothing inside the system can disagree with it.

Differential testing needs a second interpreter precisely because of that.  The
enumerating oracle the differential suite judges by is written independently
and deliberately does not call this -- an oracle sharing the interpreter it is
checking would agree with every defect in it.

It is nonetheless fail-closed rather than trusting: an unbound symbol or a sort
it cannot combine is a typed error, never a coerced value.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum

from muster.core.expr.ir import (
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
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled
from muster.core.values.sorts import ScaledSort


class EvalFailure(Enum):
    UNBOUND_SYMBOL = "UNBOUND_SYMBOL"
    ILL_TYPED = "ILL_TYPED"
    UNIT_MISMATCH = "UNIT_MISMATCH"
    NO_MATCHING_ARM = "NO_MATCHING_ARM"


@dataclass(frozen=True, slots=True)
class EvalError:
    failure: EvalFailure
    detail: str


class _Stuck(Exception):
    def __init__(self, error: EvalError) -> None:
        super().__init__(f"{error.failure.value}: {error.detail}")
        self.error = error


def _stuck(failure: EvalFailure, detail: object) -> _Stuck:
    return _Stuck(EvalError(failure, str(detail)))


def evaluate[L](expr: Expr[L], world: Mapping[L, Value]) -> Result[Value, EvalError]:
    """Evaluate an expression against a total assignment."""
    try:
        return Ok(_evaluate(expr, world))
    except _Stuck as stuck:
        return Err(stuck.error)


def evaluate_bool[L](expr: Expr[L], world: Mapping[L, Value]) -> Result[bool, EvalError]:
    outcome = evaluate(expr, world)
    if isinstance(outcome, Err):
        return outcome
    if not isinstance(outcome.value, VBool):
        return Err(EvalError(EvalFailure.ILL_TYPED, f"expected a boolean, got {outcome.value}"))
    return Ok(outcome.value.value)


def _evaluate[L](expr: Expr[L], world: Mapping[L, Value]) -> Value:
    match expr:
        case Leaf(ref):
            value = world.get(ref)
            if value is None:
                raise _stuck(EvalFailure.UNBOUND_SYMBOL, ref)
            return value
        case LitBool(value):
            return VBool(value)
        case LitInt(value):
            return VInt(value)
        case LitScaled(value):
            return value
        case LitEnum(value):
            return value
        case Not(operand):
            return VBool(not _boolean(_evaluate(operand, world)))
        case Neg(operand):
            return _numeric_map(_evaluate(operand, world), lambda number: -number)
        case NAry(op, operands):
            return _evaluate_nary(op, [_evaluate(operand, world) for operand in operands])
        case Binary(op, left, right):
            return _evaluate_binary(op, _evaluate(left, world), _evaluate(right, world))
        case MulConst(k, operand):
            return _numeric_map(_evaluate(operand, world), lambda number: k * number)
        case Scale(operand, k, to):
            magnitude = _evaluate(operand, world)
            if not isinstance(magnitude, VInt) or not isinstance(to, ScaledSort):
                raise _stuck(EvalFailure.ILL_TYPED, "scale expects an integer and a scaled sort")
            return VScaled(to.unit_tag, to.scale, magnitude.value * k)
        case Rescale(operand, to_scale):
            scaled = _evaluate(operand, world)
            if not isinstance(scaled, VScaled) or to_scale < scaled.scale:
                raise _stuck(EvalFailure.ILL_TYPED, "rescale widens a scaled value only")
            return VScaled(
                scaled.unit_tag, to_scale, scaled.minor * 10 ** (to_scale - scaled.scale)
            )
        case Ite(cond, if_true, if_false):
            branch = if_true if _boolean(_evaluate(cond, world)) else if_false
            return _evaluate(branch, world)
        case EnumTable(scrutinee, arms):
            selector = _evaluate(scrutinee, world)
            if not isinstance(selector, VEnum):
                raise _stuck(EvalFailure.ILL_TYPED, "enum table expects an enum scrutinee")
            for arm in arms:
                if arm.member == selector.member:
                    return _evaluate(arm.term, world)
            raise _stuck(EvalFailure.NO_MATCHING_ARM, selector.member)


def _evaluate_nary(op: NAryOp, values: list[Value]) -> Value:
    match op:
        case NAryOp.AND:
            return VBool(all(_boolean(value) for value in values))
        case NAryOp.OR:
            return VBool(any(_boolean(value) for value in values))
        case NAryOp.ADD:
            total = values[0]
            for value in values[1:]:
                total = _combine(total, value, lambda a, b: a + b)
            return total


def _evaluate_binary(op: BinaryOp, left: Value, right: Value) -> Value:
    match op:
        case BinaryOp.IMPLIES:
            return VBool((not _boolean(left)) or _boolean(right))
        case BinaryOp.IFF:
            return VBool(_boolean(left) == _boolean(right))
        case BinaryOp.SUB:
            return _combine(left, right, lambda a, b: a - b)
        case BinaryOp.EQ:
            return VBool(_equal(left, right))
        case BinaryOp.NE:
            return VBool(not _equal(left, right))
        case BinaryOp.LT:
            return VBool(_compare(left, right) < 0)
        case BinaryOp.LE:
            return VBool(_compare(left, right) <= 0)
        case BinaryOp.GT:
            return VBool(_compare(left, right) > 0)
        case BinaryOp.GE:
            return VBool(_compare(left, right) >= 0)


def _equal(left: Value, right: Value) -> bool:
    """Equality is only defined between values of one sort."""
    if type(left) is not type(right):
        raise _stuck(EvalFailure.ILL_TYPED, f"cannot compare {left} with {right}")
    match left, right:
        case VScaled(unit_a, scale_a, _), VScaled(unit_b, scale_b, _) if (
            unit_a != unit_b or scale_a != scale_b
        ):
            raise _stuck(EvalFailure.UNIT_MISMATCH, f"{left} vs {right}")
        case VEnum(enum_a, _), VEnum(enum_b, _) if enum_a != enum_b:
            raise _stuck(EvalFailure.ILL_TYPED, f"{enum_a} vs {enum_b}")
        case _:
            return left == right


def _compare(left: Value, right: Value) -> int:
    magnitudes = _magnitudes(left, right)
    return (magnitudes[0] > magnitudes[1]) - (magnitudes[0] < magnitudes[1])


def _combine(left: Value, right: Value, operation: Callable[[int, int], int]) -> Value:
    """Arithmetic on two values of one numeric sort. ``_magnitudes`` rejects the rest."""
    a, b = _magnitudes(left, right)
    match left:
        case VInt():
            return VInt(operation(a, b))
        case VScaled(unit_tag, scale, _):
            return VScaled(unit_tag, scale, operation(a, b))
        case _:  # pragma: no cover - _magnitudes has already rejected these
            raise _stuck(EvalFailure.ILL_TYPED, left)


def _boolean(value: Value) -> bool:
    if not isinstance(value, VBool):
        raise _stuck(EvalFailure.ILL_TYPED, f"expected a boolean, got {value}")
    return value.value


def _numeric_map(value: Value, operation: Callable[[int], int]) -> Value:
    match value:
        case VInt(number):
            return VInt(operation(number))
        case VScaled(unit_tag, scale, minor):
            return VScaled(unit_tag, scale, operation(minor))
        case _:
            raise _stuck(EvalFailure.ILL_TYPED, f"expected a numeric value, got {value}")


def _magnitudes(left: Value, right: Value) -> tuple[int, int]:
    match left, right:
        case VInt(a), VInt(b):
            return a, b
        case VScaled(unit_a, scale_a, a), VScaled(unit_b, scale_b, b):
            if unit_a != unit_b or scale_a != scale_b:
                raise _stuck(EvalFailure.UNIT_MISMATCH, f"{left} vs {right}")
            return a, b
        case _:
            raise _stuck(EvalFailure.ILL_TYPED, f"cannot order {left} against {right}")
