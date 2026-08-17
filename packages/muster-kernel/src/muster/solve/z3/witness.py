"""Turning a solver model into a witness the kernel is allowed to believe.

A ``sat`` answer is a claim, not a proof.  Everything below exists because the
claim arrives from outside the semantics: the model is decoded into production
values, every value is checked against the sort and domain its declaration
names, and then **every assertion of the original query is re-evaluated by the
concrete evaluator**.  Only a model that survives all three becomes a witness.

That last step is what makes a lowering defect harmless in the satisfiable
direction.  If the translation said something subtly different from the query,
the model it produced will not satisfy the query as written, and the answer
becomes indeterminate rather than a plausible wrong world.  The unsatisfiable
direction has no such guard, which is exactly why it is attacked differentially
rather than trusted.
"""

from __future__ import annotations

from dataclasses import dataclass

import z3

from muster.core.expr.evaluate import evaluate_bool
from muster.core.results import Err
from muster.core.values.scalars import (
    Value,
    VBool,
    VEnum,
    VInt,
    VScaled,
    value_in_domain,
)
from muster.core.values.sorts import BoolSort, EnumSort, IntSort, ScaledSort
from muster.solve.query import SolverQuery
from muster.solve.verdict import SolverModel
from muster.solve.z3.lowering import LoweredQuery, LoweredVariable, Z3Term


@dataclass(frozen=True, slots=True)
class RejectedWitness:
    """The model could not be decoded, or does not satisfy the query."""

    detail: str


def witness_of(
    lowered: LoweredQuery, model: Z3Term, query: SolverQuery
) -> SolverModel | RejectedWitness:
    """Decode a model and prove it satisfies the query it answers."""
    decoded: SolverModel = {}
    for variable in lowered.variables:
        value = _value_of(lowered, variable, model)
        if isinstance(value, RejectedWitness):
            return value
        if not value_in_domain(value, variable.domain):
            return RejectedWitness(f"{variable.var} = {value} is outside its declared domain")
        decoded[variable.var] = value

    for assertion in query.assertions:
        holds = evaluate_bool(assertion.formula, decoded)
        if isinstance(holds, Err):
            return RejectedWitness(f"{assertion.label} did not evaluate: {holds.error.detail}")
        if not holds.value:
            return RejectedWitness(f"{assertion.label} is not satisfied by the model")
    return decoded


def _value_of(
    lowered: LoweredQuery, variable: LoweredVariable, model: Z3Term
) -> Value | RejectedWitness:
    """One decoded value, or the reason there is none.

    ``model_completion`` supplies a value for a constant the solver left
    unconstrained.  It cannot smuggle anything past the checks: whatever it
    supplies is validated against the declared domain like any other value.
    """
    assigned = model.eval(variable.constant, model_completion=True)
    sort = variable.sort
    match sort:
        case BoolSort():
            if z3.is_true(assigned):
                return VBool(True)
            if z3.is_false(assigned):
                return VBool(False)
            return RejectedWitness(f"{variable.var} has no boolean value in the model")
        case IntSort():
            magnitude = _magnitude(assigned)
            if magnitude is None:
                return RejectedWitness(f"{variable.var} has no integer value in the model")
            return VInt(magnitude)
        case ScaledSort(unit_tag, scale):
            magnitude = _magnitude(assigned)
            if magnitude is None:
                return RejectedWitness(f"{variable.var} has no integer value in the model")
            return VScaled(unit_tag, scale, magnitude)
        case EnumSort(enum_id):
            return _member_of(lowered, variable, enum_id, assigned)


def _member_of(
    lowered: LoweredQuery, variable: LoweredVariable, enum_id: str, assigned: Z3Term
) -> Value | RejectedWitness:
    members = lowered.enum_members(enum_id)
    if members is None:  # pragma: no cover - lowering refuses an undeclared enum
        return RejectedWitness(f"enum {enum_id} is not declared by the query")
    index = _magnitude(assigned)
    if index is None or not 0 <= index < len(members):
        return RejectedWitness(f"{variable.var} has no declared member of {enum_id} in the model")
    return VEnum(enum_id, members[index])


def _magnitude(assigned: Z3Term) -> int | None:
    """An integer literal, or nothing.

    An expression that is not a literal -- an unresolved constant, an algebraic
    number, anything the solver chose to hand back in another shape -- has no
    integer value here and is refused rather than coerced.
    """
    if not z3.is_int_value(assigned):
        return None
    return int(assigned.as_long())
