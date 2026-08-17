"""An independent oracle: the meaning of a case, computed by enumeration.

Three implementations agreeing proves nothing if they share the part that is
wrong.  So this module deliberately shares no *semantics* with what it judges:

* it does not call :mod:`muster.core.expr.evaluate` -- the interpreter below is
  written from the frozen IR's own definition, and a defect in either one shows
  up as disagreement rather than as agreement;
* it does not call :func:`muster.policy.program.evaluate_program` or
  :func:`muster.core.actions.consequential_of` -- rule selection, field
  completion, domain checking and the consequential projection are redone here;
* it does not construct or read a ``SolverQuery``, so it is also independent of
  :mod:`muster.hinge.encode`, which is what lets it judge the encoder as well
  as the backends.

What it *does* share is the data model: sorts, values, IR node types, action
schemas.  Reimplementing those would test the wire format, which the frozen
corpus already does, and would say nothing about meaning.

Everything here enumerates.  That is the point: for a deliberately tiny state
space, truth is computable by brute force, and brute force has no abstraction
to be incomplete about.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from itertools import product

from muster.core.actions import (
    ActionKindSpec,
    ActionSchema,
    Consequentiality,
    FieldSpec,
)
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
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled
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
from muster.core.values.symbols import SymbolRef
from muster.hinge.project import ProjectedCase
from muster.policy.program import ActionTerm, DecisionProgram
from muster.solve.query import QueryVar, SolverQuery

#  A world, as this module sees one: a total map from symbol to value.
type Assignment = Mapping[SymbolRef, Value]

#  What two worlds are compared by: the kind, and the consequential fields in
#  their declared order.  Diagnostic fields are absent by construction.
type ActionSignature = tuple[str, tuple[tuple[str, Value], ...]]


#  ---- the interpreter ----------------------------------------------------


def meaning[L](expr: Expr[L], world: Mapping[L, Value]) -> Value | None:
    """The value of an expression, or ``None`` where it has none."""
    match expr:
        case Leaf(ref):
            return world.get(ref)
        case LitBool(value):
            return VBool(value)
        case LitInt(value):
            return VInt(value)
        case LitScaled(value):
            return value
        case LitEnum(value):
            return value
        case Not(operand):
            flag = _flag(meaning(operand, world))
            return None if flag is None else VBool(not flag)
        case Neg(operand):
            return _mapped(meaning(operand, world), lambda number: -number)
        case MulConst(k, operand):
            return _mapped(meaning(operand, world), lambda number: k * number)
        case NAry(op, operands):
            return _nary(op, [meaning(operand, world) for operand in operands])
        case Binary(op, left, right):
            return _binary(op, meaning(left, world), meaning(right, world))
        case Scale(operand, k, to):
            inner = meaning(operand, world)
            if not isinstance(inner, VInt) or not isinstance(to, ScaledSort):
                return None
            return VScaled(to.unit_tag, to.scale, inner.value * k)
        case Rescale(operand, to_scale):
            widened = meaning(operand, world)
            if not isinstance(widened, VScaled) or to_scale < widened.scale:
                return None
            factor = 10 ** (to_scale - widened.scale)
            return VScaled(widened.unit_tag, to_scale, widened.minor * factor)
        case Ite(cond, if_true, if_false):
            chosen = _flag(meaning(cond, world))
            if chosen is None:
                return None
            return meaning(if_true if chosen else if_false, world)
        case EnumTable(scrutinee, arms):
            selector = meaning(scrutinee, world)
            if not isinstance(selector, VEnum):
                return None
            for arm in arms:
                if arm.member == selector.member:
                    return meaning(arm.term, world)
            return None


def holds[L](expr: Expr[L], world: Mapping[L, Value]) -> bool | None:
    """The truth of a boolean expression, or ``None`` where it has none."""
    return _flag(meaning(expr, world))


def _flag(value: Value | None) -> bool | None:
    return value.value if isinstance(value, VBool) else None


def _mapped(value: Value | None, operation: Callable[[int], int]) -> Value | None:
    match value:
        case VInt(number):
            return VInt(operation(number))
        case VScaled(unit_tag, scale, minor):
            return VScaled(unit_tag, scale, operation(minor))
        case _:
            return None


def _nary(op: NAryOp, values: list[Value | None]) -> Value | None:
    if op is NAryOp.ADD:
        total = values[0]
        for value in values[1:]:
            total = _arith(total, value, lambda a, b: a + b)
        return total
    flags: list[bool] = []
    for value in values:
        flag = _flag(value)
        if flag is None:
            return None
        flags.append(flag)
    return VBool(all(flags) if op is NAryOp.AND else any(flags))


def _binary(op: BinaryOp, left: Value | None, right: Value | None) -> Value | None:
    match op:
        case BinaryOp.IMPLIES | BinaryOp.IFF:
            first, second = _flag(left), _flag(right)
            if first is None or second is None:
                return None
            return (
                VBool((not first) or second) if op is BinaryOp.IMPLIES else VBool(first == second)
            )
        case BinaryOp.SUB:
            return _arith(left, right, lambda a, b: a - b)
        case BinaryOp.EQ | BinaryOp.NE:
            same = _identical(left, right)
            if same is None:
                return None
            return VBool(same if op is BinaryOp.EQ else not same)
        case _:
            return _compared(op, left, right)


def _compared(op: BinaryOp, left: Value | None, right: Value | None) -> Value | None:
    pair = _magnitudes(left, right)
    if pair is None:
        return None
    first, second = pair
    match op:
        case BinaryOp.LT:
            return VBool(first < second)
        case BinaryOp.LE:
            return VBool(first <= second)
        case BinaryOp.GT:
            return VBool(first > second)
        case _:
            return VBool(first >= second)


def _arith(
    left: Value | None, right: Value | None, operation: Callable[[int, int], int]
) -> Value | None:
    match left, right:
        case VInt(first), VInt(second):
            return VInt(operation(first, second))
        case VScaled(unit_a, scale_a, first), VScaled(unit_b, scale_b, second) if (
            unit_a == unit_b and scale_a == scale_b
        ):
            return VScaled(unit_a, scale_a, operation(first, second))
        case _:
            return None


def _magnitudes(left: Value | None, right: Value | None) -> tuple[int, int] | None:
    match left, right:
        case VInt(first), VInt(second):
            return first, second
        case VScaled(unit_a, scale_a, first), VScaled(unit_b, scale_b, second) if (
            unit_a == unit_b and scale_a == scale_b
        ):
            return first, second
        case _:
            return None


def _identical(left: Value | None, right: Value | None) -> bool | None:
    """Equality within one sort. Across sorts there is no answer, not ``False``."""
    match left, right:
        case VBool(first), VBool(second):
            return first == second
        case VInt(first), VInt(second):
            return first == second
        case VScaled(unit_a, scale_a, first), VScaled(unit_b, scale_b, second):
            return first == second if unit_a == unit_b and scale_a == scale_b else None
        case VEnum(enum_a, first), VEnum(enum_b, second):
            return first == second if enum_a == enum_b else None
        case _:
            return None


#  ---- domains ------------------------------------------------------------


def domain_values(sort: Sort, domain: Domain) -> tuple[Value, ...]:
    """Every value of a declared domain. Empty where the pairing is nonsense."""
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


def inside(value: Value, domain: Domain) -> bool:
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


#  ---- a query, enumerated ------------------------------------------------


def query_assignments(query: SolverQuery) -> Iterator[dict[QueryVar, Value]]:
    """Every total assignment over the query's declared variables."""
    declarations = query.declarations
    choices = [domain_values(decl.sort, decl.domain) for decl in declarations]
    for combination in product(*choices):
        yield {decl.var(): value for decl, value in zip(declarations, combination, strict=True)}


def query_truth(query: SolverQuery) -> bool:
    """Whether the query is satisfiable, by enumerating its declared domains.

    Used where the subject under test is the query itself rather than a case,
    so the judge sees exactly what a backend sees and nothing else.
    """
    for model in query_assignments(query):
        satisfied = True
        for assertion in query.assertions:
            truth = holds(assertion.formula, model)
            assert truth is not None, f"{assertion.label} is not well typed"
            satisfied = satisfied and truth
        if satisfied:
            return True
    return False


#  ---- the case, enumerated ----------------------------------------------


@dataclass(frozen=True, slots=True)
class Undefined:
    """The program yields no action in this world, and says which rule stopped it.

    A distinguished value rather than ``None``, so a case where the program is
    not total over its admissible worlds is reported as a disagreement between
    the semantics rather than as a crash inside the judge.
    """

    reason: str


def admissible_worlds(case: ProjectedCase) -> list[dict[SymbolRef, Value]]:
    """Every total assignment extending what is established and satisfying
    every constraint. The complete set, computed without a solver.

    An established value outside its own declared domain admits no world at
    all: the encoder emits a domain assertion for every declaration, including
    the established ones, so a case that contradicts its own schema has an
    empty world set rather than one world nobody checked.
    """
    established = case.logical.assignment()
    for declaration in case.declarations:
        settled = established.get(declaration.ref)
        if settled is not None and not inside(settled, declaration.domain):
            return []
    open_declarations = [
        declaration for declaration in case.declarations if declaration.ref not in established
    ]
    choices = [
        domain_values(declaration.sort, declaration.domain) for declaration in open_declarations
    ]

    found: list[dict[SymbolRef, Value]] = []
    for combination in product(*choices):
        world: dict[SymbolRef, Value] = dict(established)
        for declaration, value in zip(open_declarations, combination, strict=True):
            world[declaration.ref] = value
        admitted = True
        for constraint in case.logical.constraints:
            truth = holds(constraint.formula, world)
            assert truth is not None, f"{constraint.label} is not well typed over the case"
            admitted = admitted and truth
        if admitted:
            found.append(world)
    return found


def signature_of(case: ProjectedCase, world: Assignment) -> ActionSignature | Undefined:
    """``A(w)``: the action the program produces, projected onto what matters."""
    action = _fired(case.program, world)
    if action is None:
        return Undefined("no rule guard evaluated")
    spec = _kind(case.action_schema, action.kind)
    if spec is None:
        return Undefined(f"{action.kind} is not a declared kind")

    fields: list[tuple[str, Value]] = []
    for declared in spec.fields:
        supplied = action.field_term(declared.name)
        value = _filler(declared) if supplied is None else meaning(supplied, world)
        if value is None:
            return Undefined(f"{action.kind}.{declared.name} did not evaluate")
        if not inside(value, declared.bounds):
            #  Totality includes staying inside the declared bounds; a payment
            #  outside its declared range is a rejection, not a clamp.
            return Undefined(f"{action.kind}.{declared.name}={value} is out of bounds")
        if declared.consequentiality is Consequentiality.CONSEQUENTIAL:
            fields.append((declared.name, value))
    return action.kind, tuple(fields)


def total(case: ProjectedCase) -> bool:
    """Whether the program yields an action in every admissible world.

    Not a given: the query encoder lowers a field term without its declared
    bounds, while the concrete evaluator rejects a value that leaves them.  A
    case where the two disagree is a case whose truth this module cannot state,
    so the differential asks this before asking anything else.
    """
    return all(
        not isinstance(signature_of(case, world), Undefined) for world in admissible_worlds(case)
    )


def _fired(program: DecisionProgram, world: Assignment) -> ActionTerm | None:
    for rule in program.rules:
        fired = holds(rule.guard, world)
        if fired is None:
            return None
        if fired:
            return rule.action
    return program.otherwise


def _kind(schema: ActionSchema, kind: str) -> ActionKindSpec | None:
    for spec in schema.kinds:
        if spec.kind == kind:
            return spec
    return None


def _filler(field: FieldSpec) -> Value | None:
    """A declared default, or the canonical in-domain stand-in for one."""
    if field.default is not None:
        return field.default
    match field.sort, field.bounds:
        case BoolSort(), BoolDomain():
            return VBool(False)
        case IntSort(), IntRange(lo, hi):
            return VInt(lo if lo > 0 else min(hi, 0))
        case ScaledSort(unit_tag, scale), ScaledRange(lo, hi):
            return VScaled(unit_tag, scale, lo if lo > 0 else min(hi, 0))
        case EnumSort(enum_id), EnumDomain(members):
            return VEnum(enum_id, members[0])
        case _:
            return None


#  ---- the three questions, answered by enumeration -----------------------


def feasible(case: ProjectedCase) -> bool:
    return bool(admissible_worlds(case))


def reachable_signatures(case: ProjectedCase) -> set[ActionSignature]:
    found: set[ActionSignature] = set()
    for world in admissible_worlds(case):
        signature = signature_of(case, world)
        assert not isinstance(signature, Undefined), signature.reason
        found.add(signature)
    return found


def invariant(case: ProjectedCase) -> bool:
    """Exactly one reachable action, over a non-empty world set."""
    return len(reachable_signatures(case)) == 1


def sufficient(case: ProjectedCase, fixed: frozenset[SymbolRef]) -> bool:
    """No two admissible worlds agreeing on ``fixed`` produce different actions.

    Established values are shared by every world, so agreement on ``fixed``
    alone is the whole condition -- which is exactly what the self-composed
    query is supposed to express, computed here without one.
    """
    order = _ordered(fixed)
    by_key: dict[tuple[Value, ...], ActionSignature] = {}
    for world in admissible_worlds(case):
        signature = signature_of(case, world)
        assert not isinstance(signature, Undefined), signature.reason
        key = tuple(world[ref] for ref in order)
        seen = by_key.get(key)
        if seen is None:
            by_key[key] = signature
        elif seen != signature:
            return False
    return True


def necessary(case: ProjectedCase, unresolved: tuple[SymbolRef, ...]) -> tuple[SymbolRef, ...]:
    """``Necessary(v)`` for each unresolved variable: ``not Sufficient(U \\ {v})``."""
    universe = frozenset(unresolved)
    return tuple(ref for ref in unresolved if not sufficient(case, universe - {ref}))


def _ordered(refs: frozenset[SymbolRef]) -> tuple[SymbolRef, ...]:
    return tuple(sorted(refs, key=lambda ref: (ref.predicate_id, ref.args)))


def subsets(refs: tuple[SymbolRef, ...]) -> tuple[frozenset[SymbolRef], ...]:
    """Every subset of a universe, smallest first, in a fixed order."""
    found = [
        frozenset(ref for ref, taken in zip(refs, mask, strict=True) if taken)
        for mask in product((False, True), repeat=len(refs))
    ]
    return tuple(sorted(found, key=len))
