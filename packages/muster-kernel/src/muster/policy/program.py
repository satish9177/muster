"""The decision program: policy as data, with two interpreters over one definition.

A program is an ordered first-match rule list plus a total ``otherwise``.  It is
a value, not a callable, which is what makes symbolic reasoning about it
possible at all -- and what makes "procurement policy A becomes policy B" a
change to a signed artifact rather than a change to the kernel.

``otherwise`` proves branch coverage and nothing more.  Totality additionally
needs every action term to name a declared kind, every field term to have the
declared sort, every enum table to be exhaustive, every required field to be
produced, and every produced value to land inside its declared domain.  The
first four are checked when the program is compiled; the last is checked on
evaluation, because proving it statically needs interval analysis the Phase-1
fragment does not carry.  Either way the failure is a typed rejection, never a
coerced payload.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from muster.core.actions import Action, ActionSchema, FieldSpec, complete_action
from muster.core.expr.evaluate import evaluate, evaluate_bool
from muster.core.expr.ir import (
    Binary,
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
    Neg,
    Not,
    Rescale,
    Scale,
    freevars,
)
from muster.core.expr.terms import Term, term_node
from muster.core.expr.typecheck import check
from muster.core.results import Err, Ok, Result
from muster.core.values.scalars import Value, value_in_domain
from muster.core.values.sorts import BoolSort, EnumDomain, Sort
from muster.core.values.symbols import SymbolRef, symbol_seq
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NRec, NSeq

TAG_FIELD_TERM = "FieldTerm/v1"
TAG_ACTION_TERM = "ActionTerm/v1"
TAG_PROGRAM_RULE = "ProgramRule/v1"
TAG_DECISION_PROGRAM = "DecisionProgram/v1"


@dataclass(frozen=True, slots=True)
class FieldTerm:
    name: str
    term: Term

    def to_node(self) -> NRec:
        return NRec(TAG_FIELD_TERM, (NAtom(self.name), term_node(self.term)))


@dataclass(frozen=True, slots=True)
class ActionTerm:
    kind: str
    fields: tuple[FieldTerm, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACTION_TERM,
            (NAtom(self.kind), NSeq(tuple(field.to_node() for field in self.fields))),
        )

    def field_term(self, name: str) -> Term | None:
        for field in self.fields:
            if field.name == name:
                return field.term
        return None


@dataclass(frozen=True, slots=True)
class ProgramRule:
    guard: Term
    action: ActionTerm

    def to_node(self) -> NRec:
        return NRec(TAG_PROGRAM_RULE, (term_node(self.guard), self.action.to_node()))


@dataclass(frozen=True, slots=True)
class DecisionProgram:
    """Ordered, first match wins, ``otherwise`` is reached when none does."""

    inputs: tuple[SymbolRef, ...]
    rules: tuple[ProgramRule, ...]
    otherwise: ActionTerm

    def to_node(self) -> NRec:
        return NRec(
            TAG_DECISION_PROGRAM,
            (
                symbol_seq(self.inputs),
                NSeq(tuple(rule.to_node() for rule in self.rules)),
                self.otherwise.to_node(),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.POLICY_PROGRAM, self.to_node())

    def action_terms(self) -> tuple[ActionTerm, ...]:
        return (*(rule.action for rule in self.rules), self.otherwise)

    def free_symbols(self) -> frozenset[SymbolRef]:
        found: frozenset[SymbolRef] = frozenset()
        for rule in self.rules:
            found |= freevars(rule.guard)
            found |= action_freevars(rule.action)
        return found | action_freevars(self.otherwise)


class ProgramFailure(Enum):
    GUARD_NOT_BOOLEAN = "GUARD_NOT_BOOLEAN"
    UNKNOWN_ACTION_KIND = "UNKNOWN_ACTION_KIND"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    DUPLICATE_FIELD = "DUPLICATE_FIELD"
    FIELD_SORT_MISMATCH = "FIELD_SORT_MISMATCH"
    REQUIRED_FIELD_MISSING = "REQUIRED_FIELD_MISSING"
    ILL_TYPED_TERM = "ILL_TYPED_TERM"
    INPUTS_DO_NOT_MATCH_FREE_SYMBOLS = "INPUTS_DO_NOT_MATCH_FREE_SYMBOLS"
    ENUM_TABLE_NOT_EXHAUSTIVE = "ENUM_TABLE_NOT_EXHAUSTIVE"
    FIELD_VALUE_OUT_OF_DOMAIN = "FIELD_VALUE_OUT_OF_DOMAIN"
    EVALUATION_STUCK = "EVALUATION_STUCK"


@dataclass(frozen=True, slots=True)
class ProgramError:
    failure: ProgramFailure
    detail: str


def compile_program(
    program: DecisionProgram,
    schema: ActionSchema,
    sorts: Mapping[SymbolRef, Sort],
    enum_domains: Mapping[SymbolRef, EnumDomain],
) -> Result[DecisionProgram, ProgramError]:
    """Validate a program against the pinned action schema and sort environment."""
    if set(program.inputs) != program.free_symbols():
        return Err(
            ProgramError(
                ProgramFailure.INPUTS_DO_NOT_MATCH_FREE_SYMBOLS,
                f"declared {sorted(str(ref) for ref in program.inputs)}",
            )
        )

    for rule in program.rules:
        guard_sort = check(rule.guard, sorts)
        if isinstance(guard_sort, Err):
            return Err(ProgramError(ProgramFailure.ILL_TYPED_TERM, str(guard_sort.error)))
        if not isinstance(guard_sort.value, BoolSort):
            return Err(ProgramError(ProgramFailure.GUARD_NOT_BOOLEAN, str(guard_sort.value)))
        exhaustive = check_enum_tables(rule.guard, enum_domains)
        if isinstance(exhaustive, Err):
            return exhaustive

    for action in program.action_terms():
        checked = _check_action_term(action, schema, sorts, enum_domains)
        if isinstance(checked, Err):
            return checked

    return Ok(program)


def evaluate_program(
    program: DecisionProgram,
    schema: ActionSchema,
    world: Mapping[SymbolRef, Value],
) -> Result[Action, ProgramError]:
    """Run the program concretely. First match wins; ``otherwise`` is total."""
    for rule in program.rules:
        fired = evaluate_bool(rule.guard, world)
        if isinstance(fired, Err):
            return Err(ProgramError(ProgramFailure.EVALUATION_STUCK, str(fired.error)))
        if fired.value:
            return build_action(rule.action, schema, world)
    return build_action(program.otherwise, schema, world)


def build_action(
    action: ActionTerm, schema: ActionSchema, world: Mapping[SymbolRef, Value]
) -> Result[Action, ProgramError]:
    spec = schema.kind_spec(action.kind)
    if spec is None:
        return Err(ProgramError(ProgramFailure.UNKNOWN_ACTION_KIND, action.kind))

    supplied: dict[str, Value] = {}
    for field in action.fields:
        evaluated = evaluate(field.term, world)
        if isinstance(evaluated, Err):
            return Err(ProgramError(ProgramFailure.EVALUATION_STUCK, str(evaluated.error)))
        declared = field_spec(spec.fields, field.name)
        if declared is None:
            return Err(ProgramError(ProgramFailure.UNKNOWN_FIELD, field.name))
        if not value_in_domain(evaluated.value, declared.bounds):
            #  Totality includes staying inside the declared bounds. A payment
            #  outside its declared range is a rejection, not a clamp.
            return Err(
                ProgramError(
                    ProgramFailure.FIELD_VALUE_OUT_OF_DOMAIN,
                    f"{action.kind}.{field.name}={evaluated.value}",
                )
            )
        supplied[field.name] = evaluated.value

    built = complete_action(schema, action.kind, supplied)
    if isinstance(built, Err):
        return Err(ProgramError(ProgramFailure.FIELD_VALUE_OUT_OF_DOMAIN, str(built.error)))
    return Ok(built.value)


def _check_action_term(
    action: ActionTerm,
    schema: ActionSchema,
    sorts: Mapping[SymbolRef, Sort],
    enum_domains: Mapping[SymbolRef, EnumDomain],
) -> Result[None, ProgramError]:
    spec = schema.kind_spec(action.kind)
    if spec is None:
        return Err(ProgramError(ProgramFailure.UNKNOWN_ACTION_KIND, action.kind))

    seen: set[str] = set()
    for field in action.fields:
        if field.name in seen:
            return Err(ProgramError(ProgramFailure.DUPLICATE_FIELD, field.name))
        seen.add(field.name)

        declared = field_spec(spec.fields, field.name)
        if declared is None:
            return Err(ProgramError(ProgramFailure.UNKNOWN_FIELD, field.name))

        sort = check(field.term, sorts)
        if isinstance(sort, Err):
            return Err(ProgramError(ProgramFailure.ILL_TYPED_TERM, str(sort.error)))
        if sort.value != declared.sort:
            return Err(
                ProgramError(
                    ProgramFailure.FIELD_SORT_MISMATCH,
                    f"{action.kind}.{field.name}: {sort.value} vs {declared.sort}",
                )
            )
        exhaustive = check_enum_tables(field.term, enum_domains)
        if isinstance(exhaustive, Err):
            return exhaustive

    for declared_field in spec.fields:
        missing = declared_field.name not in seen and declared_field.default is None
        if declared_field.required and missing:
            return Err(
                ProgramError(
                    ProgramFailure.REQUIRED_FIELD_MISSING,
                    f"{action.kind}.{declared_field.name}",
                )
            )

    return Ok(None)


def check_enum_tables(
    term: Term, enum_domains: Mapping[SymbolRef, EnumDomain]
) -> Result[None, ProgramError]:
    """Every enum table must cover every declared member of its scrutinee.

    Coverage is checkable only where the scrutinee's declared members are known,
    which is here: the sort checker knows sorts, and membership lives in the
    domain beside the sort.
    """
    for table in enum_tables(term):
        if not isinstance(table.scrutinee, Leaf):
            continue
        domain = enum_domains.get(table.scrutinee.ref)
        if domain is None:
            continue
        covered = {arm.member for arm in table.arms}
        missing = [member for member in domain.members if member not in covered]
        if missing:
            return Err(ProgramError(ProgramFailure.ENUM_TABLE_NOT_EXHAUSTIVE, ", ".join(missing)))
    return Ok(None)


def enum_tables[L](term: Expr[L]) -> list[EnumTable[L]]:
    found: list[EnumTable[L]] = []
    _collect_enum_tables(term, found)
    return found


def _collect_enum_tables[L](term: Expr[L], found: list[EnumTable[L]]) -> None:
    match term:
        case Leaf() | LitBool() | LitInt() | LitScaled() | LitEnum():
            return
        case Not(operand) | Neg(operand) | MulConst(_, operand) | Rescale(operand, _):
            _collect_enum_tables(operand, found)
        case Scale(operand, _, _):
            _collect_enum_tables(operand, found)
        case NAry(_, operands):
            for operand in operands:
                _collect_enum_tables(operand, found)
        case Binary(_, left, right):
            _collect_enum_tables(left, found)
            _collect_enum_tables(right, found)
        case Ite(cond, if_true, if_false):
            _collect_enum_tables(cond, found)
            _collect_enum_tables(if_true, found)
            _collect_enum_tables(if_false, found)
        case EnumTable(scrutinee, arms):
            found.append(term)
            _collect_enum_tables(scrutinee, found)
            for arm in arms:
                _collect_enum_tables(arm.term, found)


def field_spec(fields: tuple[FieldSpec, ...], name: str) -> FieldSpec | None:
    for field in fields:
        if field.name == name:
            return field
    return None


def action_freevars(action: ActionTerm) -> frozenset[SymbolRef]:
    found: frozenset[SymbolRef] = frozenset()
    for field in action.fields:
        found |= freevars(field.term)
    return found
