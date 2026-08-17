"""Symbolic lowering: one canonical query, one set of SMT formulas.

Written from the frozen expression IR and the concrete evaluator's semantics,
not from any other encoder.  Every rule below has a counterpart in
:mod:`muster.core.expr.evaluate` and :mod:`muster.core.expr.typecheck`, and the
lowering carries the *sort* of every sub-term so that the unit discipline is
re-derived here rather than assumed to have been enforced upstream: a scaled
quantity is an integer count of minor units, and two counts of different units
are not the same number.

Three decisions are load-bearing.

* **Variables are keyed by the whole ``QueryVar``, and named by position.**  A
  name derived from the symbol would let two distinct propositions collide into
  one SMT constant, which is precisely how a self-composed query becomes
  vacuous.  The declaration index cannot collide with anything.
* **The declared domain is asserted here, from the declaration.**  The encoder
  also emits a domain assertion, but a backend that can only be right when its
  caller remembers something is not fail-closed.  Asserting a declared domain
  cannot remove a legitimate model: a model outside it is rejected downstream
  anyway.
* **Anything outside the fragment is refused, never approximated.**  A
  narrowing rescale, a sort mismatch, an enum table that does not cover its
  scrutinee -- each raises, and the caller turns that into a typed unsupported
  result.  There is no branch that guesses.

An enum member becomes an integer, and *which* integer is a private detail of
this lowering rather than something the query has to supply.  Members a query
declares keep their declared positions, so the encoding is stable and readable;
members that appear only as literals are numbered in the order they are first
met.  Either way the map is injective within one query, which is the whole of
what equality over an enum needs -- the fragment does not order enum members,
and a model leaves here as a member name, never as a number.  A lowering that
refused a literal whose enum the query happens not to declare would be
answering a capability question rather than a semantic one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import z3

from muster.core.expr.ir import (
    Arm,
    Binary,
    BinaryOp,
    EnumTable,
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
    domain_matches_sort,
)
from muster.solve.query import QTerm, QueryDecl, QueryVar, SolverQuery

#  ``z3`` ships no type information, so its terms are opaque here by necessity.
#  The alias exists so that opacity is stated once and reads as a decision.
type Z3Term = Any


@dataclass(frozen=True, slots=True)
class LoweredVariable:
    """One declared query variable and the SMT constant standing for it."""

    var: QueryVar
    sort: Sort
    domain: Domain
    constant: Z3Term


@dataclass(frozen=True, slots=True)
class LoweredQuery:
    """A query restated in SMT, with everything a witness decoder needs."""

    variables: tuple[LoweredVariable, ...]
    domain_constraints: tuple[Z3Term, ...]
    assertions: tuple[tuple[str, Z3Term], ...]
    enums: tuple[tuple[str, tuple[str, ...]], ...]

    def enum_members(self, enum_id: str) -> tuple[str, ...] | None:
        for declared, members in self.enums:
            if declared == enum_id:
                return members
        return None

    def formulas(self) -> tuple[Z3Term, ...]:
        return (*self.domain_constraints, *(formula for _, formula in self.assertions))


@dataclass(frozen=True, slots=True)
class UnsupportedConstruct:
    """The query mentions something this adapter refuses to translate."""

    detail: str


class _Refused(Exception):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True, slots=True)
class _Typed:
    """An SMT term and the sort the frozen IR gives it."""

    term: Z3Term
    sort: Sort


def lower(query: SolverQuery) -> LoweredQuery | UnsupportedConstruct:
    """Translate a query, or say exactly what stopped the translation."""
    try:
        return _Lowering(query).run()
    except _Refused as refusal:
        return UnsupportedConstruct(refusal.detail)


class _Enums:
    """The member-to-integer map, seeded by what the query declares.

    One job: an injective numbering, per enum, that every term mentioning that
    enum is lowered through.  Declared members keep their declared positions so
    the encoding is stable and readable; a member met only as a literal is
    numbered when it is first seen.  Nothing here decides what an enum's
    complete member set is -- that is a question about a *scrutinee*, and it is
    answered from the scrutinee's own declaration.
    """

    def __init__(self, query: SolverQuery) -> None:
        self._order: dict[str, list[str]] = {}
        for enum in query.enums:
            if len(set(enum.members)) != len(enum.members):
                #  A repeated member would make the numbering ambiguous, and a
                #  backend that picked one of the two positions would be
                #  answering about an enum nobody declared.
                raise _Refused(f"enum {enum.enum_id} declares a member twice")
            self._order[enum.enum_id] = list(enum.members)
        for declaration in query.declarations:
            if isinstance(declaration.sort, EnumSort) and isinstance(
                declaration.domain, EnumDomain
            ):
                for member in declaration.domain.members:
                    self.index(declaration.sort.enum_id, member)

    def index(self, enum_id: str, member: str) -> int:
        members = self._order.setdefault(enum_id, [])
        if member not in members:
            members.append(member)
        return members.index(member)

    def table(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return tuple((enum_id, tuple(members)) for enum_id, members in self._order.items())


class _Lowering:
    def __init__(self, query: SolverQuery) -> None:
        self._query = query
        self._enums = _Enums(query)
        self._variables: dict[QueryVar, LoweredVariable] = {}

    def run(self) -> LoweredQuery:
        constraints: list[Z3Term] = []
        for index, declaration in enumerate(self._query.declarations):
            lowered = self._declare(index, declaration)
            self._variables[lowered.var] = lowered
            constraint = self._domain_constraint(lowered)
            if constraint is not None:
                constraints.append(constraint)

        assertions = tuple(
            (assertion.label, self._boolean(self._term(assertion.formula)))
            for assertion in self._query.assertions
        )
        return LoweredQuery(
            variables=tuple(self._variables.values()),
            domain_constraints=tuple(constraints),
            assertions=assertions,
            enums=self._enums.table(),
        )

    #  ---- declarations ---------------------------------------------------

    def _declare(self, index: int, declaration: QueryDecl) -> LoweredVariable:
        sort = declaration.sort
        domain = declaration.domain
        if not domain_matches_sort(domain, sort):
            raise _Refused(f"{declaration.ref} declares {domain} against {sort}")
        if isinstance(domain, IntRange | ScaledRange) and domain.hi < domain.lo:
            #  A range with no values makes every query mentioning it
            #  unsatisfiable, which would present a malformed declaration as a
            #  semantic answer. It is a refusal, like it is for the oracle.
            raise _Refused(f"{declaration.ref} declares the empty range {domain.lo}..{domain.hi}")
        #  Position, not identity: two propositions can render alike, and a
        #  collision here would silently merge two variables into one.
        name = f"q{index}#{declaration.side.value}"
        constant = z3.Bool(name) if isinstance(sort, BoolSort) else z3.Int(name)
        return LoweredVariable(declaration.var(), sort, domain, constant)

    def _domain_constraint(self, lowered: LoweredVariable) -> Z3Term | None:
        match lowered.domain:
            case BoolDomain():
                #  A boolean SMT constant already ranges over exactly its domain.
                return None
            case IntRange(lo, hi) | ScaledRange(lo, hi):
                return z3.And(lowered.constant >= lo, lowered.constant <= hi)
            case EnumDomain(members):
                sort = lowered.sort
                if not isinstance(sort, EnumSort):  # pragma: no cover - matched above
                    raise _Refused(f"enum domain against {sort}")
                return z3.Or(
                    [
                        lowered.constant == self._enums.index(sort.enum_id, member)
                        for member in members
                    ]
                )

    #  ---- terms ----------------------------------------------------------

    def _term(self, term: QTerm) -> _Typed:
        match term:
            case Leaf(ref):
                return self._variable(ref)
            case LitBool(value):
                return _Typed(z3.BoolVal(value), BoolSort())
            case LitInt(value):
                return _Typed(z3.IntVal(value), IntSort())
            case LitScaled(value):
                return _Typed(z3.IntVal(value.minor), ScaledSort(value.unit_tag, value.scale))
            case LitEnum(value):
                index = self._enums.index(value.enum_id, value.member)
                return _Typed(z3.IntVal(index), EnumSort(value.enum_id))
            case Not(operand):
                return _Typed(z3.Not(self._boolean(self._term(operand))), BoolSort())
            case Neg(operand):
                inner = self._numeric(self._term(operand))
                return _Typed(-inner.term, inner.sort)
            case NAry(op, operands):
                return self._nary(op, [self._term(operand) for operand in operands])
            case Binary(op, left, right):
                return self._binary(op, self._term(left), self._term(right))
            case MulConst(k, operand):
                inner = self._numeric(self._term(operand))
                return _Typed(k * inner.term, inner.sort)
            case Scale(operand, k, to):
                return self._scale(self._term(operand), k, to)
            case Rescale(operand, to_scale):
                return self._rescale(self._term(operand), to_scale)
            case Ite(cond, if_true, if_false):
                guard = self._boolean(self._term(cond))
                chosen = self._term(if_true)
                other = self._term(if_false)
                self._agree(chosen.sort, other.sort)
                return _Typed(z3.If(guard, chosen.term, other.term), chosen.sort)
            case EnumTable(selector, arms):
                return self._table(selector, self._term(selector), arms)

    def _variable(self, ref: QueryVar) -> _Typed:
        lowered = self._variables.get(ref)
        if lowered is None:
            raise _Refused(f"{ref} occurs in an assertion but is not declared")
        return _Typed(lowered.constant, lowered.sort)

    def _nary(self, op: NAryOp, operands: list[_Typed]) -> _Typed:
        match op:
            case NAryOp.AND:
                return _Typed(z3.And([self._boolean(item) for item in operands]), BoolSort())
            case NAryOp.OR:
                return _Typed(z3.Or([self._boolean(item) for item in operands]), BoolSort())
            case NAryOp.ADD:
                sort = self._numeric(operands[0]).sort
                for item in operands[1:]:
                    self._agree(sort, self._numeric(item).sort)
                return _Typed(z3.Sum([item.term for item in operands]), sort)

    def _binary(self, op: BinaryOp, left: _Typed, right: _Typed) -> _Typed:
        match op:
            case BinaryOp.IMPLIES:
                return _Typed(z3.Implies(self._boolean(left), self._boolean(right)), BoolSort())
            case BinaryOp.IFF:
                return _Typed(self._boolean(left) == self._boolean(right), BoolSort())
            case BinaryOp.SUB:
                self._agree(self._numeric(left).sort, self._numeric(right).sort)
                return _Typed(left.term - right.term, left.sort)
            case BinaryOp.EQ:
                self._agree(left.sort, right.sort)
                return _Typed(left.term == right.term, BoolSort())
            case BinaryOp.NE:
                self._agree(left.sort, right.sort)
                return _Typed(left.term != right.term, BoolSort())
            case BinaryOp.LT | BinaryOp.LE | BinaryOp.GT | BinaryOp.GE:
                #  Ordering needs an ordered sort: the evaluator refuses to
                #  order booleans and enum members, and so does this.
                self._agree(self._numeric(left).sort, self._numeric(right).sort)
                return _Typed(_ordered(op, left.term, right.term), BoolSort())

    def _scale(self, operand: _Typed, k: int, to: Sort) -> _Typed:
        if not isinstance(operand.sort, IntSort):
            raise _Refused(f"scale expects an integer operand, got {operand.sort}")
        if not isinstance(to, ScaledSort):
            raise _Refused(f"scale expects a scaled target sort, got {to}")
        return _Typed(operand.term * k, to)

    def _rescale(self, operand: _Typed, to_scale: int) -> _Typed:
        sort = operand.sort
        if not isinstance(sort, ScaledSort):
            raise _Refused(f"rescale expects a scaled operand, got {sort}")
        if to_scale < sort.scale:
            #  Narrowing needs a rounding mode the frozen wire type does not
            #  carry.  Refusing is the only answer that cannot invent one.
            raise _Refused(f"narrowing rescale {sort.scale} -> {to_scale}")
        factor = 10 ** (to_scale - sort.scale)
        return _Typed(operand.term * factor, ScaledSort(sort.unit_tag, to_scale))

    def _table(self, selector: QTerm, scrutinee: _Typed, arms: tuple[Arm[QueryVar], ...]) -> _Typed:
        """An exhaustive table, lowered **over its arms**.

        Over the arms rather than over the enum's declared members, because the
        arms are what the evaluator selects between: an arm for a member the
        query never declared is still an arm, and dropping it would make the
        table mean something the evaluator does not.  Members are unique, so
        first-match and only-match coincide and the chain is exact wherever the
        evaluator has a value.
        """
        sort = scrutinee.sort
        if not isinstance(sort, EnumSort):
            raise _Refused(f"an enum table needs an enum scrutinee, got {sort}")

        covered: dict[str, _Typed] = {}
        for arm in arms:
            if arm.member in covered:
                raise _Refused(f"enum table repeats arm {arm.member}")
            covered[arm.member] = self._term(arm.term)

        result_sort = covered[arms[0].member].sort
        for arm in arms:
            self._agree(result_sort, covered[arm.member].sort)

        missing = [member for member in self._required(selector, sort) if member not in covered]
        if missing:
            raise _Refused(f"enum table does not cover {', '.join(missing)}")

        #  Built from the last arm outwards. The final fallback duplicates that
        #  arm rather than inventing a value, so the encoding is defined where
        #  the evaluator is stuck -- which can only admit a world the evaluator
        #  rejects, never hide one it accepts, and the extra worlds are caught
        #  when the witness is revalidated.
        result = covered[arms[-1].member].term
        for arm in reversed(arms[:-1]):
            guard = scrutinee.term == self._enums.index(sort.enum_id, arm.member)
            result = z3.If(guard, covered[arm.member].term, result)
        return _Typed(result, result_sort)

    def _required(self, selector: QTerm, sort: EnumSort) -> tuple[str, ...]:
        """Which members a table must cover: its scrutinee's own declared domain.

        The same rule the program compiler applies, so a program that compiled
        is never refused here.  Where the scrutinee is a composed term its range
        is stated nowhere, and demanding coverage of every member any *other*
        declaration happens to allow would refuse queries that are perfectly
        decidable.
        """
        del sort
        if isinstance(selector, Leaf):
            declared = self._variables.get(selector.ref)
            if declared is not None and isinstance(declared.domain, EnumDomain):
                return declared.domain.members
        return ()

    #  ---- sort discipline ------------------------------------------------

    def _boolean(self, typed: _Typed) -> Z3Term:
        if not isinstance(typed.sort, BoolSort):
            raise _Refused(f"expected a boolean, got {typed.sort}")
        return typed.term

    def _numeric(self, typed: _Typed) -> _Typed:
        if not isinstance(typed.sort, IntSort | ScaledSort):
            raise _Refused(f"expected a numeric sort, got {typed.sort}")
        return typed

    def _agree(self, expected: Sort, actual: Sort) -> None:
        if expected != actual:
            raise _Refused(f"sort mismatch: {expected} vs {actual}")


def _ordered(op: BinaryOp, left: Z3Term, right: Z3Term) -> Z3Term:
    match op:
        case BinaryOp.LT:
            return left < right
        case BinaryOp.LE:
            return left <= right
        case BinaryOp.GT:
            return left > right
        case _:
            return left >= right
