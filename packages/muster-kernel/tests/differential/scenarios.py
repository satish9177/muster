"""Tiny cases, generated systematically rather than sampled.

A random case that happens to be easy proves nothing.  Every scenario below is
small enough that its truth is computable by enumeration, and the generator is
a **product** rather than a sample: for each variable shape, every subset of a
constraint pool, against every program written for that shape, against every
declared set of established values.  Infeasible combinations, redundant
constraints, correlated variables and variables that matter to nothing all
arise from the product instead of being remembered.

The shapes cover ``|U| = 0`` through ``|U| = 4``, booleans, small integer
intervals including negative ones, enums and scaled quantities, programs whose
*kind* varies and programs whose *amount* varies, and one program in which no
single variable decides the action.

The cases are built directly as ``ProjectedCase`` values.  Going through the
bundle loader would test admission control, which milestone A already covers,
and would make the interesting shapes -- an unsatisfiable constraint set, a
variable no rule reads -- impossible to state.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product

from muster.core.actions import (
    ActionKindSpec,
    ActionSchema,
    Consequentiality,
    FieldSpec,
)
from muster.core.analysis.logical_case import LogicalCase
from muster.core.case.constraints import Constraint, StructuralDeriv
from muster.core.case.facts import AttestedBy, EstablishedFact
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
    NAry,
    NAryOp,
    Neg,
    Not,
    Rescale,
    Scale,
)
from muster.core.expr.terms import Term
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
from muster.core.wire.codec import canonical_order
from muster.core.wire.digests import Digest
from muster.hinge.project import ProjectedCase, SymbolDeclaration
from muster.policy.program import ActionTerm, DecisionProgram, FieldTerm, ProgramRule

#  A stand-in for artifacts a projected case pins but the solver never reads.
#  The predicate schema is one of them: a query is a function of symbols,
#  sorts, domains and formulas, and this digest travels only inside the case
#  identity.
PLACEHOLDER = Digest(bytes(32))

CURRENCY = "INR"
CURRENCY_SCALE = 2
MONEY = ScaledSort(CURRENCY, CURRENCY_SCALE)

ENUM_COLOUR = "colour"
COLOURS: tuple[str, ...] = ("RED", "GREEN", "BLUE")
#  A member of the same enum that no declared domain admits. It can still be
#  written as a literal, and a table that scrutinises a *computed* term can
#  still reach it -- which is the shape a lowering keyed on declared members
#  gets wrong.
COLOUR_UNDECLARED = "AMBER"
ENUM_HOLD = "hold_reason"
HOLD_REASONS: tuple[str, ...] = ("REVIEW", "BLOCKED")
ENUM_TIER = "tier"
TIERS: tuple[str, ...] = ("LOW", "HIGH")
ENUM_SOLE = "sole"
SOLE_MEMBERS: tuple[str, ...] = ("ONLY",)

ACTION_PAY = "PAY"
ACTION_HOLD = "HOLD"
ACTION_REFUND = "REFUND"
FIELD_AMOUNT = "amount"
FIELD_REASON = "reason"
FIELD_TIER = "tier"
FIELD_MEMO = "memo"

FLAG_A = SymbolRef("flag", ("A",))
FLAG_B = SymbolRef("flag", ("B",))
COUNT = SymbolRef("count", ("A",))
OFFSET = SymbolRef("offset", ("A",))
TINT = SymbolRef("tint", ("A",))
RATE = SymbolRef("rate", ("A",))
#  A variable a constraint determines from the others, the way a definitional
#  bundle rule determines a normative conclusion from its premises.
PAYABLE = SymbolRef("payable", ("A",))

#  Two distinct propositions whose human rendering is the same string. A
#  lowering that named its variables after the rendering would merge them.
TWIN_ARGS = SymbolRef("twin", ("a", "b"))
TWIN_JOINED = SymbolRef("twin", ("a, b",))

#  Wide integer domains, for the cases that attack the bounded backend's
#  threshold abstraction rather than its enumeration.
DURATION = SymbolRef("minutes", ("A",))
WINDOW = SymbolRef("window", ("A",))
STEPS = SymbolRef("steps", ("A",))
SMALL = SymbolRef("small", ("A",))
#  A scaled quantity wide enough that the threshold abstraction has to reduce
#  it, which no integer-only corpus exercises.
PURSE = SymbolRef("purse", ("A",))

#  Wider than any enumeration budget, so a variable the abstraction cannot
#  apply to has to be refused rather than enumerated.
HUGE = SymbolRef("huge", ("A",))

#  A third integer of the same sort, so an equality chain can be three long
#  rather than a single pair.
TALLY = SymbolRef("tally", ("A",))

#  Degenerate but legal domains: one value, no non-negative value, one member.
PINNED = SymbolRef("pinned", ("A",))
DEBT = SymbolRef("debt", ("A",))
SOLE = SymbolRef("sole", ("A",))

DECLARATIONS: dict[SymbolRef, tuple[Sort, Domain]] = {
    FLAG_A: (BoolSort(), BoolDomain()),
    FLAG_B: (BoolSort(), BoolDomain()),
    COUNT: (IntSort(), IntRange(0, 3)),
    OFFSET: (IntSort(), IntRange(-2, 2)),
    TINT: (EnumSort(ENUM_COLOUR), EnumDomain(COLOURS)),
    RATE: (MONEY, ScaledRange(0, 3)),
    PAYABLE: (BoolSort(), BoolDomain()),
    TWIN_ARGS: (BoolSort(), BoolDomain()),
    TWIN_JOINED: (BoolSort(), BoolDomain()),
    DURATION: (IntSort(), IntRange(0, 1440)),
    WINDOW: (IntSort(), IntRange(0, 60)),
    STEPS: (IntSort(), IntRange(0, 3)),
    SMALL: (IntSort(), IntRange(0, 20)),
    PURSE: (MONEY, ScaledRange(0, 5_000)),
    HUGE: (IntSort(), IntRange(0, 300_000)),
    TALLY: (IntSort(), IntRange(0, 3)),
    PINNED: (IntSort(), IntRange(2, 2)),
    DEBT: (IntSort(), IntRange(-4, -1)),
    SOLE: (EnumSort(ENUM_SOLE), EnumDomain(SOLE_MEMBERS)),
}

#  The same two kinds, with an amount range wide enough for a payment that
#  varies with a duration rather than with a flag.
WIDE_SCHEMA = ActionSchema(
    schema_id="threshold-actions",
    schema_version=1,
    kinds=(
        ActionKindSpec(
            kind=ACTION_PAY,
            fields=(
                FieldSpec(
                    name=FIELD_AMOUNT,
                    sort=MONEY,
                    bounds=ScaledRange(0, 1_000_000),
                    consequentiality=Consequentiality.CONSEQUENTIAL,
                    required=True,
                ),
            ),
        ),
        ActionKindSpec(
            kind=ACTION_HOLD,
            fields=(
                FieldSpec(
                    name=FIELD_REASON,
                    sort=EnumSort(ENUM_HOLD),
                    bounds=EnumDomain(HOLD_REASONS),
                    consequentiality=Consequentiality.CONSEQUENTIAL,
                    required=True,
                ),
            ),
        ),
    ),
)


def money(minor: int) -> VScaled:
    return VScaled(CURRENCY, CURRENCY_SCALE, minor)


def colour(member: str) -> Term:
    return LitEnum(VEnum(ENUM_COLOUR, member))


def synthetic_schema() -> ActionSchema:
    """Two kinds, a consequential field each, and a diagnostic field shared.

    The diagnostic field is what makes "same action, different debug text" a
    testable claim rather than an assertion in a docstring.
    """
    memo = FieldSpec(
        name=FIELD_MEMO,
        sort=IntSort(),
        bounds=IntRange(0, 9),
        consequentiality=Consequentiality.DIAGNOSTIC,
        required=False,
        default=VInt(0),
    )
    return ActionSchema(
        schema_id="differential-actions",
        schema_version=1,
        kinds=(
            ActionKindSpec(
                kind=ACTION_PAY,
                fields=(
                    FieldSpec(
                        name=FIELD_AMOUNT,
                        sort=MONEY,
                        bounds=ScaledRange(0, 100),
                        consequentiality=Consequentiality.CONSEQUENTIAL,
                        required=True,
                    ),
                    memo,
                ),
            ),
            ActionKindSpec(
                kind=ACTION_HOLD,
                fields=(
                    FieldSpec(
                        name=FIELD_REASON,
                        sort=EnumSort(ENUM_HOLD),
                        bounds=EnumDomain(HOLD_REASONS),
                        consequentiality=Consequentiality.CONSEQUENTIAL,
                        required=True,
                    ),
                    memo,
                ),
            ),
        ),
    )


SCHEMA = synthetic_schema()

#  Three kinds rather than two, one of them carrying *two* consequential
#  fields, one consequential field name shared across two kinds, and one
#  consequential field that is optional with no declared default.  Each of
#  those turns on a branch the two-kind schema leaves dead: the disjunction
#  over several field differences in the action comparison, the cross-kind
#  field-sort agreement rule, the three-deep kind selector, and the derived
#  filler -- which decides a *consequential* value and therefore decides
#  whether two worlds hold the same action.
RICH_SCHEMA = ActionSchema(
    schema_id="rich-actions",
    schema_version=1,
    kinds=(
        ActionKindSpec(
            kind=ACTION_PAY,
            fields=(
                FieldSpec(
                    name=FIELD_AMOUNT,
                    sort=MONEY,
                    bounds=ScaledRange(0, 100),
                    consequentiality=Consequentiality.CONSEQUENTIAL,
                    required=True,
                ),
                FieldSpec(
                    name=FIELD_TIER,
                    sort=EnumSort(ENUM_TIER),
                    bounds=EnumDomain(TIERS),
                    consequentiality=Consequentiality.CONSEQUENTIAL,
                    required=True,
                ),
                FieldSpec(
                    name=FIELD_MEMO,
                    sort=IntSort(),
                    bounds=IntRange(0, 9),
                    consequentiality=Consequentiality.DIAGNOSTIC,
                    required=False,
                    default=VInt(0),
                ),
            ),
        ),
        ActionKindSpec(
            kind=ACTION_REFUND,
            fields=(
                #  The same field name as PAY's, so the schema's "one name, one
                #  sort" rule is the thing keeping the comparison well typed.
                FieldSpec(
                    name=FIELD_AMOUNT,
                    sort=MONEY,
                    bounds=ScaledRange(0, 100),
                    consequentiality=Consequentiality.CONSEQUENTIAL,
                    required=True,
                ),
            ),
        ),
        ActionKindSpec(
            kind=ACTION_HOLD,
            fields=(
                #  Optional and defaultless, so an action term that omits it
                #  takes the derived filler -- on a field that counts.
                FieldSpec(
                    name=FIELD_REASON,
                    sort=EnumSort(ENUM_HOLD),
                    bounds=EnumDomain(HOLD_REASONS),
                    consequentiality=Consequentiality.CONSEQUENTIAL,
                    required=False,
                ),
            ),
        ),
    ),
)


def pay(amount: Term, memo: Term | None = None) -> ActionTerm:
    fields = [FieldTerm(FIELD_AMOUNT, amount)]
    if memo is not None:
        fields.append(FieldTerm(FIELD_MEMO, memo))
    return ActionTerm(ACTION_PAY, tuple(fields))


def hold(reason: str, memo: Term | None = None) -> ActionTerm:
    fields = [FieldTerm(FIELD_REASON, LitEnum(VEnum(ENUM_HOLD, reason)))]
    if memo is not None:
        fields.append(FieldTerm(FIELD_MEMO, memo))
    return ActionTerm(ACTION_HOLD, tuple(fields))


def program(rules: tuple[ProgramRule, ...], otherwise: ActionTerm) -> DecisionProgram:
    """A program whose declared inputs are exactly its free symbols."""
    draft = DecisionProgram(inputs=(), rules=rules, otherwise=otherwise)
    inputs = canonical_order(draft.free_symbols(), lambda ref: ref.to_node())
    return DecisionProgram(inputs=inputs, rules=rules, otherwise=otherwise)


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    case: ProjectedCase

    def unresolved(self) -> tuple[SymbolRef, ...]:
        return self.case.unresolved()


def build(
    *,
    name: str,
    universe: tuple[SymbolRef, ...],
    known: dict[SymbolRef, Value],
    constraints: tuple[tuple[str, Term], ...],
    decision: DecisionProgram,
    schema: ActionSchema = SCHEMA,
) -> Scenario:
    """Assemble one projected case from its logical content."""
    declarations = canonical_order(
        (SymbolDeclaration(ref, *DECLARATIONS[ref]) for ref in universe),
        lambda declaration: declaration.ref.to_node(),
    )
    facts = canonical_order(
        (EstablishedFact(ref, value, AttestedBy(PLACEHOLDER)) for ref, value in known.items()),
        lambda fact: fact.to_node(),
    )
    formulas = canonical_order(
        (
            Constraint(label, formula, StructuralDeriv(PLACEHOLDER))
            for label, formula in constraints
        ),
        lambda constraint: constraint.to_node(),
    )
    logical = LogicalCase(
        universe=canonical_order(universe, lambda ref: ref.to_node()),
        known=facts,
        constraints=formulas,
        decision_program_digest=decision.digest(),
        action_schema_digest=schema.digest(),
        predicate_schema_digest=PLACEHOLDER,
    )
    return Scenario(name, ProjectedCase(logical, declarations, decision, schema))


#  ---- the systematic product --------------------------------------------


@dataclass(frozen=True, slots=True)
class Shape:
    """One variable configuration, its constraint pool and its programs."""

    name: str
    universe: tuple[SymbolRef, ...]
    pool: tuple[tuple[str, Term], ...]
    programs: tuple[tuple[str, DecisionProgram], ...]
    established: tuple[tuple[str, dict[SymbolRef, Value]], ...]
    schema: ActionSchema = SCHEMA


def _flag_shape() -> Shape:
    kinds = program(
        rules=(ProgramRule(guard=Leaf(FLAG_A), action=pay(LitScaled(money(5)))),),
        otherwise=hold("REVIEW"),
    )
    amounts = program(
        rules=(),
        otherwise=pay(
            NAry(
                NAryOp.ADD,
                (
                    Ite(Leaf(FLAG_A), LitScaled(money(2)), LitScaled(money(0))),
                    Ite(Leaf(FLAG_B), LitScaled(money(3)), LitScaled(money(0))),
                ),
            )
        ),
    )
    return Shape(
        name="flags",
        universe=(FLAG_A, FLAG_B),
        pool=(
            ("K1", NAry(NAryOp.OR, (Leaf(FLAG_A), Leaf(FLAG_B)))),
            ("K2", Binary(BinaryOp.IMPLIES, Leaf(FLAG_A), Leaf(FLAG_B))),
            ("K3", Binary(BinaryOp.IFF, Leaf(FLAG_A), Leaf(FLAG_B))),
            ("K4", Not(Leaf(FLAG_B))),
        ),
        programs=(("kind", kinds), ("sum", amounts)),
        established=(
            ("open", {}),
            ("a-true", {FLAG_A: VBool(True)}),
            #  |U| = 0: nothing is unresolved and the case is still a case.
            ("settled", {FLAG_A: VBool(True), FLAG_B: VBool(False)}),
        ),
    )


def _count_shape() -> Shape:
    threshold = program(
        rules=(
            ProgramRule(
                guard=Binary(BinaryOp.GE, Leaf(COUNT), LitInt(2)),
                action=pay(LitScaled(money(7))),
            ),
        ),
        otherwise=pay(LitScaled(money(1))),
    )
    correlated = program(
        rules=(
            ProgramRule(
                guard=NAry(
                    NAryOp.AND,
                    (Leaf(FLAG_A), Binary(BinaryOp.GE, Leaf(COUNT), LitInt(2))),
                ),
                action=pay(LitScaled(money(9))),
            ),
        ),
        otherwise=pay(LitScaled(money(0))),
    )
    return Shape(
        name="count",
        universe=(COUNT, FLAG_A),
        pool=(
            ("K1", Binary(BinaryOp.GE, Leaf(COUNT), LitInt(2))),
            ("K2", Binary(BinaryOp.LE, Leaf(COUNT), LitInt(2))),
            ("K3", Binary(BinaryOp.EQ, Leaf(COUNT), LitInt(1))),
            (
                "K4",
                Binary(BinaryOp.IMPLIES, Leaf(FLAG_A), Binary(BinaryOp.GE, Leaf(COUNT), LitInt(3))),
            ),
        ),
        programs=(("threshold", threshold), ("correlated", correlated)),
        established=(("open", {}), ("count-2", {COUNT: VInt(2)})),
    )


def _signed_shape() -> Shape:
    total = NAry(NAryOp.ADD, (Leaf(COUNT), Leaf(OFFSET), LitInt(2)))
    scaled = program(
        rules=(),
        otherwise=pay(
            Ite(Binary(BinaryOp.GE, total, LitInt(4)), LitScaled(money(8)), LitScaled(money(4)))
        ),
    )
    signs = program(
        rules=(
            ProgramRule(
                guard=Binary(BinaryOp.LT, Leaf(OFFSET), LitInt(0)),
                action=hold("BLOCKED"),
            ),
        ),
        otherwise=pay(
            Ite(
                Binary(BinaryOp.EQ, Leaf(COUNT), LitInt(0)),
                LitScaled(money(0)),
                LitScaled(money(6)),
            )
        ),
    )
    return Shape(
        name="signed",
        universe=(COUNT, OFFSET),
        pool=(
            ("K1", Binary(BinaryOp.GE, Leaf(OFFSET), LitInt(0))),
            ("K2", Binary(BinaryOp.EQ, Leaf(OFFSET), Neg(LitInt(1)))),
            ("K3", Binary(BinaryOp.LE, NAry(NAryOp.ADD, (Leaf(COUNT), Leaf(OFFSET))), LitInt(2))),
            ("K4", Binary(BinaryOp.NE, Leaf(COUNT), LitInt(0))),
        ),
        programs=(("scaled", scaled), ("signs", signs)),
        established=(("open", {}),),
    )


def _enum_shape() -> Shape:
    table = program(
        rules=(),
        otherwise=pay(
            EnumTable(
                Leaf(TINT),
                (
                    Arm("RED", LitScaled(money(0))),
                    Arm("GREEN", LitScaled(money(1))),
                    Arm("BLUE", LitScaled(money(2))),
                ),
            )
        ),
    )
    mixed = program(
        rules=(
            ProgramRule(
                guard=Binary(BinaryOp.EQ, Leaf(TINT), colour("BLUE")),
                action=hold("BLOCKED"),
            ),
        ),
        otherwise=pay(Leaf(RATE)),
    )
    return Shape(
        name="enum",
        universe=(TINT, RATE),
        pool=(
            ("K1", Binary(BinaryOp.EQ, Leaf(TINT), colour("RED"))),
            (
                "K2",
                NAry(
                    NAryOp.OR,
                    (
                        Binary(BinaryOp.EQ, Leaf(TINT), colour("RED")),
                        Binary(BinaryOp.EQ, Leaf(TINT), colour("GREEN")),
                    ),
                ),
            ),
            #  Stated through a widening rescale, so the one arithmetic node
            #  the fragment carries that changes a term's *sort* appears in a
            #  real case rather than only in a hand-built query.
            (
                "K3",
                Binary(
                    BinaryOp.GE,
                    Rescale(Leaf(RATE), 4),
                    LitScaled(VScaled(CURRENCY, 4, 200)),
                ),
            ),
            ("K4", Binary(BinaryOp.NE, Leaf(TINT), colour("BLUE"))),
        ),
        programs=(("table", table), ("mixed", mixed)),
        established=(("open", {}), ("red", {TINT: VEnum(ENUM_COLOUR, "RED")})),
    )


def _trio_shape() -> Shape:
    """Three unresolved variables, and no one of them decides the action.

    ``PAY`` needs both flags and a count above the threshold; every single
    variable is individually droppable and the empty set is not sufficient.
    """
    joint = program(
        rules=(
            ProgramRule(
                guard=NAry(
                    NAryOp.AND,
                    (
                        Leaf(FLAG_A),
                        Leaf(FLAG_B),
                        Binary(BinaryOp.GE, Leaf(COUNT), LitInt(2)),
                    ),
                ),
                action=pay(LitScaled(money(4))),
            ),
        ),
        otherwise=hold("REVIEW"),
    )
    return Shape(
        name="trio",
        universe=(FLAG_A, FLAG_B, COUNT),
        pool=(
            ("K1", Binary(BinaryOp.IMPLIES, Leaf(FLAG_A), Leaf(FLAG_B))),
            ("K2", Binary(BinaryOp.GE, Leaf(COUNT), LitInt(1))),
            ("K3", NAry(NAryOp.OR, (Leaf(FLAG_A), Binary(BinaryOp.LE, Leaf(COUNT), LitInt(1))))),
        ),
        programs=(("joint", joint),),
        established=(("open", {}),),
    )


def _quartet_shape() -> Shape:
    """Four unresolved variables across three sorts."""
    wide = program(
        rules=(
            ProgramRule(
                guard=Binary(BinaryOp.EQ, Leaf(TINT), colour("BLUE")),
                action=hold("BLOCKED"),
            ),
            ProgramRule(
                guard=NAry(NAryOp.AND, (Leaf(FLAG_A), Leaf(FLAG_B))),
                action=pay(LitScaled(money(3))),
            ),
        ),
        otherwise=pay(
            Ite(
                Binary(BinaryOp.GE, Leaf(COUNT), LitInt(2)),
                LitScaled(money(2)),
                LitScaled(money(1)),
            )
        ),
    )
    return Shape(
        name="quartet",
        universe=(FLAG_A, FLAG_B, COUNT, TINT),
        pool=(
            ("K1", Binary(BinaryOp.NE, Leaf(TINT), colour("GREEN"))),
            (
                "K2",
                Binary(BinaryOp.IMPLIES, Leaf(FLAG_A), Binary(BinaryOp.LE, Leaf(COUNT), LitInt(1))),
            ),
        ),
        programs=(("wide", wide),),
        established=(("open", {}),),
    )


def _chain_shape() -> Shape:
    """Equalities between two *variables*, so classes are longer than a pair.

    Every other shape's only variable-to-variable equalities come from the
    encoder's own ``FIX:`` assertions, which merge exactly two.  Here the case
    supplies them, the pool is a power set, and ``a = b`` with ``b = c`` gives
    a class of three per world and six across the two.  One pool entry is a
    top-level conjunction, so a pin and a bound arrive inside one constraint
    rather than as two -- the shape a bundle rule states two facts in.
    """
    decision = program(
        rules=(),
        otherwise=pay(
            Ite(
                Binary(
                    BinaryOp.GE,
                    NAry(NAryOp.ADD, (Leaf(COUNT), Leaf(TALLY), Leaf(OFFSET))),
                    LitInt(4),
                ),
                LitScaled(money(5)),
                LitScaled(money(1)),
            )
        ),
    )
    return Shape(
        name="chain",
        universe=(COUNT, TALLY, OFFSET),
        pool=(
            ("K1", Binary(BinaryOp.EQ, Leaf(COUNT), Leaf(TALLY))),
            ("K2", Binary(BinaryOp.EQ, Leaf(TALLY), Leaf(OFFSET))),
            (
                "K3",
                NAry(
                    NAryOp.AND,
                    (
                        Binary(BinaryOp.EQ, Leaf(COUNT), LitInt(1)),
                        Binary(BinaryOp.GE, Leaf(OFFSET), LitInt(0)),
                    ),
                ),
            ),
        ),
        programs=(("sum", decision),),
        established=(("open", {}),),
    )


def _bounds_shape() -> Shape:
    """Degenerate declared domains: one value, no non-negative value, one member."""
    decision = program(
        rules=(
            ProgramRule(
                guard=Binary(BinaryOp.LT, Leaf(DEBT), LitInt(-2)),
                action=pay(LitScaled(money(1))),
            ),
        ),
        otherwise=pay(
            Ite(
                Binary(BinaryOp.EQ, Leaf(SOLE), LitEnum(VEnum(ENUM_SOLE, "ONLY"))),
                Scale(Leaf(PINNED), 10, MONEY),
                LitScaled(money(0)),
            )
        ),
    )
    return Shape(
        name="bounds",
        universe=(PINNED, DEBT, SOLE),
        pool=(
            ("K1", Binary(BinaryOp.EQ, Leaf(PINNED), LitInt(2))),
            ("K2", Binary(BinaryOp.GE, Leaf(DEBT), LitInt(-2))),
        ),
        programs=(("degenerate", decision),),
        established=(("open", {}),),
    )


def _rich_shape() -> Shape:
    """Three kinds, two consequential fields on one, and a derived filler."""
    decision = DecisionProgram(
        inputs=(),
        rules=(
            ProgramRule(
                guard=Binary(BinaryOp.EQ, Leaf(TINT), colour("BLUE")),
                #  No reason supplied: the consequential value is the filler.
                action=ActionTerm(ACTION_HOLD, ()),
            ),
            ProgramRule(
                guard=Leaf(FLAG_A),
                action=ActionTerm(
                    ACTION_PAY,
                    (
                        FieldTerm(FIELD_AMOUNT, LitScaled(money(3))),
                        FieldTerm(
                            FIELD_TIER,
                            Ite(
                                Leaf(FLAG_B),
                                LitEnum(VEnum(ENUM_TIER, "HIGH")),
                                LitEnum(VEnum(ENUM_TIER, "LOW")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        otherwise=ActionTerm(ACTION_REFUND, (FieldTerm(FIELD_AMOUNT, LitScaled(money(2))),)),
    )
    inputs = canonical_order(decision.free_symbols(), lambda ref: ref.to_node())
    closed = DecisionProgram(inputs=inputs, rules=decision.rules, otherwise=decision.otherwise)
    return Shape(
        name="rich",
        universe=(FLAG_A, FLAG_B, TINT),
        pool=(
            ("K1", Binary(BinaryOp.NE, Leaf(TINT), colour("BLUE"))),
            ("K2", Binary(BinaryOp.IMPLIES, Leaf(FLAG_A), Leaf(FLAG_B))),
        ),
        programs=(("three-kinds", closed),),
        established=(
            ("open", {}),
            #  With the colour settled on the one that fires the HOLD rule,
            #  HOLD is the *only* reachable kind -- and that is what makes the
            #  derived filler load-bearing. While several kinds are reachable
            #  the kind disjunct of the action comparison is already true, so
            #  no filler-bearing field can decide anything and the shape would
            #  carry the filler without testing it.
            ("blue", {TINT: VEnum(ENUM_COLOUR, "BLUE")}),
        ),
        schema=RICH_SCHEMA,
    )


def _composed_shape() -> Shape:
    """A table over a computed scrutinee, and a guard that is an ``ite``.

    The scrutinee can evaluate to a member no declared domain admits, so a
    lowering that built its selector chain from declared members rather than
    from the arms would drop an arm and answer a different question.  The
    program compiler skips its exhaustiveness check for a scrutinee that is not
    a bare variable, which is why nothing upstream rules this shape out.

    A dropped arm merges two payments into one, which changes the *reachable
    set* and leaves every satisfiable/unsatisfiable answer intact.  So the test
    this shape is protected by is
    ``test_the_analysis_outcome_is_the_enumerated_one``, not the query-level
    comparisons -- narrowing that one disarms this shape.
    """
    table = EnumTable(
        Ite(Leaf(FLAG_A), Leaf(TINT), LitEnum(VEnum(ENUM_COLOUR, COLOUR_UNDECLARED))),
        (
            Arm("RED", LitScaled(money(0))),
            Arm("GREEN", LitScaled(money(1))),
            Arm("BLUE", LitScaled(money(2))),
            Arm(COLOUR_UNDECLARED, LitScaled(money(9))),
        ),
    )
    decision = program(
        rules=(
            ProgramRule(
                guard=Ite(Leaf(FLAG_A), Leaf(FLAG_B), Not(Leaf(FLAG_B))),
                action=pay(table),
            ),
            #  A table in *guard* position rather than in a field term, which
            #  is the other place the type checker permits one.
            ProgramRule(
                guard=EnumTable(
                    Leaf(TINT),
                    (
                        Arm("RED", LitBool(True)),
                        Arm("GREEN", LitBool(False)),
                        Arm("BLUE", LitBool(True)),
                    ),
                ),
                action=pay(LitScaled(money(7))),
            ),
        ),
        otherwise=hold("REVIEW"),
    )
    return Shape(
        name="composed",
        universe=(FLAG_A, FLAG_B, TINT),
        pool=(
            ("K1", Binary(BinaryOp.NE, Leaf(TINT), colour("RED"))),
            ("K2", NAry(NAryOp.OR, (Leaf(FLAG_A), Leaf(FLAG_B)))),
        ),
        programs=(("table", decision),),
        established=(("open", {}),),
    )


SHAPES: tuple[Shape, ...] = (
    _flag_shape(),
    _count_shape(),
    _signed_shape(),
    _enum_shape(),
    _trio_shape(),
    _quartet_shape(),
    _chain_shape(),
    _bounds_shape(),
    _rich_shape(),
    _composed_shape(),
)


def generated_scenarios() -> tuple[Scenario, ...]:
    """Every (shape, constraint subset, program, established set) combination."""
    found: list[Scenario] = []
    for shape in SHAPES:
        for mask in product((False, True), repeat=len(shape.pool)):
            chosen = tuple(item for item, taken in zip(shape.pool, mask, strict=True) if taken)
            labels = "".join(label[-1] for label, _ in chosen) or "none"
            for program_name, decision in shape.programs:
                for known_name, known in shape.established:
                    found.append(
                        build(
                            name=f"{shape.name}/{labels}/{program_name}/{known_name}",
                            universe=shape.universe,
                            known=known,
                            constraints=chosen,
                            decision=decision,
                            schema=shape.schema,
                        )
                    )
    return tuple(found)


DEFINITIONAL_NAME = "definitional/DEF/derived/open"


def definitional_scenario() -> Scenario:
    """The workforce case's shape, in three variables.

    A constraint determines ``payable`` from the two premises, and the action
    depends only on ``payable``.  So ``{payable}`` is sufficient, ``{a, b}`` is
    sufficient, and therefore **no single variable is necessary** -- while the
    empty set is plainly not sufficient and evidence is required.  A design
    that reported a per-variable relevance flag would say nothing matters here.
    """
    decision = program(
        rules=(ProgramRule(guard=Leaf(PAYABLE), action=pay(LitScaled(money(5)))),),
        otherwise=hold("REVIEW"),
    )
    definition = Binary(BinaryOp.IFF, Leaf(PAYABLE), NAry(NAryOp.AND, (Leaf(FLAG_A), Leaf(FLAG_B))))
    return build(
        name=DEFINITIONAL_NAME,
        universe=(FLAG_A, FLAG_B, PAYABLE),
        known={},
        constraints=(("DEF", definition),),
        decision=decision,
    )


SCENARIOS: tuple[Scenario, ...] = (*generated_scenarios(), definitional_scenario())
