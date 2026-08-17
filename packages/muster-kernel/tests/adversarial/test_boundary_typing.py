"""Two boundaries where a defect used to surface later than it was made.

Neither is a soundness hole -- no wrong answer was ever produced -- but both put
a failure a long way from the thing that caused it, and one of them dressed a
condition reachable from case data as a programmer defect.

**A. A table over a composed scrutinee compiled without being exhaustive.**
Coverage was checked only where the scrutinee was a bare variable, so an
``ite`` between two enum variables, or a table whose arms are themselves
enum-valued, went unchecked.  Totality is a property of the *program*, and a
program that is not total should be refused when it is compiled -- not become
``EVALUATION_STUCK`` in whichever world first reaches the missing arm.

**B. A repeated constraint label surfaced at query construction.**  The rule is
real -- a query cannot carry two assertions under one label -- but stating it
only where the query is assembled meant an ``InvariantViolation`` at the end of
a path that starts in case data.  It is reachable from case data: two distinct
propositions can *render* alike, the readable constraint label is built from
the rendering, and a case declaring both really does produce one label twice.
The public path answers that with a typed value, and the rule now also lives on
the values that carry the constraints, so the query-level guard is unreachable
rather than merely untriggered.
"""

from __future__ import annotations

import dataclasses

import pytest

from muster.application.rebuild import RebuildFailure, rebuild, transcript_prefix
from muster.core.analysis.logical_case import LogicalCase
from muster.core.case.constraints import Constraint, StructuralDeriv
from muster.core.case.labels import constraint_label
from muster.core.case.revision import canonical_constraints, canonical_declared
from muster.core.evidence.transcript import CaseConstructionRecord
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
)
from muster.core.results import Err, InvariantViolation, Ok
from muster.core.values.scalars import VEnum
from muster.core.values.sorts import BoolSort, EnumDomain, EnumSort, Sort
from muster.core.values.symbols import SymbolRef
from muster.domains.workforce.bundle import PREDICATE_DURATION
from muster.policy.program import (
    ProgramFailure,
    check_enum_tables,
    compile_program,
    reachable_members,
)
from tests.differential.scenarios import (
    COLOUR_UNDECLARED,
    COLOURS,
    ENUM_COLOUR,
    FLAG_A,
    PLACEHOLDER,
    SCHEMA,
    TINT,
    colour,
    money,
    pay,
    program,
)
from tests.support import ravi

DOMAINS = {TINT: EnumDomain(COLOURS)}
SORTS: dict[SymbolRef, Sort] = {TINT: EnumSort(ENUM_COLOUR), FLAG_A: BoolSort()}


def _amount(member: str) -> LitScaled:
    return LitScaled(money(len(member)))


def _composed_scrutinee() -> Ite[SymbolRef]:
    """``TINT`` on one branch and a member no domain admits on the other."""
    return Ite(Leaf(FLAG_A), Leaf(TINT), LitEnum(VEnum(ENUM_COLOUR, COLOUR_UNDECLARED)))


#  ---- A. exhaustiveness over a composed scrutinee -------------------------


def test_a_bare_variable_scrutinee_is_still_checked() -> None:
    """The case that always worked, so the strengthening did not lose it."""
    table = EnumTable(Leaf(TINT), (Arm("RED", _amount("RED")), Arm("GREEN", _amount("GREEN"))))
    outcome = check_enum_tables(table, DOMAINS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is ProgramFailure.ENUM_TABLE_NOT_EXHAUSTIVE
    assert outcome.error.detail == "BLUE"


def test_an_ite_scrutinee_missing_an_arm_is_refused_at_compile_time() -> None:
    """The defect: this compiled, and got stuck in the world that reached AMBER.

    The scrutinee is ``TINT`` or the literal ``AMBER``, so the table has four
    members to cover.  It covers three.
    """
    table = EnumTable(
        _composed_scrutinee(), tuple(Arm(member, _amount(member)) for member in COLOURS)
    )
    outcome = check_enum_tables(table, DOMAINS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is ProgramFailure.ENUM_TABLE_NOT_EXHAUSTIVE
    assert outcome.error.detail == COLOUR_UNDECLARED


def test_the_same_ite_scrutinee_with_every_arm_still_compiles() -> None:
    """Strengthened, not widened: the corpus's composed shape is still legal."""
    arms: tuple[Arm[SymbolRef], ...] = tuple(
        Arm(member, _amount(member)) for member in (*COLOURS, COLOUR_UNDECLARED)
    )
    assert isinstance(check_enum_tables(EnumTable(_composed_scrutinee(), arms), DOMAINS), Ok)


def test_a_table_whose_scrutinee_is_a_table_is_bounded_by_its_arms() -> None:
    """The other composed shape the fragment permits.

    The inner table yields ``GREEN`` or ``BLUE`` and never ``RED``, so covering
    those two is exhaustive -- demanding ``RED`` as well would refuse a program
    that is total.  Bounding by the arms rather than by the enum is what makes
    the difference between the two tables below visible.
    """
    inner = EnumTable(
        Leaf(TINT),
        (
            Arm("RED", colour("GREEN")),
            Arm("GREEN", colour("GREEN")),
            Arm("BLUE", colour("BLUE")),
        ),
    )
    enough = EnumTable(inner, (Arm("GREEN", _amount("GREEN")), Arm("BLUE", _amount("BLUE"))))
    assert isinstance(check_enum_tables(enough, DOMAINS), Ok)

    short = EnumTable(inner, (Arm("GREEN", _amount("GREEN")),))
    outcome = check_enum_tables(short, DOMAINS)
    assert isinstance(outcome, Err)
    assert outcome.error.detail == "BLUE"


def test_a_literal_scrutinee_needs_exactly_the_one_arm() -> None:
    outcome = check_enum_tables(
        EnumTable(colour("RED"), (Arm("GREEN", _amount("GREEN")),)), DOMAINS
    )
    assert isinstance(outcome, Err)
    assert outcome.error.detail == "RED"


def test_an_unbounded_scrutinee_is_left_alone_rather_than_refused() -> None:
    """A variable with no declared domain bounds nothing, and says so.

    Refusing here would reject a table that is perfectly total; answering with
    the empty tuple would accept one that is not.  ``None`` is a third answer
    and the caller has to treat it as one.
    """
    unknown = SymbolRef("undeclared", ("A",))
    assert reachable_members(Leaf(unknown), DOMAINS) is None
    assert reachable_members(Ite(Leaf(FLAG_A), Leaf(unknown), colour("RED")), DOMAINS) is None
    assert isinstance(
        check_enum_tables(EnumTable(Leaf(unknown), (Arm("RED", _amount("RED")),)), DOMAINS), Ok
    )


def test_reachable_members_keeps_a_stable_order_and_deduplicates() -> None:
    """The refusal detail is part of the answer, so its order cannot drift."""
    assert reachable_members(Ite(Leaf(FLAG_A), Leaf(TINT), colour("GREEN")), DOMAINS) == COLOURS
    assert reachable_members(colour("RED"), DOMAINS) == ("RED",)
    assert reachable_members(Ite(Leaf(FLAG_A), colour("BLUE"), colour("RED")), DOMAINS) == (
        "BLUE",
        "RED",
    )


def test_a_program_carrying_the_short_table_is_refused_by_the_compiler() -> None:
    """End to end: the strengthening reaches the path that admits a program."""
    table = EnumTable(
        _composed_scrutinee(), tuple(Arm(member, _amount(member)) for member in COLOURS)
    )
    outcome = compile_program(program(rules=(), otherwise=pay(table)), SCHEMA, SORTS, DOMAINS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is ProgramFailure.ENUM_TABLE_NOT_EXHAUSTIVE


def test_the_completed_program_compiles() -> None:
    """Otherwise the refusal above could be coming from anything else."""
    arms: tuple[Arm[SymbolRef], ...] = tuple(
        Arm(member, _amount(member)) for member in (*COLOURS, COLOUR_UNDECLARED)
    )
    outcome = compile_program(
        program(rules=(), otherwise=pay(EnumTable(_composed_scrutinee(), arms))),
        SCHEMA,
        SORTS,
        DOMAINS,
    )
    assert isinstance(outcome, Ok)


def test_a_guard_position_table_is_checked_too() -> None:
    """Tables live in guards as well as in field terms."""
    guard = EnumTable(
        _composed_scrutinee(), tuple(Arm(member, LitBool(True)) for member in COLOURS)
    )
    outcome = check_enum_tables(guard, DOMAINS)
    assert isinstance(outcome, Err)
    assert outcome.error.detail == COLOUR_UNDECLARED


#  ---- B. a repeated constraint label ---------------------------------------

#  Two distinct propositions of the same arity whose rendering is one string.
#  ``', '.join`` is not injective when an argument may itself contain ``", "``.
TWIN_LEFT = SymbolRef(PREDICATE_DURATION, ("RAVI, X", "SAT"))
TWIN_RIGHT = SymbolRef(PREDICATE_DURATION, ("RAVI", "X, SAT"))


def _same_label(label: str) -> tuple[Constraint, ...]:
    return canonical_constraints(
        Constraint(label, formula, StructuralDeriv(PLACEHOLDER))
        for formula in (
            Binary(BinaryOp.GE, Leaf(TINT), LitInt(0)),
            Binary(BinaryOp.LE, Leaf(TINT), LitInt(9)),
        )
    )


def test_two_distinct_propositions_can_render_alike() -> None:
    """The premise the whole hazard rests on, stated rather than assumed."""
    assert TWIN_LEFT != TWIN_RIGHT
    assert str(TWIN_LEFT) == str(TWIN_RIGHT)
    assert constraint_label("C-DOM", TWIN_LEFT) == constraint_label("C-DOM", TWIN_RIGHT)


def test_a_case_declaring_both_twins_is_refused_with_a_typed_value() -> None:
    """Case data reaching the collision gets a value, not an exception.

    Driven through ``rebuild``, which is the public path: a case file declaring
    both propositions produces one structural domain bound label twice, and the
    condition is reported rather than raised.
    """
    case = ravi.case_file()
    construction = dataclasses.replace(
        case.construction,
        declared_instances=canonical_declared(
            (*case.construction.declared_instances, TWIN_LEFT, TWIN_RIGHT)
        ),
    )
    assert isinstance(construction, CaseConstructionRecord)

    prefix = transcript_prefix(construction.tenant_id, construction.case_id, case.entries)
    inputs = dataclasses.replace(
        case.rebuild_inputs(ravi.bundle().digest(), prefix.digest()),
        construction_digest=construction.digest(),
    )
    outcome = rebuild(inputs, construction, case.entries, ravi.bundle(), case.authorization_context)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is RebuildFailure.DUPLICATE_CONSTRAINT_LABEL
    assert outcome.error.detail == constraint_label("C-DOM", TWIN_LEFT)


def test_the_healthy_case_still_has_unique_labels() -> None:
    """The check above would pass on a case that produced no constraints at all."""
    labels = [constraint.label for constraint in ravi.revision().constraints]
    assert labels
    assert len(set(labels)) == len(labels)


def test_a_revision_cannot_hold_two_constraints_under_one_label() -> None:
    with pytest.raises(InvariantViolation, match=r"duplicate constraints\.label"):
        dataclasses.replace(ravi.revision(), constraints=_same_label("SAME"))


def test_a_logical_case_cannot_hold_two_constraints_under_one_label() -> None:
    """The projection enforces the rule the revision does, not a weaker one.

    A projection that admitted what the revision refuses would let the rule be
    satisfied on one side of the boundary and violated on the other, which is
    exactly how the failure ended up at query construction.
    """
    with pytest.raises(InvariantViolation, match="constraint labels are unique"):
        LogicalCase(
            universe=(),
            known=(),
            constraints=_same_label("SAME"),
            decision_program_digest=PLACEHOLDER,
            action_schema_digest=PLACEHOLDER,
            predicate_schema_digest=PLACEHOLDER,
        )
