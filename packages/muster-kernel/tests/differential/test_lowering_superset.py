"""The property the enum-table fallback rests on, measured pointwise.

Every other test in this suite compares *verdicts*.  A verdict is a summary,
and the thing that has to be true about the lowering is finer than any summary:
**wherever the concrete evaluator has a value, the SMT formula has the same
one.**  From that, everything else follows -- an assignment the evaluator
accepts is one the solver accepts, so an unsatisfiable answer is sound, which
is the only direction that becomes ``Invariant``.

An enum table is lowered as a chain of ``ite`` whose last arm is also its
fallback, so where the scrutinee matches no arm the encoding has a value and
the evaluator does not.  That is a deliberate over-approximation: it can only
*add* worlds, and an added world is caught when the witness is revalidated.
Single-point regressions cannot pin that -- a refactor could keep every one of
them green and still lose a model -- so this substitutes every in-domain
assignment into the lowered formulas and compares against the evaluator term by
term.

The counters are asserted in both directions, so the property cannot pass by
never reaching the interesting case.
"""

from __future__ import annotations

from dataclasses import dataclass

import z3

from muster.core.expr.evaluate import evaluate_bool
from muster.core.expr.ir import Arm, EnumTable, Ite, Leaf, LitBool, LitEnum
from muster.core.results import Ok
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled
from muster.core.values.sorts import BoolDomain, BoolSort, EnumDomain, EnumSort
from muster.core.values.symbols import SymbolRef
from muster.hinge.encode import feasibility_query, sufficiency_query
from muster.solve.query import (
    EnumDeclaration,
    LabeledAssertion,
    QueryDecl,
    QueryKind,
    QueryVar,
    SolverQuery,
    WorldSide,
)
from muster.solve.z3.lowering import LoweredQuery, UnsupportedConstruct, lower
from tests.differential import semantics
from tests.differential.scenarios import PLACEHOLDER, SCENARIOS

ESCAPE_FLAG = SymbolRef("escape_flag", ("A",))
ESCAPE_TINT = SymbolRef("escape_tint", ("A",))

#  Substituting one assignment into one formula is cheap; doing it for every
#  assignment of every query is not, so the sweep takes the queries whose
#  assignment space is small and asserts below how many that was.
ASSIGNMENT_BUDGET = 256


@dataclass(slots=True)
class Tally:
    """How each (assignment, assertion) pair came out, in four buckets."""

    agreed: int = 0
    lost: int = 0
    stuck_true: int = 0
    stuck_false: int = 0
    pairs: int = 0
    queries: int = 0


def _encoded(lowered: LoweredQuery, var: QueryVar, value: Value) -> z3.ExprRef:
    """One production value as the SMT literal the lowering would give it."""
    match value:
        case VBool(flag):
            return z3.BoolVal(flag)
        case VInt(number):
            return z3.IntVal(number)
        case VScaled(_, _, minor):
            return z3.IntVal(minor)
        case VEnum(enum_id, member):
            members = lowered.enum_members(enum_id)
            assert members is not None, f"{var} names an enum the lowering did not table"
            assert member in members, f"{member} was never numbered"
            return z3.IntVal(members.index(member))


def _measure(query: SolverQuery, tally: Tally) -> None:
    """Compare the lowered formulas with the evaluator at every assignment."""
    lowered = lower(query)
    if isinstance(lowered, UnsupportedConstruct):
        return
    tally.queries += 1

    for model in semantics.query_assignments(query):
        substitution = [
            (variable.constant, _encoded(lowered, variable.var, model[variable.var]))
            for variable in lowered.variables
        ]
        for assertion, (label, formula) in zip(query.assertions, lowered.assertions, strict=True):
            assert label == assertion.label
            grounded = z3.simplify(z3.substitute(formula, *substitution))
            assert z3.is_true(grounded) or z3.is_false(grounded), (
                f"{label} did not ground to a literal: {grounded}"
            )
            symbolic = bool(z3.is_true(grounded))

            concrete = evaluate_bool(assertion.formula, model)
            tally.pairs += 1
            if isinstance(concrete, Ok):
                if concrete.value == symbolic:
                    tally.agreed += 1
                elif concrete.value:
                    #  The evaluator accepts and the encoding does not: a model
                    #  the solver can no longer find. This is the number that
                    #  must be zero.
                    tally.lost += 1
            elif symbolic:
                tally.stuck_true += 1
            else:
                tally.stuck_false += 1


#  ---- queries whose scrutinee escapes every arm ---------------------------
#
#  The generated corpus cannot contain these: a program whose table leaves a
#  reachable member uncovered is not total, and the oracle refuses to state a
#  truth for a case like that.  So the fallback is reached here instead, on
#  queries built directly -- which is also the only way to reach it, because
#  the program compiler's exhaustiveness check is what keeps it out of a real
#  bundle whenever the scrutinee is a bare variable.

PALETTE = "palette"
DECLARED_MEMBERS: tuple[str, ...] = ("RED", "GREEN", "BLUE")
ESCAPED_MEMBER = "AMBER"


def _escaping_query(fallback: bool) -> SolverQuery:
    """A table over a computed scrutinee that can reach a member with no arm."""
    flag = QueryDecl(WorldSide.SINGLE, ESCAPE_FLAG, BoolSort(), BoolDomain())
    tint = QueryDecl(WorldSide.SINGLE, ESCAPE_TINT, EnumSort(PALETTE), EnumDomain(DECLARED_MEMBERS))
    table = EnumTable(
        Ite(Leaf(flag.var()), Leaf(tint.var()), LitEnum(VEnum(PALETTE, ESCAPED_MEMBER))),
        (
            Arm("RED", LitBool(True)),
            Arm("GREEN", LitBool(False)),
            #  The last arm is also the chain's fallback, so its value is what
            #  the encoding gives an escaped scrutinee.
            Arm("BLUE", LitBool(fallback)),
        ),
    )
    return SolverQuery(
        QueryKind.FEASIBILITY,
        PLACEHOLDER,
        (EnumDeclaration(PALETTE, DECLARED_MEMBERS),),
        (flag, tint),
        (LabeledAssertion("C:t", table),),
    )


def _queries() -> list[SolverQuery]:
    found: list[SolverQuery] = [_escaping_query(True), _escaping_query(False)]
    for scenario in SCENARIOS:
        case = scenario.case
        for query in (
            feasibility_query(case),
            *(sufficiency_query(case, fixed) for fixed in semantics.subsets(scenario.unresolved())),
        ):
            space = 1
            for declaration in query.declarations:
                space *= len(semantics.domain_values(declaration.sort, declaration.domain))
            if space <= ASSIGNMENT_BUDGET:
                found.append(query)
    return found


TALLY = Tally()
for _query in _queries():
    _measure(_query, TALLY)


def test_the_encoding_never_loses_a_world_the_evaluator_accepts() -> None:
    """The soundness of every unsatisfiable answer, in one number.

    If this is not zero, some assignment satisfies a query as written and does
    not satisfy its translation -- so a query with no other model would be
    reported unsatisfiable, and on the invariance query that is reported as
    invariance.
    """
    assert TALLY.lost == 0, f"{TALLY.lost} of {TALLY.pairs} assignments were lost in translation"


def test_the_agreement_is_not_vacuous() -> None:
    """A sweep that never reached a satisfied assertion would prove nothing."""
    assert TALLY.queries > 100, TALLY.queries
    assert TALLY.pairs > 1_000, TALLY.pairs
    assert TALLY.agreed > 0


def test_the_fallback_is_reached_in_both_directions() -> None:
    """The over-approximation is real, and it is real both ways.

    Where the evaluator is stuck the encoding still has a value, and that value
    is sometimes true and sometimes false.  Both counters being non-zero is
    what makes the zero above a measurement rather than an accident of a corpus
    that never reaches a fallback.
    """
    assert TALLY.stuck_true > 0, "no assignment ever escaped an enum table into a true fallback"
    assert TALLY.stuck_false > 0, "no assignment ever escaped an enum table into a false fallback"
