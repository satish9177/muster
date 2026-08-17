"""The attack on the one correctness risk milestone A left open.

The bounded reference backend does not enumerate a wide integer domain when the
variable occurs only in comparisons against literals.  It enumerates one
representative per equivalence class those literals induce, plus the domain
endpoints, and argues that every atom mentioning the variable is constant
within a class.  If that argument is wrong anywhere, a satisfying assignment is
missed and the query is reported unsatisfiable -- which, for the invariance
query, is reported as **invariance**.  That is the dangerous direction and it
is what these tests exist to find.

Every case below is decided three ways: by enumerating the whole domain, by the
bounded backend, and by the solver.  The domains are wide enough that the
abstraction is genuinely exercised (0 to 1440 minutes, the same shape as the
workforce case) and small enough that brute force is still the judge.

The sweep is the sharp instrument.  Rather than picking bounds near a threshold
by hand, it walks the bound across the transition point one minute at a time
and re-decides the whole case at each step, so an off-by-one in the class
representatives cannot survive in the gap between two chosen examples.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from muster.core.actions import ActionField, ConsequentialAction
from muster.core.expr.ir import (
    Binary,
    BinaryOp,
    Ite,
    Leaf,
    LitInt,
    LitScaled,
    MulConst,
    NAry,
    NAryOp,
    Scale,
)
from muster.core.expr.terms import Term
from muster.hinge.encode import feasibility_query, invariance_query, sufficiency_query
from muster.policy.program import DecisionProgram, ProgramRule
from muster.solve.verdict import Sat, Unknown, UnknownReason
from tests.differential import semantics
from tests.differential.backends import (
    Outcome,
    assert_matches_truth,
    assert_no_inversion,
    bounded,
    compare,
    smt,
)
from tests.differential.scenarios import (
    DURATION,
    FLAG_A,
    HUGE,
    MONEY,
    PURSE,
    SMALL,
    STEPS,
    WIDE_SCHEMA,
    WINDOW,
    Scenario,
    build,
    hold,
    money,
    pay,
    program,
)

QUALIFYING = 240
DOUBLE = 480


def _pay_above(operator: BinaryOp) -> DecisionProgram:
    return program(
        rules=(
            ProgramRule(
                guard=Binary(operator, Leaf(DURATION), LitInt(QUALIFYING)),
                action=pay(LitScaled(money(100_000))),
            ),
        ),
        otherwise=pay(LitScaled(money(0))),
    )


def _threshold_case(
    name: str, constraints: tuple[tuple[str, Term], ...], operator: BinaryOp = BinaryOp.GE
) -> Scenario:
    return build(
        name=name,
        universe=(DURATION,),
        known={},
        constraints=constraints,
        decision=_pay_above(operator),
        schema=WIDE_SCHEMA,
    )


def _staircase(constraints: tuple[tuple[str, Term], ...]) -> Scenario:
    """Two thresholds, so the classes below, between and above all matter."""
    decision = program(
        rules=(
            ProgramRule(
                guard=Binary(BinaryOp.GE, Leaf(DURATION), LitInt(DOUBLE)),
                action=pay(LitScaled(money(200_000))),
            ),
            ProgramRule(
                guard=Binary(BinaryOp.GE, Leaf(DURATION), LitInt(QUALIFYING)),
                action=pay(LitScaled(money(100_000))),
            ),
        ),
        otherwise=pay(LitScaled(money(0))),
    )
    return build(
        name="staircase",
        universe=(DURATION,),
        known={},
        constraints=constraints,
        decision=decision,
        schema=WIDE_SCHEMA,
    )


def _bound(label: str, operator: BinaryOp, value: int) -> tuple[str, Term]:
    return label, Binary(operator, Leaf(DURATION), LitInt(value))


@dataclass(frozen=True, slots=True)
class Attack:
    name: str
    scenario: Scenario


def _attacks() -> tuple[Attack, ...]:
    correlated = program(
        rules=(
            ProgramRule(
                guard=Binary(
                    BinaryOp.GE,
                    Binary(
                        BinaryOp.SUB, Leaf(WINDOW), NAry(NAryOp.ADD, (Leaf(STEPS), Leaf(STEPS)))
                    ),
                    LitInt(30),
                ),
                action=pay(LitScaled(money(50_000))),
            ),
        ),
        otherwise=hold("REVIEW"),
    )
    conjunctive = program(
        rules=(
            ProgramRule(
                guard=NAry(
                    NAryOp.AND,
                    (
                        Leaf(FLAG_A),
                        Binary(BinaryOp.GE, Leaf(WINDOW), LitInt(20)),
                        Binary(BinaryOp.LE, Leaf(WINDOW), LitInt(40)),
                    ),
                ),
                action=pay(LitScaled(money(70_000))),
            ),
        ),
        otherwise=pay(LitScaled(money(0))),
    )
    #  Every value of the variable is its own action, so the transition points
    #  are dense rather than at a declared threshold.
    scaled = program(
        rules=(),
        otherwise=pay(Scale(Leaf(SMALL), 500, MONEY)),
    )
    #  A guard on an arithmetic combination: the variable no longer occurs only
    #  in comparisons against literals, which is the case the abstraction is
    #  explicitly not allowed to apply to.
    arithmetic = program(
        rules=(
            ProgramRule(
                guard=Binary(
                    BinaryOp.GE,
                    NAry(NAryOp.ADD, (Leaf(WINDOW), Leaf(STEPS))),
                    LitInt(30),
                ),
                action=pay(LitScaled(money(40_000))),
            ),
        ),
        otherwise=pay(
            Ite(
                Binary(BinaryOp.EQ, Leaf(STEPS), LitInt(0)),
                LitScaled(money(1)),
                LitScaled(money(2)),
            )
        ),
    )
    return (
        Attack("open", _threshold_case("open", ())),
        Attack("on-threshold", _threshold_case("on-threshold", (_bound("K1", BinaryOp.GE, 240),))),
        Attack("below-threshold", _threshold_case("below", (_bound("K1", BinaryOp.GE, 239),))),
        Attack("above-threshold", _threshold_case("above", (_bound("K1", BinaryOp.GE, 241),))),
        Attack("capped-below", _threshold_case("capped", (_bound("K1", BinaryOp.LE, 239),))),
        Attack(
            "interval-straddling",
            _threshold_case(
                "straddle", (_bound("K1", BinaryOp.GE, 239), _bound("K2", BinaryOp.LE, 240))
            ),
        ),
        Attack(
            "interval-inside-one-class",
            _threshold_case(
                "inside", (_bound("K1", BinaryOp.GE, 300), _bound("K2", BinaryOp.LE, 400))
            ),
        ),
        Attack(
            "threshold-outside-the-interval",
            _threshold_case(
                "outside", (_bound("K1", BinaryOp.GE, 600), _bound("K2", BinaryOp.LE, 900))
            ),
        ),
        Attack(
            "strict-on-threshold",
            _threshold_case("strict", (_bound("K1", BinaryOp.EQ, 240),), operator=BinaryOp.GT),
        ),
        Attack("closed-on-threshold", _threshold_case("closed", (_bound("K1", BinaryOp.EQ, 240),))),
        Attack("staircase-open", _staircase(())),
        Attack(
            "staircase-between",
            _staircase((_bound("K1", BinaryOp.GE, 240), _bound("K2", BinaryOp.LE, 479))),
        ),
        Attack(
            "staircase-straddling",
            _staircase((_bound("K1", BinaryOp.GE, 239), _bound("K2", BinaryOp.LE, 480))),
        ),
        Attack(
            "correlated",
            build(
                name="correlated",
                universe=(WINDOW, STEPS),
                known={},
                constraints=(),
                decision=correlated,
                schema=WIDE_SCHEMA,
            ),
        ),
        Attack(
            "conjunctive-window",
            build(
                name="conjunctive",
                universe=(WINDOW, FLAG_A),
                known={},
                constraints=(),
                decision=conjunctive,
                schema=WIDE_SCHEMA,
            ),
        ),
        Attack(
            "dense-amount",
            build(
                name="dense",
                universe=(SMALL,),
                known={},
                constraints=(),
                decision=scaled,
                schema=WIDE_SCHEMA,
            ),
        ),
        Attack(
            "arithmetic-guard",
            build(
                name="arithmetic",
                universe=(WINDOW, STEPS),
                known={},
                constraints=(),
                decision=arithmetic,
                schema=WIDE_SCHEMA,
            ),
        ),
        #  The variable occurs inside arithmetic over a wide domain, so the
        #  bounded backend must enumerate it whole. One world fits its budget;
        #  two worlds do not, which is a capability difference rather than a
        #  disagreement, and the suite is required to contain one.
        #  A scaled quantity wide enough that the threshold abstraction has to
        #  reduce it. Every other wide domain in this suite is an integer, so
        #  without this the minor-unit branch of the representative
        #  construction runs only on domains small enough to enumerate whole.
        Attack(
            "scaled-threshold",
            build(
                name="scaled-threshold",
                universe=(PURSE,),
                known={},
                constraints=(
                    ("K1", Binary(BinaryOp.GE, Leaf(PURSE), LitScaled(money(2_499)))),
                    ("K2", Binary(BinaryOp.LE, Leaf(PURSE), LitScaled(money(2_501)))),
                ),
                decision=program(
                    rules=(
                        ProgramRule(
                            guard=Binary(BinaryOp.GE, Leaf(PURSE), LitScaled(money(2_500))),
                            action=pay(LitScaled(money(80_000))),
                        ),
                    ),
                    otherwise=pay(LitScaled(money(0))),
                ),
                schema=WIDE_SCHEMA,
            ),
        ),
        Attack(
            "wide-arithmetic",
            build(
                name="wide-arithmetic",
                universe=(DURATION, STEPS),
                known={},
                constraints=(),
                decision=program(
                    rules=(
                        ProgramRule(
                            guard=Binary(
                                BinaryOp.GE,
                                Binary(BinaryOp.SUB, Leaf(DURATION), MulConst(60, Leaf(STEPS))),
                                LitInt(QUALIFYING),
                            ),
                            action=pay(LitScaled(money(90_000))),
                        ),
                    ),
                    otherwise=pay(LitScaled(money(0))),
                ),
                schema=WIDE_SCHEMA,
            ),
        ),
    )


ATTACKS = _attacks()
IDS = [attack.name for attack in ATTACKS]


def _action(scenario: Scenario, signature: semantics.ActionSignature) -> ConsequentialAction:
    kind, fields = signature
    return ConsequentialAction(
        scenario.case.action_schema.digest(),
        kind,
        tuple(ActionField(name, value) for name, value in fields),
    )


@pytest.mark.parametrize("attack", ATTACKS, ids=IDS)
def test_feasibility_matches_the_enumerated_domain(attack: Attack) -> None:
    case = attack.scenario.case
    comparison = compare(feasibility_query(case), f"{attack.name}: feasibility")
    assert_no_inversion(comparison)
    assert_matches_truth(comparison, semantics.feasible(case))


@pytest.mark.parametrize("attack", ATTACKS, ids=IDS)
def test_invariance_against_every_reachable_witness(attack: Attack) -> None:
    """A missed model would show up here as unsatisfiable where enumeration
    finds a second action -- the false-invariance failure mode itself."""
    case = attack.scenario.case
    reachable = semantics.reachable_signatures(case)
    for signature in sorted(reachable, key=str):
        witness = _action(attack.scenario, signature)
        comparison = compare(
            invariance_query(case, witness), f"{attack.name}: invariance/{witness.render()}"
        )
        assert_no_inversion(comparison)
        assert_matches_truth(comparison, reachable != {signature})


@pytest.mark.parametrize("attack", ATTACKS, ids=IDS)
def test_sufficiency_over_every_subset(attack: Attack) -> None:
    case = attack.scenario.case
    for fixed in semantics.subsets(attack.scenario.unresolved()):
        comparison = compare(
            sufficiency_query(case, fixed),
            f"{attack.name}: sufficiency/{sorted(str(ref) for ref in fixed)}",
        )
        assert_no_inversion(comparison)
        assert_matches_truth(comparison, not semantics.sufficient(case, fixed))


#  ---- the sweep ----------------------------------------------------------

SWEEP = tuple(range(236, 245)) + tuple(range(476, 485)) + (0, 1, 1439, 1440)


@pytest.mark.parametrize("bound", SWEEP)
def test_a_lower_bound_swept_across_the_thresholds(bound: int) -> None:
    """Move the evidence one minute at a time and re-decide the whole case.

    A representative set that is complete at 239 and 241 but not at 240 cannot
    hide between two hand-picked examples.
    """
    scenario = _staircase((_bound("K1", BinaryOp.GE, bound),))
    case = scenario.case
    reachable = semantics.reachable_signatures(case)

    feasibility = compare(feasibility_query(case), f"sweep {bound}: feasibility")
    assert_no_inversion(feasibility)
    assert_matches_truth(feasibility, bool(reachable))

    for signature in sorted(reachable, key=str):
        witness = _action(scenario, signature)
        comparison = compare(
            invariance_query(case, witness), f"sweep {bound}: invariance/{witness.render()}"
        )
        assert_no_inversion(comparison)
        assert_matches_truth(comparison, reachable != {signature})

    for fixed in semantics.subsets(scenario.unresolved()):
        comparison = compare(sufficiency_query(case, fixed), f"sweep {bound}: sufficiency")
        assert_no_inversion(comparison)
        assert_matches_truth(comparison, not semantics.sufficient(case, fixed))


def test_the_attacks_reach_both_conclusive_answers_and_a_capability_gap() -> None:
    """The corpus must contain what it claims to contain.

    An attack suite in which every query is satisfiable would find nothing, and
    one in which the bounded backend never runs out of budget would not show
    where the two backends differ in capability rather than in meaning.
    """
    conclusive = set()
    inconclusive = 0
    for attack in ATTACKS:
        case = attack.scenario.case
        for fixed in semantics.subsets(attack.scenario.unresolved()):
            comparison = compare(sufficiency_query(case, fixed), attack.name)
            reference, solver = comparison.outcomes()
            if reference is Outcome.INCONCLUSIVE:
                inconclusive += 1
                assert solver is not Outcome.INCONCLUSIVE, attack.name
            conclusive.add(comparison.conclusive())
    assert Outcome.SATISFIABLE in conclusive
    assert Outcome.UNSATISFIABLE in conclusive
    assert inconclusive > 0, "no attack exercised the bounded backend's budget"


def test_a_single_domain_wider_than_the_budget_is_refused_not_sampled() -> None:
    """The bounded backend's other budget path, and the one that matters most.

    A variable the threshold abstraction cannot apply to must be enumerated
    whole, and a domain wider than the budget therefore cannot be enumerated at
    all.  Refusing is the only sound answer -- sampling it would miss models --
    and the solver, which does not enumerate, decides the same query.  This is
    a capability difference, and it is recorded as one: no truth is claimed
    from either side.
    """
    scenario = build(
        name="huge",
        universe=(HUGE,),
        known={},
        #  Arithmetic around the variable, so the abstraction is not permitted
        #  to apply and the whole domain would have to be enumerated.
        constraints=(
            ("K1", Binary(BinaryOp.GE, NAry(NAryOp.ADD, (Leaf(HUGE), LitInt(0))), LitInt(1_000))),
        ),
        decision=program(rules=(), otherwise=pay(LitScaled(money(0)))),
        schema=WIDE_SCHEMA,
    )
    query = feasibility_query(scenario.case)
    reference = bounded().check(query)
    assert isinstance(reference, Unknown)
    assert reference.reason is UnknownReason.BUDGET_EXHAUSTED
    assert isinstance(smt().check(query), Sat)
