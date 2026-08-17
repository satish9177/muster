"""The two production backends, and the rule for comparing their answers.

The classification here is the whole safety argument of this milestone.  Two
conclusive answers that differ are a defect, full stop -- there is no tie for
production to break, and no backend is preferred.  An answer that is
inconclusive on one side and conclusive on the other is a *capability*
difference and is recorded as one; it never licenses copying the conclusive
answer across, because the direction that would matter is the one that becomes
invariance.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.solve.query import SolverQuery
from muster.solve.reference.bounded import BoundedEnumerationBackend
from muster.solve.verdict import Sat, SolverVerdict, Unknown, Unsat, UnsupportedFragment
from muster.solve.z3.backend import Z3Backend

#  Large enough that a deliberately tiny case is never refused for budget, and
#  small enough that a generator mistake surfaces as a budget exhaustion rather
#  than as a hung suite.
ENUMERATION_BUDGET = 200_000


def bounded() -> BoundedEnumerationBackend:
    return BoundedEnumerationBackend(ENUMERATION_BUDGET)


def smt() -> Z3Backend:
    return Z3Backend()


class Outcome(Enum):
    SATISFIABLE = "SATISFIABLE"
    UNSATISFIABLE = "UNSATISFIABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


def outcome_of(verdict: SolverVerdict) -> Outcome:
    match verdict:
        case Sat():
            return Outcome.SATISFIABLE
        case Unsat():
            return Outcome.UNSATISFIABLE
        case Unknown() | UnsupportedFragment():
            return Outcome.INCONCLUSIVE


@dataclass(frozen=True, slots=True)
class Comparison:
    where: str
    reference: SolverVerdict
    solver: SolverVerdict

    def outcomes(self) -> tuple[Outcome, Outcome]:
        return outcome_of(self.reference), outcome_of(self.solver)

    def conclusive(self) -> Outcome | None:
        """The answer both backends gave, where both gave one."""
        first, second = self.outcomes()
        return first if first is second and first is not Outcome.INCONCLUSIVE else None


def compare(query: SolverQuery, where: str) -> Comparison:
    return Comparison(where, bounded().check(query), smt().check(query))


def assert_no_inversion(comparison: Comparison) -> None:
    """Two conclusive answers must be the same answer.

    This is the rule that must never be relaxed: a satisfiable/unsatisfiable
    split is a correctness defect in one of the two, and reporting it as a
    disagreement is the only honest thing to do with it.
    """
    reference, solver = comparison.outcomes()
    if Outcome.INCONCLUSIVE in (reference, solver):
        return
    assert reference is solver, (
        f"{comparison.where}: the reference backend said {reference.value} "
        f"and the solver said {solver.value}"
    )


def assert_matches_truth(comparison: Comparison, truth: bool) -> None:
    """Every conclusive answer must be the enumerated truth.

    ``truth`` comes from :mod:`tests.differential.semantics`, which shares no
    evaluation, no query construction and no search with either backend.
    """
    expected = Outcome.SATISFIABLE if truth else Outcome.UNSATISFIABLE
    for name, verdict in (("reference", comparison.reference), ("solver", comparison.solver)):
        outcome = outcome_of(verdict)
        if outcome is Outcome.INCONCLUSIVE:
            continue
        assert outcome is expected, (
            f"{comparison.where}: the {name} backend said {outcome.value} "
            f"where enumeration says {expected.value}"
        )
