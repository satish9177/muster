"""An SMT backend behind the solver port.

Four answers leave this module.  A solver failure, a resource limit, a
construct outside the fragment and a model that will not survive revalidation
are four different typed results, and none of them is ``Unsat``: the one
direction that must never be reached by accident is the one that becomes
invariance.  A solver exception and an exhausted stack are caught and become
the indeterminate answer; an ``InvariantViolation`` deliberately is not, because
that one reports a defect in the caller rather than a limit of the solver.

**The resource bound is work, not wall-clock.**  Z3 offers both; only one of
them keeps a record honest.  A wall-clock timeout makes the same query on the
same input answer differently on a loaded machine, so a record calling itself
reproducible would be lying.  ``rlimit`` counts internal work units, so
exhausting it is a property of the query rather than of the afternoon.

**An unsatisfiable answer reports every source constraint in the query.**  A
minimised core would be smaller and would also be unstable across versions and
across backends, so two conforming backends would produce two different
``Infeasible`` records for one case.  The contributing set is honestly
non-minimal instead.
"""

from __future__ import annotations

import z3

from muster.core.values.fingerprint import SolverFingerprint
from muster.solve.query import LabeledAssertion, SolverQuery
from muster.solve.verdict import (
    FragmentCapabilities,
    Sat,
    SolverVerdict,
    Unknown,
    UnknownReason,
    Unsat,
    UnsupportedFragment,
)
from muster.solve.z3.lowering import LoweredQuery, UnsupportedConstruct, lower
from muster.solve.z3.witness import RejectedWitness, witness_of

BACKEND_NAME = "z3"

#  The adapter's own contract version: which lowering and which witness rules
#  produced an answer.  Deliberately not the solver library's version -- what a
#  policy means may not depend on which build of a solver read it.
BACKEND_VERSION = "1"
BACKEND_LOGIC = "QF_LIA"

#  Assertions a certificate may repeat.  The encoder labels source-derived
#  constraints with this prefix; everything else is an internal encoding
#  assertion and stays inside the query.
SOURCE_LABEL_PREFIX = "C:"

#  This backend does not enumerate, so no assignment budget describes it.  The
#  field is the enumerating oracle's, and one is the smallest value that does
#  not read as "this backend has no budget at all".
NOT_AN_ENUMERATING_BACKEND = 1


class Z3Backend:
    """Decides the frozen quantifier-free linear integer fragment."""

    def __init__(self, *, resource_limit: int = 0, seed: int = 0) -> None:
        if resource_limit < 0:
            raise ValueError("the resource limit must not be negative")
        self._resource_limit = resource_limit
        self._seed = seed

    def capabilities(self) -> FragmentCapabilities:
        return FragmentCapabilities(
            backend=BACKEND_NAME,
            version=BACKEND_VERSION,
            requires_finite_domains=False,
            max_enumerated_assignments=NOT_AN_ENUMERATING_BACKEND,
        )

    def fingerprint(self) -> SolverFingerprint:
        return SolverFingerprint(
            backend=BACKEND_NAME,
            version=BACKEND_VERSION,
            seed=self._seed,
            logic=BACKEND_LOGIC,
            budget=self._resource_limit,
        )

    def check(self, query: SolverQuery) -> SolverVerdict:
        try:
            lowered = lower(query)
            if isinstance(lowered, UnsupportedConstruct):
                return UnsupportedFragment(lowered.detail)
            return self._decide(lowered, query)
        except (z3.Z3Exception, RecursionError):
            #  No solver failure and no exhausted stack crosses the port, and
            #  no message decides a semantics: the answer is indeterminate
            #  whatever it said.  Translation is inside the guard too, because
            #  a term deep enough to exhaust the stack does so while it is
            #  being read, before any solver has seen it.
            return Unknown(UnknownReason.BACKEND_FAILURE, "the solver did not complete")

    def _decide(self, lowered: LoweredQuery, query: SolverQuery) -> SolverVerdict:
        solver = z3.Solver()
        solver.set("random_seed", self._seed)
        if self._resource_limit:
            solver.set("rlimit", self._resource_limit)
        solver.add(*lowered.formulas())

        outcome = solver.check()
        if outcome == z3.unsat:
            return Unsat(source_labels(query.assertions))
        if outcome != z3.sat:
            return self._inconclusive()

        witness = witness_of(lowered, solver.model(), query)
        if isinstance(witness, RejectedWitness):
            #  The solver said satisfiable and the model does not survive the
            #  production semantics.  That is a defect report, not a world.
            return Unknown(UnknownReason.BACKEND_FAILURE, witness.detail)
        return Sat(witness)

    def _inconclusive(self) -> Unknown:
        if self._resource_limit:
            return Unknown(UnknownReason.BUDGET_EXHAUSTED, "the resource limit was reached")
        return Unknown(UnknownReason.BACKEND_FAILURE, "the solver did not decide the query")


def source_labels(assertions: tuple[LabeledAssertion, ...]) -> tuple[str, ...]:
    """Every source constraint the query carries, in label order."""
    return tuple(
        sorted(
            assertion.label
            for assertion in assertions
            if assertion.label.startswith(SOURCE_LABEL_PREFIX)
        )
    )
