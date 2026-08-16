"""The analysis state machine.

Every backend answer, every decoder failure and every budget exhaustion maps to
exactly one public outcome.  There is no path that falls through, and none that
turns a missing answer into a permissive one:

    feasibility unsatisfiable        -> Infeasible
    feasibility unknown              -> Indeterminate
    invariance unsatisfiable         -> Invariant(action, witness)
    invariance satisfiable           -> Divergent(reachable, two worlds)
    invariance unknown               -> Indeterminate

Reachable actions never inform the verdict.  They are an explanation, computed
by asking for a feasible world whose action is none of the ones already found,
which is why a decisively answered case can report them as not computed and
still be perfectly healthy.
"""

from __future__ import annotations

from muster.core.actions import ConsequentialAction
from muster.core.analysis.outcomes import (
    AnalysisOutcome,
    Divergent,
    ExactReachable,
    Indeterminate,
    IndeterminateReason,
    Invariant,
    KernelAnalysisRecord,
    NotComputed,
    NotComputedReason,
    ReachableActions,
    TruncatedReachable,
)
from muster.core.analysis.outcomes import (
    Infeasible as InfeasibleOutcome,
)
from muster.core.analysis.worlds import World
from muster.core.values.fingerprint import DeterminismClass
from muster.core.wire.digests import Digest
from muster.hinge.oracle import (
    Feasible,
    InvarianceFails,
    InvarianceHolds,
    NotFeasible,
    Oracle,
    OracleUnknown,
)
from muster.hinge.prepare import EngineLimits
from muster.hinge.project import ProjectedCase


def analyze(case: ProjectedCase, oracle: Oracle, limits: EngineLimits) -> KernelAnalysisRecord:
    """Answer the one question the kernel exists to answer.

    A function of its arguments: the oracle holds no state, so calling this
    twice with the same inputs produces the same record, octet for octet.
    """
    asked: list[Digest] = []
    outcome = _outcome(oracle, limits, asked)
    return KernelAnalysisRecord(
        logical_case_digest=case.logical.digest(),
        outcome=outcome,
        query_digests=tuple(asked),
        fingerprint=oracle.fingerprint,
        #  This backend reads no clock and takes no wall-clock budget, so every
        #  run of the same query returns the same verdict.  A backend with an
        #  operational time limit would mark a run that hit it NON_REPRODUCIBLE.
        determinism_class=DeterminismClass.REPRODUCIBLE,
    )


def _outcome(oracle: Oracle, limits: EngineLimits, asked: list[Digest]) -> AnalysisOutcome:
    feasibility = oracle.feasibility()
    asked.append(feasibility.query_digest)
    match feasibility:
        case NotFeasible(contributing, _):
            #  Contradictory constraints. Reported, not repaired: somebody is
            #  misreporting, or the admissibility model is wrong.
            return InfeasibleOutcome(contributing)
        case OracleUnknown(reason, _, _):
            return Indeterminate(reason)
        case Feasible(witness_world, witness_action, _):
            #  Feasibility established a witness, so invariance is a one-world
            #  question against it rather than a self-composition.
            return _invariance(oracle, limits, asked, witness_world, witness_action)


def _invariance(
    oracle: Oracle,
    limits: EngineLimits,
    asked: list[Digest],
    witness_world: World,
    witness_action: ConsequentialAction,
) -> AnalysisOutcome:
    invariance = oracle.invariance(witness_action)
    asked.append(invariance.query_digest)
    match invariance:
        case InvarianceHolds(digest):
            return Invariant(witness_action, witness_world, digest)
        case OracleUnknown(reason, _, _):
            return Indeterminate(reason)
        case InvarianceFails(other_world, other_action, _):
            reachable = _reachable(oracle, (witness_action, other_action), limits, asked)
            return Divergent(reachable, witness_world, other_world)


def _reachable(
    oracle: Oracle,
    found: tuple[ConsequentialAction, ...],
    limits: EngineLimits,
    asked: list[Digest],
) -> ReachableActions:
    """Bounded enumeration with a ``cap + 1`` probe.

    The extra probe is what distinguishes "exactly cap actions" from "at least
    cap actions", so a truncated explanation is never presented as a complete one.
    """
    actions = list(found)
    while len(actions) <= limits.reachable_action_cap:
        probe = oracle.reachable_probe(tuple(actions))
        asked.append(probe.query_digest)
        match probe:
            case NotFeasible():
                return ExactReachable(tuple(actions))
            case OracleUnknown(reason, _, _):
                return NotComputed(_not_computed(reason))
            case Feasible(_, action, _):
                actions.append(action)
    return TruncatedReachable(
        tuple(actions[: limits.reachable_action_cap]), limits.reachable_action_cap
    )


def _not_computed(reason: IndeterminateReason) -> NotComputedReason:
    """An explanation that could not be produced says which kind of limit stopped it."""
    match reason:
        case IndeterminateReason.BUDGET_EXHAUSTED:
            return NotComputedReason.BUDGET_EXHAUSTED
        case _:
            return NotComputedReason.BACKEND_FAILURE
