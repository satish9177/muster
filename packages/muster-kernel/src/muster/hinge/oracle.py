"""The three primitives, and the validation every model passes before use.

Feasibility is asked first and returns a witness.  Invariance is then a
one-world question against that witness -- cheaper than self-composition, and it
returns the action directly.  Self-composition is retained for arbitrary fixed
sets, where it is the correct general test of functional dependence.

Every model is decoded into a world that is **total** over the declared
universe, **in domain**, **extends** what is established, and **satisfies every
constraint**, checked here by concrete evaluation.  A model that fails any of
those is indeterminate, never a silently partial world: a backend answering
about a different question than the one asked is exactly the failure this guards.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.actions import ConsequentialAction, consequential_of
from muster.core.analysis.outcomes import IndeterminateReason
from muster.core.analysis.worlds import World, world_of
from muster.core.expr.evaluate import evaluate_bool
from muster.core.results import Err
from muster.core.values.fingerprint import SolverFingerprint
from muster.core.values.scalars import Value, sort_of, value_in_domain
from muster.core.values.symbols import SymbolRef
from muster.core.wire.digests import Digest
from muster.hinge.encode import (
    blocking_query,
    feasibility_query,
    invariance_query,
    sufficiency_query,
)
from muster.hinge.project import ProjectedCase
from muster.policy.program import evaluate_program
from muster.solve.backend import SolverBackend
from muster.solve.query import QueryVar, SolverQuery, WorldSide
from muster.solve.verdict import (
    Sat,
    SolverModel,
    Unknown,
    UnknownReason,
    Unsat,
    UnsupportedFragment,
)


@dataclass(frozen=True, slots=True)
class Feasible:
    world: World
    action: ConsequentialAction
    query_digest: Digest


@dataclass(frozen=True, slots=True)
class NotFeasible:
    contributing: tuple[str, ...]
    query_digest: Digest


@dataclass(frozen=True, slots=True)
class OracleUnknown:
    reason: IndeterminateReason
    detail: str
    query_digest: Digest


type FeasibilityVerdict = Feasible | NotFeasible | OracleUnknown


@dataclass(frozen=True, slots=True)
class InvarianceHolds:
    query_digest: Digest


@dataclass(frozen=True, slots=True)
class InvarianceFails:
    world: World
    action: ConsequentialAction
    query_digest: Digest


type InvarianceVerdict = InvarianceHolds | InvarianceFails | OracleUnknown


@dataclass(frozen=True, slots=True)
class Sufficient:
    query_digest: Digest


@dataclass(frozen=True, slots=True)
class Insufficient:
    left: World
    right: World
    query_digest: Digest


type SufficiencyVerdict = Sufficient | Insufficient | OracleUnknown


class Oracle:
    """Answers one question at a time about one projected case.

    Stateless: it accumulates nothing, so asking the same question twice
    returns the same answer and ``analyze`` is a function of its
    arguments.  Every verdict carries the digest of the query that
    produced it, so a caller that needs a provenance trail collects its
    own rather than sharing a mutable one.
    """

    def __init__(self, backend: SolverBackend, case: ProjectedCase) -> None:
        self._backend = backend
        self._case = case

    @property
    def fingerprint(self) -> SolverFingerprint:
        """Exactly what answered, so a record can say so."""
        return self._backend.fingerprint()

    def feasibility(self) -> FeasibilityVerdict:
        return self._one_world(feasibility_query(self._case))

    def reachable_probe(self, excluded: tuple[ConsequentialAction, ...]) -> FeasibilityVerdict:
        """A feasible world whose action is none of ``excluded``."""
        return self._one_world(blocking_query(self._case, excluded))

    def invariance(self, witness: ConsequentialAction) -> InvarianceVerdict:
        query = invariance_query(self._case, witness)
        verdict = self._one_world(query)
        match verdict:
            case Feasible(world, action, digest):
                return InvarianceFails(world, action, digest)
            case NotFeasible(_, digest):
                return InvarianceHolds(digest)
            case OracleUnknown():
                return verdict

    def sufficiency(self, fixed: frozenset[SymbolRef]) -> SufficiencyVerdict:
        query = sufficiency_query(self._case, fixed)
        digest = query.digest()
        verdict = self._backend.check(query)
        match verdict:
            case Unsat():
                return Sufficient(digest)
            case Unknown(reason, detail):
                return OracleUnknown(_map_unknown(reason), detail, digest)
            case UnsupportedFragment(detail):
                return OracleUnknown(IndeterminateReason.UNSUPPORTED_FRAGMENT, detail, digest)
            case Sat(model):
                left = self._decode(model, WorldSide.LEFT)
                right = self._decode(model, WorldSide.RIGHT)
                if left is None or right is None:
                    return OracleUnknown(
                        IndeterminateReason.MODEL_NOT_TOTAL, "self-composed model", digest
                    )
                return Insufficient(left, right, digest)

    def _one_world(self, query: SolverQuery) -> FeasibilityVerdict:
        digest = query.digest()
        verdict = self._backend.check(query)
        match verdict:
            case Unsat(contributing):
                return NotFeasible(contributing, digest)
            case Unknown(reason, detail):
                return OracleUnknown(_map_unknown(reason), detail, digest)
            case UnsupportedFragment(detail):
                return OracleUnknown(IndeterminateReason.UNSUPPORTED_FRAGMENT, detail, digest)
            case Sat(model):
                world = self._decode(model, WorldSide.SINGLE)
                if world is None:
                    return OracleUnknown(
                        IndeterminateReason.MODEL_NOT_TOTAL, "one-world model", digest
                    )
                action = self.action_of(world)
                if action is None:
                    return OracleUnknown(
                        IndeterminateReason.BACKEND_FAILURE, "program did not evaluate", digest
                    )
                return Feasible(world, action, digest)

    def action_of(self, world: World) -> ConsequentialAction | None:
        """``A(w)`` -- total for a validated world, by program compilation."""
        produced = evaluate_program(
            self._case.program, self._case.action_schema, world.assignment()
        )
        if isinstance(produced, Err):
            return None
        return consequential_of(self._case.action_schema, produced.value)

    def _decode(self, model: SolverModel, side: WorldSide) -> World | None:
        """Turn one side of a model into a validated world, or nothing."""
        case = self._case
        known = case.logical.assignment()
        assignment: dict[SymbolRef, Value] = {}

        for declaration in case.declarations:
            ref = declaration.ref
            wanted = WorldSide.SINGLE if ref in known else side
            value = model.get(QueryVar(wanted, ref))
            if value is None:
                return None
            if sort_of(value) != declaration.sort or not value_in_domain(value, declaration.domain):
                return None
            established = known.get(ref)
            if established is not None and established != value:
                return None
            assignment[ref] = value

        for constraint in case.logical.constraints:
            holds = evaluate_bool(constraint.formula, assignment)
            if isinstance(holds, Err) or not holds.value:
                return None

        return world_of(assignment)


def _map_unknown(reason: UnknownReason) -> IndeterminateReason:
    """Every backend answer maps to exactly one public reason."""
    match reason:
        case UnknownReason.BUDGET_EXHAUSTED:
            return IndeterminateReason.BUDGET_EXHAUSTED
        case UnknownReason.BACKEND_FAILURE:
            return IndeterminateReason.BACKEND_FAILURE
