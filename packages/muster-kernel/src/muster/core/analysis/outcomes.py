"""The kernel's answer, as a closed sum type.

Only ``Invariant`` carries an action, and it carries a feasibility witness with
it.  That pairing is the correction that matters: if the constraints are
contradictory the world set is empty, the invariance query is vacuously
unsatisfiable, and a design that reads UNSAT as invariance reports a decision
where no admissible world exists.  Feasibility is established first, and
invariance is asked against the witness it produced.

``Invariant`` means *the action is the same in every admissible world*.  It does
not mean *execute this*.  Naming it ``Authorized`` would concede the one rule
the architecture is built on.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.actions import ConsequentialAction
from muster.core.analysis.worlds import World
from muster.core.values.fingerprint import DeterminismClass, SolverFingerprint
from muster.core.wire.codec import canonical_set
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NInt, Node, NRec, NTagged
from muster.core.wire.shape import atoms, digests

TAG_TRUNCATED_REACHABLE = "TruncatedReachable/v1"
TAG_INVARIANT_OUTCOME = "InvariantOutcome/v1"
TAG_DIVERGENT_OUTCOME = "DivergentOutcome/v1"
TAG_INFEASIBLE_OUTCOME = "InfeasibleOutcome/v1"
TAG_INDETERMINATE_OUTCOME = "IndeterminateOutcome/v1"
TAG_KERNEL_ANALYSIS_RECORD = "KernelAnalysisRecord/v1"


class NotComputedReason(Enum):
    """Why an explanatory finding is absent. Never inferred from silence."""

    UNBOUNDED_DOMAIN = "UNBOUNDED_DOMAIN"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    BACKEND_FAILURE = "BACKEND_FAILURE"
    NOT_REQUESTED = "NOT_REQUESTED"


class IndeterminateReason(Enum):
    BACKEND_UNKNOWN = "BACKEND_UNKNOWN"
    BACKEND_FAILURE = "BACKEND_FAILURE"
    UNSUPPORTED_FRAGMENT = "UNSUPPORTED_FRAGMENT"
    MODEL_NOT_TOTAL = "MODEL_NOT_TOTAL"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


@dataclass(frozen=True, slots=True)
class ExactReachable:
    """Every action reachable in some admissible world. Explanation only."""

    actions: tuple[ConsequentialAction, ...]


@dataclass(frozen=True, slots=True)
class TruncatedReachable:
    """A sample and the cap that stopped enumeration.

    Distinguished from ``Exact`` by probing for one action beyond the cap, so
    "exactly cap actions" is never mislabelled as truncated or the reverse.
    """

    sample: tuple[ConsequentialAction, ...]
    cap: int


@dataclass(frozen=True, slots=True)
class NotComputed:
    reason: NotComputedReason


type ReachableActions = ExactReachable | TruncatedReachable | NotComputed


def reachable_node(reachable: ReachableActions) -> Node:
    match reachable:
        case ExactReachable(actions):
            return NTagged("Exact", canonical_set(action.to_node() for action in actions))
        case TruncatedReachable(sample, cap):
            return NTagged(
                "Truncated",
                NRec(
                    TAG_TRUNCATED_REACHABLE,
                    (canonical_set(action.to_node() for action in sample), NInt(cap)),
                ),
            )
        case NotComputed(reason):
            return NTagged("NotComputed", NAtom(reason.value))


@dataclass(frozen=True, slots=True)
class Invariant:
    """The pinned policy yields this action in every admissible world."""

    action: ConsequentialAction
    witness: World
    invariance_query_digest: Digest

    def to_node(self) -> NRec:
        return NRec(
            TAG_INVARIANT_OUTCOME,
            (
                self.action.to_node(),
                self.witness.to_node(),
                self.invariance_query_digest.to_node(),
            ),
        )


@dataclass(frozen=True, slots=True)
class Divergent:
    """Two admissible worlds yield different consequential actions."""

    reachable: ReachableActions
    left: World
    right: World

    def to_node(self) -> NRec:
        return NRec(
            TAG_DIVERGENT_OUTCOME,
            (reachable_node(self.reachable), self.left.to_node(), self.right.to_node()),
        )


@dataclass(frozen=True, slots=True)
class Infeasible:
    """No admissible world exists. Informative: somebody is misreporting.

    The labels are the source constraints that *contributed*, not a proof.  An
    unsatisfiable core is neither minimal nor stable, and it conflicts with
    encoding assertions the certificate never shows, so calling it a proof would
    overstate what a reader can check.
    """

    contributing: tuple[str, ...]

    def to_node(self) -> NRec:
        return NRec(TAG_INFEASIBLE_OUTCOME, (atoms(self.contributing),))


@dataclass(frozen=True, slots=True)
class Indeterminate:
    reason: IndeterminateReason

    def to_node(self) -> NRec:
        return NRec(TAG_INDETERMINATE_OUTCOME, (NAtom(self.reason.value),))


type AnalysisOutcome = Invariant | Divergent | Infeasible | Indeterminate


def outcome_node(outcome: AnalysisOutcome) -> Node:
    match outcome:
        case Invariant():
            return NTagged("Invariant", outcome.to_node())
        case Divergent():
            return NTagged("Divergent", outcome.to_node())
        case Infeasible():
            return NTagged("Infeasible", outcome.to_node())
        case Indeterminate():
            return NTagged("Indeterminate", outcome.to_node())


def outcome_class(outcome: AnalysisOutcome) -> str:
    match outcome:
        case Invariant():
            return "INVARIANT"
        case Divergent():
            return "DIVERGENT"
        case Infeasible():
            return "INFEASIBLE"
        case Indeterminate():
            return "INDETERMINATE"


def proposed_action(outcome: AnalysisOutcome) -> ConsequentialAction | None:
    """The single place an action may be read out of an outcome.

    Every other variant returns ``None`` structurally, so "infeasible but pay
    anyway" is not a state a caller can reach by forgetting a branch.
    """
    return outcome.action if isinstance(outcome, Invariant) else None


@dataclass(frozen=True, slots=True)
class KernelAnalysisRecord:
    """What the kernel produced, and enough to replay how it produced it.

    Not a certificate: the irredundant support and the evidence plan are
    computed downstream of the kernel, so assembling them here would make the
    dependency graph cyclic.
    """

    logical_case_digest: Digest
    outcome: AnalysisOutcome
    query_digests: tuple[Digest, ...]
    fingerprint: SolverFingerprint
    determinism_class: DeterminismClass

    def to_node(self) -> NRec:
        return NRec(
            TAG_KERNEL_ANALYSIS_RECORD,
            (
                self.logical_case_digest.to_node(),
                outcome_node(self.outcome),
                digests(self.query_digests),
                self.fingerprint.to_node(),
                NAtom(self.determinism_class.value),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.KERNEL_ANALYSIS_RECORD, self.to_node())
