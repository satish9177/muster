"""What the shell may be told to do. A closed union of five imperative steps.

Read the payloads: ``Propose`` carries two digests and no action, ``Dispatch``
carries a request the kernel's planner built, and none of them carries an
instruction. The orchestrator is not permitted to say "pay Ravi"; it is
permitted to say "this certificate is the one to offer for authorization", and
the difference is the whole reason authorization lives elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.evidence.requests import EvidenceRequest
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import Instant
from muster.core.wire.digests import Digest


class EscalationCause(Enum):
    """Why a human is needed. Closed, so an escalation always says which.

    Every member here is produced by ``decide`` and by nothing else, which is
    what makes the enum closed rather than merely finite.  A missed deadline is
    deliberately not a member: it is a *reading* of durable state -- an
    outstanding request whose instant has passed -- and the status projection
    reports it as ``ESCALATED`` from the request rows and the clock reading it
    was given.  Naming it here as well would put a second, unreachable spelling
    of that condition in the vocabulary, and an unreachable name is a name that
    stops describing the system the first time somebody believes it.
    """

    INFEASIBLE = "INFEASIBLE"
    ANALYSIS_INDETERMINATE = "ANALYSIS_INDETERMINATE"
    PLANNING_INDETERMINATE = "PLANNING_INDETERMINATE"
    NO_ACQUIRABLE_SUFFICIENT_SET = "NO_ACQUIRABLE_SUFFICIENT_SET"


@dataclass(frozen=True, slots=True)
class Persist:
    """Publish the revision and its certificate. Nothing else follows.

    Reached when the action is determined but the revision may never authorize
    anything -- a counterfactual rebuild.  Recording it is right; proposing it
    would offer an answer to a question nobody asked operationally.
    """

    revision_digest: Digest
    certificate_digest: Digest


@dataclass(frozen=True, slots=True)
class Dispatch:
    """Publish, and record the intent to ask for evidence by ``deadline``."""

    request: EvidenceRequest
    deadline: Instant


@dataclass(frozen=True, slots=True)
class Escalate:
    """Publish, and hand the case to a human, saying what is missing."""

    cause: EscalationCause
    detail: str
    unresolved: tuple[SymbolRef, ...]


@dataclass(frozen=True, slots=True)
class Propose:
    """Publish, and offer this certificate for authorization.

    Identifiers only. Whatever eventually reads this has to resolve both
    digests for itself, so there is nothing here to forge that is not also a
    digest the reader independently checks.
    """

    revision_digest: Digest
    certificate_digest: Digest


@dataclass(frozen=True, slots=True)
class Idle:
    """The head already names this revision. Nothing to publish, nothing to do."""

    revision_digest: Digest


type Decision = Persist | Dispatch | Escalate | Propose | Idle


def decision_class(decision: Decision) -> str:
    """The variant name, for a report that must not depend on ``repr``."""
    return type(decision).__name__
