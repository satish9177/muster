"""The case status: a total projection, never a stored column.

The brief this design came from offered thirteen candidate states, and most of
them were readings of the latest certificate rather than states: "analysed",
"proposed", "evidence required" are the outcome and planning variants;
"prepared" and "claims collected" mean the transcript has entries. Writing any
of them down creates a second source of truth that can disagree with the
certificate, which is the ordinary way a system like this begins to lie. So
nothing here is stored: status is computed from the certificate the head names,
the requests that are still bound to it, and a clock reading.

Two of the six ratified statuses are deliberately missing. ``SETTLED`` and
``AUTHORIZING`` are readings of authorization state, which is owned by a
component that does not exist yet and whose whole purpose is to own it. A
status this projection can never produce, sitting in the enum waiting for a
producer, is the same defect as a field that is declared and read by nothing --
so they arrive with their owner or not at all.
"""

from __future__ import annotations

from enum import Enum

from muster.core.analysis.certificate import AnalysisCertificate
from muster.core.analysis.planning import (
    EvidenceRequested,
    NoActionReason,
    NoActionRequired,
    NoSufficientSetAcquirable,
    PlanningIndeterminate,
)
from muster.core.values.times import Instant


class CaseStatus(Enum):
    """What a reader is told about a case. Derived on every read."""

    INTAKE = "INTAKE"
    AWAITING_EVIDENCE = "AWAITING_EVIDENCE"
    PROPOSED = "PROPOSED"
    ESCALATED = "ESCALATED"


def status(
    *,
    certificate: AnalysisCertificate | None,
    outstanding_deadlines: tuple[Instant, ...],
    now: Instant,
) -> CaseStatus:
    """Project the case status. Total over its inputs, and fail-closed."""
    if certificate is None:
        return CaseStatus.INTAKE

    if any(deadline <= now for deadline in outstanding_deadlines):
        #  The deadline is the dead-letter handler. Evidence that never arrived
        #  is a human's problem, and it outranks whatever the plan still says,
        #  because the plan is waiting for something that is not coming.
        return CaseStatus.ESCALATED

    match certificate.planning.planning_outcome:
        case NoActionRequired(NoActionReason.ACTION_INVARIANT):
            #  No authorizability guard is needed here, and adding one would be
            #  dishonest about where the rule lives: only an ``OPERATIONAL``
            #  revision is ever published, enforced by ``open_case`` and again
            #  by a column constraint, so a certificate reachable from a head
            #  is always one whose revision may authorize. ``decide`` carries
            #  the guard, because ``decide`` is reachable with a revision that
            #  was never published.
            return CaseStatus.PROPOSED
        case EvidenceRequested() if outstanding_deadlines:
            return CaseStatus.AWAITING_EVIDENCE
        case NoActionRequired() | NoSufficientSetAcquirable() | PlanningIndeterminate():
            return CaseStatus.ESCALATED
        case _:
            #  Reached when evidence was requested and no request is
            #  outstanding against this head -- which the publication path does
            #  not produce, since the request is recorded in the same
            #  transaction as the head that names it. Escalating is the
            #  fail-closed reading: a case waiting on a request that is not
            #  there is waiting forever.
            return CaseStatus.ESCALATED
