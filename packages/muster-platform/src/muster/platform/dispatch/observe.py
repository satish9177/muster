"""Turning one acquisition round into structured, content-free events.

A round already produces a complete, typed record of what happened -- which
agent was addressed, what it answered, which receipts were admitted and what
each refusal was.  So observability here is a *rendering* rather than a second
mechanism: nothing emits, nothing writes, nothing is configured, and there is no
sink.  A caller that wants these in a log calls this and logs them.

That shape is deliberate for two reasons.

**A log line cannot say more than the record it was rendered from.**  The one
thing that must never appear in a log is the source's raw material, and the
strongest form of that guarantee is that the value being rendered never held
it: an ``AcquisitionReport`` carries propositions, digests and typed failures,
and there is no field on it through which a photograph could arrive.

**And nothing here reads a clock.**  An event names what happened and not when,
because the *when* belongs to whoever is writing the line -- and a clock read
here would be a second, unreconcilable reading beside the one the case already
records.

The fields are the correlation fields the architecture names, minus the ones a
dispatcher does not hold: tenant, case, request, agent, proposition, and a
typed outcome.  Everything else a reader needs is joinable on those.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.results import Ok
from muster.platform.dispatch.acquire import (
    Abstained,
    AcquisitionReport,
    AgentExchange,
    Answered,
    EnvelopeRefused,
    Unreachable,
)

#: How much of a digest an operator can usefully read.  Enough to correlate two
#: lines by eye, never enough to be mistaken for the identity itself.
HANDLE = 12


class AcquisitionEventKind(Enum):
    """What happened.  Closed, so a reader can switch on it exhaustively."""

    #: An agent was selected from the catalog and addressed.
    AGENT_ADDRESSED = "AGENT_ADDRESSED"
    #: A target could not be routed to anybody.
    TARGET_UNROUTABLE = "TARGET_UNROUTABLE"
    #: The assignment did not arrive.
    AGENT_UNREACHABLE = "AGENT_UNREACHABLE"
    #: The source answered and declined to attest.
    SOURCE_ABSTAINED = "SOURCE_ABSTAINED"
    #: The reply did not answer the assignment; nothing was submitted.
    REPLY_REFUSED = "REPLY_REFUSED"
    #: A signed receipt became transcript membership.
    RECEIPT_ADMITTED = "RECEIPT_ADMITTED"
    #: A receipt was already a member: a duplicate delivery, and a success.
    RECEIPT_ALREADY_HELD = "RECEIPT_ALREADY_HELD"
    #: A receipt was submitted and refused, by the envelope checks or by
    #: admission -- the reason names which, including the Q-12 clause.
    RECEIPT_REFUSED = "RECEIPT_REFUSED"
    #: Admitting a receipt moved the case's head.
    REVISION_PUBLISHED = "REVISION_PUBLISHED"


@dataclass(frozen=True, slots=True)
class AcquisitionEvent:
    """One thing that happened, with nothing of the source's material in it."""

    kind: AcquisitionEventKind
    tenant_id: str
    case_id: str
    request: str
    agent_id: str
    #: The proposition this event is about, where it is about one.  A predicate
    #: identifier and its arguments are case coordinates, not evidence: they
    #: are in the officer-signed construction record and in the plan already.
    proposition: str | None
    #: A typed reason, where there is one.  Always a failure enum's value or an
    #: abstention reason -- never a message a model produced, and never a
    #: detail string, both of which can quote material.
    reason: str | None

    def render(self) -> str:
        """One line, for an operator reading a terminal rather than a query."""
        parts = [
            self.kind.value,
            f"tenant={self.tenant_id}",
            f"case={self.case_id}",
            f"request={self.request}",
            f"agent={self.agent_id}",
        ]
        if self.proposition is not None:
            parts.append(f"proposition={self.proposition}")
        if self.reason is not None:
            parts.append(f"reason={self.reason}")
        return " ".join(parts)


def acquisition_events(report: AcquisitionReport) -> tuple[AcquisitionEvent, ...]:
    """Every event one round of acquisition produced, in the order it happened."""
    events: list[AcquisitionEvent] = []
    request = report.request_id.hex[:HANDLE]

    for unroutable in report.unroutable:
        events.append(
            AcquisitionEvent(
                kind=AcquisitionEventKind.TARGET_UNROUTABLE,
                tenant_id="",
                case_id="",
                request=request,
                agent_id="",
                proposition=str(unroutable.target.proposition),
                reason=unroutable.error.failure.value,
            )
        )

    for exchange in report.exchanges:
        events.extend(_exchange_events(exchange, request))
    return tuple(events)


def _exchange_events(exchange: AgentExchange, request: str) -> list[AcquisitionEvent]:
    assignment = exchange.assignment

    def event(
        kind: AcquisitionEventKind,
        *,
        proposition: str | None = None,
        reason: str | None = None,
    ) -> AcquisitionEvent:
        return AcquisitionEvent(
            kind=kind,
            tenant_id=assignment.tenant_id,
            case_id=assignment.case_id,
            request=request,
            agent_id=assignment.agent_id,
            proposition=proposition,
            reason=reason,
        )

    events = [event(AcquisitionEventKind.AGENT_ADDRESSED)]
    result = exchange.result
    match result:
        case Unreachable(error):
            events.append(event(AcquisitionEventKind.AGENT_UNREACHABLE, reason=error.failure.value))
        case Abstained(abstention):
            events.append(
                event(AcquisitionEventKind.SOURCE_ABSTAINED, reason=abstention.reason.value)
            )
        case EnvelopeRefused(error):
            events.append(event(AcquisitionEventKind.REPLY_REFUSED, reason=error.failure.value))
        case Answered(admitted, refused):
            for receipt in admitted:
                events.append(
                    event(
                        AcquisitionEventKind.RECEIPT_ADMITTED
                        if receipt.created
                        else AcquisitionEventKind.RECEIPT_ALREADY_HELD,
                        proposition=str(receipt.proposition),
                    )
                )
                if isinstance(receipt.advanced, Ok) and receipt.advanced.value.published:
                    events.append(
                        event(
                            AcquisitionEventKind.REVISION_PUBLISHED,
                            proposition=str(receipt.proposition),
                        )
                    )
            for rejection in refused:
                events.append(
                    event(
                        AcquisitionEventKind.RECEIPT_REFUSED,
                        proposition=str(rejection.proposition),
                        reason=rejection.error.failure.value,
                    )
                )
    return events
