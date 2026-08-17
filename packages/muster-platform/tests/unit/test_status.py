"""The status projection: total, derived, and never a stored column.

The certificates here are real ones from the real pipeline; only the clock
reading and the outstanding deadlines are varied, because those are the two
inputs the projection has that the certificate does not.
"""

from __future__ import annotations

from muster.core.analysis.certificate import AnalysisCertificate
from muster.core.values.times import Duration
from muster.platform.orchestration.status import CaseStatus, status
from support import ravi
from unit.test_decide import _analysis, _without_acquirable_targets


def _certificate(*, attested: bool) -> AnalysisCertificate:
    return _analysis(attested=attested).certificate


def test_a_case_with_no_certificate_is_in_intake() -> None:
    assert status(certificate=None, outstanding_deadlines=(), now=ravi.NOW) is CaseStatus.INTAKE


def test_a_requested_plan_with_an_outstanding_request_awaits_evidence() -> None:
    deadline = ravi.ONE_HOUR.after(ravi.NOW)
    assert (
        status(
            certificate=_certificate(attested=False),
            outstanding_deadlines=(deadline,),
            now=ravi.NOW,
        )
        is CaseStatus.AWAITING_EVIDENCE
    )


def test_an_invariant_action_is_proposed() -> None:
    assert (
        status(certificate=_certificate(attested=True), outstanding_deadlines=(), now=ravi.NOW)
        is CaseStatus.PROPOSED
    )


def test_a_passed_deadline_escalates_whatever_the_plan_still_says() -> None:
    """The deadline is the dead-letter handler, and it outranks the plan.

    A case still waiting on evidence that did not arrive is not awaiting
    evidence; it is waiting for something that is not coming, and the only
    correct terminal state for that is a human.
    """
    certificate = _certificate(attested=False)
    deadline = ravi.NOW
    assert (
        status(certificate=certificate, outstanding_deadlines=(deadline,), now=ravi.NOW)
        is CaseStatus.ESCALATED
    )
    assert (
        status(certificate=certificate, outstanding_deadlines=(deadline,), now=ravi.NOW - 1)
        is CaseStatus.AWAITING_EVIDENCE
    )


def test_one_expired_request_among_several_escalates_the_case() -> None:
    certificate = _certificate(attested=False)
    deadlines = (
        ravi.ONE_HOUR.after(ravi.NOW),
        ravi.NOW - 1,
        Duration(2 * ravi.ONE_HOUR.microseconds).after(ravi.NOW),
    )
    assert (
        status(certificate=certificate, outstanding_deadlines=deadlines, now=ravi.NOW)
        is CaseStatus.ESCALATED
    )


def test_nothing_acquirable_escalates() -> None:
    certificate = _without_acquirable_targets(_analysis(attested=False)).certificate
    assert (
        status(certificate=certificate, outstanding_deadlines=(), now=ravi.NOW)
        is CaseStatus.ESCALATED
    )


def test_a_requested_plan_with_no_outstanding_request_fails_closed() -> None:
    """Unreachable through publication, and it still has to answer safely.

    The request is recorded in the same transaction as the head that names it,
    so a head whose plan requested evidence always has one outstanding. If that
    ever stopped being true, a case would be waiting on a request that is not
    there -- which is waiting forever, and escalating is the reading that says
    so rather than the one that hides it.
    """
    assert (
        status(certificate=_certificate(attested=False), outstanding_deadlines=(), now=ravi.NOW)
        is CaseStatus.ESCALATED
    )


def test_the_projection_declares_no_status_it_cannot_produce() -> None:
    """``SETTLED`` and ``AUTHORIZING`` belong to a component that does not exist.

    A member sitting in the enum waiting for a producer is the same defect as a
    field that is declared and read by nothing, so the enum is exactly what
    this milestone can reach.
    """
    assert {member.name for member in CaseStatus} == {
        "INTAKE",
        "AWAITING_EVIDENCE",
        "PROPOSED",
        "ESCALATED",
    }
