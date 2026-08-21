"""What the cloud run prints, and what it must be unable to print.

The hero job's output is the last artifact in the chain and the first one
anybody reads.  It is produced by a process that holds the whole case record,
it is written to Cloud Logging, and it is put on a screen -- so it is the place
where a leak would be most complete and least noticed.

Two properties, tested two ways.

**Nothing a source authored reaches it.**  Every failure the run can report
carries a free-text ``detail`` beside a closed enumeration: a transport error
quotes the responder's reason phrase, an abstention detail is written inside a
source, a submission error quotes what it refused.  The narration reads none of
them.  Here that is checked by *poisoning* each one and looking for the poison,
which is the form that survives somebody adding a field later.

**No source material reaches it either.**  A genuine run is narrated and its
output is searched for the distinctive strings in the sources' own files --
badge numbers, other workers' names, reader identifiers, timestamps.  A model
that put a line of the gate log in a value, a citation, or a note would have to
get it past the source's own boundary first; this is the check on the other end
of that, which is where the leak would be permanent.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from demo.cloud_hero import CloudHeroRun, RawAccess, RawAttempt, narrate

from agent_tests.support import fleet
from muster.core.evidence.acquisition import AbstentionReason, AcquisitionAbstention
from muster.core.evidence.delivery import TransportError, TransportFailure
from muster.platform.dispatch.acquire import (
    Abstained,
    Answered,
    EnvelopeRefused,
    ExchangeResult,
    RefusedReceipt,
    SubmissionError,
    SubmissionFailure,
    Unreachable,
)
from muster.platform.dispatch.assign import AssignmentError, AssignmentFailure, UnroutableTarget

#: A string no legitimate line of output could contain.  Shaped like the thing
#: it stands in for: a line of a source's private material, quoted into a
#: failure message by something outside this process.
POISON = "B-4471,RAVI,IN,2026-08-01T09:12:04+00:00,NORTH-TURNSTILE-2"


def _narrated(run: CloudHeroRun) -> str:
    lines: list[str] = []
    narrate(run, lines.append)
    return "\n".join(lines)


@pytest.fixture
def worked(cloud_run: CloudHeroRun) -> CloudHeroRun:
    """A real run, reused: the poison is put into it rather than around it."""
    return cloud_run


#  ---- a detail nobody in this process wrote -------------------------------


def test_a_poisoned_transport_failure_is_reported_by_its_failure_alone(
    worked: CloudHeroRun,
) -> None:
    """The endpoint's own reason phrase, which the responder controls."""
    output = _narrated(
        _with_result(worked, Unreachable(TransportError(TransportFailure.UNREACHABLE, POISON)))
    )
    assert POISON not in output
    assert "UNREACHABLE" in output


def test_a_poisoned_abstention_detail_is_reported_by_its_reason_alone(
    worked: CloudHeroRun,
) -> None:
    """A detail written inside a source, about material this process cannot read."""
    output = _narrated(
        _with_result(
            worked,
            Abstained(AcquisitionAbstention(AbstentionReason.EVIDENCE_UNREADABLE, POISON)),
        )
    )
    assert POISON not in output
    assert "EVIDENCE_UNREADABLE" in output


def test_a_poisoned_envelope_refusal_is_reported_by_its_failure_alone(
    worked: CloudHeroRun,
) -> None:
    output = _narrated(
        _with_result(
            worked,
            EnvelopeRefused(SubmissionError(SubmissionFailure.RESPONSE_UNREADABLE, POISON)),
        )
    )
    assert POISON not in output
    assert "RESPONSE_UNREADABLE" in output


def test_a_poisoned_receipt_refusal_is_reported_by_its_failure_alone(
    worked: CloudHeroRun,
) -> None:
    """The one that would carry an admission rejection, quoting the receipt."""
    answered = _first_answered(worked)
    refused = RefusedReceipt(
        proposition=answered.admitted[0].proposition,
        error=SubmissionError(SubmissionFailure.ADMISSION_REFUSED, POISON),
    )
    output = _narrated(_with_result(worked, Answered(admitted=(), refused=(refused,))))
    assert POISON not in output
    assert "ADMISSION_REFUSED" in output


def test_a_poisoned_routing_failure_is_reported_by_its_failure_alone(
    worked: CloudHeroRun,
) -> None:
    """Discovery's own reason travels in this detail, and it names a catalog."""
    target = worked.solicited.targets[0]
    poisoned = replace(
        worked.reports[0],
        unroutable=(
            UnroutableTarget(target, AssignmentError(AssignmentFailure.NO_AGENT_AVAILABLE, POISON)),
        ),
    )
    output = _narrated(replace(worked, reports=(poisoned,)))
    assert POISON not in output
    assert "NO_AGENT_AVAILABLE" in output


#  ---- and no material, from an honest run ---------------------------------


def test_an_honest_run_prints_none_of_the_sources_own_material(
    worked: CloudHeroRun,
) -> None:
    """Nothing distinctive from the site's or the employer's files comes out.

    The tokens are taken from the fixture files themselves rather than written
    down here, so material added to a source is material this test starts
    looking for.  Short and generic lines are skipped: 'RAVI' is the subject of
    the case and belongs in the output, and testing for it would be testing
    that the run says nothing at all.
    """
    output = _narrated(worked)
    for token in _distinctive_tokens():
        assert token not in output, token


def test_an_honest_run_names_another_worker_nowhere(worked: CloudHeroRun) -> None:
    """The sharpest single case: the gate log holds somebody else's movements.

    PRIYA is in the site's material, is nothing to do with this case, and is
    exactly what a careless interpreter or a careless narration would carry
    across.
    """
    assert "PRIYA" not in _narrated(worked)
    assert "B-4471" not in _narrated(worked)


def test_the_raw_access_line_reports_an_outcome_and_no_content(
    worked: CloudHeroRun,
) -> None:
    """Even when the boundary does not hold, what is printed is the fact of it."""
    output = _narrated(
        replace(
            worked,
            raw_access=RawAttempt(RawAccess.ALLOWED, "gs://bucket/site-a/gate-log-sat.txt", 200),
        )
    )
    assert "ALLOWED" in output
    assert "THE BOUNDARY DOES NOT HOLD" in output
    assert POISON not in output
    #  And it stops: nothing after the boundary line is printed, because
    #  nothing after it happened.
    assert "FLEET" not in output


#  ---- helpers -------------------------------------------------------------


def _with_result(run: CloudHeroRun, result: ExchangeResult) -> CloudHeroRun:
    """The same run with every exchange's outcome replaced by one value."""
    reports = tuple(
        replace(
            report,
            exchanges=tuple(replace(exchange, result=result) for exchange in report.exchanges),
        )
        for report in run.reports
    )
    return replace(run, reports=reports)


def _first_answered(run: CloudHeroRun) -> Answered:
    for report in run.reports:
        for exchange in report.exchanges:
            if isinstance(exchange.result, Answered) and exchange.result.admitted:
                return exchange.result
    raise AssertionError("the worked run admitted nothing")


def _distinctive_tokens() -> frozenset[str]:
    """Long, specific strings out of the sources' own files.

    Whitespace-separated and comma-separated pieces of at least twelve
    characters: long enough that a collision with a predicate name, a digest
    prefix or an enum value is not a thing that happens, and short enough that
    a value a model copied out of a line would still be caught.
    """
    found: set[str] = set()
    for material in (fleet.SITE_MATERIAL, fleet.EMPLOYER_MATERIAL):
        for path in sorted(material.glob("*.txt")):
            for line in path.read_text(encoding="utf-8").splitlines():
                for piece in line.replace(",", " ").split():
                    if len(piece) >= 12:
                        found.add(piece)
    assert found, "no material was read; this test is looking in the wrong place"
    return frozenset(found)
