"""The three commands, end to end, with no database and no skip.

This is what the in-memory adapter is *for*.  Everything here is a claim about
the command layer -- what ``open_case`` refuses, what an append returns, what
``case_status`` derives -- and none of it is a claim about PostgreSQL, so
paying for a connection and a migration to check it would be paying for
evidence of something else.  It also runs on a machine with no database, which
is the difference between these properties being checked on every commit and
being checked when somebody remembers to start one.

**What is deliberately absent.**  No test here contends anything.  The memory
adapter serialises writers with a lock, so a concurrency test written against
it would be a test of a mutex, and every claim this milestone makes about
compare-and-swap under contention, isolation, recovery and durability lives in
``tests/integration`` and ``tests/adversarial`` against a real instance.  The
shared port contract that keeps the two adapters from drifting is in
``tests/contract``, and it runs against both.
"""

from __future__ import annotations

import pytest

from muster.core.evidence.transcript import entry_digest
from muster.core.results import Err, Ok
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.casework.advance import Casework, advance_case
from muster.platform.casework.commands import (
    AppendFailure,
    OpenFailure,
    StatusFailure,
    append_transcript_entry,
    case_status,
    open_case,
)
from muster.platform.orchestration.status import CaseStatus
from support import ravi
from support.authority import sign_receipt
from support.ravi import RaviCase

TENANT = "tenant-in-memory"
CASE = "case-in-memory"


@pytest.fixture
def casework() -> Casework:
    return ravi.casework(MemoryDatabase())


@pytest.fixture
def case() -> RaviCase:
    return ravi.ravi(TENANT, CASE, attested=True)


def _open(casework: Casework, case: RaviCase) -> object:
    #  The case's authority state first: admission resolves the pin before it
    #  stores anything, so opening without publishing produces a case nothing
    #  can be appended to.
    ravi.publish_authority(casework.database, case)
    return open_case(
        casework,
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=case.authorization_context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )


def _append(casework: Casework, case: RaviCase, index: int) -> object:
    return append_transcript_entry(
        casework,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=case.entries[index],
        now=ravi.NOW,
    )


#  ---- open ------------------------------------------------------------------


def test_opening_a_case_leaves_it_in_intake(casework: Casework, case: RaviCase) -> None:
    opened = _open(casework, case)
    assert isinstance(opened, Ok), opened
    assert opened.value.revision_digest is None

    report = case_status(casework, tenant_id=TENANT, case_id=CASE, now=ravi.NOW)
    assert isinstance(report, Ok), report
    assert report.value.status is CaseStatus.INTAKE
    assert report.value.analysis is None
    assert report.value.outstanding == ()
    assert report.value.certificate_reproduced is True


def test_opening_the_same_case_twice_is_idempotent(casework: Casework, case: RaviCase) -> None:
    first = _open(casework, case)
    again = _open(casework, case)
    assert isinstance(first, Ok) and isinstance(again, Ok)
    assert first.value == again.value


def test_a_policy_the_registry_cannot_resolve_is_refused_and_writes_nothing(
    casework: Casework, case: RaviCase
) -> None:
    """A rejected command writes nothing, and the content store has no delete.

    Checked against the records directly, which is the in-memory equivalent of
    reaching past the repositories with raw SQL -- and it is the only way to
    show that *nothing at all* was stored rather than that nothing useful was.
    """
    database = casework.database
    assert isinstance(database, MemoryDatabase)

    refused = open_case(
        casework,
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=case.authorization_context,
        policy_id="no-such-policy",
        as_of=case.as_of,
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is OpenFailure.POLICY_UNAVAILABLE
    assert database.records.content == {}
    assert database.records.heads == {}


def test_an_entry_bound_to_another_case_is_refused_at_admission(
    casework: Casework, case: RaviCase
) -> None:
    assert isinstance(_open(casework, case), Ok)
    other = ravi.ravi(TENANT, "case-somewhere-else", attested=True)

    refused = append_transcript_entry(
        casework, tenant_id=TENANT, case_id=CASE, entry=other.entries[0], now=ravi.NOW
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is AppendFailure.ADMISSION_REFUSED
    assert "CASE_MISMATCH" in refused.error.detail


#  ---- append and advance ----------------------------------------------------


def test_appending_the_whole_transcript_publishes_a_proposed_case(
    casework: Casework, case: RaviCase
) -> None:
    """The full command path, in-process, with the real kernel and no database."""
    assert isinstance(_open(casework, case), Ok)
    for index in range(len(case.entries)):
        appended = _append(casework, case, index)
        assert isinstance(appended, Ok), appended

    report = case_status(casework, tenant_id=TENANT, case_id=CASE, now=ravi.NOW)
    assert isinstance(report, Ok), report
    assert report.value.status is CaseStatus.PROPOSED
    assert report.value.certificate_reproduced is True
    assert report.value.analysis is not None


def test_a_redelivered_entry_is_a_success_that_creates_nothing(
    casework: Casework, case: RaviCase
) -> None:
    assert isinstance(_open(casework, case), Ok)
    first = _append(casework, case, 0)
    again = _append(casework, case, 0)
    assert isinstance(first, Ok) and first.value.created is True
    assert isinstance(again, Ok) and again.value.created is False
    assert first.value.entry_digest == again.value.entry_digest == entry_digest(case.entries[0])


def test_re_driving_a_settled_case_is_idle_and_publishes_nothing(
    casework: Casework, case: RaviCase
) -> None:
    """Recovery is "call it again", and this is what calling it again does."""
    assert isinstance(_open(casework, case), Ok)
    for index in range(len(case.entries)):
        assert isinstance(_append(casework, case, index), Ok)

    again = advance_case(casework, tenant_id=TENANT, case_id=CASE, now=ravi.NOW)
    assert isinstance(again, Ok), again
    assert again.value.published is False
    assert again.value.attempts == 1


def test_an_entry_that_would_make_the_case_unrebuildable_is_refused_here_too(
    casework: Casework, case: RaviCase
) -> None:
    """The CRITICAL fix, checked against the other adapter.

    The guard lives in the command rather than in the SQL, so it has to hold
    over any implementation of the ports -- and an implementation whose
    transaction did not really roll back would show it here.
    """
    from dataclasses import replace

    from muster.core.evidence.transcript import Attestation

    database = casework.database
    assert isinstance(database, MemoryDatabase)

    assert isinstance(_open(casework, case), Ok)
    for index in range(len(case.entries)):
        assert isinstance(_append(casework, case, index), Ok)

    establishing = case.entries[18]
    assert isinstance(establishing, Attestation)
    #  Signed for real under the key the payload names.  The nonce is inside
    #  what the signature covers, so a twin that kept the original signature
    #  would be refused on authenticity -- and this test is about the check two
    #  steps after that, which only runs on a receipt that got past both.
    twin = Attestation(
        sign_receipt(
            replace(
                establishing.receipt,
                payload=replace(establishing.receipt.payload, nonce=b"\x5a" * 16),
            )
        )
    )
    before = dict(database.records.members)

    refused = append_transcript_entry(
        casework, tenant_id=TENANT, case_id=CASE, entry=twin, now=ravi.NOW
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is AppendFailure.TRANSCRIPT_WOULD_NOT_REBUILD
    assert database.records.members == before
    assert (TENANT, entry_digest(twin)) not in database.records.content


#  ---- status ----------------------------------------------------------------


def test_the_status_of_an_unopened_case_is_a_typed_absence(casework: Casework) -> None:
    missing = case_status(casework, tenant_id=TENANT, case_id="nothing", now=ravi.NOW)
    assert isinstance(missing, Err)
    assert missing.error.failure is StatusFailure.UNKNOWN_CASE


def test_a_case_awaiting_evidence_escalates_once_the_deadline_passes(casework: Casework) -> None:
    """Status is a projection over a clock reading, and nothing was stored.

    The unattested fixture asks for evidence, so this reaches ``Dispatch`` and
    a recorded deadline -- the one piece of durable wall-clock intent in the
    system -- and then reads the same durable state under two readings.
    """
    unattested = ravi.ravi(TENANT, CASE, attested=False)
    assert isinstance(_open(casework, unattested), Ok)
    for index in range(len(unattested.entries)):
        assert isinstance(_append(casework, unattested, index), Ok)

    before = case_status(casework, tenant_id=TENANT, case_id=CASE, now=ravi.NOW)
    after = case_status(casework, tenant_id=TENANT, case_id=CASE, now=ravi.ONE_HOUR.after(ravi.NOW))
    assert isinstance(before, Ok), before
    assert isinstance(after, Ok), after
    assert before.value.status is CaseStatus.AWAITING_EVIDENCE
    assert after.value.status is CaseStatus.ESCALATED
    assert before.value.head == after.value.head
    assert before.value.expired == ()
    assert len(after.value.expired) == 1


def test_two_tenants_holding_the_same_case_identifier_do_not_see_each_other(
    case: RaviCase,
) -> None:
    """The tenant boundary, over the adapter that could most easily lose it.

    A dictionary has no foreign keys to enforce it, so the keying has to carry
    the tenant -- which is the same rule the schema states with a composite
    primary key, checked here against the other implementation of it.
    """
    database = MemoryDatabase()
    casework = ravi.casework(database)
    mine = case
    theirs = ravi.ravi("tenant-someone-else", CASE, attested=True)

    assert isinstance(_open(casework, mine), Ok)
    assert isinstance(_open(casework, theirs), Ok)
    assert isinstance(_append(casework, mine, 0), Ok)

    with database.reading(theirs.tenant_id) as scope:
        members = scope.transcript.members(CASE)
    assert isinstance(members, Ok), members
    assert members.value == ()


def test_an_undurable_deadline_is_a_typed_rejection_and_not_an_exception() -> None:
    """A misconfigured TTL is refused before any transaction opens.

    ``RecordedRequest`` also refuses it -- that invariant is what keeps the two
    adapters agreeing -- but it refuses at the moment the request is built,
    which in ``_swap`` is *after* the head has already been advanced. The
    exception would then escape ``append_transcript_entry``, which promises a
    ``Result``, with the appended entry already durable. So the check is in
    ``_compute``, with nothing open, and the answer is a rejection.
    """
    from muster.core.results import Result
    from muster.core.values.times import Duration
    from muster.platform.casework.advance import Advanced, AdvanceFailure, AdvanceRejection

    database = MemoryDatabase()
    #  The unattested case asks for evidence, which is the only path that
    #  computes a deadline at all -- so the whole transcript goes in, and the
    #  last append is the one whose analysis reaches ``Dispatch``.
    case = ravi.ravi(TENANT, CASE, attested=False)
    absurd = ravi.casework(database, evidence_request_ttl=Duration(2**63))
    assert isinstance(_open(absurd, case), Ok)

    advances: list[Result[Advanced, AdvanceRejection]] = []
    for index in range(len(case.entries)):
        outcome = append_transcript_entry(
            absurd, tenant_id=TENANT, case_id=CASE, entry=case.entries[index], now=ravi.NOW
        )
        assert isinstance(outcome, Ok), outcome
        advances.append(outcome.value.advanced)

    #  The appends themselves succeeded: every entry is durable, which is what
    #  the command promised. The advance is where the refusal lives.
    last = advances[-1]
    assert isinstance(last, Err), last
    assert last.error.failure is AdvanceFailure.DEADLINE_NOT_DURABLE
    assert len(database.records.members[(TENANT, CASE)]) == len(case.entries)

    #  No request row was written, and no head was moved to carry one.
    assert database.records.requests == {}
    assert database.records.heads[(TENANT, CASE)].revision_digest is None

    #  The same case under a sane TTL publishes normally, so what was refused
    #  was the deadline and not the case.
    sane = ravi.casework(database)
    advanced = advance_case(sane, tenant_id=TENANT, case_id=CASE, now=ravi.NOW)
    assert isinstance(advanced, Ok), advanced
    assert advanced.value.published
