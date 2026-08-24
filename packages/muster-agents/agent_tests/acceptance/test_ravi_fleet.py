"""Ravi, acquired by a real agent fleet, ending in the invariant answer.

Sixteen steps, three ADK agents, two source keys, one catalog, one durable
evidence request, three signed receipts, and check Q-12 on every one of them.
No network call anywhere: the interpreters are deterministic ``BaseLlm``
implementations running through the real ADK runner, which is what makes this a
test of the agent runtime rather than of a stand-in for it.

**It calls the demo.**  ``demo/hero.py`` is the composition root the worked run
uses, and this suite drives exactly that function -- so the run demonstrated on
a stage and the run checked on every commit are one code path, and a demo that
quietly diverged from the tested one is not a thing that can happen here.

The assertions are in the order the architecture states them, and the last two
are the product claim:

    the case reaches **Invariant**
    while ``on_site_duration`` is still **unresolved**
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from demo.hero import HeroRun, narrate, run_hero

from agent_tests.support import fleet
from muster.agents.config import DEFAULT_CLAIM_MODEL
from muster.core.analysis.outcomes import Invariant
from muster.core.results import Ok
from muster.core.values.scalars import VScaled
from muster.core.values.symbols import SymbolRef
from muster.core.wire.digests import Digest, DigestKind
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.ports import CaseworkDatabase
from muster.platform.dispatch.acquire import AgentExchange, Answered
from muster.platform.orchestration.status import CaseStatus
from support import ravi

#  Six days at 850.00, which is what the case is worth if the Saturday counts.
FULL_WEEK = VScaled("INR", 2, 510_000)
#  Five, which is what the employer paid and what the case is worth if it does
#  not.  Never reached here; named so the assertion says which number it is not.
FIVE_DAYS = VScaled("INR", 2, 425_000)


@pytest.fixture
def worked_run(tenant_id: str, case_id: str) -> HeroRun:
    return run_hero(
        ravi.casework(MemoryDatabase()),
        fleet.whole_fleet(tenant_id),
        tenant_id=tenant_id,
        case_id=case_id,
    )


#  ---- what the fleet was asked, and by whom -------------------------------


def test_the_worker_claim_is_made_and_moves_nothing(worked_run: HeroRun) -> None:
    """Ravi's message becomes a claim, and the claim agrees with the site.

    Being right is not the same as being evidence.  The plan below still asks
    the site for presence, which it would not do if the claim had established
    anything -- and the claim is *correct*, which is the sharpest form of the
    point.
    """
    assert len(worked_run.claims) == 1
    claim = worked_run.claims[0]
    assert claim.proposition == SymbolRef("present_on_site", ("RAVI", "SAT"))
    assert claim.claimant == "RAVI"
    assert claim.role_in_case == "WORKER"

    asked = {target.proposition.predicate_id for target in worked_run.solicited.targets}
    assert "present_on_site" in asked


def test_live_narration_attributes_worker_claim_intake_without_granting_authority(
    worked_run: HeroRun,
) -> None:
    lines: list[str] = []

    narrate(worked_run, lines.append, worker_model_name=DEFAULT_CLAIM_MODEL)

    assert f"  model      {DEFAULT_CLAIM_MODEL}" in lines
    assert "  role       unverified claim intake" in lines
    assert "  authority  NONE · unsigned claim" in lines


def test_the_plan_names_exactly_what_nobody_has_attested(worked_run: HeroRun) -> None:
    asked = {
        (target.proposition.predicate_id, target.proposition.args)
        for target in worked_run.solicited.targets
    }
    assert asked == {
        ("scheduled", ("RAVI", "SAT")),
        ("present_on_site", ("RAVI", "SAT")),
        ("on_site_duration", ("RAVI", "SAT")),
    }


def test_the_normative_conclusion_is_never_requested(worked_run: HeroRun) -> None:
    """It is DERIVED, so no target can exist for it and no source can carry it."""
    requested = {target.proposition.predicate_id for target in worked_run.solicited.targets}
    assert "shift_payable_under_policy" not in requested


def test_one_request_routes_to_two_agents_by_source_class(worked_run: HeroRun) -> None:
    """The catalog doing real work: two institutions, one plan, no ambiguity."""
    exchanges = _exchanges(worked_run)
    addressed = {exchange.assignment.agent_id for exchange in exchanges}
    assert addressed == {fleet.SITE_AGENT_ID, fleet.EMPLOYER_AGENT_ID}
    for exchange in exchanges:
        assert isinstance(exchange.result, Answered), exchange.result


def test_each_agent_is_asked_only_for_what_it_can_attest(worked_run: HeroRun) -> None:
    by_agent = {
        exchange.assignment.agent_id: {
            target.proposition.predicate_id for target in exchange.assignment.targets
        }
        for exchange in _exchanges(worked_run)
    }
    assert by_agent[fleet.SITE_AGENT_ID] == {"present_on_site", "on_site_duration"}
    assert by_agent[fleet.EMPLOYER_AGENT_ID] == {"scheduled"}


def test_nothing_was_left_unroutable(worked_run: HeroRun) -> None:
    for report in worked_run.reports:
        assert report.unroutable == (), report.unroutable


#  ---- what came back ------------------------------------------------------


def test_every_receipt_was_admitted_through_the_ordinary_command(
    worked_run: HeroRun,
) -> None:
    admitted = _admitted(worked_run)
    assert {proposition.predicate_id for proposition in admitted} == {
        "scheduled",
        "present_on_site",
        "on_site_duration",
    }


def test_no_receipt_was_refused(worked_run: HeroRun) -> None:
    for exchange in _exchanges(worked_run):
        assert isinstance(exchange.result, Answered), exchange.result
        assert exchange.result.refused == (), exchange.result.refused


def test_the_duration_arrives_as_a_bound_rather_than_a_figure(
    worked_run: HeroRun,
) -> None:
    """The privacy claim and the evidential claim in one relation.

    The site could have said 508 minutes.  What it said is "at least 240",
    which settles the case and discloses less -- and the policy is indifferent
    between them, which is why the narrower one is the one to send.
    """
    analysis = worked_run.report.analysis
    assert analysis is not None
    duration = SymbolRef("on_site_duration", ("RAVI", "SAT"))
    assert duration not in {fact.ref for fact in analysis.revision.established}
    assert duration in set(analysis.projected.unresolved())


#  ---- what it decided -----------------------------------------------------


def test_the_case_reaches_the_invariant_answer(worked_run: HeroRun) -> None:
    analysis = worked_run.report.analysis
    assert analysis is not None
    outcome = analysis.kernel.outcome
    assert isinstance(outcome, Invariant), outcome
    assert outcome.action.kind == "PAY"
    amounts = {
        field.value for field in outcome.action.consequential_fields if field.name == "amount"
    }
    assert amounts == {FULL_WEEK}
    assert FIVE_DAYS not in amounts
    assert worked_run.report.status is CaseStatus.PROPOSED


def test_the_case_closes_while_the_duration_is_still_unresolved(
    worked_run: HeroRun,
) -> None:
    """The product claim, in one assertion.

    Every admissible world satisfies the bound, so the normative variable holds
    in all of them -- and the exact number of minutes is never established,
    never disclosed and never needed.
    """
    analysis = worked_run.report.analysis
    assert analysis is not None
    assert isinstance(analysis.kernel.outcome, Invariant)
    unresolved = {str(reference) for reference in analysis.projected.unresolved()}
    assert "on_site_duration(RAVI, SAT)" in unresolved


def test_the_certificate_replays_from_stored_octets(worked_run: HeroRun) -> None:
    """Nothing about the agents changed the property the control plane has."""
    assert worked_run.report.certificate_reproduced


#  ---- and again, against a real database ----------------------------------


@pytest.mark.postgres
def test_the_same_run_against_postgresql(
    postgres_database: CaseworkDatabase, tenant_id: str, case_id: str
) -> None:
    """The database moves no answer, exactly as it moved none at milestone C.

    Run in full rather than parametrised over the fixture, because a suite that
    skipped everything above when no database was configured would report a
    green fleet on the strength of nothing.
    """
    run = run_hero(
        ravi.casework(postgres_database),
        fleet.whole_fleet(tenant_id),
        tenant_id=tenant_id,
        case_id=case_id,
    )
    analysis = run.report.analysis
    assert analysis is not None
    outcome = analysis.kernel.outcome
    assert isinstance(outcome, Invariant), outcome
    assert run.report.status is CaseStatus.PROPOSED
    assert {proposition.predicate_id for proposition in _admitted(run)} == {
        "scheduled",
        "present_on_site",
        "on_site_duration",
    }


@pytest.mark.postgres
def test_the_receipts_are_durable_octets_and_not_objects(
    postgres_database: CaseworkDatabase, tenant_id: str, case_id: str
) -> None:
    """What an agent produced is in the store, as the artifact it is."""
    run = run_hero(
        ravi.casework(postgres_database),
        fleet.whole_fleet(tenant_id),
        tenant_id=tenant_id,
        case_id=case_id,
    )
    with postgres_database.reading(tenant_id) as scope:
        for admitted in _admitted_entries(run):
            stored = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, admitted)
            assert isinstance(stored, Ok), stored


@pytest.fixture
def postgres_database(migrated_dsn: str) -> Iterator[CaseworkDatabase]:
    yield SqlDatabase(migrated_dsn)


#  ---- helpers -------------------------------------------------------------


def _exchanges(run: HeroRun) -> tuple[AgentExchange, ...]:
    return tuple(exchange for report in run.reports for exchange in report.exchanges)


def _admitted(run: HeroRun) -> tuple[SymbolRef, ...]:
    return tuple(
        admitted.proposition
        for exchange in _exchanges(run)
        if isinstance(exchange.result, Answered)
        for admitted in exchange.result.admitted
    )


def _admitted_entries(run: HeroRun) -> tuple[Digest, ...]:
    return tuple(
        admitted.entry_digest
        for exchange in _exchanges(run)
        if isinstance(exchange.result, Answered)
        for admitted in exchange.result.admitted
    )
