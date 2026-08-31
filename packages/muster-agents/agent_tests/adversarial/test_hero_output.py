"""What the local hero says when the fleet did not answer.

The cloud narration has always guarded its closing claim on the outcome; the
local one printed it unconditionally, so a run whose Site Agent abstained
reported ``DIVERGENT`` and then asserted that the Saturday was payable *on
attested grounds* two lines later.  That is the one sentence this system is
careful never to say without having earned it.

**The divergent run here is a real one.**  Nothing is stubbed and no outcome is
substituted: the case is driven through ``run_hero`` against a transport that
holds the employer agent and not the site one, which is the shape the failure
took -- employer attests, site does not answer, the case stays outstanding.
"""

from __future__ import annotations

import pytest
from demo.hero import HeroRun, narrate, run_hero

from agent_tests.support import fleet
from muster.core.analysis.outcomes import Invariant
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.orchestration.status import CaseStatus
from support import ravi

PAYABLE = "Saturday shift is payable under the pinned policy, on attested grounds."
ESTABLISHED_NOTHING = "Nothing was established."


@pytest.fixture
def divergent_run(tenant_id: str, case_id: str) -> HeroRun:
    """The employer answers and the site never does.  Nothing is established."""
    return run_hero(
        ravi.casework(MemoryDatabase()),
        fleet.transport({fleet.EMPLOYER_ENDPOINT: fleet.employer(tenant_id)}),
        tenant_id=tenant_id,
        case_id=case_id,
    )


@pytest.fixture
def worked_run(tenant_id: str, case_id: str) -> HeroRun:
    return run_hero(
        ravi.casework(MemoryDatabase()),
        fleet.whole_fleet(tenant_id),
        tenant_id=tenant_id,
        case_id=case_id,
    )


def test_the_divergent_run_is_the_shape_the_failure_took(divergent_run: HeroRun) -> None:
    """Guarding the fixture: a run that quietly succeeded would prove nothing."""
    assert divergent_run.report.status is CaseStatus.AWAITING_EVIDENCE
    analysis = divergent_run.report.analysis
    assert analysis is not None
    assert not isinstance(analysis.kernel.outcome, Invariant)


def test_a_divergent_run_never_claims_the_shift_is_payable(divergent_run: HeroRun) -> None:
    lines: list[str] = []

    narrate(divergent_run, lines.append)

    assert PAYABLE not in "\n".join(lines)


def test_a_divergent_run_says_that_nothing_was_established(divergent_run: HeroRun) -> None:
    lines: list[str] = []

    narrate(divergent_run, lines.append)

    output = "\n".join(lines)
    assert ESTABLISHED_NOTHING in output
    assert "still outstanding, and no answer follows from what it holds." in output


def test_the_invariant_run_still_makes_the_claim_it_earned(worked_run: HeroRun) -> None:
    """The guard narrows the claim; it does not remove it."""
    lines: list[str] = []

    narrate(worked_run, lines.append)

    output = "\n".join(lines)
    assert PAYABLE in output
    assert ESTABLISHED_NOTHING not in output
