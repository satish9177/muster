"""The same agent, against a real Gemini model.  Opt-in, and never by default.

Everything else in this distribution runs the agent against a deterministic
interpreter, which is what makes the suite fast, reproducible and free.  This
file exists so that the claim "the live path calls a model" is checkable rather
than asserted -- and it is skipped unless an operator sets
``MUSTER_LIVE_MODEL=1`` and configures an agent, because it costs money and
needs credentials.

**What it asserts is deliberately not "the model got the right answer".**  A
hosted model is not reproducible and MUSTER does not need it to be: a candidate
has to survive deterministic validation whatever produced it, so a different
temperature or a model upgrade changes *which evidence gets acquired* and never
*what follows from evidence*.  What is asserted is the property that must hold
for every model, on every run:

    whatever came back, it is either signed receipts over the two propositions
    that were asked about -- bound to this tenant, this case, this request and
    this class -- or a typed abstention.  Never anything else.

A run that abstains is a **pass**.  Recording it as a failure would put the
suite in the position of preferring an answer to a refusal, which is exactly
the pressure the whole design exists to remove.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agent_tests.eval.cases import CASES, Case
from agent_tests.support import assignments, fleet
from muster.agents.config import from_environment
from muster.agents.google.models import build_model
from muster.agents.runtime.agent import AcquisitionAgent
from muster.core.evidence.acquisition import (
    AcquiredEvidence,
    AcquisitionAbstention,
    AcquisitionResponse,
)
from muster.core.results import Err

pytestmark = pytest.mark.model

TENANT = "ALPHA"
CASE = "CASE-LIVE"


@pytest.fixture
def live_site_agent(live_model_enabled: bool) -> AcquisitionAgent:
    assert live_model_enabled
    configuration = from_environment()
    if isinstance(configuration, Err):
        pytest.skip(
            f"MUSTER_LIVE_MODEL is set and the agent is not configured: "
            f"{configuration.error.failure.value}: {configuration.error.detail}"
        )
    return fleet.site(TENANT, model=build_model(configuration.value.model))


def _ask(agent: AcquisitionAgent) -> AcquisitionResponse:
    return asyncio.run(
        agent.acquire(
            assignments.site_assignment(
                tenant_id=TENANT, case_id=CASE, agent_id=fleet.SITE_AGENT_ID
            )
        )
    )


def test_the_live_model_produces_a_bounded_answer_or_abstains(
    live_site_agent: AcquisitionAgent,
) -> None:
    response = _ask(live_site_agent)
    assert response.tenant_id == TENANT
    assert response.case_id == CASE
    assert response.agent_id == fleet.SITE_AGENT_ID

    if isinstance(response.outcome, AcquisitionAbstention):
        #  A pass.  A source that declines has answered correctly about its own
        #  material, and a suite that treated that as a failure would be
        #  rewarding a model for guessing.
        return

    assert isinstance(response.outcome, AcquiredEvidence), response.outcome
    for receipt in response.outcome.receipts:
        payload = receipt.payload
        assert payload.proposition.predicate_id in {"present_on_site", "on_site_duration"}
        assert payload.tenant_id == TENANT
        assert payload.case_id == CASE
        assert payload.source_class == "SITE_ACCESS_CONTROL"
        assert payload.signer_key_ref == fleet.SITE_KEY_REF
        assert payload.request_id == assignments.request_id()


def test_the_live_model_never_leaks_the_material_it_read(
    live_site_agent: AcquisitionAgent,
) -> None:
    """Whatever it said, the octets that leave carry none of the source's own."""
    from agent_tests.adversarial.test_acquisition_boundary import RAW_NEEDLES
    from muster.core.wire.codec import encode

    octets = encode(_ask(live_site_agent).to_node())
    for needle in RAW_NEEDLES:
        assert needle not in octets, f"{needle!r} crossed the source boundary"


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_the_live_model_over_the_evaluation_set(
    case: Case, live_model_enabled: bool, tmp_path: Path
) -> None:
    """The eight cases, against a real model.  Reported, not asserted exactly.

    The expectations in ``eval/cases.py`` are what a *competent* interpreter
    produces, and a hosted model is allowed to be wrong -- that is the residual
    risk the architecture states plainly and does not pretend to have removed.
    What is asserted is the invariant: an answer is bounded and bound, or there
    is no answer.  The comparison against the expected reading is printed, so
    an operator running this sees the score without the suite pretending a
    score is a gate.
    """
    assert live_model_enabled
    configuration = from_environment()
    if isinstance(configuration, Err):
        pytest.skip("the agent is not configured")

    agent = fleet.site(
        TENANT,
        model=build_model(configuration.value.model),
        material=case.materialise(tmp_path),
    )
    response = _ask(agent)
    expected = case.expected
    if isinstance(response.outcome, AcquisitionAbstention):
        print(
            f"{case.name}: abstained {response.outcome.reason.value}; "
            f"expected {expected.abstention or expected.observations}"
        )
        return
    assert isinstance(response.outcome, AcquiredEvidence), response.outcome
    for receipt in response.outcome.receipts:
        assert receipt.payload.proposition.predicate_id in {
            "present_on_site",
            "on_site_duration",
        }
    print(
        f"{case.name}: answered "
        f"{[str(r.payload.proposition) for r in response.outcome.receipts]}; "
        f"expected {expected.abstention or expected.observations}"
    )
