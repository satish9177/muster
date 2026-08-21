"""What this runtime actually puts on the wire to Gemini, field by field.

The agent never constructs a Gemini request itself.  It builds an ADK
``LlmAgent`` and a ``RunConfig``, and ADK builds the request -- so "we do not
send a deprecated sampling parameter" is a claim about *what this code does not
set*, which is exactly the kind of claim that is true until somebody adds a
``generate_content_config=`` in a hurry and nothing anywhere notices.

The Gemini 3 family refuses, ignores or reinterprets several fields that earlier
Flash models accepted:

* ``temperature``, ``top_p``, ``top_k`` -- sampling knobs the family no longer
  honours as they were;
* ``candidate_count`` -- more than one candidate is not a thing this system has
  any use for, and asking for one is a change to what a turn costs;
* ``thinking_budget`` -- superseded by ``thinking_level``, so a request still
  carrying the old field is one written against the previous generation;
* a **prefilled model turn** -- a ``role="model"`` entry in the opening request,
  which the family treats differently and which would, here, be MUSTER putting
  words in the interpreter's mouth before it has read anything.

None of them is set anywhere in this distribution, and none of them is a field
ADK adds on its own.  This file is what makes that checkable rather than
remembered: it captures the request ADK hands the model on a real run of the
real agent, and asserts the shape.

**What it deliberately does not do is pin the fields we would send if we sent
any.**  Reasoning configuration is a legitimate future change; ``thinking_level``
is the current spelling and ``thinking_budget`` is not, so the test refuses the
retired field and stays silent about the present one.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

import pytest
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import Field

from agent_tests.support import assignments, fleet
from muster.core.evidence.acquisition import AcquisitionResponse

TENANT = "ALPHA"
CASE = "CASE-RAVI-SAT-001"

#: Every generation field this runtime must not send to a Gemini 3 model.  Named
#: rather than derived, because the point is the list: a field that stops being
#: sent by accident is fine, and one that starts being sent by accident is the
#: defect.
RETIRED = (
    "temperature",
    "top_p",
    "top_k",
    "candidate_count",
    "thinking_budget",
)


class RecordingModel(BaseLlm):
    """A ``BaseLlm`` that keeps every request ADK builds for it, then says nothing.

    A real model on the real ``Runner``: the agent, the tool declarations and
    the flow are the deployed ones, and what is captured is what would have been
    serialised to Vertex.  It answers with prose, so the turn ends after one
    call and the run produces an abstention -- which is the correct outcome and
    not what this file is asserting about.
    """

    requests: list[LlmRequest] = Field(default_factory=list)

    async def generate_content_async(
        self,
        llm_request: LlmRequest,
        stream: bool = False,  # noqa: ARG002 - part of the model contract
    ) -> AsyncGenerator[LlmResponse, None]:
        self.requests.append(llm_request)
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text="noted")]))


@pytest.fixture
def recorded() -> RecordingModel:
    """One real acquisition run, with every outbound request kept."""
    model = RecordingModel(model="recording-interpreter")
    response: AcquisitionResponse = asyncio.run(
        fleet.site(TENANT, model=model).acquire(
            assignments.site_assignment(
                tenant_id=TENANT, case_id=CASE, agent_id=fleet.SITE_AGENT_ID
            )
        )
    )
    assert response.case_id == CASE
    assert model.requests, "the agent never called the model; this test is looking wrongly"
    return model


@pytest.mark.parametrize("field", RETIRED)
def test_no_request_carries_a_field_gemini_3_no_longer_takes(
    field: str, recorded: RecordingModel
) -> None:
    """Checked on every request in the run, not only the first.

    A retired field could be introduced by the opening turn or by whatever
    reassembles the request after a tool call, and the two are different code
    paths in ADK.  Read off the *set* fields rather than the attribute, because
    an unset pydantic field and one explicitly set to ``None`` are the same
    value and not the same request.
    """
    for number, request in enumerate(recorded.requests, 1):
        config = request.config
        assert config is not None
        sent = config.model_dump(exclude_unset=True)
        assert field not in sent, f"request {number} sends {field}={sent[field]!r}"
        assert getattr(config, field, None) is None, f"request {number} carries a {field}"


def test_reasoning_is_not_configured_with_the_retired_budget_shape(
    recorded: RecordingModel,
) -> None:
    """If a thinking configuration ever appears, it is the current one.

    ``thinking_budget`` is the previous generation's spelling and
    ``thinking_level`` is the current one, so this refuses the first and permits
    the second rather than forbidding reasoning configuration outright -- which
    is a change somebody may legitimately want to make later.
    """
    for number, request in enumerate(recorded.requests, 1):
        thinking = getattr(request.config, "thinking_config", None)
        if thinking is None:
            continue
        assert getattr(thinking, "thinking_budget", None) is None, (
            f"request {number} configures reasoning with the retired thinking_budget"
        )


def test_the_opening_turn_puts_no_words_in_the_interpreters_mouth(
    recorded: RecordingModel,
) -> None:
    """The first request is the user's, and only the user's.

    A prefilled ``role="model"`` turn is a way of starting a model off mid
    sentence, and here it would be the source's own runtime asserting something
    about material the interpreter has not read.  Every candidate still has to
    survive deterministic validation, so this is not the last line of defence --
    but a prefill is the one thing on this path that would make the model's
    answer partly MUSTER's, and that is a property to keep rather than to
    re-derive.

    Later requests legitimately carry model turns: that is the tool loop feeding
    back what the model already said.  The opening one is where a prefill would
    be.
    """
    opening = recorded.requests[0]
    roles = [content.role for content in opening.contents]
    assert roles, "the opening request carries no contents"
    assert set(roles) == {"user"}, f"the opening request carries a prefilled turn: {roles}"


def test_the_call_budget_is_the_only_bound_the_runtime_sets(
    recorded: RecordingModel,
) -> None:
    """The two limits are ADK's and asyncio's, and neither is a generation field.

    ``max_llm_calls`` bounds the tool loop and the wall clock bounds the wait;
    both live outside the request.  Asserted here so that a later "just cap the
    output" does not arrive as a generation parameter this runtime has no
    business setting on the source's behalf.
    """
    for request in recorded.requests:
        assert request.config is not None
        sent = request.config.model_dump(exclude_unset=True)
        assert "max_output_tokens" not in sent
        assert "stop_sequences" not in sent
