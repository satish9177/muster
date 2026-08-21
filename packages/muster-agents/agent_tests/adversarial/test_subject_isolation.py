"""One assignment, two subjects, and the material that must not meet.

The dispatcher groups a request's targets by the **agent** that can answer
them, which is the right grouping for routing and the wrong one for a model
turn: one badge reader serves everybody on its site, so a single request can
legitimately produce an assignment naming two workers.  A source that answered
such an assignment in one turn would put both workers' local material in front
of one model together, and the answer about the first would be produced with
the second's gate log in the context window.

**Nothing downstream could see that had happened.**  Each receipt would be
well-formed, correctly scoped, signed by the right key and admitted by Q-12 --
because every check further in is about the *proposition*, and the leak is in
what was read to reach it.  There is no artifact in which it appears.

So the agent partitions by subject and runs one turn per partition.  This suite
is the check on that, from the inside: a recording interpreter reports what it
was shown in each turn, and what it was shown must name one subject.

The worked case has one subject, so none of this changes it -- which is the
other half of what is asserted here.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from pydantic import Field

from agent_tests.support import assignments, fleet
from agent_tests.support.interpreters import (
    already_declined,
    call_of,
    instruction_of,
    listing_of,
    say_of,
)
from muster.agents.runtime.agent import AcquisitionAgent
from muster.agents.sources.local import LocalDirectoryEvidenceStore
from muster.core.evidence.acquisition import AcquisitionAbstention, AcquisitionAssignment
from muster.core.values.symbols import SymbolRef

OTHER_WORKER = "PRIYA"

#: Two files, one per worker, in one site's directory.  This is the ordinary
#: shape of a site's holdings -- not a contrived one: a gate log per shift, a
#: manifest saying whom each is about.
RAVI_LINE = "B-4471,RAVI,IN,2026-08-01T09:12:04+00:00,NORTH-TURNSTILE-2"
PRIYA_LINE = "B-2210,PRIYA,IN,2026-08-01T08:55:31+00:00,NORTH-TURNSTILE-1"


class RecordingInterpreter(BaseLlm):
    """Lists what it was given, remembers it, and declines.

    Declines rather than answers, because what this suite is about is what the
    model was *shown*.  An interpreter that recorded observations would also be
    exercising validation and signing, and a failure there would look like a
    failure here.
    """

    listings: list[dict[str, str]] = Field(default_factory=list)
    briefs: list[str] = Field(default_factory=list)
    attachments: list[list[str]] = Field(default_factory=list)

    async def generate_content_async(
        self,
        llm_request: LlmRequest,
        stream: bool = False,  # noqa: ARG002 - part of the model contract
    ) -> AsyncGenerator[LlmResponse, None]:
        if already_declined(llm_request):
            #  Stop.  The runner keeps asking until the model says something
            #  that is not a tool call, and a recorder that declined twice
            #  would report two turns for one.
            yield say_of("Declined.")
            return
        listed = listing_of(llm_request)
        if listed is None:
            yield call_of("list_local_evidence", {})
            return
        self.listings.append(dict(listed))
        self.briefs.append(instruction_of(llm_request))
        self.attachments.append(_opening_text(llm_request))
        yield call_of("decline", {"reason": "no_evidence", "detail": "recording only"})


@pytest.fixture
def two_workers(tmp_path: Path) -> Path:
    """A site directory holding material about two people."""
    (tmp_path / "gate-log-ravi.txt").write_text(RAVI_LINE, encoding="utf-8")
    (tmp_path / "gate-log-priya.txt").write_text(PRIYA_LINE, encoding="utf-8")
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "ref": "gate-log-ravi",
                        "media_type": "text/plain",
                        "label": "North gate export, Saturday",
                        "file": "gate-log-ravi.txt",
                        "subject": fleet.WORKER,
                        "scope": [{"kind": "SITE", "value": fleet.SITE}],
                    },
                    {
                        "ref": "gate-log-priya",
                        "media_type": "text/plain",
                        "label": "North gate export, Saturday",
                        "file": "gate-log-priya.txt",
                        "subject": OTHER_WORKER,
                        "scope": [{"kind": "SITE", "value": fleet.SITE}],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def _agent(tenant_id: str, material: Path, model: RecordingInterpreter) -> AcquisitionAgent:
    from dataclasses import replace

    built = fleet.site(tenant_id, model=model)
    return replace(built, store=LocalDirectoryEvidenceStore(material))


def _opening_text(request: LlmRequest) -> list[str]:
    """Every text part of the first user turn -- where attached media is named."""
    for content in request.contents:
        if content.role == "user":
            return [part.text for part in content.parts or () if part.text]
    return []


#  ---- the leak, closed ----------------------------------------------------


def test_two_subjects_are_interpreted_in_two_turns(
    tenant_id: str, case_id: str, two_workers: Path
) -> None:
    """One turn each, and neither turn is shown the other's material."""
    model = RecordingInterpreter(model="recording")
    agent = _agent(tenant_id, two_workers, model)
    asyncio.run(agent.acquire(_two_subject_assignment(tenant_id, case_id)))

    assert len(model.listings) == 2, model.listings
    listed = [set(one) for one in model.listings]
    assert listed == [{"gate-log-ravi"}, {"gate-log-priya"}], listed
    assert listed[0].isdisjoint(listed[1])


def test_neither_turn_names_the_other_subject_in_its_brief(
    tenant_id: str, case_id: str, two_workers: Path
) -> None:
    """The brief is built from the turn's own targets, so it names one worker.

    A brief naming both would tell the model whose material to expect, which is
    the same leak one layer up: the model would know that the other person's
    records were in the room even if it could not read them.
    """
    model = RecordingInterpreter(model="recording")
    agent = _agent(tenant_id, two_workers, model)
    asyncio.run(agent.acquire(_two_subject_assignment(tenant_id, case_id)))

    ravi_brief, priya_brief = model.briefs
    assert fleet.WORKER in ravi_brief and OTHER_WORKER not in ravi_brief
    assert OTHER_WORKER in priya_brief and fleet.WORKER not in priya_brief


def test_no_turn_is_opened_for_a_subject_the_source_holds_nothing_for(
    tenant_id: str, case_id: str, two_workers: Path
) -> None:
    """A model asked about somebody with no material can only decline or invent.

    So it is not asked.  The assignment still gets one answer per subject the
    source can speak to, rather than an abstention for the whole of it.
    """
    model = RecordingInterpreter(model="recording")
    agent = _agent(tenant_id, two_workers, model)
    asyncio.run(
        agent.acquire(
            assignments.assignment(
                assignments.target(assignments.PRESENT),
                assignments.target(
                    SymbolRef("present_on_site", ("NOBODY", fleet.SATURDAY)), subject="NOBODY"
                ),
                tenant_id=tenant_id,
                case_id=case_id,
                agent_id=fleet.SITE_AGENT_ID,
            )
        )
    )
    assert len(model.listings) == 1
    assert set(model.listings[0]) == {"gate-log-ravi"}


def test_a_source_holding_nothing_for_anybody_asked_about_abstains(
    tenant_id: str, case_id: str, tmp_path: Path
) -> None:
    """The whole-assignment case, unchanged: no turns, and an honest abstention."""
    (tmp_path / "manifest.json").write_text(json.dumps({"items": []}), encoding="utf-8")
    model = RecordingInterpreter(model="recording")
    agent = _agent(tenant_id, tmp_path, model)
    response = asyncio.run(agent.acquire(_two_subject_assignment(tenant_id, case_id)))

    assert model.listings == []
    assert isinstance(response.outcome, AcquisitionAbstention)
    assert response.outcome.reason.value == "EVIDENCE_NOT_FOUND"


#  ---- and the ordinary case, unchanged ------------------------------------


def test_a_single_subject_assignment_is_still_one_turn(
    tenant_id: str, case_id: str, two_workers: Path
) -> None:
    """The worked case has one subject, and nothing about it moved.

    Two targets, two coordinates, one subject, one turn -- the union across a
    subject's own targets is the behaviour that was always right, and the
    partition is only ever between subjects.
    """
    model = RecordingInterpreter(model="recording")
    agent = _agent(tenant_id, two_workers, model)
    asyncio.run(
        agent.acquire(
            assignments.site_assignment(
                tenant_id=tenant_id, case_id=case_id, agent_id=fleet.SITE_AGENT_ID
            )
        )
    )
    assert len(model.listings) == 1
    assert set(model.listings[0]) == {"gate-log-ravi"}


def test_the_worked_fleet_still_answers_the_worked_case(tenant_id: str, case_id: str) -> None:
    """The positive control, over the real material: the site still attests.

    A partition that broke the ordinary path would be a fix that cost the
    demonstration, and this is the assertion that says it did not.
    """
    agent = fleet.site(tenant_id)
    response = asyncio.run(
        agent.acquire(
            assignments.site_assignment(
                tenant_id=tenant_id, case_id=case_id, agent_id=fleet.SITE_AGENT_ID
            )
        )
    )
    assert not isinstance(response.outcome, AcquisitionAbstention), response.outcome


def _two_subject_assignment(tenant_id: str, case_id: str) -> AcquisitionAssignment:
    return assignments.assignment(
        assignments.target(assignments.PRESENT),
        assignments.target(
            SymbolRef("present_on_site", (OTHER_WORKER, fleet.SATURDAY)), subject=OTHER_WORKER
        ),
        tenant_id=tenant_id,
        case_id=case_id,
        agent_id=fleet.SITE_AGENT_ID,
    )
