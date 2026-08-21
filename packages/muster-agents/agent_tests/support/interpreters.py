"""A deterministic interpreter that reacts, rather than a script that replays.

The scripted models next door play a fixed sequence, which is right for
testing one misbehaviour.  The worked case needs something else: an interpreter
that reads the brief it is actually given, pulls the material it is actually
offered, and answers the targets that are actually there -- because the *order*
of the targets in an assignment is decided by the planner, and a fake that
assumed an order would be testing the fake.

So this is a rule-based interpreter.  It is a real ``BaseLlm``, driven by the
real ADK runner, and what makes it deterministic is that its rules are a table
from predicate identifier to the relation and value a competent source would
report from the worked material.  It has no knowledge of the case, cannot see
the policy, and answers only targets the brief names -- exactly the constraints
the live model runs under.

**This is the test-mode interpreter, and the live path does not use it.**  The
demo and the live integration test inject an ADK Gemini model instead.  The
agent, the tools, the validator, the whitelist, the binding and the signing are
identical in both; what differs is which ``BaseLlm`` was handed in, and no code
under ``src`` can tell.
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator, Mapping
from dataclasses import dataclass

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import Field

#: ``T1. present_on_site(RAVI, SAT)`` -- the one line of the brief a rule needs.
_TARGET = re.compile(r"^(T\d+)\.\s+([a-z_][a-z0-9_]*)\(", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class Reading:
    """What this interpreter reports for one predicate, and from what.

    ``prefer_media`` picks the basis: an interpreter reading an attendance
    photograph cites the photograph, and one counting hours from a badge log
    cites the log.  It matters because the validator refuses a basis the source
    never offered, and a fake that always cited the first handle would never
    exercise that.
    """

    relation: str
    value: str
    observed_at: str
    prefer_media: bool = False


class RuleBasedInterpreter(BaseLlm):
    """Lists, reads, then answers each briefed target from a rule table.

    Four behaviours, in order, decided from the conversation so far rather than
    from a turn counter:

    1. list the local evidence, if it has not;
    2. read each textual item, one per turn;
    3. record one observation per briefed target it has a rule for;
    4. stop.

    A target with no rule is simply not answered, which is how the suite spells
    "the source has nothing to say about this" without teaching the fake to
    decline.
    """

    readings: dict[str, Reading] = Field(default_factory=dict)

    async def generate_content_async(
        self,
        llm_request: LlmRequest,
        stream: bool = False,  # noqa: ARG002 - part of the model contract
    ) -> AsyncGenerator[LlmResponse, None]:
        instruction = instruction_of(llm_request)
        listed = listing_of(llm_request)
        read = already_read(llm_request)
        recorded = already_recorded(llm_request)

        if listed is None:
            yield call_of("list_local_evidence", {})
            return

        unread = [
            ref
            for ref, media_type in listed.items()
            if media_type.startswith("text/") and ref not in read
        ]
        if unread:
            yield call_of("read_text_evidence", {"ref": unread[0]})
            return

        if already_declined(llm_request):
            yield say_of("Declined.")
            return

        for label, predicate in _TARGET.findall(instruction):
            if label in recorded:
                continue
            reading = self.readings.get(predicate)
            if reading is None:
                continue
            yield call_of(
                "record_observation",
                {
                    "target": label,
                    "relation": reading.relation,
                    "value": reading.value,
                    "observed_at": reading.observed_at,
                    "basis": basis_of(listed, reading.prefer_media),
                },
            )
            return
        yield say_of("Every target the local evidence supports has been recorded.")


def instruction_of(request: LlmRequest) -> str:
    instruction = request.config.system_instruction
    return instruction if isinstance(instruction, str) else ""


def responses_of(request: LlmRequest, name: str) -> list[Mapping[str, object]]:
    """Every response this conversation holds from one named tool."""
    found: list[Mapping[str, object]] = []
    for content in request.contents:
        for part in content.parts or ():
            response = part.function_response
            if response is not None and response.name == name and response.response is not None:
                found.append(response.response)
    return found


def listing_of(request: LlmRequest) -> dict[str, str] | None:
    """Reference to media type, from the listing tool, or ``None`` if unasked."""
    responses = responses_of(request, "list_local_evidence")
    if not responses:
        return None
    listed: dict[str, str] = {}
    for response in responses:
        items = response.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                ref = item.get("ref")
                media_type = item.get("media_type")
                if isinstance(ref, str) and isinstance(media_type, str):
                    listed[ref] = media_type
    return listed


def already_read(request: LlmRequest) -> set[str]:
    read: set[str] = set()
    for response in responses_of(request, "read_text_evidence"):
        ref = response.get("ref")
        if isinstance(ref, str):
            read.add(ref)
    return read


def already_recorded(request: LlmRequest) -> set[str]:
    recorded: set[str] = set()
    for response in responses_of(request, "record_observation"):
        target = response.get("target")
        if isinstance(target, str):
            recorded.add(target)
    return recorded


def already_declined(request: LlmRequest) -> bool:
    """Has this turn already declined?

    A reader that re-evaluates the same material on every step would decline
    again, and again, until its call budget ran out -- which is a real hazard
    for a rule-based interpreter and a real one for a model that has been told
    declining is acceptable.  Either way, having declined once is a reason to
    stop rather than a reason to repeat.
    """
    return bool(responses_of(request, "decline"))


def basis_of(listed: Mapping[str, str], prefer_media: bool) -> str:
    wanted = [
        ref
        for ref, media_type in sorted(listed.items())
        if media_type.startswith("text/") is not prefer_media
    ]
    if wanted:
        return wanted[0]
    return next(iter(sorted(listed)), "")


def call_of(name: str, args: dict[str, object]) -> LlmResponse:
    return LlmResponse(
        content=types.Content(
            role="model",
            parts=[types.Part(function_call=types.FunctionCall(name=name, args=args))],
        )
    )


def say_of(text: str) -> LlmResponse:
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))


class RuleBasedClaimant(BaseLlm):
    """The worker-side counterpart: one claim per briefed target it has a rule for.

    Simpler than the source interpreter because a worker's account has no
    material to pull: what the person said is the whole of the input, and the
    only question is which of the briefed propositions they asserted.
    """

    claims: dict[str, str] = Field(default_factory=dict)

    async def generate_content_async(
        self,
        llm_request: LlmRequest,
        stream: bool = False,  # noqa: ARG002 - part of the model contract
    ) -> AsyncGenerator[LlmResponse, None]:
        instruction = instruction_of(llm_request)
        recorded = {
            target
            for response in responses_of(llm_request, "record_claim")
            if isinstance(target := response.get("target"), str)
        }
        for label, predicate in _TARGET.findall(instruction):
            if label in recorded or predicate not in self.claims:
                continue
            yield call_of("record_claim", {"target": label, "value": self.claims[predicate]})
            return
        yield say_of("Recorded what they said they are claiming.")
