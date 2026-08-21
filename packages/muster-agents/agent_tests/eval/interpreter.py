"""A deterministic reader of gate logs, standing in for a model.

It genuinely reads: it lists what the source offers, pulls the textual export,
parses the access events, and answers or declines according to what is actually
in the file.  That is what makes the evaluation run below a test of the
*pipeline* -- brief, tool call, validation, whitelist, binding, signature,
abstention -- rather than a test of a table of answers.

It is not a model and does not pretend to be one.  What it cannot do is read
the attendance photograph, resolve an ambiguous phrase, or notice a
contradiction expressed in prose it has not been taught -- and where it has
been taught one, the phrase it looks for is written here in plain sight so that
nobody mistakes this for evidence about a language model.  The evaluation runs
the *same* cases against a real model when one is configured; that run is the
one that measures reading.
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator, Mapping
from dataclasses import dataclass

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse

from agent_tests.support.interpreters import (
    already_declined,
    already_read,
    already_recorded,
    call_of,
    instruction_of,
    listing_of,
    responses_of,
    say_of,
)

#: ``B-4471,RAVI,IN,2026-08-01T09:12:04+00:00,NORTH-TURNSTILE-2``
_EVENT = re.compile(
    r"^[A-Z0-9\-]+,(?P<worker>[A-Z][A-Z0-9_\-]*),(?P<event>IN|OUT),(?P<at>[0-9T:+\-]{20,32}),",
    re.MULTILINE,
)
_TARGET = re.compile(r"^(T\d+)\.\s+([a-z_][a-z0-9_]*)\(", re.MULTILINE)
_SUBJECT = re.compile(r"^\s+subject:\s+(\S+)", re.MULTILINE)

#: The one phrase this reader is taught to treat as a contradiction.  Written
#: here rather than hidden in a branch, because a stand-in that appeared to
#: "notice" contradictions would be the most misleading thing in the suite.
_DISPUTED = "cannot be relied on"


@dataclass(frozen=True, slots=True)
class _Reading:
    """What the log says about the named subject."""

    entered: str | None
    left: str | None
    others_present: bool
    disputed: bool

    @property
    def minutes(self) -> int | None:
        if self.entered is None or self.left is None:
            return None
        return (_minutes(self.left) - _minutes(self.entered)) or None


class GateLogInterpreter(BaseLlm):
    """Lists, reads the export, and answers what the export supports."""

    async def generate_content_async(
        self,
        llm_request: LlmRequest,
        stream: bool = False,  # noqa: ARG002 - part of the model contract
    ) -> AsyncGenerator[LlmResponse, None]:
        if already_declined(llm_request):
            yield say_of("Declined; the local evidence does not support an answer.")
            return

        instruction = instruction_of(llm_request)
        listed = listing_of(llm_request)
        if listed is None:
            yield call_of("list_local_evidence", {})
            return

        read = already_read(llm_request)
        unread = [
            ref
            for ref, media_type in listed.items()
            if media_type.startswith("text/") and ref not in read
        ]
        if unread:
            yield call_of("read_text_evidence", {"ref": unread[0]})
            return

        text = _text_of(llm_request)
        if text is None:
            #  Every textual item failed to read.  A reader that answered from
            #  the picture alone would be answering from something it cannot
            #  see, so it declines and names why.
            yield call_of("decline", {"reason": "unreadable", "detail": "the export did not read"})
            return

        subject = _subject_of(instruction)
        reading = _read(text, subject)
        if reading.disputed:
            yield call_of(
                "decline",
                {"reason": "contradictory", "detail": "the local records disagree"},
            )
            return
        if reading.entered is None and reading.others_present:
            yield call_of(
                "decline",
                {
                    "reason": "subject_not_identified",
                    "detail": "the export records somebody else",
                },
            )
            return

        recorded = already_recorded(llm_request)
        for label, predicate in _TARGET.findall(instruction):
            if label in recorded:
                continue
            arguments = _answer(predicate, reading, listed)
            if arguments is None:
                continue
            yield call_of("record_observation", {"target": label, **arguments})
            return
        yield say_of("Recorded what the export supports.")


def _answer(predicate: str, reading: _Reading, listed: Mapping[str, str]) -> dict[str, str] | None:
    basis = next((ref for ref, media in sorted(listed.items()) if media.startswith("text/")), "")
    observed = reading.entered or "2026-08-01T09:00:00+00:00"
    if predicate == "present_on_site":
        return {
            "relation": "exact",
            "value": "true" if reading.entered is not None else "false",
            "observed_at": observed,
            "basis": basis,
        }
    if predicate == "on_site_duration":
        minutes = reading.minutes
        if minutes is None:
            #  An entry with no exit supports presence and no duration at all.
            #  Reporting one anyway is exactly the inference the brief forbids.
            return None
        relation = "at_least" if minutes >= 240 else "at_most"
        return {
            "relation": relation,
            "value": str(240 if relation == "at_least" else minutes),
            "observed_at": observed,
            "basis": basis,
        }
    return None


def _read(text: str, subject: str) -> _Reading:
    entered: str | None = None
    left: str | None = None
    others = False
    for match in _EVENT.finditer(text):
        if match.group("worker") != subject:
            others = True
            continue
        if match.group("event") == "IN":
            entered = match.group("at")
        else:
            left = match.group("at")
    return _Reading(entered, left, others, _DISPUTED in text)


def _subject_of(instruction: str) -> str:
    found = _SUBJECT.search(instruction)
    return found.group(1) if found else ""


def _text_of(request: LlmRequest) -> str | None:
    for response in responses_of(request, "read_text_evidence"):
        text = response.get("text")
        if isinstance(text, str):
            return text
    return None


def _minutes(instant: str) -> int:
    """Minutes past midnight, from an ISO instant.  Same day, by construction."""
    time_part = instant.split("T")[1]
    hours, minutes = time_part.split(":")[:2]
    return int(hours) * 60 + int(minutes)
