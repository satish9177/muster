"""Deterministic interpreters: real ADK models that answer from a script.

The suite does not mock the agent.  It builds the same ``LlmAgent``, runs it on
the same ``Runner``, through the same tool declarations, and replaces exactly
one thing -- the model -- with a ``BaseLlm`` that answers from a script instead
of from a network.  Everything the production path does, the suite does: the
tool schemas are generated, the calls are dispatched, the responses are fed
back, the loop terminates the same way.

That is what makes these tests evidence about the runtime rather than about a
stand-in for it.  A fake ``AcquisitionAgent`` would prove that a fake returns
what it was told to; a fake *model* proves that the real agent, given a
particular model output, produces a particular receipt -- or refuses to.

The scripts below are the interesting model behaviours, and most of them are
misbehaviours: a model that answers a proposition nobody asked about, one that
returns a value outside the pinned domain, one that fabricates a source it was
never offered, one that says nothing, one that raises, one that never stops.
Each is a line in the security suite.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Sequence
from dataclasses import dataclass, field

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import Field


@dataclass(frozen=True, slots=True)
class Call:
    """One tool call the scripted model makes on its turn."""

    name: str
    args: dict[str, object]


@dataclass(frozen=True, slots=True)
class Say:
    """A turn on which the model produces prose and calls nothing.

    Prose is not an answer anywhere in MUSTER: nothing reads it, nothing stores
    it, and a run that produces only prose produces an abstention.  Scripting
    it is how the suite says so.
    """

    text: str


type Turn = Call | Say


class ScriptedModel(BaseLlm):
    """A ``BaseLlm`` that plays a fixed sequence of turns.

    Pydantic-modelled because ``BaseLlm`` is; the turn counter lives on the
    instance and each test builds its own, so no script is shared between two
    runs of anything.
    """

    script: list[Turn] = Field(default_factory=list)
    taken: int = 0

    async def generate_content_async(
        self,
        llm_request: LlmRequest,  # noqa: ARG002 - part of the model contract
        stream: bool = False,  # noqa: ARG002 - part of the model contract
    ) -> AsyncGenerator[LlmResponse, None]:
        index = self.taken
        self.taken = index + 1
        turn: Turn = self.script[index] if index < len(self.script) else Say("done")
        match turn:
            case Call(name, args):
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[
                            types.Part(function_call=types.FunctionCall(name=name, args=dict(args)))
                        ],
                    )
                )
            case Say(text):
                yield LlmResponse(
                    content=types.Content(role="model", parts=[types.Part(text=text)])
                )


class FailingModel(BaseLlm):
    """A model whose client raises, as a quota or transport failure does."""

    message: str = "429 RESOURCE_EXHAUSTED"

    async def generate_content_async(
        self,
        llm_request: LlmRequest,  # noqa: ARG002 - part of the model contract
        stream: bool = False,  # noqa: ARG002 - part of the model contract
    ) -> AsyncGenerator[LlmResponse, None]:
        #  ``yield`` first, so the function is a generator by inspection rather
        #  than by an unreachable statement after a raise.  The condition is
        #  always false; what it buys is a body a type checker can read.
        if self.message == "":  # pragma: no cover - never taken
            yield LlmResponse()
        raise RuntimeError(self.message)


class LoopingModel(BaseLlm):
    """A model that calls a tool forever.

    Bounded by ``max_llm_calls`` rather than by anything in the model, which is
    the property under test: an interpreter that never stopped would hold a
    request open until its deadline, and the deadline is the slowest possible
    way to discover it.
    """

    name: str = "list_local_evidence"
    calls: int = 0

    async def generate_content_async(
        self,
        llm_request: LlmRequest,  # noqa: ARG002 - part of the model contract
        stream: bool = False,  # noqa: ARG002 - part of the model contract
    ) -> AsyncGenerator[LlmResponse, None]:
        self.calls += 1
        yield LlmResponse(
            content=types.Content(
                role="model",
                parts=[types.Part(function_call=types.FunctionCall(name=self.name, args={}))],
            )
        )


def scripted(turns: Sequence[Turn], *, name: str = "scripted-interpreter") -> ScriptedModel:
    return ScriptedModel(model=name, script=list(turns))


#  ---- the worked behaviours ----------------------------------------------


def honest_site_reading(*, gate_log: str, photograph: str) -> list[Turn]:
    """What a competent site interpreter does with the worked material.

    Lists what it holds, reads the gate log, records presence exactly and the
    duration as a **lower bound** rather than a figure.  The lower bound is the
    interesting part and it is not an accident of scripting: the log shows an
    entry and an exit, the policy needs four hours, and a source that states a
    floor discloses less than one that states a total.
    """
    return [
        Call("list_local_evidence", {}),
        Call("read_text_evidence", {"ref": gate_log}),
        Call(
            "record_observation",
            {
                "target": "T1",
                "relation": "exact",
                "value": "true",
                "observed_at": "2026-08-15T09:12:00+00:00",
                "basis": photograph,
            },
        ),
        Call(
            "record_observation",
            {
                "target": "T2",
                "relation": "at_least",
                "value": "240",
                "observed_at": "2026-08-15T09:12:00+00:00",
                "basis": gate_log,
            },
        ),
        Say("Recorded both observations from the local gate log and the attendance photograph."),
    ]


def declining(reason: str, detail: str) -> list[Turn]:
    return [Call("decline", {"reason": reason, "detail": detail}), Say("Declined.")]


@dataclass(frozen=True, slots=True)
class Recording:
    """One ``record_observation`` call, as a script fragment."""

    target: str = "T1"
    relation: str = "exact"
    value: str = "true"
    observed_at: str = "2026-08-15T09:12:00+00:00"
    basis: str = ""

    def call(self) -> Call:
        return Call(
            "record_observation",
            {
                "target": self.target,
                "relation": self.relation,
                "value": self.value,
                "observed_at": self.observed_at,
                "basis": self.basis,
            },
        )


def recording(*recordings: Recording) -> list[Turn]:
    turns: list[Turn] = [record.call() for record in recordings]
    turns.append(Say("done"))
    return turns


@dataclass(frozen=True, slots=True)
class ClaimScript:
    """The worker model's script: one claim, or a decline."""

    turns: list[Turn] = field(default_factory=list)


def claiming(target: str, value: str) -> list[Turn]:
    return [Call("record_claim", {"target": target, "value": value}), Say("Recorded.")]
