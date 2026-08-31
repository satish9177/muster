"""Running one ADK agent over one assignment, under the source's own identity.

This is the only module in MUSTER that invokes a model, and it is a thin one on
purpose.  It builds an ADK ``LlmAgent`` over the closed tool set, hands it the
source's own material, runs it under a call budget and a wall-clock bound, and
returns *what the model did* -- a recorder full of untrusted strings.  It
decides nothing, validates nothing and signs nothing.

**The model is injected, never named here.**  A deployed agent is given an ADK
Gemini model; a test is given a scripted one.  Both are ``BaseLlm``, both run
through the same ``Runner``, and the code below cannot tell them apart -- which
is what makes the deterministic suite an exercise of the real agent runtime
rather than of a stand-in for it.

**Textual material is pulled by the model; media is attached.**  Reading a gate
log is a tool call, because choosing which local records to pull is a real
source-local operation and a model that pulls only what it needs reads less
than one handed everything.  Images are attached to the opening turn instead,
because a JSON tool response cannot carry an image and a round trip that
pretended otherwise would be worse than saying so.  Both paths carry content to
the configured model endpoint -- that is what an interpreter call is -- and
neither carries it anywhere else: nothing read here appears in the response
this agent returns, in a receipt, or in a log.

**Every failure is a value.**  A model that times out, exhausts its call budget,
errors, or simply talks without calling anything produces an outcome the caller
turns into an abstention.  There is no path from a failure here to a receipt.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum

from google.adk.agents import LlmAgent
from google.adk.agents.run_config import RunConfig
from google.adk.models.base_llm import BaseLlm
from google.adk.runners import InMemoryRunner
from google.genai import types

from muster.agents.runtime.brief import compose_instruction
from muster.agents.runtime.toolkit import InterpretationRecorder, build_tools
from muster.agents.sources.ports import EvidenceHandle, SourceEvidenceStore
from muster.core.evidence.acquisition import AcquisitionAssignment
from muster.core.results import Err, InvariantViolation, Ok, Result

#: The name ADK knows the interpreter by.  One name for all three profiles:
#: they run the same runtime, and a per-profile name would suggest the runtime
#: differed when only the identity and the material do.
AGENT_NAME = "source_interpreter"

#: The caller that a session is opened for.  An assignment is machine traffic
#: with no human on the other end; naming the caller honestly keeps anyone from
#: reading the session as a conversation with a person.
CALLER_ID = "control-plane"


@dataclass(frozen=True, slots=True)
class InterpreterLimits:
    """The two bounds a model invocation runs under.

    Both are required and neither has a default, for the reason the control
    plane's own limits have none: an unbounded model loop and an unbounded wait
    are failures that look like working software until the day they are not.
    """

    max_model_calls: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        if self.max_model_calls < 1:
            raise InvariantViolation(f"at least one model call: {self.max_model_calls}")
        if self.timeout_seconds <= 0:
            raise InvariantViolation(f"a positive timeout: {self.timeout_seconds}")


class InterpreterFailure(Enum):
    """Why a model invocation produced nothing usable."""

    #: The wall-clock bound elapsed.
    TIMED_OUT = "TIMED_OUT"
    #: The model, or the transport under it, raised.  Quota, authentication,
    #: an unsupported media type, a network fault -- all one fact to a case.
    MODEL_ERROR = "MODEL_ERROR"


@dataclass(frozen=True, slots=True)
class InterpreterError:
    failure: InterpreterFailure
    detail: str


async def interpret_async(
    *,
    assignment: AcquisitionAssignment,
    source_class: str,
    store: SourceEvidenceStore,
    handles: tuple[EvidenceHandle, ...],
    model: BaseLlm,
    limits: InterpreterLimits,
) -> Result[InterpretationRecorder, InterpreterError]:
    """One model turn over one assignment.  Returns what it did, never what it means."""
    recorder = InterpretationRecorder()
    opening = _opening_turn(assignment, store, handles, recorder)

    agent = LlmAgent(
        name=AGENT_NAME,
        model=model,
        description="Interprets one source's own evidence into bounded observations.",
        instruction=compose_instruction(assignment, source_class=source_class),
        tools=list(build_tools(recorder, store, handles)),
    )
    runner = InMemoryRunner(agent, app_name=AGENT_NAME)
    try:
        await asyncio.wait_for(_drive(runner, opening, limits), timeout=limits.timeout_seconds)
    except TimeoutError:
        return Err(
            InterpreterError(InterpreterFailure.TIMED_OUT, f"{limits.timeout_seconds:g}s elapsed")
        )
    except Exception as failure:
        #  Deliberately broad.  A model transport can raise a quota error, an
        #  authentication error, a protocol error or a library-specific type
        #  this package has never heard of, and every one of them means the
        #  same thing to a case: no evidence was acquired.  Narrowing this to
        #  the exceptions known today would turn tomorrow's client upgrade into
        #  an exception escaping a function that promises a ``Result``.
        return Err(InterpreterError(InterpreterFailure.MODEL_ERROR, _describe(failure)))
    finally:
        await runner.close()
    return Ok(recorder)


def interpret(
    *,
    assignment: AcquisitionAssignment,
    source_class: str,
    store: SourceEvidenceStore,
    handles: tuple[EvidenceHandle, ...],
    model: BaseLlm,
    limits: InterpreterLimits,
) -> Result[InterpretationRecorder, InterpreterError]:
    """The synchronous face of :func:`interpret_async`, for a synchronous caller.

    The control plane's commands are synchronous and so is the in-process
    transport, so an agent invoked beside one runs here.  A deployed agent
    serving an event loop uses the asynchronous form directly; calling this one
    from inside a running loop would deadlock, and Python raises rather than
    letting it.
    """
    return asyncio.run(
        interpret_async(
            assignment=assignment,
            source_class=source_class,
            store=store,
            handles=handles,
            model=model,
            limits=limits,
        )
    )


async def _drive(runner: InMemoryRunner, opening: types.Content, limits: InterpreterLimits) -> None:
    """Run the agent to completion, discarding every event it emits.

    The events are discarded because none of them is an answer.  What the model
    *said* is prose, and prose is not something this system has any way to
    admit; what it *did* is in the recorder, and the recorder is what is judged.
    """
    session = await runner.session_service.create_session(app_name=AGENT_NAME, user_id=CALLER_ID)
    config = RunConfig(max_llm_calls=limits.max_model_calls)
    async for _event in runner.run_async(
        user_id=CALLER_ID, session_id=session.id, new_message=opening, run_config=config
    ):
        continue


def _opening_turn(
    assignment: AcquisitionAssignment,
    store: SourceEvidenceStore,
    handles: tuple[EvidenceHandle, ...],
    recorder: InterpretationRecorder,
) -> types.Content:
    """The first message: the request, plus any media the model cannot pull itself.

    A non-textual item is read here and attached, and the read failure is
    recorded rather than raised: a site whose camera file is missing should
    still get its gate log interpreted, and the caller needs the failure in
    order to abstain with the right reason if nothing else works either.
    """
    parts: list[types.Part] = [
        types.Part(
            text=(
                f"Evidence request {assignment.request_id.hex[:12]} for "
                f"{len(assignment.targets)} target(s). Begin."
            )
        )
    ]
    for handle in handles:
        if handle.media_type.startswith("text/"):
            continue
        item = store.read(handle.ref)
        if isinstance(item, Err):
            recorder.read_failures.append(item.error)
            continue
        recorder.reads.append(handle.ref)
        parts.append(types.Part(text=f"Attached local evidence '{handle.ref}': {handle.label}"))
        parts.append(
            types.Part(inline_data=types.Blob(mime_type=handle.media_type, data=item.value.octets))
        )
    return types.Content(role="user", parts=parts)


def _describe(failure: BaseException) -> str:
    """A failure's type, and nothing else.

    **Not its message.**  A model client's exception can quote the request body
    it failed on, and a request body here is the source's raw material -- so a
    truncated message is a truncated leak rather than a safe one, and this
    value travels: the caller turns it into an abstention detail, which is
    encoded into the response that crosses the source boundary.

    A type name is enough to tell a quota error from an authentication error
    from a transport error, which is what an operator is deciding between. The
    message stays inside the source, where an operator with access to the agent
    can read it beside the material it is about.
    """
    return type(failure).__name__
