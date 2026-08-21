"""The worker agent: a person's account in, an inert claim out.

The one agent whose justification is not evidential.  A worker's narrative is
the least reliable material in the system and the most sensitive, and both facts
point the same way: interpret it where the worker is, keep the narrative there,
and let what leaves be a structured claim that moves nothing.

    "I worked Saturday too, but the payment only counted five days."
        -> present_on_site(RAVI, SAT) = true, asserted by RAVI as WORKER
        -> admitted, recorded, and consequential in no world

**Two tools, and neither of them can attest.**  There is no signer here, no
receipt builder imported, and no argument through which a source class could
arrive.  If this file wanted to mint an attestation it would have to import a
module the worker profile does not have, which is the point of building it
separately from the acquisition runtime.

**The narrative does not leave.**  What the worker typed is attached to one
model turn and is discarded with it.  It is not in the claim, not in a log line
this package writes, and not in anything the control plane receives.

**Consent is the caller's, not the model's.**  This function produces candidate
statements; whether they are submitted is a decision the worker makes in their
own interface, and there is no path from a model turn to an appended transcript
entry that does not pass through a caller who was told what would be said.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from google.adk.agents import LlmAgent
from google.adk.agents.run_config import RunConfig
from google.adk.models.base_llm import BaseLlm
from google.adk.runners import InMemoryRunner
from google.genai import types

from muster.agents.common.environment import SourceClock
from muster.agents.runtime.claims import (
    CLAIM_DECLINE_REASONS,
    CandidateClaim,
    ClaimBrief,
    ClaimDecline,
    ClaimRecorder,
    build_statements,
    validate_claims,
)
from muster.agents.runtime.interpret import InterpreterLimits
from muster.agents.runtime.observations import label_for
from muster.core.evidence.transcript import StatementRecord
from muster.core.results import Err

AGENT_NAME = "claim_intake"
CALLER_ID = "worker"

#: What the worker agent is for, and the two things it must never do.  The
#: second rule is the one that matters: a model told to be helpful will
#: cheerfully convert "I think I was there most of the day" into a duration,
#: and a duration nobody stated is a fact the worker did not assert.
STANDING_RULES = """\
You help one person state what they are claiming, in their own words, so that a
record can be made of it. You are not deciding anything and you are not
gathering evidence.

Rules, in order of precedence:

1. Record a claim only for something the person actually asserts. Do not record
   what they imply, guess at, or might mean.
2. If they are unclear, or say nothing about any of the targets below, decline.
   Declining is a correct answer.
3. Record at most one claim per target.
4. Do not tell the person what their claim will decide, whether it will help
   them, or what anyone else has said. You do not know, and it is not yours to
   say.
"""


class ClaimFailure(Enum):
    """Why an account produced no claim."""

    TIMED_OUT = "TIMED_OUT"
    MODEL_ERROR = "MODEL_ERROR"
    #: The person asserted nothing the brief asks about, or was unclear.
    NOTHING_CLAIMED = "NOTHING_CLAIMED"
    #: The model answered outside its vocabulary: an unknown target, a value
    #: that is not of the declared sort, a value outside the declared domain.
    INTERPRETATION_REJECTED = "INTERPRETATION_REJECTED"


@dataclass(frozen=True, slots=True)
class ClaimRejection:
    failure: ClaimFailure
    detail: str


@dataclass(frozen=True, slots=True)
class ClaimAgent:
    """The worker-side runtime.  Holds a clock and a model, and no key."""

    model: BaseLlm
    clock: SourceClock
    limits: InterpreterLimits

    async def interpret(
        self, brief: ClaimBrief, account: str
    ) -> tuple[StatementRecord, ...] | ClaimRejection:
        """One turn over one person's account.  Never raises."""
        recorder = ClaimRecorder()
        agent = LlmAgent(
            name=AGENT_NAME,
            model=self.model,
            description="Turns one party's own account into the claims they are making.",
            instruction=_instruction(brief),
            tools=list(_tools(recorder)),
        )
        runner = InMemoryRunner(agent, app_name=AGENT_NAME)
        try:
            await asyncio.wait_for(
                _drive(runner, account, self.limits), timeout=self.limits.timeout_seconds
            )
        except TimeoutError:
            return ClaimRejection(
                ClaimFailure.TIMED_OUT, f"{self.limits.timeout_seconds:g}s elapsed"
            )
        except Exception as failure:
            #  The type, never the message.  A model client's exception can
            #  quote the request body, and the request body here is what the
            #  worker typed -- which this agent exists to keep where he typed
            #  it.
            return ClaimRejection(ClaimFailure.MODEL_ERROR, type(failure).__name__)
        finally:
            await runner.close()

        if not recorder.candidates:
            #  The declared reason, and never the model's note.  ``decline``
            #  takes a free-text note so that an operator reading this agent's
            #  own diagnostics can see what it made of the account; carrying it
            #  out would make it the one field through which the worker's
            #  narrative could leave his own agent.
            declared = (
                recorder.declines[0][0]
                if recorder.declines
                else ClaimDecline.NOTHING_ASSERTED.value
            )
            return ClaimRejection(
                ClaimFailure.NOTHING_CLAIMED,
                #  Only a reason the tool advertises.  Anything else is a model
                #  answering outside its vocabulary, and a string it invented is
                #  not one this agent will repeat.
                declared if declared in CLAIM_DECLINE_REASONS else "declined",
            )

        validated = validate_claims(tuple(recorder.candidates), targets=brief.labelled())
        if isinstance(validated, Err):
            #  The clause, not its detail: a validation detail quotes the value
            #  the model produced, and a model that put the worker's own words
            #  in it would have them echoed back out.
            return ClaimRejection(
                ClaimFailure.INTERPRETATION_REJECTED, validated.error.failure.value
            )
        return build_statements(validated.value, brief=brief, stated_at=self.clock.now())


def _instruction(brief: ClaimBrief) -> str:
    lines = [
        STANDING_RULES,
        "",
        f"The person speaking is {brief.claimant}, taking part as {brief.role_in_case}.",
        "",
        "Targets they may be making a claim about:",
        "",
    ]
    for index, target in enumerate(brief.targets):
        arguments = ", ".join(target.proposition.args)
        lines.append(
            f"{label_for(index)}. {target.proposition.predicate_id}({arguments})\n"
            f"    means: {target.description}\n"
            f"    value: {target.value_sort}, within {target.domain}"
        )
        lines.append("")
    lines.append(
        "Read what they said, then record a claim for each target they assert, or decline."
    )
    return "\n".join(lines)


def _tools(recorder: ClaimRecorder) -> list[Callable[..., dict[str, object]]]:
    def record_claim(target: str, value: str) -> dict[str, object]:
        """Record one claim the person is actually making.

        Args:
            target: the target label from the brief, such as T1.
            value: what they assert, spelled as the target's stated type
                requires.
        """
        recorder.candidates.append(CandidateClaim(label=target, value=value))
        return {"status": "recorded", "target": target}

    def decline(reason: str, detail: str) -> dict[str, object]:
        """Decline, when the person asserts nothing about any target.

        Args:
            reason: one of nothing_asserted, unclear, out_of_scope.
            detail: a short factual note about what they said.
        """
        recorder.declines.append((reason, detail))
        #  An acknowledgement, and nothing about what would have been accepted.
        #  Echoing the permitted vocabulary back would be a retry channel: a
        #  model told which answers pass tries again until one does, which
        #  produces a well-formed answer rather than a truer one.
        return {"status": "declined"}

    return [record_claim, decline]


async def _drive(runner: InMemoryRunner, account: str, limits: InterpreterLimits) -> None:
    session = await runner.session_service.create_session(app_name=AGENT_NAME, user_id=CALLER_ID)
    async for _event in runner.run_async(
        user_id=CALLER_ID,
        session_id=session.id,
        new_message=types.Content(role="user", parts=[types.Part(text=account)]),
        run_config=RunConfig(max_llm_calls=limits.max_model_calls),
    ):
        continue
