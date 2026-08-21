"""The closed tool set a model is given, and the sink its calls land in.

Four tools, built fresh for one invocation over one recorder, and there is no
fifth.  What a model can do inside an agent is exactly this list:

* **list the local evidence** -- handles only: an identifier, a media type, an
  operator-written label.  No content, so the listing is safe to log;
* **read one textual item** -- inside the source's boundary, where reading it
  is the whole point;
* **record an observation** -- five strings, every one of them judged later by
  deterministic code that this tool does not call;
* **decline** -- naming one of a closed set of reasons.

There is no tool that signs, no tool that submits, no tool that reaches another
case, no tool that reaches the control plane, and no tool that reaches a second
source.  ``sign_and_submit`` as a *model-callable* operation is deliberately
absent: signing happens after the run, in code no tool exposes, so the model
cannot cause a signature at all -- not even one that would have been refused.

**The recording tool validates nothing and answers nothing.**  It takes the
strings it was given, stores them, and returns an acknowledgement.  A tool that
answered "that value is out of domain" would be a retry channel: the model would
try again, and again, until something passed -- which produces a well-typed
answer rather than a truer one, and is exactly the nudged-retry loop the
architecture forbids on a single request.  Judgement happens once, after the
turn, with no way back.

**The recorder is per invocation and dies with it.**  Nothing here is shared
between assignments, so there is no state for one case to leak into another and
none for a second call to inherit.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from muster.agents.runtime.observations import CandidateObservation
from muster.agents.sources.ports import (
    EvidenceHandle,
    EvidenceStoreError,
    EvidenceStoreFailure,
    SourceEvidenceStore,
)
from muster.core.results import Err

#: What a model may name when it declines.  A closed list, mapped later onto
#: the wire contract's abstention reasons: a free-text reason would be a field
#: through which a model could describe the case, and describing the case is
#: not something a source-local interpreter has any standing to do.
DECLINE_REASONS: tuple[str, ...] = (
    "no_evidence",
    "subject_not_identified",
    "ambiguous",
    "contradictory",
    "unreadable",
)


@dataclass(slots=True)
class InterpretationRecorder:
    """Everything one model turn did, as data rather than as side effects.

    Mutable, and the only mutable value in the runtime.  It exists for the
    length of one invocation and is read once, afterwards, by code that decides
    what -- if anything -- any of it becomes.
    """

    candidates: list[CandidateObservation] = field(default_factory=list)
    declines: list[tuple[str, str]] = field(default_factory=list)
    #: Which references the interpreter actually received octets for -- both
    #: the textual items it pulled and the media attached to the opening turn.
    #:
    #: **This is the set a citation is checked against**, and it is not the same
    #: as the set of handles the source offered.  A handle comes from the
    #: manifest; whether the object behind it could be read is a separate
    #: question with a separate answer, and validating against the offered set
    #: would let a storage failure become a signed attestation about material
    #: nobody saw.  Reading a thing is still not evidence about it -- what this
    #: buys is that a source cannot stand behind something it never received.
    reads: list[str] = field(default_factory=list)
    #: Reads that failed inside the source.  Carried so that a run which
    #: produced nothing can say whether the material was missing, denied or
    #: corrupt, rather than reporting the same silence for all three.
    read_failures: list[EvidenceStoreError] = field(default_factory=list)


def build_tools(
    recorder: InterpretationRecorder,
    store: SourceEvidenceStore,
    handles: tuple[EvidenceHandle, ...],
) -> list[Callable[..., dict[str, object]]]:
    """The four tools, closed over one recorder and one source.

    ``handles`` is the listing the source already produced for *this*
    assignment -- scoped by subject and by resource coordinate before the model
    was involved.  A read for anything outside it is refused here, so the tool
    set cannot be used to enumerate a source's holdings about somebody else.
    """
    permitted = {handle.ref: handle for handle in handles}

    def list_local_evidence() -> dict[str, object]:
        """List the local evidence available for this request.

        Returns a reference, a media type and a short label for each item. It
        returns no content: use read_text_evidence to read a textual item.
        Images and other media are already attached to this conversation.
        """
        return {
            "items": [
                {"ref": handle.ref, "media_type": handle.media_type, "label": handle.label}
                for handle in handles
            ]
        }

    def read_text_evidence(ref: str) -> dict[str, object]:
        """Read one textual local evidence item by its reference.

        Args:
            ref: the reference of the item, as given by list_local_evidence.
        """
        handle = permitted.get(ref)
        if handle is None:
            return {"status": "unavailable", "reason": "no such local evidence", "ref": ref}
        if not handle.media_type.startswith("text/"):
            return {
                "status": "unavailable",
                "reason": "not a textual item; media is already attached",
                "ref": ref,
            }
        item = store.read(ref)
        if isinstance(item, Err):
            recorder.read_failures.append(item.error)
            return {"status": "unavailable", "reason": item.error.failure.value, "ref": ref}
        try:
            text = item.value.octets.decode("utf-8")
        except UnicodeDecodeError:
            #  A textual item that is not text.  Recorded as a source-side
            #  failure rather than returned as content, because handing a model
            #  a lossy decode of corrupt octets is how a corrupted file becomes
            #  a confident reading of whatever survived.
            recorder.read_failures.append(
                EvidenceStoreError(EvidenceStoreFailure.UNREADABLE, f"{ref} is not valid UTF-8")
            )
            return {"status": "unavailable", "reason": "UNREADABLE", "ref": ref}
        recorder.reads.append(ref)
        return {"status": "ok", "ref": ref, "text": text}

    def record_observation(
        target: str, relation: str, value: str, observed_at: str, basis: str
    ) -> dict[str, object]:
        """Record one observation that the local evidence directly supports.

        Call this once per target you can answer. Do not call it for a target
        the local evidence does not directly support: decline instead.

        Args:
            target: the target label from the request, such as T1.
            relation: one of exact, at_least, at_most, one_of.
            value: the observed value, spelled as the target's stated type
                requires.
            observed_at: when the evidence shows this, as an ISO-8601 timestamp
                including its UTC offset.
            basis: the reference of the local evidence item that supports it.
        """
        recorder.candidates.append(
            CandidateObservation(
                label=target,
                relation=relation,
                value=value,
                observed_at=observed_at,
                basis=basis,
            )
        )
        return {"status": "recorded", "target": target}

    def decline(reason: str, detail: str) -> dict[str, object]:
        """Decline to answer, when the local evidence does not support an answer.

        Args:
            reason: one of no_evidence, subject_not_identified, ambiguous,
                contradictory, unreadable.
            detail: a short factual note about the local evidence, with no
                conclusion about the case.
        """
        recorder.declines.append((reason, detail))
        return {"status": "declined", "reason": reason}

    return [list_local_evidence, read_text_evidence, record_observation, decline]
