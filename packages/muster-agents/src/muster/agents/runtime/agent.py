"""One agent, one assignment, one response.  The whole source-side pipeline.

    assignment
      -> is this mine?            tenant, agent, capability, resource scope
      -> what do I hold?          handles, per subject, scoped by coordinate
      -> interpret                one ADK turn per subject, bounded, inside
      -> validate                 sort, domain, instant, target whitelist
      -> bind and sign            tenant, case, request, schema, class, key
      -> respond                  receipts, or an abstention that says why

**Every exit before the last one is an abstention, and an abstention creates
nothing.**  A mis-routed assignment, an empty store, a timed-out model, a
malformed candidate, a value outside the pinned domain, a window that does not
cover the case's instant, a signer that will not sign -- all of them produce a
typed reason and no evidence.  There is no branch in this file that emits a
receipt any of those conditions could have reached.

**The refusals before the model run are not politeness.**  An assignment naming
a resource this source does not serve, or a predicate it does not offer, is
refused *before* a model is invoked and before a signature is spent.  Q-12
would refuse the resulting receipt anyway -- authority is decided by the
registry, not here -- so what this buys is a fleet-routing fault reported as
one, instead of an authority failure that looks like a compromised key.

**One turn per subject, and no retry.**  A rejected candidate is a defect, not
a transient, and there is no loop here that re-prompts a model whose answer was
refused.  The case is exactly as it was and its request is still outstanding;
the next round is the caller's decision, made against a durable record, rather
than this function's made against none.

**Why per subject rather than per assignment.**  An assignment may name more
than one subject -- the dispatcher groups targets by the *agent* that can
answer them, and one badge reader serves everybody on its site.  A single turn
over such an assignment would put every named subject's local material in front
of one model together, so answering about one worker would be done with another
worker's gate log in the context window.  Nothing downstream could see that had
happened: the receipts would be well-formed, correctly scoped and signed.  So
the material is partitioned by subject and each partition gets its own turn,
its own brief and its own citation set, and a subject the source holds nothing
for gets no turn at all.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from google.adk.models.base_llm import BaseLlm

from muster.agents.common.environment import NonceSource, SourceClock
from muster.agents.common.identity import SourceIdentity
from muster.agents.runtime.interpret import (
    InterpreterError,
    InterpreterLimits,
    interpret_async,
)
from muster.agents.runtime.observations import ValidatedObservation, labelled, validate_all
from muster.agents.runtime.receipts import AttestationPolicy, build_receipts
from muster.agents.runtime.toolkit import InterpretationRecorder
from muster.agents.sources.ports import (
    EvidenceHandle,
    EvidenceStoreError,
    EvidenceStoreFailure,
    SourceEvidenceStore,
)
from muster.core.authority.signing import SourceSigner
from muster.core.evidence.acquisition import (
    AbstentionReason,
    AcquiredEvidence,
    AcquisitionAbstention,
    AcquisitionAssignment,
    AcquisitionResponse,
    AcquisitionTargetSpec,
)
from muster.core.results import Err, Ok

#: What a model's declared reason means on the wire.  The mapping is total over
#: the closed list the tool advertises; anything else is a model that answered
#: outside its vocabulary, which is a rejected interpretation rather than a
#: reason of its own.
_DECLINE_REASONS: dict[str, AbstentionReason] = {
    "no_evidence": AbstentionReason.EVIDENCE_NOT_FOUND,
    "subject_not_identified": AbstentionReason.SUBJECT_NOT_IDENTIFIED,
    "ambiguous": AbstentionReason.EVIDENCE_AMBIGUOUS,
    "contradictory": AbstentionReason.EVIDENCE_CONTRADICTORY,
    "unreadable": AbstentionReason.EVIDENCE_UNREADABLE,
}

#: What an abstention says when a model declined.  A fixed phrase rather than
#: the model's own note, because the note is the one string on this path a
#: model authors and the response is the one artifact that leaves the source.
_DECLINED = "the interpreter declined"

_STORE_REASONS: dict[EvidenceStoreFailure, AbstentionReason] = {
    EvidenceStoreFailure.NOT_FOUND: AbstentionReason.EVIDENCE_NOT_FOUND,
    #  A denial *inside* the source is not "no such evidence": the material
    #  exists and this process could not read it, which is a deployment fault
    #  an operator has to see rather than an absence a case should absorb.
    EvidenceStoreFailure.ACCESS_DENIED: AbstentionReason.EVIDENCE_UNREADABLE,
    EvidenceStoreFailure.UNREADABLE: AbstentionReason.EVIDENCE_UNREADABLE,
    EvidenceStoreFailure.STORE_UNAVAILABLE: AbstentionReason.INTERPRETER_UNAVAILABLE,
}


@dataclass(frozen=True, slots=True)
class _Turn:
    """One subject's share of an assignment, and only that subject's material."""

    assignment: AcquisitionAssignment
    handles: tuple[EvidenceHandle, ...]


def _by_subject(
    targets: tuple[AcquisitionTargetSpec, ...],
) -> tuple[tuple[AcquisitionTargetSpec, ...], ...]:
    """The targets, partitioned by subject, in the order the subjects appear.

    Order is the assignment's rather than sorted, so an assignment naming one
    subject produces exactly the targets it already had -- the ordinary case,
    unchanged, and the labels a brief renders from it identical to before.
    """
    grouped: dict[str, list[AcquisitionTargetSpec]] = {}
    for target in targets:
        grouped.setdefault(target.subject, []).append(target)
    return tuple(tuple(group) for group in grouped.values())


def _spoke_first(read: list[tuple[_Turn, InterpretationRecorder]]) -> InterpretationRecorder:
    """Which turn's silence to report when no turn recorded an observation.

    A decline is the most informative of the three silences and a read failure
    the next, so the first turn that produced one is the one whose reason the
    caller reports.  Reporting the first turn's silence regardless would let a
    subject the source simply has nothing to say about mask a storage failure
    on the next one.
    """
    for _turn, recorder in read:
        if recorder.declines:
            return recorder
    for _turn, recorder in read:
        if recorder.read_failures:
            return recorder
    return read[0][1]


@dataclass(frozen=True, slots=True)
class AcquisitionAgent:
    """Everything one source-local agent is, assembled by a composition root.

    Holds no state between calls.  The durable institutional record is the
    control plane's transcript; an agent that remembered a case between
    assignments would be a second, unsigned record of it, and the first thing
    somebody would do is trust it.
    """

    identity: SourceIdentity
    store: SourceEvidenceStore
    model: BaseLlm
    signer: SourceSigner
    clock: SourceClock
    nonces: NonceSource
    limits: InterpreterLimits
    policy: AttestationPolicy

    async def acquire(self, assignment: AcquisitionAssignment) -> AcquisitionResponse:
        """Answer one assignment.  Always returns a response, never raises."""
        refusal = self._refuse_if_not_mine(assignment)
        if refusal is not None:
            return self._respond(assignment, refusal)

        prepared = self._turns(assignment)
        if isinstance(prepared, Err):
            return self._respond(assignment, _store_abstention(prepared.error))
        if not prepared.value:
            return self._respond(
                assignment,
                AcquisitionAbstention(
                    AbstentionReason.EVIDENCE_NOT_FOUND,
                    "this source holds nothing for the subject and resource asked about",
                ),
            )

        read: list[tuple[_Turn, InterpretationRecorder]] = []
        for turn in prepared.value:
            interpreted = await interpret_async(
                assignment=turn.assignment,
                source_class=self.identity.source_class,
                store=self.store,
                handles=turn.handles,
                model=self.model,
                limits=self.limits,
            )
            if isinstance(interpreted, Err):
                return self._respond(assignment, _interpreter_abstention(interpreted.error))
            read.append((turn, interpreted.value))

        if not any(recorder.candidates for _turn, recorder in read):
            return self._respond(assignment, _nothing_recorded(_spoke_first(read)))

        #  One reading, used for every turn: the instant an observation is
        #  bounded against and the instant the payload is issued at have to be
        #  the same, or a candidate can be validated against an earlier moment
        #  than the one it is signed for.  Read after the last turn, so no
        #  observation is bounded against an instant that preceded its own
        #  interpretation.
        issued_at = self.clock.now()
        observations: list[ValidatedObservation] = []
        for turn, recorder in read:
            validated = validate_all(
                tuple(recorder.candidates),
                #  This turn's targets, not the assignment's.  The labels a
                #  brief uses are positions within the turn it briefed, so
                #  validating one turn's answers against the whole assignment
                #  would let a label mean a different target than the model was
                #  shown -- and the receipt would name a subject nobody asked
                #  this turn about.
                targets=labelled(turn.assignment),
                #  **What the interpreter actually received, not what this
                #  source offered.**  A handle is listed from the manifest;
                #  whether the object behind it could be *read* is a separate
                #  question, and the answer can be no -- a rotated binding, a
                #  deleted object, a transient denial.  Validating a citation
                #  against the offered set would let an observation cite
                #  material that never loaded, so a storage failure at the
                #  source would come out as a signed attestation about evidence
                #  nobody saw.  ``reads`` holds exactly the references whose
                #  octets reached this turn, so a citation outside it -- or one
                #  naming another subject's material -- is refused by name.
                offered=frozenset(recorder.reads),
                issued_at=issued_at,
                horizon=self.policy.horizon(issued_at),
            )
            if isinstance(validated, Err):
                return self._respond(
                    assignment,
                    #  The failure, and not its detail.  A rejection detail
                    #  quotes what the model produced -- a label, a value, an
                    #  instant, a citation -- and a model that put a line of the
                    #  gate log in its ``value`` field would have it echoed
                    #  across the source boundary in the refusal.  The clause
                    #  name is what an operator needs; the rest stays inside the
                    #  source.
                    AcquisitionAbstention(
                        AbstentionReason.INTERPRETATION_REJECTED,
                        validated.error.failure.value,
                    ),
                )
            observations.extend(validated.value)

        signed = build_receipts(
            tuple(observations),
            assignment=assignment,
            identity=self.identity,
            signer=self.signer,
            issued_at=issued_at,
            nonces=self.nonces,
            policy=self.policy,
        )
        if isinstance(signed, Err):
            return self._respond(
                assignment,
                AcquisitionAbstention(
                    AbstentionReason.ASSIGNMENT_REFUSED, signed.error.failure.value
                ),
            )
        return self._respond(assignment, AcquiredEvidence(signed.value))

    def _refuse_if_not_mine(
        self, assignment: AcquisitionAssignment
    ) -> AcquisitionAbstention | None:
        """Is this assignment addressed to this agent, and can it serve all of it?

        All of it, not part of it.  The dispatcher groups an assignment's
        targets by the agent that can answer them, so a target this source does
        not serve means the routing was wrong -- and answering the part that
        happened to fit would hide the fault behind a partial success.
        """
        if assignment.tenant_id != self.identity.tenant_id:
            return AcquisitionAbstention(
                AbstentionReason.ASSIGNMENT_REFUSED,
                f"{assignment.tenant_id!r} addressed an agent of {self.identity.tenant_id!r}",
            )
        if assignment.agent_id != self.identity.agent_id:
            return AcquisitionAbstention(
                AbstentionReason.ASSIGNMENT_REFUSED,
                f"{assignment.agent_id!r} addressed {self.identity.agent_id!r}",
            )
        for target in assignment.targets:
            predicate = target.proposition.predicate_id
            if not self.identity.may_be_asked_for(predicate):
                return AcquisitionAbstention(
                    AbstentionReason.NOT_SERVED_BY_THIS_SOURCE,
                    f"{self.identity.agent_id} does not acquire {predicate}",
                )
            if not self.identity.serves(target.resource_scope):
                return AcquisitionAbstention(
                    AbstentionReason.NOT_SERVED_BY_THIS_SOURCE,
                    f"{self.identity.agent_id} does not serve "
                    f"{', '.join(str(scope) for scope in target.resource_scope)}",
                )
            if self.identity.source_class not in target.permitted_source_classes:
                #  The assignment was addressed to a class this agent does not
                #  speak as.  Refused rather than answered: a source that
                #  answered anyway would be presenting itself as an institution
                #  it is not, and Q-12(b) would refuse the receipt -- after the
                #  signature had been spent and the fault made to look like a
                #  key problem.
                return AcquisitionAbstention(
                    AbstentionReason.NOT_SERVED_BY_THIS_SOURCE,
                    f"{self.identity.source_class} was not the class asked for "
                    f"{target.proposition}",
                )
        return None

    def _turns(
        self, assignment: AcquisitionAssignment
    ) -> Ok[tuple[_Turn, ...]] | Err[EvidenceStoreError]:
        """One turn per subject, each holding only that subject's material.

        A subject this source holds nothing for produces no turn rather than an
        empty one: there is nothing to interpret, and a model asked about a
        subject with no material in front of it can only decline or invent.
        An assignment where *every* subject is like that produces no turns at
        all, which the caller reports as evidence not found.
        """
        turns: list[_Turn] = []
        for targets in _by_subject(assignment.targets):
            held = self._holdings(targets)
            if isinstance(held, Err):
                return held
            if not held.value:
                continue
            turns.append(_Turn(replace(assignment, targets=targets), held.value))
        return Ok(tuple(turns))

    def _holdings(
        self, targets: tuple[AcquisitionTargetSpec, ...]
    ) -> Ok[tuple[EvidenceHandle, ...]] | Err[EvidenceStoreError]:
        """Everything this source holds for one subject's targets.

        Listed per target and then unioned within the subject, because one
        subject's two targets may name two resource coordinates and both are
        legitimately in front of the same turn.  The union never crosses a
        subject: that is the whole of the isolation, and it is here.
        """
        found: dict[str, EvidenceHandle] = {}
        for target in targets:
            listed = self.store.handles(subject=target.subject, coordinates=target.resource_scope)
            if isinstance(listed, Err):
                return listed
            for handle in listed.value:
                found.setdefault(handle.ref, handle)
        return Ok(tuple(found[ref] for ref in sorted(found)))

    def _respond(
        self, assignment: AcquisitionAssignment, outcome: AcquiredEvidence | AcquisitionAbstention
    ) -> AcquisitionResponse:
        return AcquisitionResponse(
            tenant_id=assignment.tenant_id,
            case_id=assignment.case_id,
            request_id=assignment.request_id,
            agent_id=self.identity.agent_id,
            outcome=outcome,
        )


def _store_abstention(error: EvidenceStoreError) -> AcquisitionAbstention:
    """The failure, never its detail.

    A store's detail names an object, a path or an operating-system message,
    and all three describe the inside of a source.  The reason is what a case
    needs; where the file was is the site's own business.
    """
    return AcquisitionAbstention(_STORE_REASONS[error.failure], error.failure.value)


def _interpreter_abstention(error: InterpreterError) -> AcquisitionAbstention:
    """A model that timed out and one that raised are the same fact to a case.

    The detail carries the failure and the *type* of whatever went wrong, and
    never a message: a model client's exception can quote the request body, and
    a request body here is the source's raw material.
    """
    return AcquisitionAbstention(
        AbstentionReason.INTERPRETER_UNAVAILABLE, f"{error.failure.value}: {error.detail}"
    )


def _nothing_recorded(recorder: InterpretationRecorder) -> AcquisitionAbstention:
    """The turn ended with no observation.  Say which of three things happened.

    A model that declined, a source whose material would not read, and a model
    that simply talked are three different operational facts, and reporting one
    silence for all of them is how a fleet problem gets debugged as a model
    problem.

    **The reason is mapped and the model's own words are not carried.**  The
    ``decline`` tool takes a free-text note so that an operator reading the
    source's own diagnostics can see what the interpreter thought; carrying it
    onto the wire would make it the one field through which a model could put a
    line of a private gate log into an artifact that crosses the boundary.  The
    reason is drawn from a closed list, and a reason outside that list is a
    model answering outside its vocabulary, which is a rejected interpretation
    rather than a reason of its own.
    """
    if recorder.declines:
        reason, _note = recorder.declines[0]
        return AcquisitionAbstention(
            _DECLINE_REASONS.get(reason, AbstentionReason.INTERPRETATION_REJECTED),
            _DECLINED,
        )
    if recorder.read_failures:
        return _store_abstention(recorder.read_failures[0])
    return AcquisitionAbstention(
        AbstentionReason.INTERPRETATION_REJECTED,
        "the interpreter recorded no observation and declined none",
    )
