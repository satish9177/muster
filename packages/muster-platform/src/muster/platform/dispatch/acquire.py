"""Driving one round of acquisition: ask, check the envelope, admit the answer.

The loop is short on purpose, because every interesting property is somewhere
else:

    outstanding requests  ->  assignments  ->  transport  ->  envelope checks
                                                          ->  AppendTranscriptEntry

**The last arrow is the ordinary command.**  There is no shortcut, no
"pre-verified" flag and no second admission path -- a receipt that arrived
through a deployed agent is admitted by exactly the function that admits a
receipt pasted in by an operator, and is judged by check Q-12 against the
authority snapshot the case pinned.  That is what makes "routing grants no
authority" a fact about the code rather than a sentence in a document.

**The envelope checks in between are narrowing, never widening.**  They compare
what came back against what was asked -- this tenant, this case, this request,
this agent, this proposition, this source class -- and every one of them can
only *remove* a receipt from the batch.  None of them can admit anything, and
none of them is consulted downstream.  They exist because a refusal that
happens before an entry becomes durable is worth more than the same refusal
afterwards: transcript membership is append-only, and an entry nothing can
remove is not "no effect".

**A refused receipt does not cost the batch.**  Each receipt is judged and
submitted independently, so a source that answers the two propositions it was
asked for and adds a third nobody asked for has the third dropped and the first
two admitted.  Refusing everything on the strength of the extra one would make
the safest behaviour -- reporting more than was asked -- the most expensive.

**And nothing here retries.**  A transport failure leaves the case exactly as
it was, with its request still outstanding and its deadline still running; the
caller drives another round or the deadline escalates.  A retry loop inside
this function would be a second scheduler with no durable state, and the one
failure it could not survive is the one it would cause: a source answering
twice with two independently signed receipts for one proposition, which the
rebuild refuses as a duplicate and which would freeze the case if it ever
became durable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.case.revision import AuthorizationContext
from muster.core.evidence.acquisition import (
    AcquiredEvidence,
    AcquisitionAbstention,
    AcquisitionAssignment,
    AcquisitionResponse,
    read_acquisition_response,
)
from muster.core.evidence.delivery import AcquisitionTransport, TransportError
from muster.core.evidence.requests import EvidenceRequest, read_evidence_request
from muster.core.evidence.transcript import (
    Attestation,
    CaseConstructionRecord,
    VerificationReceipt,
)
from muster.core.results import Err, Ok, Result
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import Instant
from muster.core.wire.codec import decode, encode
from muster.core.wire.digests import Digest, DigestKind
from muster.core.wire.shape import decoded
from muster.platform.casework.advance import Advanced, AdvanceRejection, Casework
from muster.platform.casework.commands import AppendRejection, append_transcript_entry
from muster.platform.casework.ports import RecordedRequest, TenantScope
from muster.platform.casework.snapshot import SnapshotError, read_case_inputs
from muster.platform.dispatch.assign import (
    AddressedAssignment,
    UnroutableTarget,
    assign_request,
)
from muster.policy.manifest import LoadedBundle


class SubmissionFailure(Enum):
    """Why a reply was not submitted for admission.

    Every member is a comparison between what came back and what was asked, so
    every one of them is answerable by the responder -- and none of them is a
    statement about authority, which is decided afterwards and elsewhere.
    """

    #: The octets are not a canonical acquisition response.
    RESPONSE_UNREADABLE = "RESPONSE_UNREADABLE"
    #: The envelope names another tenant, case or request.
    RESPONSE_NOT_FOR_THIS_REQUEST = "RESPONSE_NOT_FOR_THIS_REQUEST"
    #: The envelope names an agent other than the one addressed.  Network
    #: identity is a different question asked at a different layer; this one
    #: is "did the agent we routed to answer the assignment we sent it".
    RESPONSE_FROM_ANOTHER_AGENT = "RESPONSE_FROM_ANOTHER_AGENT"
    #: The signed payload cites a different request.  A reply to a question
    #: nobody asked in this round is not submitted, whatever else is true of
    #: it -- including a reply bound to a request this case has since
    #: superseded, which is a stale answer to a stale revision.
    RECEIPT_NOT_BOUND_TO_THIS_REQUEST = "RECEIPT_NOT_BOUND_TO_THIS_REQUEST"
    #: The signed payload names another tenant or case.
    RECEIPT_NOT_FOR_THIS_CASE = "RECEIPT_NOT_FOR_THIS_CASE"
    #: The payload carries a proposition the assignment never named.  A source
    #: answers what it was asked; it does not decide what else the case
    #: should learn about the subject.
    UNREQUESTED_PROPOSITION = "UNREQUESTED_PROPOSITION"
    #: The payload declares a source class the assignment did not address.  A
    #: source cannot promote itself into another institution's class -- and
    #: Q-12(b) would refuse it anyway, one layer further in.
    UNPERMITTED_SOURCE_CLASS = "UNPERMITTED_SOURCE_CLASS"
    #: The payload names a different subject than the assignment did.
    #:
    #: ``subject`` is signed provenance that no downstream check reads -- not
    #: the rebuild, not Q-12, not a view -- so it is correct today only because
    #: an honest agent copies it from the target it was given.  A source that
    #: attributed an observation to somebody the case never asked about would
    #: put an unverifiable name inside a signature, permanently, and nothing
    #: further in would notice.  It is compared here because here is the last
    #: place that holds both the answer and the question.
    UNREQUESTED_SUBJECT = "UNREQUESTED_SUBJECT"
    #: The receipt was submitted and the admission path refused it.  The detail
    #: carries the admission rejection, including the Q-12 clause.
    ADMISSION_REFUSED = "ADMISSION_REFUSED"


@dataclass(frozen=True, slots=True)
class SubmissionError:
    failure: SubmissionFailure
    detail: str


@dataclass(frozen=True, slots=True)
class AdmittedReceipt:
    """One receipt that became transcript membership, and what followed."""

    proposition: SymbolRef
    entry_digest: Digest
    #: ``False`` when the entry was already a member -- a duplicate delivery,
    #: and a success.  Structural idempotence: a receipt is identified by its
    #: own digest, so re-delivering the same octets adds nothing.
    created: bool
    advanced: Result[Advanced, AdvanceRejection]


@dataclass(frozen=True, slots=True)
class RefusedReceipt:
    """One receipt that was not admitted, and the reason it was not."""

    proposition: SymbolRef
    error: SubmissionError


@dataclass(frozen=True, slots=True)
class Unreachable:
    """The assignment never arrived.  The case is exactly as it was."""

    error: TransportError


@dataclass(frozen=True, slots=True)
class Abstained:
    """The source answered and declined to attest.  Also a non-event."""

    abstention: AcquisitionAbstention


@dataclass(frozen=True, slots=True)
class EnvelopeRefused:
    """The reply did not answer the assignment.  Nothing was submitted."""

    error: SubmissionError


@dataclass(frozen=True, slots=True)
class Answered:
    """The source attested.  Each receipt was judged and submitted on its own."""

    admitted: tuple[AdmittedReceipt, ...]
    refused: tuple[RefusedReceipt, ...]


type ExchangeResult = Unreachable | Abstained | EnvelopeRefused | Answered


@dataclass(frozen=True, slots=True)
class AgentExchange:
    """One assignment, sent to one agent, and everything that came of it."""

    assignment: AcquisitionAssignment
    endpoint_ref: str
    result: ExchangeResult


@dataclass(frozen=True, slots=True)
class AcquisitionReport:
    """One outstanding request, after one round of acquisition."""

    request_id: Digest
    exchanges: tuple[AgentExchange, ...]
    unroutable: tuple[UnroutableTarget, ...]


class AcquisitionFailure(Enum):
    """Why a round could not be run at all.  None of these admits anything."""

    SNAPSHOT_REFUSED = "SNAPSHOT_REFUSED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    REQUESTS_UNREADABLE = "REQUESTS_UNREADABLE"


@dataclass(frozen=True, slots=True)
class AcquisitionRejection:
    failure: AcquisitionFailure
    detail: str


def acquire_outstanding(
    casework: Casework,
    transport: AcquisitionTransport,
    *,
    tenant_id: str,
    case_id: str,
    now: Instant,
) -> Result[tuple[AcquisitionReport, ...], AcquisitionRejection]:
    """Run one acquisition round for every request this case has outstanding.

    Idempotent and re-drivable, for the same reason every other command here
    is: a receipt is identified by its own digest and membership is a set, so a
    round that re-delivers an answer the case already holds adds nothing and
    reports the duplicate as such.

    Requests are handled in ascending request-digest order, which is the order
    both repositories return them in.  Nothing about the result depends on it,
    and fixing it anyway is what keeps two runs of one case comparable.
    """
    prepared = _prepare(casework, tenant_id=tenant_id, case_id=case_id)
    if isinstance(prepared, Err):
        return prepared
    context = prepared.value

    reports: list[AcquisitionReport] = []
    for recorded, request in context.outstanding:
        reports.append(
            _run_one(
                casework,
                transport,
                tenant_id=tenant_id,
                case_id=case_id,
                context=context,
                recorded=recorded,
                request=request,
                now=now,
            )
        )
    return Ok(tuple(reports))


@dataclass(frozen=True, slots=True)
class _Context:
    """Everything a round reads once, before it starts asking anybody."""

    construction: CaseConstructionRecord
    authorization_context: AuthorizationContext
    bundle: LoadedBundle
    as_of: Instant
    outstanding: tuple[tuple[RecordedRequest, EvidenceRequest], ...]


def _prepare(
    casework: Casework, *, tenant_id: str, case_id: str
) -> Result[_Context, AcquisitionRejection]:
    with casework.database.reading(tenant_id) as scope:
        inputs = read_case_inputs(
            scope, case_id, casework.publisher_verifier, casework.officer_verifier
        )
        if isinstance(inputs, Err):
            return Err(_snapshot_refused(inputs.error))
        recorded = scope.requests.outstanding(case_id)
        if isinstance(recorded, Err):
            return Err(
                AcquisitionRejection(
                    AcquisitionFailure.REQUESTS_UNREADABLE,
                    f"{recorded.error.failure.value}: {recorded.error.detail}",
                )
            )
        resolved: list[tuple[RecordedRequest, EvidenceRequest]] = []
        for row in recorded.value:
            request = _read_request(scope, row.request_id)
            if request is None:
                #  Stored by the publication that recorded the row, under a
                #  foreign key to it, so an unreadable one is corruption rather
                #  than absence -- and a request whose targets cannot be read
                #  cannot be resolved into anything a source could answer.
                return Err(
                    AcquisitionRejection(
                        AcquisitionFailure.REQUESTS_UNREADABLE,
                        f"{row.request_id.hex[:12]} cannot be read",
                    )
                )
            resolved.append((row, request))

    loaded = casework.registry.load_by_digest(inputs.value.head.inputs.bundle_manifest_digest)
    if isinstance(loaded, Err):
        return Err(
            AcquisitionRejection(
                AcquisitionFailure.POLICY_UNAVAILABLE,
                f"{loaded.error.failure.value}: {loaded.error.detail}",
            )
        )
    return Ok(
        _Context(
            construction=inputs.value.construction,
            authorization_context=inputs.value.authorization_context,
            bundle=loaded.value,
            as_of=inputs.value.head.inputs.as_of,
            outstanding=tuple(resolved),
        )
    )


def _snapshot_refused(error: SnapshotError) -> AcquisitionRejection:
    return AcquisitionRejection(
        AcquisitionFailure.SNAPSHOT_REFUSED, f"{error.failure.value}: {error.detail}"
    )


def _read_request(scope: TenantScope, request_id: Digest) -> EvidenceRequest | None:
    stored = scope.content.get(DigestKind.EVIDENCE_REQUEST, request_id)
    if isinstance(stored, Err):
        return None
    node = decode(stored.value)
    if isinstance(node, Err):  # pragma: no cover - the store re-derives the digest
        return None
    request = decoded(lambda: read_evidence_request(node.value))
    if isinstance(request, Err):  # pragma: no cover - stored by this package
        return None
    return request.value


def _run_one(
    casework: Casework,
    transport: AcquisitionTransport,
    *,
    tenant_id: str,
    case_id: str,
    context: _Context,
    recorded: RecordedRequest,
    request: EvidenceRequest,
    now: Instant,
) -> AcquisitionReport:
    with casework.database.reading(tenant_id) as scope:
        assignments = assign_request(
            scope,
            casework.publisher_verifier,
            request=request,
            construction=context.construction,
            authorization_context=context.authorization_context,
            bundle=context.bundle,
            as_of=context.as_of,
            deadline=recorded.deadline,
        )

    exchanges = tuple(
        _exchange(
            casework, transport, tenant_id=tenant_id, case_id=case_id, addressed=addressed, now=now
        )
        for addressed in assignments.deliverable
    )
    return AcquisitionReport(recorded.request_id, exchanges, assignments.unroutable)


def _exchange(
    casework: Casework,
    transport: AcquisitionTransport,
    *,
    tenant_id: str,
    case_id: str,
    addressed: AddressedAssignment,
    now: Instant,
) -> AgentExchange:
    assignment = addressed.assignment
    endpoint_ref = addressed.profile.endpoint_ref
    delivered = transport.deliver(
        endpoint_ref=endpoint_ref, assignment=encode(assignment.to_node())
    )
    if isinstance(delivered, Err):
        return AgentExchange(assignment, endpoint_ref, Unreachable(delivered.error))

    response = _read_response(delivered.value)
    if isinstance(response, Err):
        return AgentExchange(assignment, endpoint_ref, EnvelopeRefused(response.error))

    bound = _check_envelope(response.value, assignment)
    if isinstance(bound, Err):
        return AgentExchange(assignment, endpoint_ref, EnvelopeRefused(bound.error))

    outcome = response.value.outcome
    if isinstance(outcome, AcquisitionAbstention):
        return AgentExchange(assignment, endpoint_ref, Abstained(outcome))

    return AgentExchange(
        assignment,
        endpoint_ref,
        _submit_all(
            casework,
            tenant_id=tenant_id,
            case_id=case_id,
            assignment=assignment,
            acquired=outcome,
            now=now,
        ),
    )


def _read_response(octets: bytes) -> Result[AcquisitionResponse, SubmissionError]:
    node = decode(octets)
    if isinstance(node, Err):
        return Err(SubmissionError(SubmissionFailure.RESPONSE_UNREADABLE, str(node.error)))
    read = decoded(lambda: read_acquisition_response(node.value))
    if isinstance(read, Err):
        return Err(SubmissionError(SubmissionFailure.RESPONSE_UNREADABLE, str(read.error)))
    return Ok(read.value)


def _check_envelope(
    response: AcquisitionResponse, assignment: AcquisitionAssignment
) -> Result[None, SubmissionError]:
    """Did the agent we asked answer the assignment we sent it?

    Four equalities, and none of them establishes anything: the envelope is
    written by the responder, so agreement proves only that the responder is
    consistent with what it was handed.  Disagreement, on the other hand, is
    decisive -- a reply about another case cannot be an answer to this one.
    """
    if response.agent_id != assignment.agent_id:
        return Err(
            SubmissionError(
                SubmissionFailure.RESPONSE_FROM_ANOTHER_AGENT,
                f"{assignment.agent_id!r} was asked and {response.agent_id!r} answered",
            )
        )
    for name, expected, found in (
        ("tenant", assignment.tenant_id, response.tenant_id),
        ("case", assignment.case_id, response.case_id),
    ):
        if expected != found:
            return Err(
                SubmissionError(
                    SubmissionFailure.RESPONSE_NOT_FOR_THIS_REQUEST,
                    f"{name} {found!r} answered an assignment for {expected!r}",
                )
            )
    if response.request_id != assignment.request_id:
        return Err(
            SubmissionError(
                SubmissionFailure.RESPONSE_NOT_FOR_THIS_REQUEST,
                f"{response.request_id.hex[:12]} answered {assignment.request_id.hex[:12]}",
            )
        )
    return Ok(None)


def _submit_all(
    casework: Casework,
    *,
    tenant_id: str,
    case_id: str,
    assignment: AcquisitionAssignment,
    acquired: AcquiredEvidence,
    now: Instant,
) -> Answered:
    admitted: list[AdmittedReceipt] = []
    refused: list[RefusedReceipt] = []
    for receipt in acquired.receipts:
        checked = _check_receipt(receipt, assignment)
        if isinstance(checked, Err):
            refused.append(RefusedReceipt(receipt.payload.proposition, checked.error))
            continue
        appended = append_transcript_entry(
            casework,
            tenant_id=tenant_id,
            case_id=case_id,
            entry=Attestation(receipt),
            now=now,
        )
        if isinstance(appended, Err):
            refused.append(
                RefusedReceipt(receipt.payload.proposition, _admission_refused(appended.error))
            )
            continue
        admitted.append(
            AdmittedReceipt(
                proposition=receipt.payload.proposition,
                entry_digest=appended.value.entry_digest,
                created=appended.value.created,
                advanced=appended.value.advanced,
            )
        )
    return Answered(tuple(admitted), tuple(refused))


def _check_receipt(
    receipt: VerificationReceipt, assignment: AcquisitionAssignment
) -> Result[None, SubmissionError]:
    """Is this signed payload an answer to something this assignment asked for?

    The request binding is checked here as well as at admission, and the two
    are not the same check.  Admission asks whether the case has *anything*
    outstanding that permits this class, which is a question about the case;
    this asks whether the receipt answers *this* assignment, which is a
    question about the round.  A source returning a receipt bound to an earlier
    request would pass the first as volunteered evidence and fails the second,
    and failing it is right: a dispatcher that submitted a stale answer as
    though it were the reply it had just asked for would be reporting a round
    that did not happen.
    """
    payload = receipt.payload
    if payload.tenant_id != assignment.tenant_id or payload.case_id != assignment.case_id:
        return Err(
            SubmissionError(
                SubmissionFailure.RECEIPT_NOT_FOR_THIS_CASE,
                f"{payload.tenant_id}/{payload.case_id} answered "
                f"{assignment.tenant_id}/{assignment.case_id}",
            )
        )
    if payload.request_id != assignment.request_id:
        return Err(
            SubmissionError(
                SubmissionFailure.RECEIPT_NOT_BOUND_TO_THIS_REQUEST,
                f"{payload.proposition} cites {payload.request_id.hex[:12]}, "
                f"not {assignment.request_id.hex[:12]}",
            )
        )
    target = assignment.target_for(payload.proposition)
    if target is None:
        return Err(
            SubmissionError(
                SubmissionFailure.UNREQUESTED_PROPOSITION,
                f"{payload.proposition} was not asked for",
            )
        )
    if payload.source_class not in target.permitted_source_classes:
        return Err(
            SubmissionError(
                SubmissionFailure.UNPERMITTED_SOURCE_CLASS,
                f"{payload.source_class} answered a target addressed to "
                f"{', '.join(target.permitted_source_classes)}",
            )
        )
    if payload.subject != target.subject:
        return Err(
            SubmissionError(
                SubmissionFailure.UNREQUESTED_SUBJECT,
                f"{payload.subject!r} answered a target about {target.subject!r}",
            )
        )
    return Ok(None)


def _admission_refused(rejection: AppendRejection) -> SubmissionError:
    return SubmissionError(
        SubmissionFailure.ADMISSION_REFUSED, f"{rejection.failure.value}: {rejection.detail}"
    )
