"""The acquisition protocol: what a control plane asks a source, and what comes back.

An :class:`~muster.core.evidence.requests.EvidenceRequest` says *what the case
needs*.  It does not say what a source would have to know to answer -- the sort
a value must carry, the domain it must lie in, the schema pin the reply must
cite, the instant its validity has to cover, or the resource coordinate the
authority registry will test it against.  All of that lives in the pinned
bundle, the pinned authorization context and the officer-signed construction
record, and a source holds none of them.

So the assignment below is the **resolved** form of one request for one source:
every field is derived from artifacts the source could not choose, and the
source is handed exactly enough to produce a well-formed reply and nothing more.

Three properties decide the shape.

**It is a transport artifact, not a signed one.**  Nothing here is digested and
nothing here is signed, deliberately -- there is no digest domain for any of
it.  Authority travels in the opposite direction: the *receipts* inside a
response are signed by the source and judged by check Q-12 against the snapshot
the case pinned, and an assignment that carried a signature would invite a
reader to treat "the control plane asked for this" as a reason to admit the
answer.  It is not one.  Deleting every assignment ever sent would change which
evidence gets acquired and would change no admission decision.

**It narrows and never widens.**  ``permitted_source_classes`` here is the
bundle's set for the predicate intersected with the request target's, which is
both halves of Q-12(a) already resolved; ``resource_scope`` is the exact
coordinate set Q-12(d) will test.  A source reading this can refuse *before*
spending a signature on something the registry would reject -- which is the
whole purpose of a pre-check, and is why the resolved values travel rather than
the raw inputs a source would have to resolve for itself.

**A response binds to the request it answers.**  ``request_id`` is the digest
of the ``EvidenceRequest``, it is inside every signed payload, and it is
repeated on the response envelope so that a reply reaching the wrong case, the
wrong revision or the wrong agent is refused on the envelope before a signature
is verified.  The envelope's own claims are unauthenticated and are treated as
such: they can only ever produce a refusal, never an acceptance.

**And a source may decline.**  Abstention is a first-class outcome with its own
reasons, because the alternative -- a source that must answer -- is a source
that will guess.  An abstention creates no evidence, moves no value and leaves
the case exactly as it was.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.authority.scope import ResourceScope, read_scope_set, scope_set
from muster.core.evidence.transcript import (
    VerificationReceipt,
    read_verification_receipt,
)
from muster.core.results import InvariantViolation, Result
from muster.core.values.classification import AcquisitionClass, EvidenceLayer
from muster.core.values.sorts import Domain, Sort, read_domain, read_sort
from muster.core.values.symbols import SymbolRef, read_symbol_ref
from muster.core.values.times import Instant
from muster.core.wire.codec import canonical_set
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import NAtom, NInt, Node, NRec, NSeq, NTagged
from muster.core.wire.shape import (
    WireError,
    WireFailure,
    atom_or_none,
    decoded,
    fail,
    option_node,
    read_atom,
    read_digest,
    read_int,
    read_member,
    read_option,
    read_rec,
    read_seq,
    read_set,
    read_tagged,
)

TAG_ACQUISITION_TARGET_SPEC = "AcquisitionTargetSpec/v1"
TAG_ACQUISITION_ASSIGNMENT = "AcquisitionAssignment/v1"
TAG_ACQUIRED_EVIDENCE = "AcquiredEvidence/v1"
TAG_ACQUISITION_ABSTENTION = "AcquisitionAbstention/v1"
TAG_ACQUISITION_RESPONSE = "AcquisitionResponse/v1"

_LAYERS = frozenset(member.value for member in EvidenceLayer)
_ACQUISITION_CLASSES = frozenset(member.value for member in AcquisitionClass)


@dataclass(frozen=True, slots=True)
class AcquisitionTargetSpec:
    """One proposition a source is being asked about, fully resolved.

    ``value_sort``, ``domain``, ``layer``, ``acquisition`` and
    ``measurement_class`` are the pinned bundle's declaration for the
    predicate, copied here rather than referenced, because a source holds no
    bundle and must not be asked to resolve one.  Copying is safe precisely
    because none of it is authority: a source that lied about the sort it was
    given would produce a receipt whose sort fails Q-4 at rebuild, judged
    against the bundle rather than against this.

    ``resource_scope`` is the coordinate set Q-12(d) will test -- resolved by
    the control plane from the pinned schema and the officer-signed
    construction record, so that a source can compare it against what it
    actually holds and decline rather than sign something the registry will
    refuse.

    A target for a predicate that is not ``ATTESTABLE`` is not constructible.
    A derived conclusion has no source, and offering one to an agent would be
    offering it something no key could ever carry.
    """

    proposition: SymbolRef
    #: The case participant the observation is *about*, for provenance.  It is
    #: resolved by the control plane from the construction record's declared
    #: subjects; a source neither chooses it nor is believed about it.
    subject: str
    value_sort: Sort
    domain: Domain
    layer: EvidenceLayer
    acquisition: AcquisitionClass
    #: Which classes may answer *this* target, resolved by the control plane.
    #:
    #: It is at most both halves of Q-12(a) intersected -- the bundle's
    #: permitted classes for this predicate, narrowed by what the request's own
    #: target permits -- and a producer may narrow it further, to the single
    #: class it actually routed to.  MUSTER's own dispatcher does exactly that:
    #: telling the badge reader that the payroll system would also have been
    #: acceptable is information it has no use for, and one field closer to a
    #: source choosing its own class.
    #:
    #: A source compares its own configured class against this and declines if
    #: it is absent.  Narrowing is therefore always safe and never necessary:
    #: the receipt is judged again at admission against the set the rebuild
    #: resolves for itself, and this field cannot widen that.
    permitted_source_classes: tuple[str, ...]
    resource_scope: tuple[ResourceScope, ...]
    measurement_class: str | None

    def __post_init__(self) -> None:
        if not self.subject:
            raise InvariantViolation(f"an acquisition target names a subject: {self.proposition}")
        if self.acquisition is not AcquisitionClass.ATTESTABLE:
            raise InvariantViolation(
                f"{self.proposition} is {self.acquisition.value} and no source may attest it"
            )
        if self.layer is EvidenceLayer.NORMATIVE:
            #  Unreachable through ``ATTESTABLE`` under a well-formed bundle --
            #  the schema refuses a normative attestable predicate when it
            #  loads -- and refused here as well, because "the bundle would
            #  have caught it" is a property of a different artifact.
            raise InvariantViolation(f"{self.proposition} is NORMATIVE and has no source")
        if not self.permitted_source_classes:
            raise InvariantViolation(f"no source class may answer for {self.proposition}")
        if not self.resource_scope:
            #  Q-12(d) refuses an empty coordinate set rather than reading it
            #  as unrestricted, so an assignment carrying one would be asking a
            #  source for something that could never be authorized.
            raise InvariantViolation(f"{self.proposition} resolves no resource coordinate")

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACQUISITION_TARGET_SPEC,
            (
                self.proposition.to_node(),
                NAtom(self.subject),
                self.value_sort.to_node(),
                self.domain.to_node(),
                NAtom(self.layer.value),
                NAtom(self.acquisition.value),
                canonical_set(NAtom(source) for source in self.permitted_source_classes),
                scope_set(self.resource_scope),
                option_node(atom_or_none(self.measurement_class)),
            ),
        )


def read_acquisition_target_spec(node: Node) -> AcquisitionTargetSpec:
    fields = read_rec(node, TAG_ACQUISITION_TARGET_SPEC, 9)
    return AcquisitionTargetSpec(
        proposition=read_symbol_ref(fields[0]),
        subject=read_atom(fields[1]),
        value_sort=read_sort(fields[2]),
        domain=read_domain(fields[3]),
        layer=EvidenceLayer(read_member(fields[4], _LAYERS, "EvidenceLayer")),
        acquisition=AcquisitionClass(
            read_member(fields[5], _ACQUISITION_CLASSES, "AcquisitionClass")
        ),
        permitted_source_classes=read_set(fields[6], read_atom, minimum=1),
        resource_scope=read_scope_set(fields[7], minimum=1),
        measurement_class=read_option(fields[8], read_atom),
    )


@dataclass(frozen=True, slots=True)
class AcquisitionAssignment:
    """One request, resolved for one cataloged agent.

    ``as_of`` is the revision's own instant, and it is here because a receipt
    is admissible only inside the validity window it was signed for, judged
    against that instant and never against a clock.  A source that declared a
    window not covering it would produce a receipt that is admitted, stored
    forever, and inert -- so the instant travels, and the source can refuse
    instead.

    ``deadline`` is the control plane's wall-clock intent for the request and
    is operational rather than semantic: passing it changes no admission
    decision, it changes whether the case has already escalated.

    Nothing else about the case travels.  Not the parties, not the other
    propositions, not the policy, not what has already been established, and
    not what the answer would decide.  An agent that knew whether its answer
    settles the case is an agent with a reason to prefer one answer.
    """

    tenant_id: str
    case_id: str
    #: The digest of the ``EvidenceRequest`` this assignment resolves.  Every
    #: signed reply carries it, and the response envelope repeats it.
    request_id: Digest
    revision_semantic_digest: Digest
    #: Q-9's pin: the predicate schema a reply must cite to be interpretable.
    predicate_schema_digest: Digest
    authorization_policy_version: int
    as_of: Instant
    deadline: Instant
    #: The cataloged agent this assignment was addressed to.  Repeated on the
    #: response, so a reply from somewhere else is refused on the envelope.
    agent_id: str
    targets: tuple[AcquisitionTargetSpec, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant", self.tenant_id),
            ("case", self.case_id),
            ("agent", self.agent_id),
        ):
            if not value:
                raise InvariantViolation(f"an acquisition assignment names a {name}")
        if not self.targets:
            raise InvariantViolation("an acquisition assignment names at least one target")
        propositions = [target.proposition for target in self.targets]
        if len(set(propositions)) != len(propositions):
            raise InvariantViolation("acquisition targets are unique by proposition")

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACQUISITION_ASSIGNMENT,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                self.request_id.to_node(),
                self.revision_semantic_digest.to_node(),
                self.predicate_schema_digest.to_node(),
                NInt(self.authorization_policy_version),
                NInt(self.as_of),
                NInt(self.deadline),
                NAtom(self.agent_id),
                NSeq(tuple(target.to_node() for target in self.targets)),
            ),
        )

    def target_for(self, proposition: SymbolRef) -> AcquisitionTargetSpec | None:
        """The target naming this proposition, or ``None`` if it was not asked for.

        Absence is the answer that keeps an agent from broadening a request: a
        candidate observation over a proposition nothing here names has no
        specification to be validated against, and is refused rather than
        validated against a default.
        """
        for target in self.targets:
            if target.proposition == proposition:
                return target
        return None


def read_acquisition_assignment(node: Node) -> AcquisitionAssignment:
    fields = read_rec(node, TAG_ACQUISITION_ASSIGNMENT, 10)
    return AcquisitionAssignment(
        tenant_id=read_atom(fields[0]),
        case_id=read_atom(fields[1]),
        request_id=read_digest(fields[2]),
        revision_semantic_digest=read_digest(fields[3]),
        predicate_schema_digest=read_digest(fields[4]),
        authorization_policy_version=read_int(fields[5]),
        as_of=read_int(fields[6]),
        deadline=read_int(fields[7]),
        agent_id=read_atom(fields[8]),
        targets=read_seq(fields[9], read_acquisition_target_spec, minimum=1),
    )


def decode_acquisition_assignment(node: Node) -> Result[AcquisitionAssignment, WireError]:
    return decoded(lambda: read_acquisition_assignment(node))


class AbstentionReason(Enum):
    """Why a source produced no evidence.  Every member fails safe.

    An abstention is a *success* of the protocol and a non-event for the case:
    nothing is admitted, nothing is established, and the unresolved set is
    exactly what it was.  The members are distinct because the operational
    responses differ completely -- a source that holds no such evidence needs a
    different fleet than one whose interpreter timed out, and both differ from
    one that read its evidence and found it did not support an answer.

    There is deliberately no ``LOW_CONFIDENCE`` member.  A confidence figure is
    not a fact about the world, and a reason named after one would invite a
    reader to convert it into a threshold and the threshold into a truth.
    """

    #: The source holds nothing matching the assignment's resource and subject.
    EVIDENCE_NOT_FOUND = "EVIDENCE_NOT_FOUND"
    #: Evidence exists and does not identify the named subject.
    SUBJECT_NOT_IDENTIFIED = "SUBJECT_NOT_IDENTIFIED"
    #: Evidence exists, is readable, and supports no single answer.
    EVIDENCE_AMBIGUOUS = "EVIDENCE_AMBIGUOUS"
    #: Two local records disagree.  Refused rather than arbitrated.
    EVIDENCE_CONTRADICTORY = "EVIDENCE_CONTRADICTORY"
    #: The material could not be read: corrupt, truncated, unsupported media.
    EVIDENCE_UNREADABLE = "EVIDENCE_UNREADABLE"
    #: The interpreter did not answer -- timeout, quota, transport failure.
    INTERPRETER_UNAVAILABLE = "INTERPRETER_UNAVAILABLE"
    #: The interpreter answered and the answer was refused by the validator:
    #: malformed, out of domain, wrong sort, or about something nobody asked.
    INTERPRETATION_REJECTED = "INTERPRETATION_REJECTED"
    #: The assignment names a resource or a predicate this source does not
    #: serve.  A routing fault, and a refusal rather than an attempt.
    NOT_SERVED_BY_THIS_SOURCE = "NOT_SERVED_BY_THIS_SOURCE"
    #: The assignment could not be honoured at all: it is bound to another
    #: tenant, another case, or an instant this source cannot cover.
    ASSIGNMENT_REFUSED = "ASSIGNMENT_REFUSED"


_ABSTENTION_REASONS = frozenset(member.value for member in AbstentionReason)


@dataclass(frozen=True, slots=True)
class AcquiredEvidence:
    """One or more signed receipts, each carrying one proposition."""

    receipts: tuple[VerificationReceipt, ...]

    def __post_init__(self) -> None:
        if not self.receipts:
            #  "Acquired nothing" is an abstention and has to say why.  An
            #  empty success would be a refusal with the reason discarded.
            raise InvariantViolation("acquired evidence carries at least one receipt")
        propositions = [receipt.payload.proposition for receipt in self.receipts]
        if len(set(propositions)) != len(propositions):
            raise InvariantViolation("a source answers each proposition at most once")

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACQUIRED_EVIDENCE,
            (NSeq(tuple(receipt.to_node() for receipt in self.receipts)),),
        )


@dataclass(frozen=True, slots=True)
class AcquisitionAbstention:
    """No evidence, and the reason.  Creates nothing anywhere."""

    reason: AbstentionReason
    detail: str

    def to_node(self) -> NRec:
        return NRec(TAG_ACQUISITION_ABSTENTION, (NAtom(self.reason.value), NAtom(self.detail)))


type AcquisitionOutcome = AcquiredEvidence | AcquisitionAbstention


def outcome_node(outcome: AcquisitionOutcome) -> Node:
    match outcome:
        case AcquiredEvidence():
            return NTagged("AcquiredEvidence", outcome.to_node())
        case AcquisitionAbstention():
            return NTagged("AcquisitionAbstention", outcome.to_node())


def read_outcome(node: Node) -> AcquisitionOutcome:
    tag, payload = read_tagged(node, "AcquisitionOutcome")
    match tag:
        case "AcquiredEvidence":
            (receipts,) = read_rec(payload, TAG_ACQUIRED_EVIDENCE, 1)
            return AcquiredEvidence(read_seq(receipts, read_verification_receipt, minimum=1))
        case "AcquisitionAbstention":
            reason, detail = read_rec(payload, TAG_ACQUISITION_ABSTENTION, 2)
            return AcquisitionAbstention(
                AbstentionReason(read_member(reason, _ABSTENTION_REASONS, "AbstentionReason")),
                read_atom(detail),
            )
        case _:
            raise fail(WireFailure.UNKNOWN_VARIANT, "AcquisitionOutcome", tag)


@dataclass(frozen=True, slots=True)
class AcquisitionResponse:
    """What a source returns, and what the envelope lets a reader refuse.

    Every field here is **claimed by the responder** and none of it is
    authenticated by anything in this module.  That is exactly why the envelope
    exists in this shape: the control plane compares each field against what it
    asked -- this tenant, this case, this request, this agent -- and a mismatch
    is a refusal.  There is no field whose value could turn a refusal into an
    acceptance, because acceptance is decided downstream by a signature and by
    check Q-12, neither of which reads anything here.
    """

    tenant_id: str
    case_id: str
    request_id: Digest
    agent_id: str
    outcome: AcquisitionOutcome

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant", self.tenant_id),
            ("case", self.case_id),
            ("agent", self.agent_id),
        ):
            if not value:
                raise InvariantViolation(f"an acquisition response names a {name}")

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACQUISITION_RESPONSE,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                self.request_id.to_node(),
                NAtom(self.agent_id),
                outcome_node(self.outcome),
            ),
        )


def read_acquisition_response(node: Node) -> AcquisitionResponse:
    tenant_id, case_id, request_id, agent_id, outcome = read_rec(node, TAG_ACQUISITION_RESPONSE, 5)
    return AcquisitionResponse(
        tenant_id=read_atom(tenant_id),
        case_id=read_atom(case_id),
        request_id=read_digest(request_id),
        agent_id=read_atom(agent_id),
        outcome=read_outcome(outcome),
    )


def decode_acquisition_response(node: Node) -> Result[AcquisitionResponse, WireError]:
    return decoded(lambda: read_acquisition_response(node))
