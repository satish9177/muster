"""Binding a validated observation to the request, and signing it.

Everything security-bearing in a receipt is copied from the **assignment**, not
from the model and not from this agent's own opinion: the tenant, the case, the
request identifier, the schema pin and the authorization-policy version.  What
the source contributes is what a source is for -- the proposition it was asked
about, the relation it observed, when it observed it, and its own identity.

**One receipt carries one proposition.**  Not a batch, not a report, not a
summary of the visit.  That is the privacy claim and the evidential claim in
the same sentence: what leaves the source is an acquisition relation over one
declared proposition, and there is no field on the way out that could carry a
frame, a transcript, a confidence, or the reference to the local material the
observation came from.

**The validity window is the source's own statement and is still checked.**  A
source says how long it stands behind an observation; the case says which
instant the receipt has to be admissible at.  A window that does not contain
that instant produces a receipt that verifies, admits, and does nothing -- the
most confusing possible failure -- so it is refused here, before a signature is
spent, and the refusal names the instant rather than leaving an operator to
work out why a valid receipt had no effect.

**Signing is not something the model can reach.**  There is no tool that calls
this, no argument that arrives from a tool call, and no branch that runs while
the model is still running.  A signature is applied to a payload built from an
assignment and a validated observation, by code invoked after the turn is over.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.agents.common.environment import NonceSource
from muster.agents.common.identity import SourceIdentity
from muster.agents.runtime.observations import ValidatedObservation
from muster.core.authority.signing import SourceSigner
from muster.core.evidence.acquisition import AcquisitionAssignment
from muster.core.evidence.signing import attestation_preimage
from muster.core.evidence.transcript import AcquisitionPayload, VerificationReceipt
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.times import Duration, HalfOpenInterval, Instant


class ReceiptFailure(Enum):
    """Why an observation did not become a signed receipt."""

    #: The signer presents a key the agent's own identity does not name.  A
    #: payload naming one key and signed by another is a receipt nothing can
    #: verify, and building one would spend a signature to produce garbage.
    KEY_MISMATCH = "KEY_MISMATCH"
    #: The window this source would stand behind does not contain the instant
    #: the case is decided at.
    OUTSIDE_CASE_INSTANT = "OUTSIDE_CASE_INSTANT"
    #: The signer raised.  A key management failure is an operational fact and
    #: never an excuse to emit something unsigned.
    SIGNING_FAILED = "SIGNING_FAILED"


@dataclass(frozen=True, slots=True)
class ReceiptError:
    failure: ReceiptFailure
    detail: str


@dataclass(frozen=True, slots=True)
class AttestationPolicy:
    """How long this source stands behind what it observed.

    A ``Duration`` rather than an ``Instant``, for the reason the control
    plane's request deadline is one: an operator configures a length, and only
    one operation turns a length into a moment.  There is no default, because
    a source that has not decided how long its observation holds has not
    decided something a signature is about to commit it to.
    """

    validity_ttl: Duration
    #: How far back this source will attest to having observed anything.
    #:
    #: A **different length** from the validity window, and deliberately so.
    #: The window says how long an answer stands after it is given; the horizon
    #: says how old the material a source will read may be.  A site issuing on
    #: a Thursday about the previous Saturday is ordinary, and folding the two
    #: into one number would either forbid that or make the validity window
    #: absurdly long.
    #:
    #: What it exists for is narrow: the observation instant is the one field a
    #: model authors freely, and it decides where the receipt's validity window
    #: *starts*.  Unbounded below, a model could date an observation to the
    #: epoch and make its receipt admissible at any case instant at all.
    observation_horizon: Duration

    def __post_init__(self) -> None:
        if not self.validity_ttl.is_positive():
            raise InvariantViolation(f"a validity window has length: {self.validity_ttl}")
        if not self.observation_horizon.is_positive():
            raise InvariantViolation(
                f"an observation horizon has length: {self.observation_horizon}"
            )

    def horizon(self, issued_at: Instant) -> Instant:
        """The earliest instant this source will attest to having observed.

        Floored at zero because an instant is microseconds since the epoch and
        a negative one is not a time.  A deployment whose clock is genuinely
        near the epoch has larger problems than this bound.
        """
        return max(0, issued_at - self.observation_horizon.microseconds)


def build_receipts(
    observations: tuple[ValidatedObservation, ...],
    *,
    assignment: AcquisitionAssignment,
    identity: SourceIdentity,
    signer: SourceSigner,
    issued_at: Instant,
    nonces: NonceSource,
    policy: AttestationPolicy,
) -> Result[tuple[VerificationReceipt, ...], ReceiptError]:
    """Sign every observation, or none of them.

    All-or-nothing, because these are one turn's reading of one source's
    material: emitting the half that could be signed would present a partial
    reading as a complete answer, and the case cannot tell the difference.

    ``issued_at`` is a value rather than a clock, and the caller reads it once.
    Two reads would let an observation be *bounded* against one instant and
    *signed* for another, which is a whole class of edge case to reason about
    in exchange for nothing.
    """
    if signer.key_ref != identity.key_ref:
        return Err(
            ReceiptError(
                ReceiptFailure.KEY_MISMATCH,
                f"{identity.agent_id} is configured for {identity.key_ref!r} "
                f"and holds a signer for {signer.key_ref!r}",
            )
        )
    receipts: list[VerificationReceipt] = []
    for observation in observations:
        built = _one(
            observation,
            assignment=assignment,
            identity=identity,
            signer=signer,
            issued_at=issued_at,
            nonce=nonces.nonce(),
            policy=policy,
        )
        if isinstance(built, Err):
            return Err(built.error)
        receipts.append(built.value)
    return Ok(tuple(receipts))


def _one(
    observation: ValidatedObservation,
    *,
    assignment: AcquisitionAssignment,
    identity: SourceIdentity,
    signer: SourceSigner,
    issued_at: Instant,
    nonce: bytes,
    policy: AttestationPolicy,
) -> Result[VerificationReceipt, ReceiptError]:
    validity = _window(observation.observed_at, issued_at, policy.validity_ttl)
    if not validity.contains(assignment.as_of):
        return Err(
            ReceiptError(
                ReceiptFailure.OUTSIDE_CASE_INSTANT,
                f"{observation.proposition} would be valid over "
                f"[{validity.start}, {validity.end}) and the case is decided at "
                f"{assignment.as_of}",
            )
        )
    payload = AcquisitionPayload(
        tenant_id=assignment.tenant_id,
        case_id=assignment.case_id,
        subject=observation.target.subject,
        proposition=observation.proposition,
        relation=observation.relation,
        value_sort=observation.target.value_sort,
        predicate_schema_digest=assignment.predicate_schema_digest,
        observed_at=observation.observed_at,
        issued_at=issued_at,
        validity=validity,
        nonce=nonce,
        #  Configuration, never model output and never an argument.  A source
        #  class a model could choose would make "a shared source class is not
        #  a shared authority" rest on a string a language model produced.
        source_class=identity.source_class,
        signer_key_ref=identity.key_ref,
        authorization_policy_version=assignment.authorization_policy_version,
        request_id=assignment.request_id,
    )
    try:
        signature = signer.sign(attestation_preimage(payload))
    except Exception as failure:
        #  Broad on purpose: a local key, a hardware token and a managed key
        #  service each raise their own family, and all of them mean the same
        #  thing here -- this observation is not attestable right now, and
        #  nothing unsigned may take its place.
        #  The type, and not the message.  A key service's exception can quote
        #  the octets it was handed, and this one is handed a digest of the
        #  source's own reading -- so the message is confined to the source and
        #  the type is what travels.
        return Err(ReceiptError(ReceiptFailure.SIGNING_FAILED, type(failure).__name__))
    return Ok(VerificationReceipt(payload, signature))


def _window(observed_at: Instant, issued_at: Instant, ttl: Duration) -> HalfOpenInterval:
    """From the observation to a configured length after it was signed for.

    The start is the earlier of the two instants rather than the issue time,
    and the difference is operational rather than cosmetic: a case is opened at
    an instant, evidence about it is gathered afterwards, and a window that
    began when the signature was applied would exclude the case it was gathered
    for.  A source that observed something is prepared to say so about the
    moment it observed it.
    """
    return HalfOpenInterval(min(observed_at, issued_at), ttl.after(issued_at))
