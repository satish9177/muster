"""Admitting canonical octets to the store.

Four rules now, and the last two are milestone E.

**The octets are the artifact.**  Everything here takes octets, decodes them to
check what they are, and then stores *the octets it was given* -- never a
re-encoding of what it decoded.  A decode-then-re-encode admission path
silently canonicalises a non-canonical input, which changes its digest, which
means the artifact stored is not the artifact anybody signed.  The check that
makes this real is the equality assertion below: the octets must already be
what the encoder would produce.

**Binding is checked before storage, not after.**  An entry carries its own
tenant and case inside the octets a signature covers.  Those have to match the
case being appended to, and the mismatch has to be refused here -- ``rebuild``
also refuses it, but refusing at admission means a cross-tenant entry never
becomes durable at all.

**Signatures are verified.**  A source attestation is checked against the
source keyring before anything else looks at what it says.  This establishes
**authenticity and nothing else**: which key produced these octets.

**And authenticity is not authority.**  A perfectly valid signature from a real,
unrevoked key is admitted only if check Q-12 also holds -- the pinned bundle
permits that class for that predicate, the pinned authority snapshot grants
*this* key that class for this tenant, this resource and this predicate, in
force at the case's ``as_of``, unrevoked, under the pinned policy version.  A
receipt that fails is refused **before its octets reach the store**, so an
unauthorized receipt never becomes transcript membership and leaves no
content-addressed orphan behind either.

**And one question is asked of the present rather than of the pin.**  Q-12(f)
reads the revocation snapshot the *case* pinned, which is right for derivation:
a decided case must replay to the same answer, so a revocation published
afterwards must not reach backwards into it.  It is wrong for admission.  A
case pins its authority when it is opened and nothing moves that pin, so a key
revoked a month later would go on establishing facts in every case that was
already open -- the pin predates the revocation, and Q-12(f) would never see
it.  So admission additionally refuses any key withdrawn by **any** revocation
snapshot the tenant has published.  It is a strictly extra gate: it can only
refuse, it writes nothing, and no derivation reads it, so replay is untouched.

The asymmetry is deliberate and worth stating.  Withdrawal is applied forward;
granting is not.  Consulting the newest *registry* would let a snapshot
published after a case opened authorize evidence into it, which is escalation
rather than protection -- and the pin exists to prevent exactly that.

Two deliberate limits, stated rather than left to be discovered.

*Statements are not signature-verified.*  A ``StatementRecord`` is inert by
construction -- no justification variant accepts one, so it can never appear in
``established`` and can never move a value -- and verifying an artifact whose
authenticity cannot change any outcome would be adding a signing body to the
frozen surface for no security gain.  It is refused on binding like everything
else.

*An attestation the pinned bundle cannot interpret is refused, not admitted
and left inert.*  A receipt whose schema pin is not the case's, or whose
predicate the bundle does not declare, or whose predicate is DERIVED, can never
be authorized: ``derive`` refuses it before Q-12 is reached and it can only ever
become a recorded non-effect.  An earlier draft let it through on exactly that
reasoning, and the reasoning is wrong.  Membership is append-only, so an inert
entry still changes the transcript prefix, the revision digest and every
artifact downstream of them -- permanently, for a receipt whose authority was
never established.  "An unauthorized receipt never becomes transcript
membership" cannot carry an "except when it could not have been authorized
anyway" clause, so these are refused here, before the store.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.authority.check import (
    AuthorityView,
    SourceClaim,
    check_authority,
    required_coordinates,
)
from muster.core.authority.signing import OfficerVerifier, SourceVerifier
from muster.core.evidence.requests import EvidenceRequest, read_evidence_request
from muster.core.evidence.signing import attestation_preimage, case_construction_preimage
from muster.core.evidence.transcript import (
    Attestation,
    CaseConstructionRecord,
    Statement,
    TranscriptEntry,
    VerificationReceipt,
    entry_node,
    read_entry,
)
from muster.core.results import Err, Ok, Result
from muster.core.values.classification import AcquisitionClass
from muster.core.wire.codec import decode, encode
from muster.core.wire.digests import Digest, DigestKind
from muster.core.wire.shape import decoded
from muster.platform.casework.ports import (
    DecidingScope,
    RecordedRequest,
    RequestFailure,
    StoreError,
)
from muster.policy.predicates import PredicateSchema


class AdmissionFailure(Enum):
    NOT_CANONICAL = "NOT_CANONICAL"
    NOT_A_TRANSCRIPT_ENTRY = "NOT_A_TRANSCRIPT_ENTRY"
    #  The octets decode, and re-encoding them produces something else. The
    #  input was a non-canonical spelling of a value, and storing it would put
    #  two octet strings under one meaning.
    RE_ENCODES_DIFFERENTLY = "RE_ENCODES_DIFFERENTLY"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    CASE_MISMATCH = "CASE_MISMATCH"
    STORE_REFUSED = "STORE_REFUSED"
    #  A signature does not verify against the keyring for its role -- a
    #  source's over an attestation payload, an officer's over a construction
    #  record body.  Says nothing about authority: this is the question of
    #  *which key* produced these octets, and it is asked first because the
    #  answer decides whether there is a key whose authority is worth looking
    #  up -- or, for the construction record, whether the coordinates Q-12(d)
    #  will resolve the case's site from came from anybody this reader trusts.
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    #  The signature verified and check Q-12 refused.  The detail carries the
    #  typed clause -- wrong class, wrong site, wrong tenant, expired, revoked
    #  -- because "unauthorized" without which clause is what makes a
    #  legitimate agent's misconfiguration undebuggable.
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    #  The receipt answers a request this case did not issue, or answers one it
    #  did with a proposition that request never asked for.
    UNSOLICITED_REPLY = "UNSOLICITED_REPLY"
    #  The signing key has been withdrawn by a revocation snapshot published
    #  since this case pinned its authority.  Distinguished from the Q-12(f)
    #  refusal that reads the pin, because the two answer different questions
    #  and an operator needs to know which one fired.
    KEY_WITHDRAWN = "KEY_WITHDRAWN"
    #  The receipt is not one this case's pinned bundle could ever admit: it
    #  cites another predicate schema, names a predicate the bundle does not
    #  declare, or names one that is DERIVED and therefore attestable by
    #  nobody.  Refused rather than admitted-and-inert, because membership is
    #  append-only and an entry nothing can remove is not "no effect".
    NOT_ADMISSIBLE_FOR_THIS_CASE = "NOT_ADMISSIBLE_FOR_THIS_CASE"


@dataclass(frozen=True, slots=True)
class AdmissionError:
    failure: AdmissionFailure
    detail: str


@dataclass(frozen=True, slots=True)
class AdmittedEntry:
    entry: TranscriptEntry
    entry_digest: Digest


@dataclass(frozen=True, slots=True)
class AdmissionAuthority:
    """Everything admission needs to decide authenticity and then authority.

    Assembled by the caller from the case's own pinned state -- never from the
    entry being admitted.  It is a required argument rather than an optional
    one on purpose: an ``AdmissionAuthority | None`` would make "admit without
    checking" a thing a caller could spell, and the whole milestone is that
    nobody can.
    """

    source_verifier: SourceVerifier
    schema: PredicateSchema
    pinned_schema_digest: Digest
    view: AuthorityView
    #: Every key this tenant has withdrawn, from every revocation snapshot it
    #: has published -- not only the one this case pinned.  See the module
    #: docstring: the pin is right for replay and cannot protect a case that
    #: was already open when a key was compromised.
    withdrawn_keys: frozenset[str]


def admit_entry(
    scope: DecidingScope, case_id: str, entry: TranscriptEntry, authority: AdmissionAuthority
) -> Result[AdmittedEntry, AdmissionError]:
    """Admit an entry this process holds as a value."""
    return admit_entry_octets(scope, case_id, encode(entry_node(entry)), authority)


def admit_entry_octets(
    scope: DecidingScope, case_id: str, octets: bytes, authority: AdmissionAuthority
) -> Result[AdmittedEntry, AdmissionError]:
    """Admit an entry from the octets that are its identity.

    The order is the ratified admission order, and every step before the store
    is a step whose refusal leaves nothing behind at all:

    1. decode and canonical-form validation;
    2. tenant and case binding;
    3. cryptographic authenticity;
    4. source authority, check Q-12;
    5. only then, the content-addressed write.

    Putting the write last is what makes an unauthorized receipt leave *no*
    trace -- not an orphaned preimage, not a row the enclosing transaction has
    to roll back, nothing.  The transaction would roll it back anyway; not
    writing it is the belt to that pair of braces.
    """
    node = decode(octets)
    if isinstance(node, Err):
        return Err(AdmissionError(AdmissionFailure.NOT_CANONICAL, str(node.error)))
    read = decoded(lambda: read_entry(node.value))
    if isinstance(read, Err):
        return Err(AdmissionError(AdmissionFailure.NOT_A_TRANSCRIPT_ENTRY, str(read.error)))
    entry = read.value

    if encode(entry_node(entry)) != octets:
        return Err(AdmissionError(AdmissionFailure.RE_ENCODES_DIFFERENTLY, str(len(octets))))

    binding = _binding_of(entry)
    bound = _check_binding(scope.tenant_id, case_id, binding)
    if isinstance(bound, Err):
        return bound

    if isinstance(entry, Attestation):
        judged = _judge(scope, case_id, entry.receipt, authority)
        if isinstance(judged, Err):
            return judged

    stored = scope.content.put(DigestKind.TRANSCRIPT_ENTRY, octets)
    if isinstance(stored, Err):
        return Err(_store_refused(stored.error))
    return Ok(AdmittedEntry(entry, stored.value))


def _judge(
    scope: DecidingScope,
    case_id: str,
    receipt: VerificationReceipt,
    authority: AdmissionAuthority,
) -> Result[None, AdmissionError]:
    """Authenticity, then authority. Two questions, asked in that order."""
    payload = receipt.payload
    if not authority.source_verifier.verify(
        key_ref=payload.signer_key_ref,
        preimage=attestation_preimage(payload),
        signature=receipt.signature,
    ):
        return Err(
            AdmissionError(
                AdmissionFailure.SIGNATURE_INVALID,
                f"{payload.signer_key_ref} did not sign this payload",
            )
        )

    if payload.signer_key_ref in authority.withdrawn_keys - set(
        authority.view.revocation.revoked_key_refs
    ):
        #  Asked before anything about content, and before Q-12, because a
        #  withdrawn key is withdrawn whatever it is trying to say.  The
        #  signature still verifies -- revocation withdraws authority, not
        #  mathematics -- which is exactly why this is here and not in the
        #  verifier.
        #
        #  **Minus what the case already pinned.**  This clause says "withdrawn
        #  *since this case was opened*", and a key the pinned snapshot already
        #  names was not withdrawn since -- it is Q-12(f)'s answer, and Q-12(f)
        #  reports it as ``KeyRevoked``.  Without the subtraction this clause
        #  shadowed that one for every key in both, so the distinction the two
        #  failure codes exist to draw was unobservable: an operator could not
        #  tell "the case has always refused this key" from "the key was
        #  compromised after the case opened".  Nothing is admitted that was
        #  not admitted before -- a key in the pinned snapshot is refused one
        #  clause later, by name.
        return Err(
            AdmissionError(
                AdmissionFailure.KEY_WITHDRAWN,
                f"{payload.signer_key_ref} has been withdrawn since this case was opened",
            )
        )

    #  Q-9: the schema this receipt validated against must be the one the case
    #  is pinned to.  The authority question below cannot be answered against a
    #  schema this case does not use -- and answering it against a different one
    #  would be worse than not answering it -- so a mismatch is refused rather
    #  than waved through to be inert later.
    if payload.predicate_schema_digest != authority.pinned_schema_digest:
        return Err(
            AdmissionError(
                AdmissionFailure.NOT_ADMISSIBLE_FOR_THIS_CASE,
                f"the receipt cites another predicate schema for "
                f"{payload.proposition.predicate_id}",
            )
        )
    spec = authority.schema.spec_for(payload.proposition)
    if spec is None:
        return Err(
            AdmissionError(
                AdmissionFailure.NOT_ADMISSIBLE_FOR_THIS_CASE,
                f"the pinned bundle declares no {payload.proposition.predicate_id} of this arity",
            )
        )
    if spec.acquisition is not AcquisitionClass.ATTESTABLE:
        #  The normative barrier, met at the earliest point it can be: a DERIVED
        #  conclusion has no source, so a receipt carrying one is refused before
        #  its octets are stored rather than after they are irremovable.
        return Err(
            AdmissionError(
                AdmissionFailure.NOT_ADMISSIBLE_FOR_THIS_CASE,
                f"{payload.proposition.predicate_id} is {spec.acquisition.value} "
                f"and no source may attest it",
            )
        )

    solicited = _check_solicitation(scope, case_id, receipt)
    if isinstance(solicited, Err):
        return solicited

    checked = check_authority(
        SourceClaim(
            tenant_id=payload.tenant_id,
            signer_key_ref=payload.signer_key_ref,
            source_class=payload.source_class,
            proposition=payload.proposition,
            authorization_policy_version=payload.authorization_policy_version,
        ),
        frozenset(spec.permitted_source_classes),
        required_coordinates(
            payload.proposition,
            spec.arg_kinds,
            spec.resource_scope_kinds,
            authority.view.case_scope_coordinates,
        ),
        authority.view,
    )
    if isinstance(checked, Err):
        return Err(
            AdmissionError(
                AdmissionFailure.NOT_AUTHORIZED,
                f"{checked.error.failure.value}: {checked.error.detail}",
            )
        )
    return Ok(None)


def _check_solicitation(
    scope: DecidingScope, case_id: str, receipt: VerificationReceipt
) -> Result[None, AdmissionError]:
    """The other half of Q-12(a): the *request's* permitted classes.

    An evidence request names, per proposition, which source classes may answer
    it -- and a permitted-class list nothing compares against is not a control,
    which is the defect this whole milestone exists to close.

    **Driven by what the case issued, never by what the receipt cites.**  An
    earlier draft resolved ``payload.request_id`` and, where it resolved to
    nothing, performed no target check at all.  That field is inside the
    payload the *signer* writes, so a source facing a request that narrowed
    answerers to one class needed only to cite a digest nothing stores: the
    narrowing was unenforceable against anybody willing to omit a valid
    identifier.  It was harmless only because no producer narrows a target
    today -- and "harmless because of a property somewhere else" is what a
    control is not.

    So the request is found by asking the case what it has outstanding, and the
    narrowing is decided without reading ``payload.request_id``.  There is no
    value an attacker can set that makes this check not apply.  The citation is
    still checked -- see :func:`_check_citation` -- but it is checked *after*,
    as a separate question with a separate answer, so that reading it can only
    add a refusal and never remove one.

    A proposition nothing outstanding asks about is **volunteered**, and
    proceeds to Q-12 proper.  That is a legitimate thing -- a source offering
    an observation it holds a grant for -- and it is not a gap: Q-12 is the
    control either way, and this clause only ever narrows it further.

    **Every outstanding request is consulted, and any one of them refusing is
    the answer.**  More than one request can be outstanding against a single
    revision -- the rows are keyed by request digest and "outstanding" is a
    join on the revision, not a unique row -- so two of them may name the same
    proposition with different permitted classes.  Returning on the first match
    would make the verdict a function of iteration order, which both adapters
    fix as ascending request digest: a control decided by a SHA-256 tiebreak
    over content nobody chose.  Intersecting instead is the only reading under
    which a narrower request cannot be overridden by a broader one that
    happened to sort first.
    """
    outstanding = scope.requests.outstanding(case_id)
    if isinstance(outstanding, Err):
        if outstanding.error.failure is not RequestFailure.UNKNOWN_CASE:
            #  Fails closed: not knowing what was asked is not the same as
            #  knowing nothing was, and a request repository that cannot answer
            #  has not established that this proposition was unrestricted.
            return Err(
                AdmissionError(
                    AdmissionFailure.UNSOLICITED_REPLY,
                    f"{case_id} has no readable request state",
                )
            )
        #  A case this tenant does not have.  That *is* an answer -- there is no
        #  case here, so there is nothing outstanding here -- and it is not the
        #  kind of ignorance the branch above exists for.  Refusing here would
        #  also be refusing for the wrong reason: an entry cannot join a case
        #  that does not exist, and the transcript's own foreign key is what
        #  says so.
        return Ok(None)
    for recorded in outstanding.value:
        request = _read_request(scope, recorded.request_id)
        if request is None:
            #  Stored by this package under its own digest and referenced by a
            #  row with a foreign key to it, so an unreadable one is corruption
            #  rather than absence -- and a target that cannot be read cannot be
            #  shown to permit this class.
            return Err(
                AdmissionError(
                    AdmissionFailure.UNSOLICITED_REPLY,
                    f"{recorded.request_id.hex[:12]} cannot be read",
                )
            )
        matched = _match_target(request, receipt)
        if isinstance(matched, Err):
            return matched
    return _check_citation(scope, case_id, receipt, outstanding.value)


def _check_citation(
    scope: DecidingScope,
    case_id: str,
    receipt: VerificationReceipt,
    outstanding: tuple[RecordedRequest, ...],
) -> Result[None, AdmissionError]:
    """A cited request must be one *this* case has outstanding.

    The check above is driven by what the case issued and never reads
    ``payload.request_id``, which is what makes it unevadable.  This one is the
    opposite direction and is safe precisely because of that: it reads the
    citation, and nothing a citation can say makes the narrowing above not
    apply -- so the worst an attacker achieves by choosing a value here is a
    refusal.

    Citing an identifier that resolves to *another case's* request is refused:
    one case's solicitation must not admit evidence into another, and a
    borrowed identifier is how that would be spelled.  Citing an identifier
    this case has nothing outstanding for is **volunteered** evidence, which is
    legitimate -- a source offering an observation it holds a grant for -- and
    proceeds to Q-12 proper.  The distinction is drawn on membership in this
    case's outstanding set rather than on resolvability, because "resolves to
    nothing" and "resolves to somebody else's" are not the same claim and only
    the second is an attempt to borrow.
    """
    cited = receipt.payload.request_id
    if any(recorded.request_id == cited for recorded in outstanding):
        return Ok(None)
    borrowed = _read_request(scope, cited)
    if borrowed is None:
        return Ok(None)
    if borrowed.case_id == case_id and borrowed.tenant_id == scope.tenant_id:
        #  This case's own request, no longer outstanding because the head has
        #  moved past the revision it was raised against.  Stale, not borrowed.
        return Ok(None)
    return Err(
        AdmissionError(
            AdmissionFailure.UNSOLICITED_REPLY,
            f"{cited.hex[:12]} is a request issued by {borrowed.case_id!r}, not by {case_id!r}",
        )
    )


def _read_request(scope: DecidingScope, request_id: Digest) -> EvidenceRequest | None:
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


def _match_target(
    request: EvidenceRequest, receipt: VerificationReceipt
) -> Result[None, AdmissionError] | None:
    """This request's verdict on this receipt, or ``None`` if it is silent.

    Three outcomes rather than two.  ``None`` means the request does not name
    this proposition, so it has no opinion; ``Ok`` means it names it and
    permits this class; ``Err`` means it names it and forbids it.  Collapsing
    the first two would make "no request asked about this" and "this request
    permits it" the same value, which is the ambiguity the old shape turned
    into a bypass -- and the caller distinguishes them precisely because a
    permission from one request must not end the search while another request
    may still refuse.
    """
    payload = receipt.payload
    for target in request.targets:
        if target.proposition != payload.proposition:
            continue
        if payload.source_class not in target.permitted_source_classes:
            return Err(
                AdmissionError(
                    AdmissionFailure.NOT_AUTHORIZED,
                    f"SourceClassNotPermittedForPredicate: {payload.source_class} "
                    f"may not answer the request outstanding for "
                    f"{payload.proposition.predicate_id}",
                )
            )
        return Ok(None)
    return None


def admit_case_construction(
    scope: DecidingScope,
    case_id: str,
    record: CaseConstructionRecord,
    officer_verifier: OfficerVerifier,
) -> Result[Digest, AdmissionError]:
    """Admit the record that opens a case, under the same binding rule.

    **Every party is checked, not only the record.**  A construction record
    carries the parties and their roles -- roles come from here, signed by an
    officer, and never from a party's own assertion about itself -- and each
    party names a tenant of its own.  Checking the outer binding alone would
    let a case in one tenant permanently hold an authored role declaration for
    another tenant's principal, under a digest that looks entirely valid.  The
    store is keyed by tenant, so nothing could *read* it across the boundary;
    what it would corrupt is the tenant's own authored state, and there is no
    operation that deletes a stored preimage.

    The case's resource coordinates travel in this record and are therefore
    fixed by the officer who opened the case.  Nothing later can move them: an
    agent cannot re-site a case, because re-siting it would mean re-signing
    this record under a different digest, and the head pins the digest.

    **That sentence is only true because the signature is checked here.**  The
    record used to be stored on binding checks alone, which made "signed by an
    officer" a claim in this docstring rather than a fact about the octets --
    and ``case_scope_coordinates`` is the input Q-12(d) resolves the case's
    site from.  Anything that could reach ``open_case`` could therefore name
    the site it already held a grant over, and a genuine, unrevoked, correctly
    scoped key would attest into a case that was actually about somewhere else,
    with every clause passing.  The signature is verified *before* the record
    is stored, so a record nobody trusted never becomes something a head can
    pin.
    """
    if not officer_verifier.verify(
        key_ref=record.signer_key_ref,
        preimage=case_construction_preimage(record.body()),
        signature=record.signature,
    ):
        return Err(
            AdmissionError(
                AdmissionFailure.SIGNATURE_INVALID,
                f"CaseConstructionRecord for {case_id!r} is not signed by a trusted officer",
            )
        )
    bound = _check_binding(scope.tenant_id, case_id, (record.tenant_id, record.case_id))
    if isinstance(bound, Err):
        return bound
    for party in record.parties:
        if party.tenant_id != scope.tenant_id:
            return Err(
                AdmissionError(
                    AdmissionFailure.TENANT_MISMATCH,
                    f"party {party.principal_id!r} names {party.tenant_id!r} "
                    f"in a case under {scope.tenant_id!r}",
                )
            )
    stored = scope.content.put(DigestKind.CASE_CONSTRUCTION, encode(record.to_node()))
    if isinstance(stored, Err):
        return Err(_store_refused(stored.error))
    return Ok(stored.value)


def _binding_of(entry: TranscriptEntry) -> tuple[str, str]:
    match entry:
        case Attestation(receipt):
            return receipt.payload.tenant_id, receipt.payload.case_id
        case Statement(record):
            return record.tenant_id, record.case_id


def _check_binding(
    tenant_id: str, case_id: str, binding: tuple[str, str]
) -> Result[None, AdmissionError]:
    carried_tenant, carried_case = binding
    if carried_tenant != tenant_id:
        return Err(
            AdmissionError(
                AdmissionFailure.TENANT_MISMATCH, f"{carried_tenant!r} into {tenant_id!r}"
            )
        )
    if carried_case != case_id:
        return Err(
            AdmissionError(AdmissionFailure.CASE_MISMATCH, f"{carried_case!r} into {case_id!r}")
        )
    return Ok(None)


def _store_refused(error: StoreError) -> AdmissionError:
    return AdmissionError(
        AdmissionFailure.STORE_REFUSED, f"{error.failure.value} {error.digest} {error.detail}"
    )
