"""Turning durable octets back into the values ``rebuild`` takes.

Two reads, and the difference between them is the difference between "what is
true now" and "what the head committed to".

``read_working`` resolves the *current* membership set: it is what a case is
advanced from.  ``read_published`` resolves the membership the head's own
transcript prefix names: it is what the head is *replayed* from.  They differ
exactly when an entry has arrived and not yet been published, which is a normal
state and not a fault, and conflating them would either replay a head that
never existed or advance a case while ignoring evidence it already holds.

``read_certificate`` is the third, and it is a read rather than a derivation on
purpose.  A revision is a pure function of the rebuild inputs and the store, so
replaying it proves the case; a *certificate* also records what a particular
solver, at a particular version, under a particular budget, answered -- and the
certificate binds that fingerprint precisely because it is not a constant of the
system.  Recomputing one therefore asks today's engine to reproduce yesterday's
answer, which it may legitimately decline to do after an operator raises a bound
or changes a backend.  So the revision is replayed and the certificate is read.

``read_published`` is why the prefix is stored at all.  A prefix digest is a
hash of a digest list and nothing recovers the list from it, so a revision
cannot be rebuilt from ``RebuildInputs`` and a store unless the store holds the
prefix.  Replay is defined as ``rebuild(RebuildInputs, store)``; the prefix is
the part of the store that makes the definition true.

Every artifact is re-bound on the way in.  The store is keyed by tenant, so a
cross-tenant read is already unrepresentable, but a case naming another case's
construction record inside one tenant is not -- and an artifact that says which
case it belongs to should be believed about it or refused, never ignored.

**The authority state comes with the snapshot, and only by pin.**  A case's
authorization context names one authority registry snapshot and one revocation
snapshot by digest, and both are resolved here, signature-verified, and handed
to ``rebuild`` alongside the entries.  There is no code path in this module
that reaches "the current registry": a read resolves the digest the head
carries or it fails, so a historical replay is judged by the authority that
applied when it was published and a newer publication is invisible to it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from muster.core.analysis.certificate import AnalysisCertificate, read_analysis_certificate
from muster.core.authority.signing import OfficerVerifier, PublisherVerifier, SourceVerifier
from muster.core.case.revision import (
    AuthorizationContext,
    TranscriptPrefix,
    read_authorization_context,
    read_transcript_prefix,
)
from muster.core.evidence.requests import EvidenceRequest, read_evidence_request
from muster.core.evidence.signing import attestation_preimage, case_construction_preimage
from muster.core.evidence.transcript import (
    Attestation,
    CaseConstructionRecord,
    Statement,
    TranscriptEntry,
    read_case_construction,
    read_entry,
)
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest, DigestKind
from muster.core.wire.nodes import Node
from muster.core.wire.shape import decoded
from muster.platform.authority.resolve import ResolvedAuthority, resolve_authority
from muster.platform.casework.ports import (
    CaseHead,
    DecidingScope,
    StoreError,
    StoreFailure,
)


class SnapshotFailure(Enum):
    UNKNOWN_CASE = "UNKNOWN_CASE"
    CONTENT_ABSENT = "CONTENT_ABSENT"
    #  Stored octets that the codec or a typed reader refuses. Not a decode
    #  detail a caller can recover from: an artifact the store cannot read back
    #  is an artifact the case can no longer be rebuilt from.
    CONTENT_UNREADABLE = "CONTENT_UNREADABLE"
    #  A stored artifact naming a different tenant or case than the one that
    #  reached for it.
    BINDING_MISMATCH = "BINDING_MISMATCH"
    NOT_ANALYSED = "NOT_ANALYSED"
    #  The authority or revocation snapshot this case pinned could not be
    #  resolved, could not be verified, or does not carry the digest it is
    #  stored under.  Fails closed: a case whose authority state cannot be
    #  established has not established that anything is authorized.
    AUTHORITY_UNRESOLVED = "AUTHORITY_UNRESOLVED"


@dataclass(frozen=True, slots=True)
class SnapshotError:
    failure: SnapshotFailure
    detail: str


@dataclass(frozen=True, slots=True)
class CaseInputs:
    """The case's authored state, without its transcript.

    Read on its own because admission needs it *before* an entry is stored: the
    authority a receipt is judged against is a property of the case, not of the
    receipt, and resolving it after the membership row exists would be resolving
    it too late to refuse.
    """

    head: CaseHead
    construction: CaseConstructionRecord
    authorization_context: AuthorizationContext
    authority: ResolvedAuthority


@dataclass(frozen=True, slots=True)
class CaseSnapshot:
    """Everything ``rebuild`` needs, read at one instant."""

    head: CaseHead
    construction: CaseConstructionRecord
    authorization_context: AuthorizationContext
    authority: ResolvedAuthority
    entries: tuple[TranscriptEntry, ...]
    #: Every evidence request cited by a receipt in ``entries``, resolved from
    #: the content store by the digest the receipt cites.  Carries the second
    #: half of Q-12(a) into ``rebuild``; see
    #: ``muster.core.evidence.solicitation`` for what it can establish.
    solicitations: tuple[EvidenceRequest, ...]


def read_case_inputs(
    scope: DecidingScope, case_id: str, verifier: PublisherVerifier, officer: OfficerVerifier
) -> Result[CaseInputs, SnapshotError]:
    """The head, its construction record, and the authority state it pinned."""
    head = scope.heads.read(case_id)
    if isinstance(head, Err):
        return Err(SnapshotError(SnapshotFailure.UNKNOWN_CASE, head.error.detail))
    return _inputs(scope, head.value, verifier, officer)


def read_working(
    scope: DecidingScope,
    case_id: str,
    verifier: PublisherVerifier,
    officer: OfficerVerifier,
    source: SourceVerifier,
) -> Result[CaseSnapshot, SnapshotError]:
    """The head, and every transcript member that has arrived so far."""
    head = scope.heads.read(case_id)
    if isinstance(head, Err):
        return Err(SnapshotError(SnapshotFailure.UNKNOWN_CASE, head.error.detail))
    members = scope.transcript.members(case_id)
    if isinstance(members, Err):
        return Err(SnapshotError(SnapshotFailure.UNKNOWN_CASE, members.error.detail))
    return _assemble(scope, head.value, members.value, verifier, officer, source)


def read_published(
    scope: DecidingScope,
    case_id: str,
    verifier: PublisherVerifier,
    officer: OfficerVerifier,
    source: SourceVerifier,
) -> Result[CaseSnapshot, SnapshotError]:
    """The head, and exactly the members its own transcript prefix names."""
    head = scope.heads.read(case_id)
    if isinstance(head, Err):
        return Err(SnapshotError(SnapshotFailure.UNKNOWN_CASE, head.error.detail))
    if head.value.revision_digest is None:
        return Err(SnapshotError(SnapshotFailure.NOT_ANALYSED, case_id))
    prefix = _read_prefix(scope, head.value)
    if isinstance(prefix, Err):
        return prefix
    return _assemble(scope, head.value, prefix.value.entry_digests, verifier, officer, source)


def read_certificate(
    scope: DecidingScope, head: CaseHead
) -> Result[AnalysisCertificate, SnapshotError]:
    """The certificate the head names, as the value that was assembled.

    Three checks, and each one closes a different door.

    The **store** hands back only octets that hash to the key they are stored
    under, so a row edited in place is refused before anything reads it.

    The **round trip** is checked here: the decoded certificate is re-encoded
    and its digest compared against the key it came from.  That is not a
    restatement of the store's check -- it is the claim that *this reader is
    lossless for these octets*.  Every leaf a commitment publishes is
    re-encoded from the value this returns, so a reader that quietly dropped a
    field would produce a smaller record that still verified against itself.
    It cannot: the digest would move, and the read fails instead.

    The **binding** is checked last, because an artifact that says which case it
    belongs to should be believed about it or refused, never ignored -- the same
    rule every other read in this module follows.

    What is *not* checked here is the revision: a certificate cites one by
    digest, and comparing that against a replayed revision needs the replay,
    which is the caller's.
    """
    digest = head.certificate_digest
    if digest is None:
        return Err(SnapshotError(SnapshotFailure.NOT_ANALYSED, head.case_id))
    octets = scope.content.get(DigestKind.ANALYSIS_CERTIFICATE, digest)
    if isinstance(octets, Err):
        return Err(_store_error(octets.error))
    certificate = _read(octets.value, read_analysis_certificate, "AnalysisCertificate")
    if isinstance(certificate, Err):
        return certificate
    if certificate.value.digest() != digest:
        return Err(
            SnapshotError(
                SnapshotFailure.CONTENT_UNREADABLE,
                f"AnalysisCertificate: re-encoding what was read under {digest.hex} "
                f"produces {certificate.value.digest().hex}",
            )
        )
    bound = _bound(
        (certificate.value.tenant_id, certificate.value.case_id),
        scope.tenant_id,
        head.case_id,
        "AnalysisCertificate",
    )
    if isinstance(bound, Err):
        return bound
    return certificate


def _read_prefix(scope: DecidingScope, head: CaseHead) -> Result[TranscriptPrefix, SnapshotError]:
    octets = scope.content.get(DigestKind.TRANSCRIPT_PREFIX, head.inputs.transcript_prefix_digest)
    if isinstance(octets, Err):
        return Err(_store_error(octets.error))
    prefix = _read(octets.value, read_transcript_prefix, "TranscriptPrefix")
    if isinstance(prefix, Err):
        return prefix
    bound = _bound(
        (prefix.value.tenant_id, prefix.value.case_id),
        scope.tenant_id,
        head.case_id,
        "TranscriptPrefix",
    )
    if isinstance(bound, Err):
        return bound
    return prefix


def _inputs(
    scope: DecidingScope, head: CaseHead, verifier: PublisherVerifier, officer: OfficerVerifier
) -> Result[CaseInputs, SnapshotError]:
    construction = _read_construction(scope, head, officer)
    if isinstance(construction, Err):
        return construction
    context = _read_context(scope, head)
    if isinstance(context, Err):
        return context
    authority = resolve_authority(scope, context.value, verifier)
    if isinstance(authority, Err):
        return Err(
            SnapshotError(
                SnapshotFailure.AUTHORITY_UNRESOLVED,
                f"{authority.error.failure.value}: {authority.error.detail}",
            )
        )
    return Ok(CaseInputs(head, construction.value, context.value, authority.value))


def _assemble(
    scope: DecidingScope,
    head: CaseHead,
    members: tuple[Digest, ...],
    verifier: PublisherVerifier,
    officer: OfficerVerifier,
    source: SourceVerifier,
) -> Result[CaseSnapshot, SnapshotError]:
    inputs = _inputs(scope, head, verifier, officer)
    if isinstance(inputs, Err):
        return inputs

    entries: list[TranscriptEntry] = []
    for member in members:
        octets = scope.content.get(DigestKind.TRANSCRIPT_ENTRY, member)
        if isinstance(octets, Err):
            return Err(_store_error(octets.error))
        entry = _read(octets.value, read_entry, "TranscriptEntry")
        if isinstance(entry, Err):
            return entry
        authentic = _authentic(entry.value, source)
        if isinstance(authentic, Err):
            return authentic
        bound = _bound(_binding_of(entry.value), scope.tenant_id, head.case_id, "TranscriptEntry")
        if isinstance(bound, Err):
            return bound
        entries.append(entry.value)

    solicitations = _read_solicitations(scope, tuple(entries))
    if isinstance(solicitations, Err):
        return solicitations

    return Ok(
        CaseSnapshot(
            head,
            inputs.value.construction,
            inputs.value.authorization_context,
            inputs.value.authority,
            tuple(entries),
            solicitations.value,
        )
    )


def _read_solicitations(
    scope: DecidingScope, entries: tuple[TranscriptEntry, ...]
) -> Result[tuple[EvidenceRequest, ...], SnapshotError]:
    """Resolve the request each attested receipt cites, content-addressed.

    Driven by the citations in the transcript rather than by what the case has
    *outstanding*, and the difference is the whole reason this is a rebuild
    input at all.  Outstanding-ness is present-tense state: it changes as the
    head moves, so a replay that consulted it would decide a settled case by
    what is being asked today, and two replays a week apart would disagree.  A
    citation, by contrast, is inside a signed payload inside a transcript entry
    inside the prefix the revision pins -- it cannot move, and SHA-256 binds it
    to exactly one request.

    **A citation that resolves to nothing is not an error here.**  It is
    volunteered evidence, which is legitimate and which admission has already
    judged under the unevadable, outstanding-driven form of the same clause.
    Failing the whole read would instead make a case unrebuildable the moment it
    held one volunteered receipt.

    Deduplicated by citation, because a case's receipts usually answer one
    request and reading it once per receipt would be N reads of one row.
    """
    cited: dict[Digest, None] = {}
    for entry in entries:
        if isinstance(entry, Attestation):
            cited.setdefault(entry.receipt.payload.request_id, None)

    found: list[EvidenceRequest] = []
    for request_id in cited:
        octets = scope.content.get(DigestKind.EVIDENCE_REQUEST, request_id)
        if isinstance(octets, Err):
            if octets.error.failure is StoreFailure.CONTENT_ABSENT:
                #  Nothing was stored under that digest, so this case never
                #  issued it: volunteered.  Distinguished from a store that
                #  could not answer, which is the branch below and is a refusal.
                continue
            return Err(_store_error(octets.error))
        request = _read(octets.value, read_evidence_request, "EvidenceRequest")
        if isinstance(request, Err):
            #  Stored by this package under its own digest, so octets that will
            #  not read back are corruption rather than absence -- and a request
            #  that cannot be read cannot be shown to permit anything.
            return request
        found.append(request.value)
    #  Ordered by citation digest so two reads of one case produce one tuple.
    #  ``SolicitationView`` keys by digest and the order decides nothing, which
    #  is exactly why it is fixed: an input whose order is arbitrary is one an
    #  auditor has to prove does not matter.
    return Ok(tuple(sorted(found, key=lambda request: request.digest().octets)))


def _authentic(entry: TranscriptEntry, source: SourceVerifier) -> Result[None, SnapshotError]:
    """Re-verify an attestation's source signature on the way out of the store.

    **The same rule the construction record already follows, applied to the
    artifact it is read beside.**  ``_read_construction`` re-verifies the
    officer signature here rather than trusting that admission did, and gives
    the reason: admission is one of two doors into the store, and the other is
    an operator with SQL.  Every word of that applies to an attestation, and it
    was not being done -- so a row inserted past admission, naming a genuinely
    authorized key and carrying a signature that verifies against nothing,
    passed Q-12(b) through (f) on the strength of a ``signer_key_ref`` nobody
    had checked, established a fact, and authorized a payment.

    That is the precise failure the milestone's own headline forbids: durable
    transcript membership must not be sufficient to make an attestation
    consequential.  Authority answers *may this key say this*; it presupposes
    an answer to *did this key say it*, and presupposing is not checking.

    **Why here and not in ``rebuild``.**  ``rebuild`` takes no collaborators --
    no store, no clock, no keyring -- and giving it a verifier would make the
    kernel's purest function depend on a trust root.  The platform read path is
    the seam where octets stop being octets, it is where the officer signature
    is already checked, and it is the boundary every rebuild of a durable case
    passes through.  A statement is deliberately not checked: a claim has no
    signature to verify and is provably inert.
    """
    if not isinstance(entry, Attestation):
        return Ok(None)
    payload = entry.receipt.payload
    if not source.verify(
        key_ref=payload.signer_key_ref,
        preimage=attestation_preimage(payload),
        signature=entry.receipt.signature,
    ):
        return Err(
            SnapshotError(
                SnapshotFailure.CONTENT_UNREADABLE,
                f"the stored attestation over {payload.proposition.predicate_id} "
                f"is not signed by {payload.signer_key_ref}",
            )
        )
    return Ok(None)


def _read_construction(
    scope: DecidingScope, head: CaseHead, officer: OfficerVerifier
) -> Result[CaseConstructionRecord, SnapshotError]:
    octets = scope.content.get(DigestKind.CASE_CONSTRUCTION, head.inputs.construction_digest)
    if isinstance(octets, Err):
        return Err(_store_error(octets.error))
    record = _read(octets.value, read_case_construction, "CaseConstructionRecord")
    if isinstance(record, Err):
        return record
    #  Re-verified on the way out as well as on the way in, for the reason the
    #  party binding below is: admission is one of two doors into the store and
    #  the other is an operator with SQL.  A construction record is where
    #  Q-12(d) reads the case's site from, so a row written past admission must
    #  not be a row a rebuild will authorize against.
    if not officer.verify(
        key_ref=record.value.signer_key_ref,
        preimage=case_construction_preimage(record.value.body()),
        signature=record.value.signature,
    ):
        return Err(
            SnapshotError(
                SnapshotFailure.CONTENT_UNREADABLE,
                f"CaseConstructionRecord for {head.case_id!r} is not signed by a trusted officer",
            )
        )
    bound = _bound(
        (record.value.tenant_id, record.value.case_id),
        scope.tenant_id,
        head.case_id,
        "CaseConstructionRecord",
    )
    if isinstance(bound, Err):
        return bound
    for party in record.value.parties:
        #  Re-checked on the way out as well as on the way in. Admission is one
        #  of two doors into the store -- the other is an operator with SQL --
        #  and a role declaration for another tenant's principal is exactly the
        #  thing a case must not be rebuilt from because somebody put it there.
        party_bound = _bound(
            (party.tenant_id, head.case_id), scope.tenant_id, head.case_id, "PartyRecord"
        )
        if isinstance(party_bound, Err):
            return party_bound
    return record


def _read_context(
    scope: DecidingScope, head: CaseHead
) -> Result[AuthorizationContext, SnapshotError]:
    octets = scope.content.get(
        DigestKind.AUTHORIZATION_CONTEXT, head.inputs.authorization_context_digest
    )
    if isinstance(octets, Err):
        return Err(_store_error(octets.error))
    #  An authorization context carries no tenant of its own -- it pins external
    #  authority state, not case identity -- so there is nothing to re-bind. Its
    #  digest is in the head, and ``rebuild`` checks it against the inputs.
    return _read(octets.value, read_authorization_context, "AuthorizationContext")


def _read[T](octets: bytes, reader: Callable[[Node], T], what: str) -> Result[T, SnapshotError]:
    """Stored octets as a typed value, or a refusal -- never an exception.

    Two failure modes, and the second is the one worth naming.  A typed reader
    reports a shape it cannot parse by raising ``WireDecodeError``, which
    ``decoded`` turns into a value.  A *constructor* reports an invariant the
    parsed shape violates -- a world binding one reference twice, a request
    naming one proposition twice -- by raising ``InvariantViolation``, which is
    right when the system is building the value and wrong here: these octets
    came from a store, so a violated invariant is a finding about the row, and
    a finding has to reach the caller as a value.  Left uncaught it would be an
    exception on the reading path, where a corrupt row is meant to look like a
    refusal and not like a crash.
    """
    node = decode(octets)
    if isinstance(node, Err):
        return Err(SnapshotError(SnapshotFailure.CONTENT_UNREADABLE, f"{what}: {node.error}"))
    decoded_node = node.value
    try:
        read = decoded(lambda: reader(decoded_node))
    except InvariantViolation as violation:
        return Err(SnapshotError(SnapshotFailure.CONTENT_UNREADABLE, f"{what}: {violation}"))
    if isinstance(read, Err):
        return Err(SnapshotError(SnapshotFailure.CONTENT_UNREADABLE, f"{what}: {read.error}"))
    return Ok(read.value)


def _binding_of(entry: TranscriptEntry) -> tuple[str, str]:
    match entry:
        case Attestation(receipt):
            return receipt.payload.tenant_id, receipt.payload.case_id
        case Statement(record):
            return record.tenant_id, record.case_id


def _bound(
    binding: tuple[str, str], tenant_id: str, case_id: str, what: str
) -> Result[None, SnapshotError]:
    carried_tenant, carried_case = binding
    if carried_tenant != tenant_id or carried_case != case_id:
        return Err(
            SnapshotError(
                SnapshotFailure.BINDING_MISMATCH,
                f"{what} names {carried_tenant!r}/{carried_case!r}, "
                f"read under {tenant_id!r}/{case_id!r}",
            )
        )
    return Ok(None)


def _store_error(error: StoreError) -> SnapshotError:
    failure = (
        SnapshotFailure.CONTENT_ABSENT
        if error.failure is StoreFailure.CONTENT_ABSENT
        else SnapshotFailure.CONTENT_UNREADABLE
    )
    return SnapshotError(failure, f"{error.failure.value} {error.digest} {error.detail}")
