"""Committing a published revision, and reading that commitment back.

**This runs after publication, not inside it.**  A commitment is a statement
*about* a revision that is already head, already durable and already replayable;
computing it inside the head's compare-and-swap would hold a transaction across
hashing and a signature for no property that is not available afterwards.  What
the ratified property actually requires is that no participant can fetch a view
for a revision that is not head, and that is preserved on the reading side
instead: every read resolves the head first and asks for the commitment *that
head's* revision has.  A revision that has moved on is unreachable rather than
stale, and a revision committed a moment ago is simply absent until it is not.

**A historical disclosure does not need today's solver.**  The committed record
has two halves, and they are recovered two different ways because they are two
different kinds of thing.

The **revision** is replayed.  It is a pure function of the head's own rebuild
inputs and the store, so re-deriving it proves that the case still says what it
said -- and a replay that produces a different revision is a fault worth
refusing rather than a configuration difference.

The **certificate** is read.  It records what a particular solver, at a
particular version, under a particular budget, answered about that revision;
binding the fingerprint is how it says so.  Re-deriving it would ask *this
process's* engine to reproduce an answer given by an engine that may since have
been reconfigured -- so an operator raising a case-size cap would make every
case committed before the change permanently undisclosable, with nothing wrong
anywhere.  The stored octets are the artifact.  They are read back through a
typed reader and accepted only if re-encoding the value reproduces the digest
the head names, it names this tenant and case, it cites the revision that was
just replayed, and it pins the bundle the head pins.  A certificate failing any
of those is refused, so nothing here trusts a row; it checks one.

No solver runs on this path at all, which is also why regenerating a view costs
a rebuild rather than an analysis.

**And what that costs, said plainly.**  The architecture materialises revisions
and certificates by digest "only as a cache -- deleting them loses nothing".
That stays true of the revision, which is replayed here from inputs.  It is no
longer true of the certificate on *this* path: pruning a certificate row makes
the cases it belonged to undisclosable until an engine that still reproduces it
puts it back.  Fail-closed rather than lossy -- the head still names what was
certified, and nothing is served from a record that was not read -- but a
retention rule for that table is now an operational decision with a consequence,
where before it was housekeeping.

Two custody rotations are the same shape and are handled differently.  Rotating
the **envelope signing key** is survivable and is survived: a stored envelope
names the key that signed it, and this reads it under any reference the control
plane accepts or has retired.  Rotating or destroying the **salt root** is not,
and cannot be made so here: every commitment in the tenant is a function of the
case salts that root derives, so losing it is crypto-shredding by design -- the
property ``commit.salts`` is written for -- and nothing in the frozen envelope
records which generation of the root a case was committed under.

Regenerating a view also rebuilds the revision twice, once for the audience and
once inside the commitment read.  Named rather than optimised: the second is
what makes the commitment read self-contained, and a rebuild is bounded by the
per-case entry cap.

**Idempotent by content, not by bookkeeping.**  Everything except the signature
is a deterministic function of the record and the case salt, so re-running this
recomputes an identical envelope; the store keeps whichever arrived first and
says it created nothing.  Reading then recomputes the same envelope and compares
it field by field against what was stored -- so a row that was tampered with, or
written by a build that disagreed about any committed field, is refused instead
of served.  That check is the reason the store itself does not try: there is one
implementation of "is this the envelope the record implies", and it is here,
where the record is.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.application.rebuild import rebuild
from muster.core.analysis.certificate import AnalysisCertificate
from muster.core.case.revision import CaseRevision
from muster.core.results import Err, Ok, Result
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest
from muster.core.wire.shape import decoded
from muster.platform.casework.advance import Casework
from muster.platform.casework.ports import CaseHead, CommitmentFailure, PublishedCommitment
from muster.platform.casework.snapshot import (
    CaseSnapshot,
    SnapshotError,
    SnapshotFailure,
    read_certificate,
    read_published,
)
from muster.platform.commit.build import CaseCommitment, build_commitment, derive_commitment
from muster.platform.commit.envelope import (
    EnvelopeSigner,
    EnvelopeVerifier,
    read_signed_envelope,
    verify_envelope,
)
from muster.platform.commit.record import InternalAnalysisRecord
from muster.platform.commit.salts import CaseSaltSource
from muster.platform.disclose.policy import validate_policy
from muster.policy.manifest import LoadedBundle


@dataclass(frozen=True, slots=True)
class Commitment:
    """Everything committing a case needs, and nothing that holds state.

    The salt source and the signer are separate ports rather than one "crypto"
    object because they are separate keys with separate custody: a MAC key that
    can derive every case salt in the tenant, and a signing key whose public
    half every participant holds.  A single object holding both is a single
    thing to compromise.

    The **verifier** is here because the control plane reads envelopes it wrote
    earlier, and "earlier" may be before the current signing key existed.
    ``retired_key_refs`` names the keys it has stopped signing under and has not
    stopped honouring; ``accepted_key_refs`` is that set plus the signer's own.
    Without them a key rotation would make every commitment taken before it
    permanently unreadable -- the same failure as an engine change, one layer up
    -- and *with* them the read path has to establish authenticity itself rather
    than inferring it from a key reference it assumed.
    """

    casework: Casework
    salts: CaseSaltSource
    signer: EnvelopeSigner
    verifier: EnvelopeVerifier
    retired_key_refs: frozenset[str] = frozenset()

    @property
    def accepted_key_refs(self) -> frozenset[str]:
        """Every signer reference a stored envelope of this tenant may name."""
        return self.retired_key_refs | {self.signer.key_ref}


class CommitmentFailureReason(Enum):
    #: The case, or one of the artifacts it is pinned to, could not be read.
    SNAPSHOT_REFUSED = "SNAPSHOT_REFUSED"
    #: The case is open and has never been analysed, so there is no record to
    #: commit.  Not an error in the case, only in asking now.
    NOT_ANALYSED = "NOT_ANALYSED"
    #: The head names a certificate the store hands back as octets that are not
    #: one: undecodable, refused by the typed reader, or not reproducing the
    #: digest it is stored under.  Fails closed -- no path here proceeds on
    #: octets it could not read.
    CERTIFICATE_UNREADABLE = "CERTIFICATE_UNREADABLE"
    #: The head names a certificate the store does not have.  A retention
    #: question rather than an integrity one, and the distinction is the whole
    #: reason it has its own name: the row is recoverable by an engine that
    #: still reproduces it, and a corrupt one is not.
    CERTIFICATE_ABSENT = "CERTIFICATE_ABSENT"
    #: The head could not be rebuilt at all.
    REBUILD_REFUSED = "REBUILD_REFUSED"
    #: Replaying the head's own inputs produced a different revision than the
    #: head names.  A revision is a pure function of those inputs and the store,
    #: so this is never a configuration difference: one of them is not what it
    #: was.
    REVISION_DIVERGED = "REVISION_DIVERGED"
    #: The stored certificate is well-formed and belongs somewhere else: it
    #: names another case, cites another revision, or pins another bundle than
    #: the head does.  Distinguished from unreadable because it says the
    #: opposite thing -- the artifact is fine, and it is not this case's.
    CERTIFICATE_NOT_BOUND = "CERTIFICATE_NOT_BOUND"
    #: The bundle the head pins is not resolvable in this process.
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    #: The pinned bundle's disclosure policy would not survive being applied.
    #: Refused at pin time, so a policy that could over-disclose never reaches
    #: the point of producing a view.
    POLICY_INVALID = "POLICY_INVALID"
    #: The record's leaf set could not be extracted.
    RECORD_NOT_COMMITTABLE = "RECORD_NOT_COMMITTABLE"
    #: Durable custody refused the envelope.
    STORE_REFUSED = "STORE_REFUSED"
    #: No envelope has been published for the revision the head names.
    COMMITMENT_ABSENT = "COMMITMENT_ABSENT"
    #: A stored envelope naming a signer reference this control plane does not
    #: hold and has not retired.  Refused before anything is derived from it:
    #: the key reference decides which key the signature is checked against, so
    #: believing the row about it is believing the row about its own
    #: authenticity.
    SIGNER_NOT_ACCEPTED = "SIGNER_NOT_ACCEPTED"
    #: A stored envelope whose signature does not verify under the key it names.
    #: The row was written by something that could not sign, which is the shape
    #: an attacker with database access has.
    ENVELOPE_NOT_AUTHENTIC = "ENVELOPE_NOT_AUTHENTIC"
    #: A stored envelope that is not the one this record implies.  Either the
    #: row was altered, or it was written by something that disagreed about a
    #: committed field; both are refusals rather than a choice between them.
    COMMITMENT_INCONSISTENT = "COMMITMENT_INCONSISTENT"


@dataclass(frozen=True, slots=True)
class CommitmentRejection:
    failure: CommitmentFailureReason
    detail: str


@dataclass(frozen=True, slots=True)
class CommittedCase:
    """A committed case, with what it was committed from still to hand."""

    commitment: CaseCommitment
    bundle: LoadedBundle
    record: InternalAnalysisRecord
    published: bool

    @property
    def revision_digest(self) -> Digest:
        return self.record.revision.digest()

    def __repr__(self) -> str:
        return (
            f"CommittedCase(revision={self.revision_digest.hex}, "
            f"published={self.published}, commitment={self.commitment!r}, "
            f"record={self.record!r})"
        )


def _prepare(
    commitment: Commitment, *, tenant_id: str, case_id: str
) -> Result[tuple[LoadedBundle, InternalAnalysisRecord], CommitmentRejection]:
    """Replay the head, read the certificate it names, and assemble the record.

    One read transaction, then everything expensive outside it.  The rebuild is
    deterministic and solver-free, which is what makes committing -- and reading
    a commitment back on every disclosure -- affordable at all.
    """
    with commitment.casework.database.reading(tenant_id) as scope:
        snapshot = read_published(
            scope,
            case_id,
            commitment.casework.publisher_verifier,
            commitment.casework.officer_verifier,
            commitment.casework.source_verifier,
        )
        if isinstance(snapshot, Err):
            return Err(_from_snapshot(snapshot.error, tenant_id, case_id))
        certificate = read_certificate(scope, snapshot.value.head)
        if isinstance(certificate, Err):
            return Err(_from_certificate(certificate.error))

    head = snapshot.value.head
    loaded = commitment.casework.registry.load_by_digest(head.inputs.bundle_manifest_digest)
    if isinstance(loaded, Err):
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.POLICY_UNAVAILABLE,
                f"{loaded.error.failure.value}: {loaded.error.detail}",
            )
        )
    bundle = loaded.value

    valid = validate_policy(bundle.disclosure_policy, ratifications=bundle.ratifications)
    if isinstance(valid, Err):
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.POLICY_INVALID,
                f"{valid.error.failure.value}: {valid.error.detail}",
            )
        )

    replayed = _replay(snapshot.value, bundle)
    if isinstance(replayed, Err):
        return replayed
    revision = replayed.value

    bound = _certificate_binds(certificate.value, head=head, revision=revision)
    if isinstance(bound, Err):
        return bound

    record = InternalAnalysisRecord(
        certificate=certificate.value,
        revision=revision,
        #  The kernel keeps the projected action; nothing here reconstructs the
        #  unprojected one, so ``action.full`` is not among the committed paths.
        full_action=None,
        salt=commitment.salts.salt_for(tenant_id=tenant_id, case_id=case_id),
    )
    return Ok((bundle, record))


def _from_certificate(error: SnapshotError) -> CommitmentRejection:
    """Three operationally different states, kept apart.

    A pruned row, a corrupt one and an artifact belonging to another case are
    the same refusal to a caller and three different problems to an operator:
    retention, integrity, and something that should not exist.  Collapsing them
    would leave whoever is paged with only "the certificate is unreadable".
    """
    match error.failure:
        case SnapshotFailure.CONTENT_ABSENT:
            reason = CommitmentFailureReason.CERTIFICATE_ABSENT
        case SnapshotFailure.BINDING_MISMATCH:
            reason = CommitmentFailureReason.CERTIFICATE_NOT_BOUND
        case _:
            reason = CommitmentFailureReason.CERTIFICATE_UNREADABLE
    return CommitmentRejection(reason, f"{error.failure.value}: {error.detail}")


def _from_snapshot(error: SnapshotError, tenant_id: str, case_id: str) -> CommitmentRejection:
    if error.failure is SnapshotFailure.NOT_ANALYSED:
        return CommitmentRejection(
            CommitmentFailureReason.NOT_ANALYSED, f"{tenant_id}/{case_id} has no revision"
        )
    return CommitmentRejection(
        CommitmentFailureReason.SNAPSHOT_REFUSED, f"{error.failure.value}: {error.detail}"
    )


def _replay(
    snapshot: CaseSnapshot, bundle: LoadedBundle
) -> Result[CaseRevision, CommitmentRejection]:
    """The head's own revision, derived again from the artifacts it pins.

    Reading the certificate instead of recomputing it weakens nothing about
    revision reproduction: the revision still has to come back out of the store
    exactly, and a case whose replay disagrees with its head is refused here
    precisely as it was before.
    """
    head = snapshot.head
    derived = rebuild(
        head.inputs,
        snapshot.construction,
        snapshot.entries,
        bundle,
        snapshot.authorization_context,
        snapshot.authority.snapshot,
        snapshot.authority.revocation,
        snapshot.solicitations,
    )
    if isinstance(derived, Err):
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.REBUILD_REFUSED,
                f"{derived.error.failure.value}: {derived.error.detail}",
            )
        )
    if derived.value.digest() != head.revision_digest:
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.REVISION_DIVERGED,
                f"replay produced {derived.value.digest().hex}",
            )
        )
    return Ok(derived.value)


def _certificate_binds(
    certificate: AnalysisCertificate, *, head: CaseHead, revision: CaseRevision
) -> Result[None, CommitmentRejection]:
    """Is this stored certificate the one this replayed case was decided under?

    ``read_certificate`` has already established that the octets are readable,
    that reading them is lossless, and that they name this tenant and this case.
    What is left is the pair of bindings only a caller holding the replay can
    check: the certificate must cite the revision the rebuild produced, and it
    must pin the bundle the head pins.  Without the first, a certificate from an
    earlier revision of the same case would commit leaves describing a decision
    that has since been superseded.  Without the second, a decision taken under
    one rulebook would be committed as though it had been taken under another.
    """
    if certificate.revision_semantic_digest != revision.digest():
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.CERTIFICATE_NOT_BOUND,
                f"the stored certificate cites {certificate.revision_semantic_digest.hex}, "
                f"and the head replayed to {revision.digest().hex}",
            )
        )
    if certificate.bundle_manifest_digest != head.inputs.bundle_manifest_digest:
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.CERTIFICATE_NOT_BOUND,
                f"the stored certificate pins {certificate.bundle_manifest_digest.hex}, "
                f"and the head pins {head.inputs.bundle_manifest_digest.hex}",
            )
        )
    return Ok(None)


def commit_case(
    commitment: Commitment, *, tenant_id: str, case_id: str
) -> Result[CommittedCase, CommitmentRejection]:
    """Commit the revision this case's head names, and publish the envelope.

    No clock, and nothing here for one to decide.  What is committed is a
    function of the head, the artifacts it pins and the case salt, and every one
    of those is fixed before this is called -- so an instant could only be
    recorded, and recording it would put a field in a signed envelope that no
    recipient could ever check.
    """
    prepared = _prepare(commitment, tenant_id=tenant_id, case_id=case_id)
    if isinstance(prepared, Err):
        return prepared
    bundle, record = prepared.value

    built = build_commitment(
        record,
        disclosure_policy_digest=bundle.disclosure_policy.digest(),
        signer=commitment.signer,
    )
    if isinstance(built, Err):
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.RECORD_NOT_COMMITTABLE,
                f"{built.error.path_failure.value}: {built.error.detail}",
            )
        )
    case_commitment = built.value

    revision_digest = record.revision.digest()
    with commitment.casework.database.writing(tenant_id) as scope:
        published = scope.commitments.publish(
            PublishedCommitment(
                case_id=case_id,
                revision_digest=revision_digest,
                envelope_octets=case_commitment.signed_envelope.octets(),
            )
        )
        if isinstance(published, Err):
            return Err(
                CommitmentRejection(
                    CommitmentFailureReason.STORE_REFUSED,
                    f"{published.error.failure.value}: {published.error.detail}",
                )
            )
        created = published.value

    if created:
        return Ok(CommittedCase(case_commitment, bundle, record, published=True))

    #  Somebody committed this revision first.  Theirs is the artifact every
    #  participant will be handed, so this call adopts it rather than returning
    #  an envelope nobody stored -- after checking it is the same commitment.
    adopted = read_commitment(commitment, tenant_id=tenant_id, case_id=case_id)
    if isinstance(adopted, Err):
        return adopted
    return Ok(CommittedCase(adopted.value.commitment, bundle, record, published=False))


def read_commitment(
    commitment: Commitment, *, tenant_id: str, case_id: str
) -> Result[CommittedCase, CommitmentRejection]:
    """The published envelope for the head's revision, checked against the record.

    Three checks in one order that matters.  The row's signer reference must be
    one this control plane accepts; the stored signature must verify under it;
    and the envelope re-derived from the record must match the stored one field
    by field.  The signature is then kept as-is rather than re-issued -- it is
    the one part that is not reproducible, and it is what a participant checks
    for themselves.

    Verifying here does not make the participant's check redundant.  It is the
    control plane refusing to *serve* an artifact it cannot itself authenticate,
    which is a different question from the recipient refusing to *believe* one.
    """
    prepared = _prepare(commitment, tenant_id=tenant_id, case_id=case_id)
    if isinstance(prepared, Err):
        return prepared
    bundle, record = prepared.value
    revision_digest = record.revision.digest()

    with commitment.casework.database.reading(tenant_id) as scope:
        stored = scope.commitments.read(case_id, revision_digest)
    if isinstance(stored, Err):
        reason = (
            CommitmentFailureReason.COMMITMENT_ABSENT
            if stored.error.failure is CommitmentFailure.COMMITMENT_ABSENT
            else CommitmentFailureReason.STORE_REFUSED
        )
        return Err(CommitmentRejection(reason, stored.error.detail))

    node = decode(stored.value.envelope_octets)
    if isinstance(node, Err):
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.COMMITMENT_INCONSISTENT,
                f"the stored envelope does not decode: {node.error.failure.value}",
            )
        )
    #  Typed, because these octets are a row rather than a value this process
    #  produced. A malformed record and an out-of-range field both raise out of
    #  the readers, and an exception escaping here would turn a one-byte
    #  corruption into a crash on the disclosure path instead of a refusal --
    #  observably different from "absent", which is itself a disclosure.
    read = decoded(lambda: read_signed_envelope(node.value))
    if isinstance(read, Err):
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.COMMITMENT_INCONSISTENT,
                f"the stored envelope is not a well-formed one: {read.error}",
            )
        )
    signed = read.value

    #  Authenticity first, and it is established rather than assumed.
    #
    #  The key reference is re-derived *from the row* below, which on its own
    #  would make the field comparison tautological on exactly the field an
    #  attacker with write access would move.  What stops that is this pair of
    #  checks: the reference must be one this control plane holds or has
    #  retired, and the signature must verify under it.  An envelope
    #  re-attributed to a foreign key fails the first; one re-attributed to
    #  another accepted key fails the second, because whoever wrote the row
    #  could not sign for that key either.
    #
    #  Deriving from the row is what makes a key rotation survivable: an
    #  envelope signed last year names last year's key, and demanding it name
    #  today's would refuse every commitment taken before the rotation.
    if signed.envelope.signer_key_ref not in commitment.accepted_key_refs:
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.SIGNER_NOT_ACCEPTED,
                f"the stored envelope names {signed.envelope.signer_key_ref!r}",
            )
        )
    if not verify_envelope(signed, commitment.verifier, trusted_keys=commitment.accepted_key_refs):
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.ENVELOPE_NOT_AUTHENTIC,
                f"{tenant_id}/{case_id}: the stored signature does not verify",
            )
        )

    rebuilt = derive_commitment(
        record,
        disclosure_policy_digest=bundle.disclosure_policy.digest(),
        signer_key_ref=signed.envelope.signer_key_ref,
    )
    if isinstance(rebuilt, Err):
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.RECORD_NOT_COMMITTABLE,
                f"{rebuilt.error.path_failure.value}: {rebuilt.error.detail}",
            )
        )
    if rebuilt.value.envelope != signed.envelope:
        return Err(
            CommitmentRejection(
                CommitmentFailureReason.COMMITMENT_INCONSISTENT,
                f"{tenant_id}/{case_id}: the stored envelope is not the one this record implies",
            )
        )
    return Ok(
        CommittedCase(CaseCommitment(rebuilt.value.tree, signed), bundle, record, published=False)
    )
