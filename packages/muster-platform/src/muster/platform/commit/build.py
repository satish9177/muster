"""Assembling one case commitment: extract, salt, hash, bind, sign.

Five steps and one value out.  The order is not arbitrary -- each step's output
is the next one's input and there is no point at which a caller supplies
something it could have chosen differently:

    committed leaves   from the record alone, by the frozen extractor
    salted commitments from the case salt and the record's own digests
    the tree           from the leaves, in canonical path order
    the envelope       from the tree, the pins, and the signer's own key
    the signature      over the envelope, by the signing port

The reason this is one function rather than a builder object is that a
half-built commitment is not a useful value.  A tree with no envelope proves
nothing to anybody, and an envelope with no tree cannot be disclosed against.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.results import Err, Ok, Result
from muster.core.wire.digests import Digest
from muster.platform.commit.envelope import (
    CommitmentEnvelope,
    EnvelopeSigner,
    SignedCommitmentEnvelope,
    sign_envelope,
)
from muster.platform.commit.paths import PathFailure
from muster.platform.commit.record import InternalAnalysisRecord
from muster.platform.commit.salts import case_commitment, revision_commitment
from muster.platform.commit.tree import (
    CommitmentTree,
    LeafBinding,
    RootBinding,
    build_tree,
)


class CommitFailure(Enum):
    #: The record's leaf set could not be extracted.  Carries the path-level
    #: reason rather than flattening it: a duplicate path and an unknown path
    #: are different defects with different fixes.
    RECORD_NOT_EXTRACTABLE = "RECORD_NOT_EXTRACTABLE"


@dataclass(frozen=True, slots=True)
class CommitRejection:
    failure: CommitFailure
    path_failure: PathFailure
    detail: str


@dataclass(frozen=True, slots=True)
class UnsignedCommitment:
    """A commitment that has been derived but not yet authenticated.

    It exists because deriving and signing are needed separately: publishing
    does both, and *reading back* does only the first -- it re-derives the
    envelope to check the stored one against, and must be able to do that
    without holding a signing key.
    """

    tree: CommitmentTree
    envelope: CommitmentEnvelope

    def __repr__(self) -> str:
        return f"UnsignedCommitment(envelope={self.envelope!r}, tree={self.tree!r})"


@dataclass(frozen=True, slots=True)
class CaseCommitment:
    """A committed case: the tree it was committed as, and the signed envelope.

    The tree stays on this side of the boundary because it holds every field
    salt.  What a participant receives is the envelope plus one salt per path
    their policy entry permits, which is why disclosure takes the commitment
    rather than the other way round.
    """

    tree: CommitmentTree
    signed_envelope: SignedCommitmentEnvelope

    @property
    def envelope(self) -> CommitmentEnvelope:
        return self.signed_envelope.envelope

    def __repr__(self) -> str:
        #  Spelled out rather than inherited, so that the tree's own redaction
        #  cannot be undone by a wrapper somebody added later.
        return f"CaseCommitment(envelope={self.envelope!r}, tree={self.tree!r})"


def derive_commitment(
    record: InternalAnalysisRecord,
    *,
    disclosure_policy_digest: Digest,
    signer_key_ref: str,
) -> Result[UnsignedCommitment, CommitRejection]:
    """Everything a commitment is, short of the signature over it.

    ``disclosure_policy_digest`` is an argument rather than something read off
    the record because it is a *pin*, not a derivation: the envelope's job is to
    state which policy the views over this commitment were resolved against, so
    that a reader supplied with a different policy detects the substitution
    instead of quietly resolving against it.
    """
    extracted = record.committed()
    if isinstance(extracted, Err):
        return Err(
            CommitRejection(
                CommitFailure.RECORD_NOT_EXTRACTABLE,
                extracted.error.failure,
                extracted.error.detail,
            )
        )
    committed = extracted.value

    revision = record.revision
    certificate = record.certificate
    case = case_commitment(record.salt, revision.construction_digest)
    revised = revision_commitment(record.salt, revision.digest())
    schema_version = certificate.certificate_schema_version

    tree = build_tree(
        binding=LeafBinding(
            tenant_id=revision.tenant_id,
            case_commitment=case,
            revision_commitment=revised,
            certificate_schema_version=schema_version,
        ),
        root_binding=RootBinding(
            tenant_id=revision.tenant_id,
            case_id=revision.case_id,
            revision_commitment=revised,
            bundle_manifest_digest=certificate.bundle_manifest_digest,
            certificate_schema_version=schema_version,
        ),
        record=committed,
        salt=record.salt,
    )

    envelope = CommitmentEnvelope(
        tenant_id=revision.tenant_id,
        case_id=revision.case_id,
        case_commitment=case,
        revision_commitment=revised,
        bundle_manifest_digest=certificate.bundle_manifest_digest,
        disclosure_policy_digest=disclosure_policy_digest,
        certificate_schema_version=schema_version,
        leaf_count=tree.leaf_count,
        root=tree.root,
        signer_key_ref=signer_key_ref,
    )
    return Ok(UnsignedCommitment(tree, envelope))


def build_commitment(
    record: InternalAnalysisRecord,
    *,
    disclosure_policy_digest: Digest,
    signer: EnvelopeSigner,
) -> Result[CaseCommitment, CommitRejection]:
    """Commit a decided case under its own salt, and authenticate the result."""
    derived = derive_commitment(
        record,
        disclosure_policy_digest=disclosure_policy_digest,
        signer_key_ref=signer.key_ref,
    )
    if isinstance(derived, Err):
        return derived
    return Ok(CaseCommitment(derived.value.tree, sign_envelope(derived.value.envelope, signer)))
