"""Publishing the fleet catalog.

The same trusted-publisher discipline the authority registry uses, for the same
reason and with a different digest domain: an agent cannot publish its own
profile, and a signature over a catalog can never be replayed as a signature
over a grant.

**Publishing a catalog grants nothing.**  That is worth stating where the code
is, because this is the function an attacker would want: if publishing a
profile that claims ``acquirable_predicates = {present_on_site}`` conferred any
authority at all, the whole registry would be decoration.  It does not.  The
profile is a routing record; the grant lives in an artifact this module cannot
write and does not import.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.authority.signing import PublisherRole, PublisherSigner, PublisherVerifier
from muster.core.catalog.profiles import (
    AgentCatalogSnapshot,
    AgentCatalogSnapshotBody,
    SignedAgentCatalogSnapshot,
)
from muster.core.catalog.publishing import catalog_snapshot_preimage
from muster.core.results import Err, Ok, Result
from muster.core.wire.codec import encode
from muster.platform.casework.ports import CaseworkDatabase, Publication


class PublishCatalogFailure(Enum):
    TENANT_MISMATCH = "TENANT_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    STORE_REFUSED = "STORE_REFUSED"
    #: The catalog names an authority snapshot this tenant has not published.
    #: The field is provenance and nothing reads it to decide anything -- which
    #: is exactly why it has to be true: an operator reads "this fleet was
    #: published against that authority", and a provenance field that can name
    #: 32 zero octets is worse than an absent one.
    AUTHORITY_SNAPSHOT_ABSENT = "AUTHORITY_SNAPSHOT_ABSENT"


@dataclass(frozen=True, slots=True)
class PublishCatalogRejection:
    failure: PublishCatalogFailure
    detail: str


@dataclass(frozen=True, slots=True)
class CatalogPublisher:
    """Everything publishing the fleet needs. Holds no state."""

    database: CaseworkDatabase
    signer: PublisherSigner
    verifier: PublisherVerifier


def publish_catalog_snapshot(
    publisher: CatalogPublisher,
    *,
    tenant_id: str,
    snapshot: AgentCatalogSnapshot,
) -> Result[SignedAgentCatalogSnapshot, PublishCatalogRejection]:
    """Sign, verify and store a fleet catalog snapshot.

    **There is no ``now``.**  There was, and it was the row's ordering column --
    a caller's clock reading that nothing reconciled against the signed
    ``published_at``, so a first publication could pin itself at the top of the
    recency order and no successor could ever retire an agent, while every
    signature and digest check still passed.  Recency comes from the signature
    or it is not a fact about the fleet, and the cleanest way to say that is to
    have no other value in scope.
    """
    if snapshot.tenant_id != tenant_id:
        return Err(
            PublishCatalogRejection(
                PublishCatalogFailure.TENANT_MISMATCH,
                f"{snapshot.tenant_id!r} published under {tenant_id!r}",
            )
        )
    body = AgentCatalogSnapshotBody(snapshot, publisher.signer.key_ref)
    preimage = catalog_snapshot_preimage(body)
    signed = SignedAgentCatalogSnapshot(body, publisher.signer.sign(preimage))
    if not publisher.verifier.verify(
        role=PublisherRole.CATALOG,
        key_ref=body.signer_key_ref,
        preimage=preimage,
        signature=signed.signature,
    ):
        return Err(
            PublishCatalogRejection(
                PublishCatalogFailure.SIGNATURE_INVALID,
                f"{body.signer_key_ref} is not a trusted publisher",
            )
        )
    with publisher.database.writing(tenant_id) as scope:
        #  The provenance check comes before the write, so a rejection still
        #  leaves nothing behind -- the early return exits the block normally
        #  and commits a transaction that did nothing.
        named = scope.authority.read_authority(snapshot.authority_registry_snapshot_digest)
        if isinstance(named, Err):
            return Err(
                PublishCatalogRejection(
                    PublishCatalogFailure.AUTHORITY_SNAPSHOT_ABSENT,
                    f"{snapshot.authority_registry_snapshot_digest.hex} has not been published",
                )
            )
        #  Keyed by the **signed** instant, not by the caller's ``now``.  The
        #  ordering column is what ``latest`` reads, and a caller-supplied
        #  value nothing reconciles against the signed content lets a first
        #  publication pin itself at the top of the order forever -- after
        #  which no successor can retire an agent, because no successor can
        #  win.  ``now`` stays in the signature only as the operational
        #  reading, and is not what decides recency.
        stored = scope.catalog.publish(
            Publication(snapshot.digest(), encode(signed.to_node()), snapshot.published_at)
        )
    if isinstance(stored, Err):
        return Err(
            PublishCatalogRejection(
                PublishCatalogFailure.STORE_REFUSED,
                f"{stored.error.failure.value}: {stored.error.detail}",
            )
        )
    return Ok(signed)
