"""Routing: resolve the current catalog, then discover one candidate in it.

Two steps with a boundary between them, and the boundary is why this is not one
function.  Resolving a catalog is custody work -- read the octets, verify the
publisher signature, re-derive the digest, bind the tenant.  Discovery is a
pure function over the resolved snapshot, so it is in the kernel, testable
without a database, and structurally unable to reach an authority snapshot.

**A route is an address, not a permission.**  Everything this module returns is
"you could ask this agent".  When that agent answers, its receipt goes through
signature verification and Q-12 exactly as any other receipt does, against the
authority snapshot the *case* pinned -- which this module never reads and could
not influence.  Deleting the catalog would change which agent gets asked and
would change no admission decision at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.authority.signing import PublisherRole, PublisherVerifier
from muster.core.catalog.discovery import (
    DiscoveryError,
    DiscoveryQuery,
    discover,
)
from muster.core.catalog.profiles import (
    AgentCatalogSnapshot,
    AgentProfile,
    read_signed_agent_catalog_snapshot,
)
from muster.core.catalog.publishing import catalog_snapshot_preimage
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest
from muster.core.wire.shape import decoded
from muster.platform.casework.ports import TenantScope


class CatalogResolutionFailure(Enum):
    CATALOG_ABSENT = "CATALOG_ABSENT"
    CATALOG_UNREADABLE = "CATALOG_UNREADABLE"
    CATALOG_SIGNATURE_INVALID = "CATALOG_SIGNATURE_INVALID"
    CATALOG_DIGEST_MISMATCH = "CATALOG_DIGEST_MISMATCH"
    CATALOG_TENANT_MISMATCH = "CATALOG_TENANT_MISMATCH"


@dataclass(frozen=True, slots=True)
class CatalogResolutionError:
    failure: CatalogResolutionFailure
    detail: str


type RouteError = CatalogResolutionError | DiscoveryError


def resolve_catalog(
    scope: TenantScope, verifier: PublisherVerifier, snapshot_digest: Digest | None = None
) -> Result[AgentCatalogSnapshot, CatalogResolutionError]:
    """The tenant's catalog: a named snapshot, or the most recent one.

    ``snapshot_digest`` is optional here and has no optional counterpart in the
    authority seam, which is the asymmetry that keeps the two apart.  Asking
    "which agent can I ask now" from the newest catalog is correct.  Asking
    "what was this key allowed to say" from the newest registry would be the
    substitution the pin exists to prevent, so there is no way to spell it.
    """
    fetched = (
        scope.catalog.latest() if snapshot_digest is None else scope.catalog.read(snapshot_digest)
    )
    if isinstance(fetched, Err):
        return Err(
            CatalogResolutionError(
                CatalogResolutionFailure.CATALOG_ABSENT,
                f"{fetched.error.failure.value}: {fetched.error.detail}",
            )
        )
    node = decode(fetched.value.signed_octets)
    if isinstance(node, Err):
        return Err(_unreadable(str(node.error)))
    payload = node.value
    try:
        read = decoded(lambda: read_signed_agent_catalog_snapshot(payload))
    except InvariantViolation as violation:
        #  A catalog with two active versions of one agent, or two profiles
        #  sharing an identity, is refused by its constructor.  Read back from
        #  a store that has to be a value, not an exception on a routing path.
        return Err(_unreadable(str(violation)))
    if isinstance(read, Err):
        return Err(_unreadable(str(read.error)))
    signed = read.value

    if not verifier.verify(
        role=PublisherRole.CATALOG,
        key_ref=signed.body.signer_key_ref,
        preimage=catalog_snapshot_preimage(signed.body),
        signature=signed.signature,
    ):
        return Err(
            CatalogResolutionError(
                CatalogResolutionFailure.CATALOG_SIGNATURE_INVALID,
                f"{signed.body.signer_key_ref} did not sign this catalog",
            )
        )
    catalog = signed.body.snapshot
    if catalog.digest() != fetched.value.snapshot_digest:
        return Err(
            CatalogResolutionError(
                CatalogResolutionFailure.CATALOG_DIGEST_MISMATCH,
                f"stored under {fetched.value.snapshot_digest.hex}, carries {catalog.digest().hex}",
            )
        )
    if catalog.tenant_id != scope.tenant_id:
        return Err(
            CatalogResolutionError(
                CatalogResolutionFailure.CATALOG_TENANT_MISMATCH,
                f"{catalog.tenant_id!r} read under {scope.tenant_id!r}",
            )
        )
    return Ok(catalog)


def route(
    scope: TenantScope, verifier: PublisherVerifier, query: DiscoveryQuery
) -> Result[AgentProfile, RouteError]:
    """The single cataloged agent this request could go to, or why none can.

    The query's tenant is checked twice -- once here against the scope, and
    again inside ``discover`` against the catalog's own tenant.  The scope
    already makes a cross-tenant *read* unrepresentable; this check catches the
    other direction, a correctly-scoped read asked a question about somebody
    else, which would leak the existence of another tenant's fleet.
    """
    if query.tenant_id != scope.tenant_id:
        return Err(
            CatalogResolutionError(
                CatalogResolutionFailure.CATALOG_TENANT_MISMATCH,
                f"a query for {query.tenant_id!r} was run under {scope.tenant_id!r}",
            )
        )
    catalog = resolve_catalog(scope, verifier)
    if isinstance(catalog, Err):
        return catalog
    return discover(catalog.value, query)


def _unreadable(detail: str) -> CatalogResolutionError:
    return CatalogResolutionError(
        CatalogResolutionFailure.CATALOG_UNREADABLE, f"AgentCatalogSnapshot: {detail}"
    )
