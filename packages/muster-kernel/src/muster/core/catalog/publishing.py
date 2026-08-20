"""What a catalog publisher signature covers.

The preimage *type* is shared with the authority registry's publisher boundary
-- both are control-plane publications and both are signed by a publisher key,
so inventing a second, incompatible signing stack for the catalog would buy
nothing and would double the surface that has to stay in step.  What is not
shared is the **domain**: the preimage is digested under
``AGENT_CATALOG_SNAPSHOT_BODY``, so a signature over a catalog can never be
replayed as a signature over an authority registry, whatever a key is trusted
for.

That is the whole reason the two publications are separable even under one key:
domain separation makes "this publisher signed a catalog" and "this publisher
signed a grant" two different statements about two different preimages.
"""

from __future__ import annotations

from muster.core.authority.signing import PublisherPreimage
from muster.core.catalog.profiles import AgentCatalogSnapshotBody
from muster.core.wire.codec import encode
from muster.core.wire.digests import DigestKind, digest_octets


def catalog_snapshot_preimage(body: AgentCatalogSnapshotBody) -> PublisherPreimage:
    """What a publisher signs when it publishes the fleet."""
    return PublisherPreimage(
        digest_octets(DigestKind.AGENT_CATALOG_SNAPSHOT_BODY, encode(body.to_node())).octets
    )
