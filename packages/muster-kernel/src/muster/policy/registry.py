"""Resolving a policy, and loading one by digest.

Two operations, and they are not the same operation:

* ``resolve(policy_id, as_of)`` picks the manifest that is effective at an
  instant.  It can fail two ways that must not be conflated -- nothing
  effective, or more than one effective.  Silently choosing the newest of two
  overlapping bundles would make the pin depend on insertion order.
* ``load_by_digest(digest)`` returns exactly the tuple that was ratified.
  Replay uses only this one, so replay resolves nothing and cannot drift.

Retention is immutable and total: a digest that ever resolved keeps resolving.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.times import Instant
from muster.core.wire.digests import Digest
from muster.policy.manifest import LoadedBundle


class RegistryFailure(Enum):
    POLICY_VERSION_UNAVAILABLE = "PolicyVersionUnavailable"
    POLICY_NOT_EFFECTIVE = "PolicyNotEffective"
    AMBIGUOUS_POLICY_RESOLUTION = "AmbiguousPolicyResolution"


@dataclass(frozen=True, slots=True)
class RegistryError:
    failure: RegistryFailure
    detail: str


class BundleRegistry:
    """An immutable, content-addressed set of loaded bundles.

    Concrete and in-memory.  There is one implementation and no persistence
    requirement in this milestone, so there is no port here to abstract over --
    the seam that will matter later is the content store, not this lookup.
    """

    def __init__(self, bundles: tuple[LoadedBundle, ...]) -> None:
        by_digest: dict[Digest, LoadedBundle] = {}
        for bundle in bundles:
            digest = bundle.digest()
            if digest in by_digest:
                raise InvariantViolation(f"bundle {digest} registered twice")
            by_digest[digest] = bundle
        self._by_digest = by_digest

    def load_by_digest(self, digest: Digest) -> Result[LoadedBundle, RegistryError]:
        bundle = self._by_digest.get(digest)
        if bundle is None:
            return Err(RegistryError(RegistryFailure.POLICY_VERSION_UNAVAILABLE, digest.hex))
        return Ok(bundle)

    def resolve(self, policy_id: str, as_of: Instant) -> Result[Digest, RegistryError]:
        effective = [
            bundle
            for bundle in self._by_digest.values()
            if bundle.manifest.policy_id == policy_id and bundle.is_effective_at(as_of)
        ]
        if not effective:
            return Err(RegistryError(RegistryFailure.POLICY_NOT_EFFECTIVE, policy_id))
        if len(effective) > 1:
            #  Overlapping effective intervals are a publication defect. Picking
            #  one would make the answer depend on iteration order.
            return Err(
                RegistryError(
                    RegistryFailure.AMBIGUOUS_POLICY_RESOLUTION,
                    f"{policy_id}: {len(effective)} effective at {as_of}",
                )
            )
        return Ok(effective[0].digest())
