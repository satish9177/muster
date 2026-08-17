"""The content store, as four statements.

``put`` derives the key from the octets and the domain, so there is no way to
ask this store to file a preimage under a name that is not its own.  What
remains is the case the design has to be explicit about: a row already exists
under that key.  Almost always the octets are identical and the write is an
idempotent no-op -- at-least-once delivery, a retry after a lost
compare-and-swap, the same receipt submitted twice.  If they are *not*
identical, under SHA-256, this is not a race and not something to retry: it is
corruption or a forged row, and the only safe answer is to refuse loudly.

``get`` recomputes the digest of what it read and refuses a mismatch.  That
costs one hash of a few kilobytes and buys the property every other guarantee
here rests on: a store that hands back the wrong preimage makes every digest in
the system a lie, and it would do it silently.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.digests import Digest, DigestKind, digest_octets
from muster.platform.casework.ports import StoreError, StoreFailure

_INSERT = """
INSERT INTO store.content (tenant_id, digest, kind, octets)
VALUES (%s, %s, %s, %s)
ON CONFLICT (tenant_id, digest) DO NOTHING
"""

_SELECT = "SELECT kind, octets FROM store.content WHERE tenant_id = %s AND digest = %s"


@dataclass(frozen=True, slots=True)
class SqlContentStore:
    """Bound to one tenant and one transaction. Neither is a parameter."""

    connection: psycopg.Connection[tuple[object, ...]]
    tenant_id: str

    def put(self, kind: DigestKind, octets: bytes) -> Result[Digest, StoreError]:
        digest = digest_octets(kind, octets)
        inserted = self.connection.execute(
            _INSERT, (self.tenant_id, digest.octets, kind.value, octets)
        )
        if inserted.rowcount == 1:
            return Ok(digest)

        #  The insert conflicted, which means PostgreSQL waited for whichever
        #  transaction held the conflicting tuple and then found it committed.
        #  A read-committed statement therefore sees it now.
        existing = self.connection.execute(_SELECT, (self.tenant_id, digest.octets)).fetchone()
        if existing is None:
            return Err(
                StoreError(
                    StoreFailure.CONTENT_NOT_VISIBLE,
                    digest.hex,
                    "conflicting row is not visible to this transaction",
                )
            )
        stored_kind, stored_octets = _row(existing)
        if stored_octets != octets or stored_kind != kind.value:
            return Err(
                StoreError(
                    StoreFailure.DIGEST_COLLISION,
                    digest.hex,
                    f"stored {stored_kind}/{len(stored_octets)} octets, "
                    f"offered {kind.value}/{len(octets)} octets",
                )
            )
        return Ok(digest)

    def get(self, kind: DigestKind, digest: Digest) -> Result[bytes, StoreError]:
        found = self.connection.execute(_SELECT, (self.tenant_id, digest.octets)).fetchone()
        if found is None:
            return Err(StoreError(StoreFailure.CONTENT_ABSENT, digest.hex, kind.value))
        stored_kind, octets = _row(found)
        if stored_kind != kind.value:
            return Err(
                StoreError(
                    StoreFailure.CONTENT_CORRUPT,
                    digest.hex,
                    f"stored as {stored_kind}, read as {kind.value}",
                )
            )
        if digest_octets(kind, octets) != digest:
            return Err(
                StoreError(
                    StoreFailure.CONTENT_CORRUPT, digest.hex, "octets do not hash to their key"
                )
            )
        return Ok(octets)


def _row(row: tuple[object, ...]) -> tuple[str, bytes]:
    """Narrow a driver row to the column types the schema declares.

    The columns are ``NOT NULL text`` and ``NOT NULL bytea``, so a value of any
    other shape means the code and the schema have drifted apart -- programmer
    error, which is what ``InvariantViolation`` is for, rather than a typed
    rejection that would invite a caller to carry on.
    """
    kind, octets = row
    if not isinstance(kind, str) or not isinstance(octets, bytes | memoryview):
        raise InvariantViolation(f"store.content row is not (text, bytea): {type(kind).__name__}")
    return kind, bytes(octets)
