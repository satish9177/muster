"""Transcript membership: an append-only set, and nothing that can shrink it.

There is one write statement and it is an insert with ``ON CONFLICT DO
NOTHING``.  Two consequences fall out and both are load-bearing:

* two appenders of *different* entries never collide, because they write
  different primary keys, so neither can lose the other's row;
* two appenders of the *same* entry produce one member, because the primary
  key is the entry digest, so a retried delivery costs nothing.

There is no ``remove``, no ``replace`` and no ordinal column.  Arrival order is
not recorded because a revision does not commit to it -- the prefix is a sorted
set of digests -- and a column recording it would eventually be read by
something that then depended on it.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.digests import Digest
from muster.platform.casework.ports import TranscriptError, TranscriptFailure

_INSERT = """
INSERT INTO casework.transcript_entry (tenant_id, case_id, entry_digest)
VALUES (%s, %s, %s)
ON CONFLICT (tenant_id, case_id, entry_digest) DO NOTHING
"""

_SELECT = """
SELECT entry_digest FROM casework.transcript_entry
WHERE tenant_id = %s AND case_id = %s
ORDER BY entry_digest
"""

_CASE_EXISTS = "SELECT 1 FROM casework.case_head WHERE tenant_id = %s AND case_id = %s"


@dataclass(frozen=True, slots=True)
class SqlTranscriptRepository:
    connection: psycopg.Connection[tuple[object, ...]]
    tenant_id: str

    def add(self, case_id: str, entry_digest: Digest) -> Result[bool, TranscriptError]:
        #  Checked rather than caught. A case is never deleted, so "it exists"
        #  cannot stop being true between this statement and the next, and the
        #  foreign key stays as the guard against a defect rather than as the
        #  mechanism -- a caught constraint violation would have aborted the
        #  transaction that the caller is still trying to finish.
        if self.connection.execute(_CASE_EXISTS, (self.tenant_id, case_id)).fetchone() is None:
            return Err(TranscriptError(TranscriptFailure.UNKNOWN_CASE, case_id))
        try:
            with self.connection.transaction():
                inserted = self.connection.execute(
                    _INSERT, (self.tenant_id, case_id, entry_digest.octets)
                )
                created = inserted.rowcount == 1
        except psycopg.errors.ForeignKeyViolation as violation:
            #  The only remaining reference is the one to the octets, and it can
            #  only fail if a caller appended membership without admitting the
            #  preimage first. Rolled back to the savepoint, so the caller's
            #  transaction survives to report it.
            return Err(
                TranscriptError(
                    TranscriptFailure.CONTENT_NOT_STORED, str(violation.diag.message_primary)
                )
            )
        return Ok(created)

    def members(self, case_id: str) -> Result[tuple[Digest, ...], TranscriptError]:
        if self.connection.execute(_CASE_EXISTS, (self.tenant_id, case_id)).fetchone() is None:
            return Err(TranscriptError(TranscriptFailure.UNKNOWN_CASE, case_id))
        rows = self.connection.execute(_SELECT, (self.tenant_id, case_id)).fetchall()
        return Ok(tuple(Digest(_octets(row)) for row in rows))


def _octets(row: tuple[object, ...]) -> bytes:
    (value,) = row
    if not isinstance(value, bytes | memoryview):
        raise InvariantViolation(f"entry_digest is not bytea: {type(value).__name__}")
    return bytes(value)
