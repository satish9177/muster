"""Commitment envelopes: one immutable row per published revision.

``INSERT ... ON CONFLICT DO NOTHING`` and a ``SELECT``.  There is no ``UPDATE``
in this file and there must never be one -- a participant who verified an
envelope yesterday has to be able to verify *that* envelope today, and a row
that can be rewritten makes "the record MUSTER committed to" a thing with a
history.

Two publications of one revision therefore keep the first, and the second is
told it created nothing.  That is not last-writer-loses arbitrariness: the
envelope's content is a function of the record and the case salt, so both
publications agree about every field except the signature, and two valid
signatures over identical content are equally true.  Keeping the earlier one is
the only choice that makes the artifact stable.

The read re-checks nothing about the envelope's content, deliberately.  This
layer stores octets; whether those octets are the envelope the record implies
is a question with an answer, and the answer belongs where the record is --
``commit.publish`` recomputes it and refuses a mismatch.  A store that also
tried would be a second, weaker implementation of the same check.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.digests import Digest
from muster.platform.casework.ports import (
    CommitmentError,
    CommitmentFailure,
    PublishedCommitment,
)

_INSERT = """
INSERT INTO casework.case_commitment (tenant_id, case_id, revision_digest, envelope)
VALUES (%s, %s, %s, %s)
ON CONFLICT (tenant_id, case_id, revision_digest) DO NOTHING
"""

_SELECT = """
SELECT envelope FROM casework.case_commitment
WHERE tenant_id = %s AND case_id = %s AND revision_digest = %s
"""

_CASE_EXISTS = "SELECT 1 FROM casework.case_head WHERE tenant_id = %s AND case_id = %s"


@dataclass(frozen=True, slots=True)
class SqlCommitmentRepository:
    connection: psycopg.Connection[tuple[object, ...]]
    tenant_id: str

    def publish(self, commitment: PublishedCommitment) -> Result[bool, CommitmentError]:
        if (
            self.connection.execute(_CASE_EXISTS, (self.tenant_id, commitment.case_id)).fetchone()
            is None
        ):
            #  Checked before the insert rather than left to the foreign key,
            #  so an unknown case is a typed rejection instead of an integrity
            #  error that takes the caller's whole transaction down with it.
            return Err(CommitmentError(CommitmentFailure.UNKNOWN_CASE, commitment.case_id))
        cursor = self.connection.execute(
            _INSERT,
            (
                self.tenant_id,
                commitment.case_id,
                commitment.revision_digest.octets,
                commitment.envelope_octets,
            ),
        )
        return Ok(cursor.rowcount == 1)

    def read(
        self, case_id: str, revision_digest: Digest
    ) -> Result[PublishedCommitment, CommitmentError]:
        row = self.connection.execute(
            _SELECT, (self.tenant_id, case_id, revision_digest.octets)
        ).fetchone()
        if row is None:
            return Err(
                CommitmentError(
                    CommitmentFailure.COMMITMENT_ABSENT,
                    f"{case_id} has no commitment for {revision_digest.hex}",
                )
            )
        octets = row[0]
        if not isinstance(octets, bytes | memoryview):
            raise InvariantViolation(f"case_commitment.envelope is not bytea: {octets!r}")
        return Ok(PublishedCommitment(case_id, revision_digest, bytes(octets)))
