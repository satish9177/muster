"""Evidence requests: durable intent, immutable rows, derived outstandingness.

Every column except ``deadline`` is a function of the primary key, because the
key *is* the digest of a record containing the revision and the targets.  So a
duplicate registration is a no-op and a registration that disagrees with the
existing row cannot be a legitimate re-registration -- it is a digest naming two
different things, and it is refused as such.

"Outstanding" is a join, not a column.  A request is outstanding exactly while
the head still names the revision it was raised against; storing that as a
status would be writing down something the head already says, and giving a
crash a window in which the two disagree.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.digests import Digest
from muster.platform.casework.ports import RecordedRequest, RequestError, RequestFailure

_INSERT = """
INSERT INTO casework.evidence_request (tenant_id, case_id, request_id, revision_digest, deadline)
VALUES (%s, %s, %s, %s, %s)
ON CONFLICT (tenant_id, case_id, request_id) DO NOTHING
"""

_SELECT_ONE = """
SELECT revision_digest, deadline FROM casework.evidence_request
WHERE tenant_id = %s AND case_id = %s AND request_id = %s
"""

#  Outstanding is defined by the join, so a request stops being outstanding the
#  instant the head moves -- with no second write and therefore no window.
_SELECT_OUTSTANDING = """
SELECT r.request_id, r.revision_digest, r.deadline
  FROM casework.evidence_request AS r
  JOIN casework.case_head AS h
    ON h.tenant_id = r.tenant_id AND h.case_id = r.case_id
 WHERE r.tenant_id = %s AND r.case_id = %s
   AND r.revision_digest = h.revision_digest
 ORDER BY r.request_id
"""

_CASE_EXISTS = "SELECT 1 FROM casework.case_head WHERE tenant_id = %s AND case_id = %s"


@dataclass(frozen=True, slots=True)
class SqlEvidenceRequestRepository:
    connection: psycopg.Connection[tuple[object, ...]]
    tenant_id: str

    def record(self, request: RecordedRequest) -> Result[bool, RequestError]:
        if (
            self.connection.execute(_CASE_EXISTS, (self.tenant_id, request.case_id)).fetchone()
            is None
        ):
            return Err(RequestError(RequestFailure.UNKNOWN_CASE, request.case_id))
        try:
            with self.connection.transaction():
                inserted = self.connection.execute(
                    _INSERT,
                    (
                        self.tenant_id,
                        request.case_id,
                        request.request_id.octets,
                        request.revision_digest.octets,
                        request.deadline,
                    ),
                )
                created = inserted.rowcount == 1
        except psycopg.errors.ForeignKeyViolation as violation:
            return Err(
                RequestError(RequestFailure.CONTENT_NOT_STORED, str(violation.diag.constraint_name))
            )
        if created:
            return Ok(True)

        existing = self.connection.execute(
            _SELECT_ONE, (self.tenant_id, request.case_id, request.request_id.octets)
        ).fetchone()
        if existing is None:
            return Err(
                RequestError(
                    RequestFailure.REQUEST_IDENTITY_CONFLICT,
                    f"{request.request_id.hex} conflicted and is not visible",
                )
            )
        revision, deadline = existing
        if Digest(_octets(revision)) != request.revision_digest:
            return Err(
                RequestError(
                    RequestFailure.REQUEST_IDENTITY_CONFLICT,
                    f"{request.request_id.hex} already names another revision",
                )
            )
        #  The deadline is the one field the digest does not cover, so a
        #  re-registration keeps the one already recorded rather than moving
        #  it. A retry must not be able to extend a deadline it did not set.
        _ = deadline
        return Ok(False)

    def outstanding(self, case_id: str) -> Result[tuple[RecordedRequest, ...], RequestError]:
        if self.connection.execute(_CASE_EXISTS, (self.tenant_id, case_id)).fetchone() is None:
            return Err(RequestError(RequestFailure.UNKNOWN_CASE, case_id))
        rows = self.connection.execute(_SELECT_OUTSTANDING, (self.tenant_id, case_id)).fetchall()
        return Ok(
            tuple(
                RecordedRequest(
                    case_id=case_id,
                    request_id=Digest(_octets(row[0])),
                    revision_digest=Digest(_octets(row[1])),
                    deadline=_integer(row[2]),
                )
                for row in rows
            )
        )


def _octets(value: object) -> bytes:
    if not isinstance(value, bytes | memoryview):
        raise InvariantViolation(f"expected bytea, found {type(value).__name__}")
    return bytes(value)


def _integer(value: object) -> int:
    if not isinstance(value, int):
        raise InvariantViolation(f"expected an integer column, found {type(value).__name__}")
    return value
