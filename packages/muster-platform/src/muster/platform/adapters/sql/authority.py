"""Authority and catalog publications: insert-if-absent, read, never rewritten.

``INSERT ... ON CONFLICT DO NOTHING`` and a ``SELECT``, three times over.  **No
published snapshot is ever updated, and none may be**: a case pins the
authority snapshot it was decided under, and a row that could be rewritten
would make "what this key was permitted to say in March" a thing with a
history.  Withdrawing a grant is publishing a successor snapshot under a new
digest, which is a new row.

**One row here is mutable, and it holds no snapshot.**
``authority.publication_state`` records two present-tense facts per tenant --
which registry is in force for cases opened *now*, and how many times authority
state has moved -- and both are answers about the present with no past to
destroy.  Every snapshot it has ever named is still in ``registry_snapshot``
under its own digest, and every case that pinned one still resolves it.  The
distinction the old wording collapsed is worth keeping sharp: rewriting a
*snapshot* rewrites history, and rewriting a *pointer to the current snapshot*
is what having a current snapshot means.

Two publications of one snapshot keep the first, exactly as a commitment
envelope does and for the same reason: the octets differ only in a randomised
signature, both are equally valid, and an auditor who verified one yesterday
must be handed the same one today.

The read re-checks nothing about the content.  This layer stores octets;
whether they carry the snapshot they are keyed by, and whether a trusted
publisher signed them, are questions with answers -- and the answers belong in
``platform.authority.resolve``, which asks both on every read.  A store that
also tried would be a second, weaker copy of the same checks.
"""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.digests import Digest
from muster.platform.casework.ports import (
    Publication,
    PublicationError,
    PublicationFailure,
    PublicationState,
)

_INSERT = """
INSERT INTO {table} (tenant_id, snapshot_digest, signed_octets, published_at)
VALUES (%s, %s, %s, %s)
ON CONFLICT (tenant_id, snapshot_digest) DO NOTHING
"""

_SELECT = """
SELECT signed_octets, published_at FROM {table}
WHERE tenant_id = %s AND snapshot_digest = %s
"""

_ALL_REVOCATIONS = """
SELECT snapshot_digest, signed_octets, published_at FROM authority.revocation_snapshot
WHERE tenant_id = %s
ORDER BY published_at, snapshot_digest
"""

_LATEST = """
SELECT snapshot_digest, signed_octets, published_at FROM catalog.agent_snapshot
WHERE tenant_id = %s
ORDER BY published_at DESC, snapshot_digest DESC
LIMIT 2
"""

#  ---- the publication state: one row per tenant ---------------------------
#
#  Three statements and one discipline: every path that reaches this row takes
#  a lock on it *before* it reads it, and holds that lock for the rest of the
#  transaction.  A read without a lock would be a value that stopped being true
#  the instant it was returned, which is the whole defect this closes.
#
#  ``FOR SHARE`` for readers and a plain ``UPDATE`` for writers.  Share locks do
#  not conflict with one another, so concurrent admissions and concurrent case
#  openings never wait; ``UPDATE`` takes a row-exclusive lock, which conflicts
#  with both, so a publisher waits for the readers already in flight and every
#  reader that arrives afterwards waits for it.  That is the linearization, and
#  it is one tuple wide: another tenant's row is a different tuple, and no path
#  here touches more than its own.
_HOLD_STATE = """
SELECT in_force_digest, in_force_revocation, epoch FROM authority.publication_state
WHERE tenant_id = %s
FOR SHARE
"""

#  The only ``UPDATE ... SET`` on a content column in this package, and it is
#  an upsert because the first authority publication for a tenant creates the
#  row.  ``epoch`` advances on this path too: naming a new registry is a change
#  to what keys may say, and an admission must be able to tell that it happened.
_SET_IN_FORCE = """
INSERT INTO authority.publication_state (tenant_id, in_force_digest, epoch)
VALUES (%s, %s, 1)
ON CONFLICT (tenant_id) DO UPDATE
    SET in_force_digest = excluded.in_force_digest,
        epoch = authority.publication_state.epoch + 1
RETURNING in_force_digest, in_force_revocation, epoch
"""

#  The revocation half.  A separate statement over a separate column rather
#  than one upsert with two parameters, because the two publications are
#  separate acts: an authority publication must not silently restate which
#  revocation list is current, and a revocation publication must not restate
#  the registry.  Each writes the column it owns and leaves the other alone.
_SET_IN_FORCE_REVOCATION = """
INSERT INTO authority.publication_state (tenant_id, in_force_revocation, epoch)
VALUES (%s, %s, 1)
ON CONFLICT (tenant_id) DO UPDATE
    SET in_force_revocation = excluded.in_force_revocation,
        epoch = authority.publication_state.epoch + 1
RETURNING in_force_digest, in_force_revocation, epoch
"""

_REGISTRY = "authority.registry_snapshot"
_REVOCATION = "authority.revocation_snapshot"
_AGENTS = "catalog.agent_snapshot"

#  The three table names are module constants and the statements are built from
#  them at import time, so no caller can pass a table name in.  A parameterised
#  identifier would be the one place in this package where a string reaches SQL
#  outside a bound parameter.
_STATEMENTS = {
    table: (_INSERT.format(table=table), _SELECT.format(table=table))
    for table in (_REGISTRY, _REVOCATION, _AGENTS)
}


def _publish(
    connection: psycopg.Connection[tuple[object, ...]],
    tenant_id: str,
    table: str,
    publication: Publication,
) -> Result[bool, PublicationError]:
    insert, _ = _STATEMENTS[table]
    cursor = connection.execute(
        insert,
        (
            tenant_id,
            publication.snapshot_digest.octets,
            publication.signed_octets,
            publication.published_at,
        ),
    )
    return Ok(cursor.rowcount == 1)


def _read(
    connection: psycopg.Connection[tuple[object, ...]],
    tenant_id: str,
    table: str,
    snapshot_digest: Digest,
) -> Result[Publication, PublicationError]:
    _, select = _STATEMENTS[table]
    row = connection.execute(select, (tenant_id, snapshot_digest.octets)).fetchone()
    if row is None:
        return Err(
            PublicationError(
                PublicationFailure.PUBLICATION_ABSENT,
                f"{table} holds nothing under {snapshot_digest.hex}",
            )
        )
    return Ok(Publication(snapshot_digest, _octets(row[0], table), _instant(row[1], table)))


def _octets(value: object, table: str) -> bytes:
    if not isinstance(value, bytes | memoryview):
        raise InvariantViolation(f"{table}.signed_octets is not bytea: {value!r}")
    return bytes(value)


def _instant(value: object, table: str) -> int:
    if not isinstance(value, int):
        raise InvariantViolation(f"{table}.published_at is not bigint: {value!r}")
    return value


def _optional_digest(value: object, column: str) -> Digest | None:
    """A digest, or ``None`` for a publication that has not happened yet.

    ``None`` is a value here rather than an error: a tenant whose registry is
    published and whose revocation list is not has a real, momentary state, and
    the refusal belongs where a case is opened rather than where a row is read.
    """
    if value is None:
        return None
    if not isinstance(value, bytes | memoryview):
        raise InvariantViolation(f"{column} is not bytea: {value!r}")
    return Digest(bytes(value))


def _epoch(value: object) -> int:
    if not isinstance(value, int):
        raise InvariantViolation(f"authority.publication_state.epoch is not bigint: {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class SqlAuthorityRepository:
    """Authority and revocation snapshots for one tenant.

    Deliberately offers no ``latest``.  The port does not declare one and this
    adapter does not implement one, so "resolve the current authority" is not a
    call a caller can make by mistake -- authority is reached only through the
    pin a revision already carries.
    """

    connection: psycopg.Connection[tuple[object, ...]]
    tenant_id: str

    def publish_authority(self, publication: Publication) -> Result[bool, PublicationError]:
        return _publish(self.connection, self.tenant_id, _REGISTRY, publication)

    def read_authority(self, snapshot_digest: Digest) -> Result[Publication, PublicationError]:
        return _read(self.connection, self.tenant_id, _REGISTRY, snapshot_digest)

    def publish_revocation(self, publication: Publication) -> Result[bool, PublicationError]:
        return _publish(self.connection, self.tenant_id, _REVOCATION, publication)

    def read_revocation(self, snapshot_digest: Digest) -> Result[Publication, PublicationError]:
        return _read(self.connection, self.tenant_id, _REVOCATION, snapshot_digest)

    def in_force_authority(self) -> Result[PublicationState, PublicationError]:
        return self._state(_HOLD_STATE, (self.tenant_id,), what="no authority is in force")

    def hold_publication_state(self) -> Result[PublicationState, PublicationError]:
        #  The same statement as ``in_force_authority``, and deliberately so:
        #  the lock is the point of both, and two statements would be two
        #  chances for one of them to stop taking it.  They are separate
        #  methods because their *callers* are separate -- one may consult the
        #  digest and the other may not -- and an architecture test enforces
        #  which is which by name.
        return self._state(_HOLD_STATE, (self.tenant_id,), what="no authority is in force")

    def set_in_force_authority(
        self, snapshot_digest: Digest
    ) -> Result[PublicationState, PublicationError]:
        return self._state(
            _SET_IN_FORCE,
            (self.tenant_id, snapshot_digest.octets),
            what="the publication state could not be written",
        )

    def set_in_force_revocation(
        self, snapshot_digest: Digest
    ) -> Result[PublicationState, PublicationError]:
        return self._state(
            _SET_IN_FORCE_REVOCATION,
            (self.tenant_id, snapshot_digest.octets),
            what="the publication state could not be written",
        )

    def _state(
        self, statement: str, parameters: tuple[object, ...], *, what: str
    ) -> Result[PublicationState, PublicationError]:
        row = self.connection.execute(statement, parameters).fetchone()
        if row is None:
            #  Absent state is a refusal everywhere it is read.  A tenant with
            #  no authority in force has not established that any key may
            #  speak, and "the row is missing" is the least safe thing to read
            #  as "no restriction applies".
            return Err(
                PublicationError(
                    PublicationFailure.PUBLICATION_STATE_ABSENT, f"{self.tenant_id}: {what}"
                )
            )
        return Ok(
            PublicationState(
                _optional_digest(row[0], "authority.publication_state.in_force_digest"),
                _optional_digest(row[1], "authority.publication_state.in_force_revocation"),
                _epoch(row[2]),
            )
        )

    def revocations(self) -> Result[tuple[Publication, ...], PublicationError]:
        rows = self.connection.execute(_ALL_REVOCATIONS, (self.tenant_id,)).fetchall()
        #  Ordered for reproducibility rather than for precedence: the caller
        #  takes the union, so the order changes nothing about the answer and
        #  changes everything about whether two runs report the same thing.
        return Ok(
            tuple(
                Publication(
                    Digest(_octets(row[0], _REVOCATION)),
                    _octets(row[1], _REVOCATION),
                    _instant(row[2], _REVOCATION),
                )
                for row in rows
            )
        )


@dataclass(frozen=True, slots=True)
class SqlCatalogRepository:
    """Fleet catalog snapshots for one tenant."""

    connection: psycopg.Connection[tuple[object, ...]]
    tenant_id: str

    def publish(self, publication: Publication) -> Result[bool, PublicationError]:
        return _publish(self.connection, self.tenant_id, _AGENTS, publication)

    def read(self, snapshot_digest: Digest) -> Result[Publication, PublicationError]:
        return _read(self.connection, self.tenant_id, _AGENTS, snapshot_digest)

    def latest(self) -> Result[Publication, PublicationError]:
        #  Two rows, so a tie is visible.  One row and a digest tiebreak would
        #  answer every query and answer some of them wrongly.
        rows = self.connection.execute(_LATEST, (self.tenant_id,)).fetchall()
        if not rows:
            return Err(
                PublicationError(
                    PublicationFailure.PUBLICATION_ABSENT,
                    f"{self.tenant_id} has published no catalog",
                )
            )
        if len(rows) > 1 and _instant(rows[0][2], _AGENTS) == _instant(rows[1][2], _AGENTS):
            return Err(
                PublicationError(
                    PublicationFailure.PUBLICATION_AMBIGUOUS,
                    f"{self.tenant_id} published two catalogs at {_instant(rows[0][2], _AGENTS)}",
                )
            )
        return Ok(
            Publication(
                Digest(_octets(rows[0][0], _AGENTS)),
                _octets(rows[0][1], _AGENTS),
                _instant(rows[0][2], _AGENTS),
            )
        )
