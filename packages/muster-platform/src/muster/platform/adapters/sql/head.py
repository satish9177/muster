"""The case head: one row per case, and the only compare-and-swap in the system.

The swap is worth reading closely, because everything about concurrency here
rests on it:

```sql
UPDATE casework.case_head SET ... WHERE tenant_id = ? AND case_id = ?
  AND revision_number  = ?
  AND revision_digest IS NOT DISTINCT FROM ?
  AND construction_digest = ? AND transcript_prefix_digest = ?
  AND bundle_manifest_digest = ? AND as_of = ? AND mode = ?
  AND authorization_context_digest = ?
```

It matches on the **entire parent state**, not on the revision digest alone.
Three separate hazards close at once:

* *lost update.*  Two computations from one parent both try to publish; one
  matches, the other matches zero rows and is told so.  PostgreSQL re-evaluates
  the predicate against the updated row after waiting for the concurrent
  writer, so read-committed is sufficient and no lock is taken by hand.
* *ABA.*  ``revision_number`` is monotone and is part of the predicate, so even
  a revision digest that somehow recurred could not let a stale writer publish
  over a newer head.
* *analysing one thing and publishing onto another.*  The pinned inputs are in
  the predicate, so a computation that ran under one policy pin, one ``as_of``
  or one authorization context cannot land on a head carrying different ones.

And the transcript prefix is the only rebuild input this operation can change,
because it is taken from an argument and every other field is copied from the
parent.  A repin is therefore not something ``advance`` can do by accident; it
would be a different operation, and this milestone does not have one.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

import psycopg

from muster.core.case.revision import RebuildInputs, RebuildMode
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.digests import Digest
from muster.platform.casework.ports import (
    CaseHead,
    HeadError,
    HeadFailure,
    is_durable_instant,
    same_authored_case,
)

_COLUMNS = """
    construction_digest, transcript_prefix_digest, bundle_manifest_digest,
    as_of, mode, authorization_context_digest,
    revision_digest, revision_number, certificate_digest
"""

_INSERT = f"""
INSERT INTO casework.case_head (
    tenant_id, case_id, {_COLUMNS}
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NULL, 0, NULL)
ON CONFLICT (tenant_id, case_id) DO NOTHING
"""  # noqa: S608 - _COLUMNS is a frozen constant, never caller input

_SELECT = f"""
SELECT {_COLUMNS} FROM casework.case_head WHERE tenant_id = %s AND case_id = %s
"""  # noqa: S608 - as above

#  The same row, held until this transaction ends.
#
#  ``FOR UPDATE`` rather than ``FOR NO KEY UPDATE``, and the reason is the
#  foreign keys rather than the swap. Two ``NO KEY UPDATE`` locks already
#  conflict with each other, so either mode would serialise two admissions
#  against one publication. What only ``FOR UPDATE`` also conflicts with is the
#  ``KEY SHARE`` lock a foreign-key check takes -- and ``transcript_entry`` and
#  ``evidence_request`` both reference this row. The stronger mode is what makes
#  the hold cover every writer that can touch the case, not only the ones that
#  update the head.
_SELECT_FOR_UPDATE = f"""
SELECT {_COLUMNS} FROM casework.case_head
 WHERE tenant_id = %s AND case_id = %s
   FOR UPDATE
"""  # noqa: S608 - as above

_ADVANCE = """
UPDATE casework.case_head
   SET transcript_prefix_digest = %(prefix)s,
       revision_digest          = %(revision)s,
       revision_number          = %(number)s,
       certificate_digest       = %(certificate)s
 WHERE tenant_id = %(tenant)s
   AND case_id   = %(case)s
   AND revision_number = %(parent_number)s
   AND revision_digest IS NOT DISTINCT FROM %(parent_revision)s
   AND construction_digest = %(construction)s
   AND transcript_prefix_digest = %(parent_prefix)s
   AND bundle_manifest_digest = %(pin)s
   AND as_of = %(as_of)s
   AND mode = %(mode)s
   AND authorization_context_digest = %(authorization)s
"""


@dataclass(frozen=True, slots=True)
class SqlCaseHeadRepository:
    connection: psycopg.Connection[tuple[object, ...]]
    tenant_id: str

    def open(self, inputs: RebuildInputs) -> Result[CaseHead, HeadError]:
        if inputs.tenant_id != self.tenant_id:
            return Err(HeadError(HeadFailure.UNKNOWN_CASE, f"inputs name {inputs.tenant_id!r}"))
        if inputs.mode is not RebuildMode.OPERATIONAL:
            #  A counterfactual rebuild answers a question. It is not a state a
            #  case can be in, and the column constraint says the same thing a
            #  second time.
            return Err(HeadError(HeadFailure.MODE_NOT_PUBLISHABLE, inputs.mode.value))
        if not is_durable_instant(inputs.as_of):
            #  ``as_of`` goes into a ``bigint``. Refused as a value rather than
            #  left to the driver, so this adapter and the in-memory one give the
            #  same answer instead of one accepting what the other cannot store.
            return Err(HeadError(HeadFailure.INSTANT_NOT_DURABLE, f"as_of={inputs.as_of}"))
        try:
            with self.connection.transaction():
                self.connection.execute(
                    _INSERT,
                    (
                        self.tenant_id,
                        inputs.case_id,
                        inputs.construction_digest.octets,
                        inputs.transcript_prefix_digest.octets,
                        inputs.bundle_manifest_digest.octets,
                        inputs.as_of,
                        inputs.mode.value,
                        inputs.authorization_context_digest.octets,
                    ),
                )
        except psycopg.errors.ForeignKeyViolation as violation:
            #  One of the three artifacts the head pins is not in the store, so
            #  the case would be unreplayable from the instant it existed.
            #  Reported as what it is rather than as "unknown case", which says
            #  the opposite thing about a case being created.
            return Err(
                HeadError(HeadFailure.INPUTS_NOT_STORED, str(violation.diag.constraint_name))
            )

        head = self.read(inputs.case_id)
        if isinstance(head, Err):
            return head
        if not same_authored_case(head.value.inputs, inputs):
            #  Opening is idempotent by what the officer authored, not by the
            #  case identifier. Silently returning the first would answer the
            #  second caller's request with somebody else's case. The predicate
            #  is in ``ports`` because every adapter owes the same answer.
            return Err(HeadError(HeadFailure.CASE_ALREADY_OPEN, inputs.case_id))
        return head

    def read(self, case_id: str) -> Result[CaseHead, HeadError]:
        row = self.connection.execute(_SELECT, (self.tenant_id, case_id)).fetchone()
        if row is None:
            return Err(HeadError(HeadFailure.UNKNOWN_CASE, case_id))
        return Ok(_head(self.tenant_id, case_id, row))

    def hold(self, case_id: str) -> Result[CaseHead, HeadError]:
        """``SELECT ... FOR UPDATE``: one row, one case, until the commit.

        Row-level and case-scoped. Two appenders on *different* cases take two
        different row locks and never meet; a reader takes none, because
        PostgreSQL readers do not block on writers. The transaction ends and
        the hold ends with it, on commit or on rollback, with nothing to
        release by hand and nothing to leak if the process dies.
        """
        row = self.connection.execute(_SELECT_FOR_UPDATE, (self.tenant_id, case_id)).fetchone()
        if row is None:
            return Err(HeadError(HeadFailure.UNKNOWN_CASE, case_id))
        return Ok(_head(self.tenant_id, case_id, row))

    def advance(
        self,
        *,
        parent: CaseHead,
        prefix_digest: Digest,
        revision_digest: Digest,
        certificate_digest: Digest,
    ) -> Result[CaseHead, HeadError]:
        if parent.inputs.tenant_id != self.tenant_id:
            return Err(HeadError(HeadFailure.UNKNOWN_CASE, parent.inputs.tenant_id))
        number = parent.revision_number + 1
        try:
            #  A savepoint, so that the one integrity failure this statement can
            #  raise -- a prefix whose octets were never stored -- comes back as
            #  a value instead of aborting the transaction the caller is still
            #  in the middle of. The publication path stores the prefix first,
            #  so this is a guard against a defect rather than a path.
            with self.connection.transaction():
                swapped = self.connection.execute(
                    _ADVANCE,
                    {
                        "prefix": prefix_digest.octets,
                        "revision": revision_digest.octets,
                        "number": number,
                        "certificate": certificate_digest.octets,
                        "tenant": self.tenant_id,
                        "case": parent.case_id,
                        "parent_number": parent.revision_number,
                        "parent_revision": _optional(parent.revision_digest),
                        "construction": parent.inputs.construction_digest.octets,
                        "parent_prefix": parent.inputs.transcript_prefix_digest.octets,
                        "pin": parent.inputs.bundle_manifest_digest.octets,
                        "as_of": parent.inputs.as_of,
                        "mode": parent.inputs.mode.value,
                        "authorization": parent.inputs.authorization_context_digest.octets,
                    },
                )
                matched = swapped.rowcount
        except psycopg.errors.ForeignKeyViolation as violation:
            return Err(
                HeadError(HeadFailure.PREFIX_NOT_STORED, str(violation.diag.constraint_name))
            )
        if matched != 1:
            return Err(
                HeadError(
                    HeadFailure.HEAD_MOVED,
                    f"{parent.case_id} was not at revision {parent.revision_number}",
                )
            )
        return Ok(
            CaseHead(
                case_id=parent.case_id,
                inputs=replace(parent.inputs, transcript_prefix_digest=prefix_digest),
                revision_digest=revision_digest,
                revision_number=number,
                certificate_digest=certificate_digest,
            )
        )


def _optional(digest: Digest | None) -> bytes | None:
    return None if digest is None else digest.octets


def _head(tenant_id: str, case_id: str, row: tuple[object, ...]) -> CaseHead:
    return CaseHead(
        case_id=case_id,
        inputs=RebuildInputs(
            tenant_id=tenant_id,
            case_id=case_id,
            construction_digest=Digest(_octets(row[0])),
            transcript_prefix_digest=Digest(_octets(row[1])),
            bundle_manifest_digest=Digest(_octets(row[2])),
            as_of=_integer(row[3]),
            mode=RebuildMode(_text(row[4])),
            authorization_context_digest=Digest(_octets(row[5])),
        ),
        revision_digest=None if row[6] is None else Digest(_octets(row[6])),
        revision_number=_integer(row[7]),
        certificate_digest=None if row[8] is None else Digest(_octets(row[8])),
    )


def _octets(value: object) -> bytes:
    if not isinstance(value, bytes | memoryview):
        raise InvariantViolation(f"expected bytea, found {type(value).__name__}")
    return bytes(value)


def _integer(value: object) -> int:
    if not isinstance(value, int):
        raise InvariantViolation(f"expected an integer column, found {type(value).__name__}")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise InvariantViolation(f"expected a text column, found {type(value).__name__}")
    return value
