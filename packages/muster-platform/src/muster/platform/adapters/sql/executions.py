"""PostgreSQL execution reservations and compare-and-swap state transitions."""

from __future__ import annotations

from dataclasses import dataclass

import psycopg

from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.times import Instant
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest
from muster.platform.casework.ports import is_durable_instant
from muster.platform.gate.model import (
    ActionIntent,
    ExecutionKey,
    ExecutionRecord,
    ExecutionState,
    binding_mismatches,
    read_action_intent,
    reconciliation_transition_is_legal,
    transition_is_legal,
)
from muster.platform.gate.ports import (
    DispatchClaim,
    ExecutionStoreError,
    ExecutionStoreFailure,
    ReconciliationClaim,
    Reservation,
)

_COLUMNS = """
    case_id, execution_id, intent_octets,
    revision_number, revision_digest, certificate_digest, kernel_result_digest,
    bundle_manifest_digest, authorization_context_digest,
    action_schema_digest, action_digest, action_kind, gate_id, executor_id,
    requested_by, state, reserved_at, dispatched_at, finalized_at,
    external_reference, outcome_code, detail, reconciled_at, reconciled_from
"""

_INSERT = f"""
INSERT INTO action_gate.execution (
    tenant_id, {_COLUMNS}
) VALUES (
    %(tenant)s, %(case)s, %(execution)s, %(intent)s,
    %(revision_number)s, %(revision)s, %(certificate)s, %(kernel_result)s,
    %(bundle)s, %(authorization)s, %(action_schema)s, %(action)s,
    %(action_kind)s, %(gate)s, %(executor)s, %(requested_by)s,
    'RESERVED', %(now)s, NULL, NULL, NULL, NULL, NULL, NULL, NULL
)
ON CONFLICT DO NOTHING
RETURNING {_COLUMNS}
"""  # noqa: S608 - both interpolations are frozen column constants

_SELECT = f"""
SELECT {_COLUMNS} FROM action_gate.execution
 WHERE tenant_id = %s AND execution_id = %s
"""  # noqa: S608

_SELECT_CASE = f"""
SELECT {_COLUMNS} FROM action_gate.execution
 WHERE tenant_id = %s AND case_id = %s
 ORDER BY revision_number DESC, reserved_at DESC, execution_id DESC
 LIMIT 1
"""  # noqa: S608

_SELECT_PROPOSAL = f"""
SELECT {_COLUMNS} FROM action_gate.execution
 WHERE tenant_id = %(tenant)s
   AND case_id = %(case)s
   AND revision_number = %(revision_number)s
   AND revision_digest = %(revision)s
   AND certificate_digest = %(certificate)s
   AND kernel_result_digest = %(kernel_result)s
   AND bundle_manifest_digest = %(bundle)s
   AND authorization_context_digest = %(authorization)s
   AND action_schema_digest = %(action_schema)s
   AND action_digest = %(action)s
"""  # noqa: S608

_BEGIN = f"""
UPDATE action_gate.execution
   SET state = 'DISPATCHED', dispatched_at = %(now)s
 WHERE tenant_id = %(tenant)s AND execution_id = %(execution)s
   AND state = 'RESERVED'
RETURNING {_COLUMNS}
"""  # noqa: S608

_FINALIZE = f"""
UPDATE action_gate.execution
   SET state = %(state)s, finalized_at = %(now)s,
       external_reference = %(external_reference)s,
       outcome_code = %(outcome_code)s, detail = %(detail)s
 WHERE tenant_id = %(tenant)s AND execution_id = %(execution)s
   AND state = 'DISPATCHED'
RETURNING {_COLUMNS}
"""  # noqa: S608

_RECONCILE = f"""
UPDATE action_gate.execution
   SET state = %(state)s,
       -- DISPATCHED has no final timestamp; UNCERTAIN already has the timestamp
       -- of its original unknown finalization and reconciliation preserves it.
       finalized_at = COALESCE(finalized_at, %(now)s),
       external_reference = %(external_reference)s,
       outcome_code = %(outcome_code)s, detail = %(detail)s,
       -- SET expressions see the pre-update row, so this atomically records
       -- the exact source state whose compare-and-swap succeeded.
       reconciled_at = %(now)s, reconciled_from = state
 WHERE tenant_id = %(tenant)s AND execution_id = %(execution)s
   AND state IN ('DISPATCHED', 'UNCERTAIN')
   AND state = %(source_state)s
RETURNING {_COLUMNS}
"""  # noqa: S608


@dataclass(frozen=True, slots=True)
class SqlExecutionRepository:
    connection: psycopg.Connection[tuple[object, ...]]
    tenant_id: str

    def reserve(
        self, intent: ActionIntent, *, requested_by: str, now: Instant
    ) -> Result[Reservation, ExecutionStoreError]:
        durable = _durable(now)
        if durable is not None:
            return durable
        if intent.tenant_id != self.tenant_id:
            return Err(
                ExecutionStoreError(
                    ExecutionStoreFailure.CASE_IDENTITY_CONFLICT,
                    f"intent names tenant {intent.tenant_id!r}",
                )
            )
        key = intent.execution_key()
        try:
            row = self.connection.execute(
                _INSERT,
                {
                    "tenant": self.tenant_id,
                    "case": intent.case_id,
                    "execution": key.octets,
                    "intent": intent.canonical_octets(),
                    "revision_number": intent.revision_number,
                    "revision": intent.revision_digest.octets,
                    "certificate": intent.certificate_digest.octets,
                    "kernel_result": intent.kernel_result_digest.octets,
                    "bundle": intent.bundle_manifest_digest.octets,
                    "authorization": intent.authorization_context_digest.octets,
                    "action_schema": intent.action_schema_digest.octets,
                    "action": intent.action_digest.octets,
                    "action_kind": intent.action.kind,
                    "gate": intent.gate_id,
                    "executor": intent.executor_id,
                    "requested_by": requested_by,
                    "now": now,
                },
            ).fetchone()
        except psycopg.errors.ForeignKeyViolation:
            return Err(ExecutionStoreError(ExecutionStoreFailure.ABSENT, intent.case_id))
        if row is not None:
            return Ok(Reservation(_record(self.tenant_id, row), acquired=True))

        # The primary key catches the exact full intent. The second uniqueness
        # boundary catches the same already-authorized proposal even if a
        # caller tries to rebind it to another gate/executor configuration.
        existing = self.read(key)
        if isinstance(existing, Err):
            row = self.connection.execute(
                _SELECT_PROPOSAL, self._proposal_parameters(intent)
            ).fetchone()
            if row is None:
                return Err(
                    ExecutionStoreError(
                        ExecutionStoreFailure.ABSENT,
                        "a conflicting execution row was not visible",
                    )
                )
            existing_record = _record(self.tenant_id, row)
            return Err(
                ExecutionStoreError(
                    ExecutionStoreFailure.CASE_IDENTITY_CONFLICT,
                    "the authorized proposal is already reserved as "
                    f"{existing_record.execution_key.hex}",
                )
            )
        mismatches = binding_mismatches(existing.value.intent, intent)
        if mismatches:
            return Err(
                ExecutionStoreError(
                    ExecutionStoreFailure.EXECUTION_KEY_COLLISION,
                    ", ".join(mismatches),
                )
            )
        return Ok(Reservation(existing.value, acquired=False))

    def read(
        self, execution_key: ExecutionKey
    ) -> Result[ExecutionRecord, ExecutionStoreError]:
        """One row by ``(tenant_id, execution_id)``, which is the primary key.

        Also the whole of the idempotency read's store access, which is why
        that path needs no query of its own and U2 needs no migration 6: the
        durable identity a retry presents *is* this key, so the answer is one
        row or ``ABSENT`` -- there is no ordering to get wrong, no ``LIMIT`` to
        hide a second match behind, and nothing here that depends on the case's
        current head.

        ``_record`` re-derives the canonical value on the way out: the octets
        must decode, re-encode byte-identically, hash to this key, and agree
        with every identity column the row carries.
        """
        row = self.connection.execute(
            _SELECT, (self.tenant_id, execution_key.octets)
        ).fetchone()
        if row is None:
            return Err(ExecutionStoreError(ExecutionStoreFailure.ABSENT, execution_key.hex))
        return Ok(_record(self.tenant_id, row))

    def read_for_case(self, case_id: str) -> Result[ExecutionRecord, ExecutionStoreError]:
        row = self.connection.execute(_SELECT_CASE, (self.tenant_id, case_id)).fetchone()
        if row is None:
            return Err(ExecutionStoreError(ExecutionStoreFailure.ABSENT, case_id))
        return Ok(_record(self.tenant_id, row))

    def begin_dispatch(
        self, execution_key: ExecutionKey, *, now: Instant
    ) -> Result[DispatchClaim, ExecutionStoreError]:
        durable = _durable(now)
        if durable is not None:
            return durable
        row = self.connection.execute(
            _BEGIN,
            {"tenant": self.tenant_id, "execution": execution_key.octets, "now": now},
        ).fetchone()
        if row is not None:
            return Ok(DispatchClaim(_record(self.tenant_id, row), acquired=True))
        current = self.read(execution_key)
        if isinstance(current, Err):
            return current
        if current.value.state is not ExecutionState.RESERVED:
            return Ok(DispatchClaim(current.value, acquired=False))
        return Err(
            ExecutionStoreError(
                ExecutionStoreFailure.ILLEGAL_TRANSITION,
                "the dispatch CAS changed no row but the execution is still RESERVED",
            )
        )

    def _proposal_parameters(self, intent: ActionIntent) -> dict[str, object]:
        return {
            "tenant": self.tenant_id,
            "case": intent.case_id,
            "revision_number": intent.revision_number,
            "revision": intent.revision_digest.octets,
            "certificate": intent.certificate_digest.octets,
            "kernel_result": intent.kernel_result_digest.octets,
            "bundle": intent.bundle_manifest_digest.octets,
            "authorization": intent.authorization_context_digest.octets,
            "action_schema": intent.action_schema_digest.octets,
            "action": intent.action_digest.octets,
        }

    def finalize(
        self,
        execution_key: ExecutionKey,
        *,
        state: ExecutionState,
        outcome_code: str,
        external_reference: str | None,
        detail: str | None,
        now: Instant,
    ) -> Result[ExecutionRecord, ExecutionStoreError]:
        durable = _durable(now)
        if durable is not None:
            return durable
        if not transition_is_legal(ExecutionState.DISPATCHED, state):
            return Err(
                ExecutionStoreError(
                    ExecutionStoreFailure.ILLEGAL_TRANSITION,
                    f"DISPATCHED -> {state.value}",
                )
            )
        row = self.connection.execute(
            _FINALIZE,
            {
                "tenant": self.tenant_id,
                "execution": execution_key.octets,
                "state": state.value,
                "now": now,
                "external_reference": external_reference,
                "outcome_code": outcome_code,
                "detail": detail,
            },
        ).fetchone()
        if row is not None:
            return Ok(_record(self.tenant_id, row))
        return self._transition_refusal(execution_key, state)

    def reconcile(
        self,
        execution_key: ExecutionKey,
        *,
        source_state: ExecutionState,
        state: ExecutionState,
        outcome_code: str,
        external_reference: str | None,
        detail: str | None,
        now: Instant,
    ) -> Result[ReconciliationClaim, ExecutionStoreError]:
        durable = _durable(now)
        if durable is not None:
            return durable
        if not reconciliation_transition_is_legal(source_state, state):
            return Err(
                ExecutionStoreError(
                    ExecutionStoreFailure.ILLEGAL_TRANSITION,
                    f"{source_state.value} -> {state.value}",
                )
            )
        row = self.connection.execute(
            _RECONCILE,
            {
                "tenant": self.tenant_id,
                "execution": execution_key.octets,
                "source_state": source_state.value,
                "state": state.value,
                "now": now,
                "external_reference": external_reference,
                "outcome_code": outcome_code,
                "detail": detail,
            },
        ).fetchone()
        if row is not None:
            return Ok(ReconciliationClaim(_record(self.tenant_id, row), applied=True))

        current = self.read(execution_key)
        if isinstance(current, Err):
            return current
        if current.value.state is not source_state and current.value.state in {
            ExecutionState.CONFIRMED,
            ExecutionState.FAILED,
            ExecutionState.UNCERTAIN,
        }:
            return Ok(ReconciliationClaim(current.value, applied=False))
        return Err(
            ExecutionStoreError(
                ExecutionStoreFailure.ILLEGAL_TRANSITION,
                f"{current.value.state.value} -> {state.value}",
            )
        )

    def _transition_refusal(
        self, execution_key: ExecutionKey, after: ExecutionState
    ) -> Result[ExecutionRecord, ExecutionStoreError]:
        current = self.read(execution_key)
        if isinstance(current, Err):
            return current
        return Err(
            ExecutionStoreError(
                ExecutionStoreFailure.ILLEGAL_TRANSITION,
                f"{current.value.state.value} -> {after.value}",
            )
        )


def _durable(now: Instant) -> Err[ExecutionStoreError] | None:
    if is_durable_instant(now):
        return None
    return Err(
        ExecutionStoreError(
            ExecutionStoreFailure.INSTANT_NOT_DURABLE,
            str(now),
        )
    )


def _record(tenant_id: str, row: tuple[object, ...]) -> ExecutionRecord:
    case_id = _text(row[0])
    execution_key = ExecutionKey(_octets(row[1]))
    intent_octets = _octets(row[2])
    decoded = decode(intent_octets)
    if isinstance(decoded, Err):
        raise InvariantViolation(f"stored ActionIntent is not canonical wire data: {decoded.error}")
    intent = read_action_intent(decoded.value)
    if intent.canonical_octets() != intent_octets:
        raise InvariantViolation("reading and re-encoding the stored ActionIntent changed it")
    if intent.execution_key() != execution_key:
        raise InvariantViolation("stored execution_id is not the key of intent_octets")

    bindings: tuple[tuple[str, object, object], ...] = (
        ("tenant_id", tenant_id, intent.tenant_id),
        ("case_id", case_id, intent.case_id),
        ("revision_number", _integer(row[3]), intent.revision_number),
        ("revision_digest", Digest(_octets(row[4])), intent.revision_digest),
        ("certificate_digest", Digest(_octets(row[5])), intent.certificate_digest),
        ("kernel_result_digest", Digest(_octets(row[6])), intent.kernel_result_digest),
        ("bundle_manifest_digest", Digest(_octets(row[7])), intent.bundle_manifest_digest),
        (
            "authorization_context_digest",
            Digest(_octets(row[8])),
            intent.authorization_context_digest,
        ),
        ("action_schema_digest", Digest(_octets(row[9])), intent.action_schema_digest),
        ("action_digest", Digest(_octets(row[10])), intent.action_digest),
        ("action_kind", _text(row[11]), intent.action.kind),
        ("gate_id", _text(row[12]), intent.gate_id),
        ("executor_id", _text(row[13]), intent.executor_id),
    )
    for name, stored, canonical in bindings:
        if stored != canonical:
            raise InvariantViolation(f"execution row {name} disagrees with intent_octets")

    return ExecutionRecord(
        intent=intent,
        state=ExecutionState(_text(row[15])),
        requested_by=_text(row[14]),
        reserved_at=_integer(row[16]),
        dispatched_at=_optional_integer(row[17]),
        finalized_at=_optional_integer(row[18]),
        external_reference=_optional_text(row[19]),
        outcome_code=_optional_text(row[20]),
        detail=_optional_text(row[21]),
        reconciled_at=_optional_integer(row[22]),
        reconciled_from=_optional_execution_state(row[23]),
    )


def _octets(value: object) -> bytes:
    if not isinstance(value, bytes | memoryview):
        raise InvariantViolation(f"expected bytea, found {type(value).__name__}")
    return bytes(value)


def _integer(value: object) -> int:
    if not isinstance(value, int):
        raise InvariantViolation(f"expected integer, found {type(value).__name__}")
    return value


def _optional_integer(value: object) -> int | None:
    return None if value is None else _integer(value)


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise InvariantViolation(f"expected text, found {type(value).__name__}")
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _optional_execution_state(value: object) -> ExecutionState | None:
    return None if value is None else ExecutionState(_text(value))
