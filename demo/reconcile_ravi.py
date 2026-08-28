"""Local PostgreSQL proof of durable reconciliation after process death.

This utility composes the existing Action Gate, the durable sandbox executor,
and ``demo.durable_ravi``.  It adds no recovery mechanism of its own: the
dispatching process is deliberately killed inside the simulated external
system after that system commits, and later processes use only the Gate's
ordinary read, reconciliation, and execution entry points.  The resulting
artifact therefore reports PostgreSQL facts rather than reconstructing a
successful story from values kept alive in one Python process.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn, cast

import psycopg

REPOSITORY = Path(__file__).resolve().parent.parent
for _entry in (
    REPOSITORY / "packages" / "muster-kernel" / "src",
    REPOSITORY / "packages" / "muster-kernel",
    REPOSITORY / "packages" / "muster-platform" / "src",
    REPOSITORY / "packages" / "muster-platform" / "tests",
    REPOSITORY / "packages" / "muster-agents" / "src",
    REPOSITORY / "packages" / "muster-agents",
):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

if TYPE_CHECKING:
    from demo.durable_ravi import (
        durable_case,
        durable_casework,
        open_durable_case,
    )

    from support.ravi import RaviCase
elif __package__:
    from demo.durable_ravi import (  # type: ignore[no-redef]
        durable_case,
        durable_casework,
        open_durable_case,
    )
else:
    from durable_ravi import (  # type: ignore[import-not-found,no-redef]
        durable_case,
        durable_casework,
        open_durable_case,
    )

from muster.core.analysis.outcomes import Invariant  # noqa: E402
from muster.core.results import Err, InvariantViolation, Result  # noqa: E402
from muster.core.values.times import Instant  # noqa: E402
from muster.platform.adapters.sql.database import SqlDatabase  # noqa: E402
from muster.platform.adapters.sql.sandbox_rail import (  # noqa: E402
    DurableSandboxPaymentExecutor,
)
from muster.platform.adapters.sql.schema import migrate  # noqa: E402
from muster.platform.casework.advance import Casework  # noqa: E402
from muster.platform.casework.commands import CaseReport, case_status  # noqa: E402
from muster.platform.gate.authority import (  # noqa: E402
    ExecutionGrant,
    GateCaller,
    LocalExecutionAuthority,
)
from muster.platform.gate.executor import (  # noqa: E402
    ActionExecutor,
    Confirmed,
    ExecutorDispatch,
    ExecutorOutcome,
)
from muster.platform.gate.model import (  # noqa: E402
    ExecuteProposal,
    ExecutionKey,
    ExecutionLookup,
    ExecutionRecord,
    ExecutionState,
    finality,
)
from muster.platform.gate.service import ActionGate, GateRejection  # noqa: E402
from support import ravi  # noqa: E402
from support.fixtures import append_all  # noqa: E402

SCHEMA_VERSION = "muster.gate-reconciliation/v1"
DEFAULT_TENANT = "MUSTER-RECONCILE-DEMO"
DEFAULT_CASE = "CASE-RAVI-RECONCILE-DEMO"
DSN_ENVIRONMENT = "MUSTER_RECONCILE_DSN"
OPERATOR = GateCaller("reconciliation-demo-operator")
#: These statuses are an explicit rendezvous with the parent process.  An
#: ordinary Python failure must never be accepted as the requested crash.
DIED_AFTER_EXTERNAL_EFFECT = 72
DIED_BEFORE_EXTERNAL_EFFECT = 71

_PROVENANCE_NOTE = (
    "The dispatching process was killed inside the executor call, after "
    "the simulated external system committed its own transaction and "
    "before the Gate could finalize. No real funds exist and no payment "
    "rail was contacted."
)


class _DiesAfterTheExternalEffect(DurableSandboxPaymentExecutor):
    """The one crash window this demo is about.

    ``super().dispatch`` returns only after the simulated external system's
    own transaction has committed, and the Gate has not yet been given the
    answer -- so the durable Gate row is still DISPATCHED and the synthetic
    transfer already exists.  Death here is the whole proof: it is the exact
    state a real process killed between an accepted payment and its own
    bookkeeping would leave behind.

    This is demo-only failure injection.  It subclasses the simulated
    external system, not the Gate, and neither adds a transition nor weakens a
    production transition.  The record file is only a rendezvous telling the
    parent which already-durable execution to inspect; it is not later used as
    authority for the outcome.
    """

    def __init__(self, dsn: str, *, accepted_at: Instant, record: Path) -> None:
        super().__init__(dsn, accepted_at=accepted_at)
        self._record = record

    def dispatch(self, request: ExecutorDispatch) -> ExecutorOutcome:
        outcome = super().dispatch(request)
        if not isinstance(outcome, Confirmed):
            raise InvariantViolation(
                "the simulated external effect did not return a confirmation"
            )
        self._record.write_text(
            json.dumps(
                {
                    "execution_key": request.idempotency_key,
                    "external_reference": outcome.external_reference,
                }
            ),
            encoding="utf-8",
        )
        os._exit(DIED_AFTER_EXTERNAL_EFFECT)


class _DiesBeforeTheExternalEffect(DurableSandboxPaymentExecutor):
    """Die after durable ATTEMPTED evidence exists, before any transfer exists.

    The inherited dispatcher commits its attempt marker before calling this
    protected hook.  Exiting here leaves evidence that an attempt began but no
    evidence from which either execution or non-execution can be concluded;
    reconciliation must therefore remain conservative.

    Like the primary crash injector, this demo-only subclass changes the
    simulated external system and no Gate code.  It exists to demonstrate the
    state machine's refusal to guess, not to manufacture a new failure state.
    """

    def __init__(self, dsn: str, *, accepted_at: Instant, record: Path) -> None:
        super().__init__(dsn, accepted_at=accepted_at)
        self._record = record

    def _before_external_effect(self, request: ExecutorDispatch) -> None:
        self._record.write_text(
            json.dumps({"execution_key": request.idempotency_key}),
            encoding="utf-8",
        )
        os._exit(DIED_BEFORE_EXTERNAL_EFFECT)


def _gate(
    dsn: str, tenant_id: str, executor: ActionExecutor
) -> tuple[ActionGate, Casework]:
    """Compose the existing Gate with one exact local execution grant.

    The executor's defaults intentionally bind ``sandbox-payment/v1`` to
    ``local-action-gate/v1``.  Those are the local demo identities used by the
    Gate itself, not the cloud executor or cloud Gate identity, and this proof
    does not invent a third identity merely to label its presentation.
    """
    database = SqlDatabase(dsn)
    casework = durable_casework(database)
    gate = ActionGate(
        casework=casework,
        executor=executor,
        authority=LocalExecutionAuthority(
            (
                ExecutionGrant(
                    principal_id=OPERATOR.principal_id,
                    tenant_id=tenant_id,
                    action_kind="PAY",
                    gate_id=executor.trusted_gate_id,
                    executor_id=executor.executor_id,
                ),
            )
        ),
    )
    return gate, casework


def _prepared_case(casework: Casework, tenant_id: str, case_id: str) -> RaviCase:
    """Idempotently establish the exact synthetic case every acting phase uses.

    Repeating this preparation never substitutes for an execution retry.  The
    durable case has content-derived identities, so reopening and re-appending
    only prove the same authored inputs are present before the ordinary Gate
    entry point is called.
    """
    case = durable_case(tenant_id, case_id)
    open_durable_case(casework, case)
    append_all(casework, case, now=ravi.NOW)
    return case


def _proposal(
    casework: Casework, tenant_id: str, case_id: str
) -> tuple[CaseReport, ExecuteProposal]:
    """Re-derive the executable proposal from the durable case head."""
    reported = case_status(
        casework,
        tenant_id=tenant_id,
        case_id=case_id,
        now=ravi.NOW,
    )
    if isinstance(reported, Err):
        raise InvariantViolation(
            "reconciliation demo case unavailable: "
            f"{reported.error.failure.value}: {reported.error.detail}"
        )
    report = reported.value
    analysis = report.analysis
    revision_digest = report.head.revision_digest
    certificate_digest = report.head.certificate_digest
    if (
        analysis is None
        or not isinstance(analysis.kernel.outcome, Invariant)
        or revision_digest is None
        or certificate_digest is None
    ):
        raise InvariantViolation(
            "the durable Ravi case does not carry one invariant executable proposal"
        )
    outcome = analysis.kernel.outcome
    return report, ExecuteProposal(
        case_id=case_id,
        revision_digest=revision_digest,
        certificate_digest=certificate_digest,
        action_digest=outcome.action.digest(),
    )


def _gate_row(dsn: str, tenant_id: str, execution_key_hex: str) -> dict[str, object]:
    """Read the lifecycle columns the proof claims, without taking a write path."""
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        row = connection.execute(
            "SELECT state, external_reference, outcome_code, dispatched_at, "
            "finalized_at, reconciled_at, reconciled_from "
            "FROM action_gate.execution "
            "WHERE tenant_id = %s AND execution_id = %s",
            (tenant_id, bytes.fromhex(execution_key_hex)),
        ).fetchone()
    if row is None:
        raise InvariantViolation("the reconciliation demo execution row is absent")
    (
        state,
        external_reference,
        outcome_code,
        dispatched_at,
        finalized_at,
        reconciled_at,
        reconciled_from,
    ) = row
    return {
        "state": _text(state, "Gate state"),
        "external_reference": _optional_text(external_reference, "external reference"),
        "outcome_code": _optional_text(outcome_code, "outcome code"),
        "dispatched_at": _optional_integer(dispatched_at, "dispatch instant"),
        "finalized_at": _optional_integer(finalized_at, "finalization instant"),
        "reconciled_at": _optional_integer(reconciled_at, "reconciliation instant"),
        "reconciled_from": _optional_text(reconciled_from, "reconciliation source"),
    }


def _external(dsn: str, execution_key_hex: str) -> dict[str, object]:
    """Read only the simulated external evidence for this exact execution key."""
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        attempt_row = connection.execute(
            "SELECT outcome FROM sandbox_rail.attempt WHERE idempotency_key = %s",
            (execution_key_hex,),
        ).fetchone()
        transfer_row = connection.execute(
            "SELECT external_reference FROM sandbox_rail.transfer "
            "WHERE idempotency_key = %s",
            (execution_key_hex,),
        ).fetchone()
        count_row = connection.execute(
            "SELECT count(*) FROM sandbox_rail.transfer WHERE idempotency_key = %s",
            (execution_key_hex,),
        ).fetchone()
    if count_row is None:
        raise InvariantViolation("the simulated external transfer count is absent")
    return {
        "attempt": (
            None
            if attempt_row is None
            else _text(attempt_row[0], "simulated external attempt outcome")
        ),
        "transfer_count": _integer(count_row[0], "simulated external transfer count"),
        "external_reference": (
            None
            if transfer_row is None
            else _text(transfer_row[0], "simulated external reference")
        ),
    }


def crash_phase(
    dsn: str,
    tenant_id: str,
    case_id: str,
    *,
    window: str,
    record: Path,
) -> NoReturn:
    """Cross the real Gate dispatch path and die in the requested executor window."""
    migrate(dsn)
    executor: DurableSandboxPaymentExecutor
    if window == "after-external":
        executor = _DiesAfterTheExternalEffect(dsn, accepted_at=ravi.NOW, record=record)
    elif window == "before-external":
        executor = _DiesBeforeTheExternalEffect(dsn, accepted_at=ravi.NOW, record=record)
    else:
        raise ValueError(f"unsupported crash window {window!r}")
    gate, casework = _gate(dsn, tenant_id, executor)
    _prepared_case(casework, tenant_id, case_id)
    _, proposal = _proposal(casework, tenant_id, case_id)

    # There is no hand-driven reservation here.  ``ActionGate.execute`` must
    # perform the authority check, durable reservation, DISPATCHED CAS, and
    # executor call itself; otherwise this would demonstrate adapter mechanics
    # while evading the application path the proof advertises.
    gate.execute(caller=OPERATOR, tenant_id=tenant_id, request=proposal, now=ravi.NOW)
    raise InvariantViolation("the crash window did not close")


def observe_phase(
    dsn: str, tenant_id: str, case_id: str, execution_key_hex: str
) -> dict[str, object]:
    """Read the post-crash execution in a process that has no mutation path.

    The plain executor is composed only because an Action Gate has an executor
    identity.  This function calls the idempotency-read boundary, which cannot
    call ``dispatch``, and deliberately does not call ``reconcile_execution``.
    Its dispatch and inspection counters are therefore structural zeros, not
    counters reset after hidden work.
    """
    executor = DurableSandboxPaymentExecutor(dsn, accepted_at=ravi.NOW)
    gate, _ = _gate(dsn, tenant_id, executor)
    execution = _execution_record(
        gate.read_authorized_execution(
            caller=OPERATOR,
            tenant_id=tenant_id,
            lookup=_lookup(execution_key_hex, case_id),
        ),
        "observe",
    )
    return {
        "phase": "OBSERVE",
        "process_id": os.getpid(),
        "execution_key": execution.execution_key.hex,
        "state": execution.state.value,
        "finality": finality(execution.state).value,
        "external_reference": execution.external_reference,
        "outcome_code": execution.outcome_code,
        "gate_row": _gate_row(dsn, tenant_id, execution.execution_key.hex),
        "external": _external(dsn, execution.execution_key.hex),
        "dispatches": executor.dispatch_count,
        "inspections": executor.inspection_count,
    }


def reconcile_phase(
    dsn: str, tenant_id: str, case_id: str, execution_key_hex: str
) -> dict[str, object]:
    """Inspect once and durably refine the post-crash Gate row in a fresh process.

    ``executor_inspection`` is derived from the durable state written by the
    Gate: CONFIRMED means EXECUTED, FAILED means NOT_EXECUTED, and UNCERTAIN
    means STILL_UNKNOWN.  Calling ``inspect`` again merely to label the first
    answer would create a second external observation and let the presentation
    print something different from the observation that actually moved the
    row, so this phase refuses to do that.
    """
    executor = DurableSandboxPaymentExecutor(dsn, accepted_at=ravi.NOW)
    gate, _ = _gate(dsn, tenant_id, executor)
    lookup = _lookup(execution_key_hex, case_id)
    before = _execution_record(
        gate.read_authorized_execution(
            caller=OPERATOR,
            tenant_id=tenant_id,
            lookup=lookup,
        ),
        "reconciliation pre-read",
    )
    after = _execution_record(
        gate.reconcile_execution(
            caller=OPERATOR,
            tenant_id=tenant_id,
            lookup=lookup,
            now=ravi.NOW + 1,
        ),
        "reconciliation",
    )
    return {
        "phase": "RECONCILE",
        "process_id": os.getpid(),
        "execution_key": after.execution_key.hex,
        "before": {
            "state": before.state.value,
            "finality": finality(before.state).value,
        },
        "after": {
            "state": after.state.value,
            "finality": finality(after.state).value,
            "outcome_code": after.outcome_code,
            "external_reference": after.external_reference,
            "reconciled_from": (
                None if after.reconciled_from is None else after.reconciled_from.value
            ),
            "reconciled_at": after.reconciled_at,
        },
        "executor_inspection": _inspection_label(after.state),
        "dispatches": executor.dispatch_count,
        "inspections": executor.inspection_count,
        "external": _external(dsn, after.execution_key.hex),
    }


def repeat_phase(dsn: str, tenant_id: str, case_id: str) -> dict[str, object]:
    """Call the ordinary first-execution entry point a second exact time.

    Nothing in this phase is special-cased as a retry.  It re-derives the
    proposal from the durable case and calls ``ActionGate.execute`` with a
    fresh executor; the durable reservation is what returns the prior record
    and keeps that executor's dispatch counter at zero.
    """
    executor = DurableSandboxPaymentExecutor(dsn, accepted_at=ravi.NOW)
    gate, casework = _gate(dsn, tenant_id, executor)
    _prepared_case(casework, tenant_id, case_id)
    _, proposal = _proposal(casework, tenant_id, case_id)
    execution = _execution_record(
        gate.execute(
            caller=OPERATOR,
            tenant_id=tenant_id,
            request=proposal,
            now=ravi.NOW,
        ),
        "exact repeat",
    )
    return {
        "phase": "REPEAT",
        "process_id": os.getpid(),
        "execution_key": execution.execution_key.hex,
        "state": execution.state.value,
        "external_reference": execution.external_reference,
        "dispatches": executor.dispatch_count,
        "external": _external(dsn, execution.execution_key.hex),
    }


def reset_case(dsn: str, tenant_id: str, case_id: str, confirmation: str) -> dict[str, int]:
    """Remove only the relational rows authored for this one synthetic case."""
    expected = _confirmation(tenant_id, case_id)
    if confirmation != expected:
        raise ValueError(f"refusing reset: confirmation must exactly match {expected}")
    migrate(dsn)
    statements = (
        (
            "sandbox_rail_transfer",
            "DELETE FROM sandbox_rail.transfer WHERE idempotency_key IN "
            "(SELECT encode(execution_id, 'hex') FROM action_gate.execution "
            "WHERE tenant_id = %s AND case_id = %s)",
        ),
        (
            "sandbox_rail_attempt",
            "DELETE FROM sandbox_rail.attempt WHERE idempotency_key IN "
            "(SELECT encode(execution_id, 'hex') FROM action_gate.execution "
            "WHERE tenant_id = %s AND case_id = %s)",
        ),
        (
            "action_gate_execution",
            "DELETE FROM action_gate.execution WHERE tenant_id=%s AND case_id=%s",
        ),
        (
            "case_commitment",
            "DELETE FROM casework.case_commitment WHERE tenant_id=%s AND case_id=%s",
        ),
        (
            "evidence_request",
            "DELETE FROM casework.evidence_request WHERE tenant_id=%s AND case_id=%s",
        ),
        (
            "transcript_entry",
            "DELETE FROM casework.transcript_entry WHERE tenant_id=%s AND case_id=%s",
        ),
        (
            "case_head",
            "DELETE FROM casework.case_head WHERE tenant_id=%s AND case_id=%s",
        ),
    )
    deleted: dict[str, int] = {}
    with psycopg.connect(dsn) as connection, connection.transaction():
        # The simulated external tables have no tenant column, so their only
        # safe reset scope is the hexadecimal execution ids selected through
        # this tenant and case's own Gate rows.  Deleting by a broad prefix, or
        # clearing the tables, would let a demo reach into external evidence
        # created by somebody else's case; the Gate rows stay present until
        # both scoped external deletes have completed for exactly this reason.
        for name, statement in statements:
            deleted[name] = connection.execute(statement, (tenant_id, case_id)).rowcount
    return deleted


def prove(
    dsn: str,
    tenant_id: str,
    case_id: str,
    confirmation: str,
    *,
    with_conservative_beat: bool,
) -> dict[str, object]:
    """Run each proof beat in its own process and validate the combined artifact."""
    with tempfile.TemporaryDirectory(prefix="muster-reconcile-") as temporary:
        directory = Path(temporary)
        _run_phase(
            "reset",
            dsn,
            tenant_id,
            case_id,
            "--confirm-demo-only-reset",
            confirmation,
        )
        crash_record = directory / "after-external.json"
        crash, crash_exit_code = _run_crash_phase(
            dsn,
            tenant_id,
            case_id,
            window="after-external",
            record=crash_record,
            expected_exit=DIED_AFTER_EXTERNAL_EFFECT,
            require_external_reference=True,
        )
        execution_key = _required_text(crash.get("execution_key"), "crash execution key")
        external_reference = _required_text(
            crash.get("external_reference"), "crash external reference"
        )
        observe = _run_phase(
            "observe",
            dsn,
            tenant_id,
            case_id,
            "--execution",
            execution_key,
        )
        reconcile = _run_phase(
            "reconcile",
            dsn,
            tenant_id,
            case_id,
            "--execution",
            execution_key,
        )
        repeat = _run_phase("repeat", dsn, tenant_id, case_id)

        conservative: dict[str, object] | None = None
        if with_conservative_beat:
            conservative_case = f"{case_id}-CONSERVATIVE"
            _run_phase(
                "reset",
                dsn,
                tenant_id,
                conservative_case,
                "--confirm-demo-only-reset",
                _confirmation(tenant_id, conservative_case),
            )
            conservative_record = directory / "before-external.json"
            conservative_crash, conservative_exit_code = _run_crash_phase(
                dsn,
                tenant_id,
                conservative_case,
                window="before-external",
                record=conservative_record,
                expected_exit=DIED_BEFORE_EXTERNAL_EFFECT,
                require_external_reference=False,
            )
            conservative_key = _required_text(
                conservative_crash.get("execution_key"),
                "conservative crash execution key",
            )
            conservative_reconcile = _run_phase(
                "reconcile",
                dsn,
                tenant_id,
                conservative_case,
                "--execution",
                conservative_key,
            )
            conservative_observe = _run_phase(
                "observe",
                dsn,
                tenant_id,
                conservative_case,
                "--execution",
                conservative_key,
            )
            conservative_external = _record(conservative_observe, "external")
            conservative_after = _record(conservative_reconcile, "after")
            conservative = {
                "case": {"tenant_id": tenant_id, "case_id": conservative_case},
                "crash": {
                    "exit_code": conservative_exit_code,
                    "execution_key": conservative_key,
                },
                "events": [conservative_reconcile, conservative_observe],
                "claims": {
                    "attempt_marker_committed": (
                        conservative_external.get("attempt") == "ATTEMPTED"
                    ),
                    "external_transfer_absent": (
                        conservative_external.get("transfer_count") == 0
                    ),
                    "inspection_stayed_unknown": (
                        conservative_reconcile.get("executor_inspection")
                        == "STILL_UNKNOWN"
                    ),
                    "recovered_state_uncertain": (
                        conservative_after.get("state") == "UNCERTAIN"
                    ),
                    "finality_stayed_unknown": (
                        conservative_after.get("finality") == "OUTCOME_UNKNOWN"
                    ),
                    "redispatches": conservative_reconcile.get("dispatches") == 0,
                },
            }

    observe_gate = _record(observe, "gate_row")
    observe_external = _record(observe, "external")
    reconcile_after = _record(reconcile, "after")
    reconcile_external = _record(reconcile, "external")
    repeat_external = _record(repeat, "external")
    process_ids = tuple(event.get("process_id") for event in (observe, reconcile, repeat))
    artifact: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "provenance": {
            "source": "local-postgresql-reconciliation-proof",
            "label": "LOCAL POSTGRESQL RECONCILIATION PROOF",
            "environment": "SYNTHETIC_DEMO",
            "cloud_execution": False,
            "real_funds": False,
            "note": _PROVENANCE_NOTE,
        },
        "case": {"tenant_id": tenant_id, "case_id": case_id},
        "crash": {
            "exit_code": crash_exit_code,
            "execution_key": execution_key,
            "external_reference": external_reference,
        },
        "events": [observe, reconcile, repeat],
        "claims": {
            "distinct_processes": len(set(process_ids)) == len(process_ids),
            "gate_row_was_dispatched_after_the_crash": (
                observe_gate.get("state") == "DISPATCHED"
            ),
            "external_transfer_committed_before_the_crash": (
                observe_external.get("transfer_count") == 1
                and observe_external.get("external_reference") == external_reference
            ),
            "gate_was_not_finalized_before_reconciliation": (
                observe_gate.get("finalized_at") is None
            ),
            "finality_was_unknown_after_restart": (
                observe.get("finality") == "OUTCOME_UNKNOWN"
            ),
            "reconciled_from_dispatched": (
                reconcile_after.get("reconciled_from") == "DISPATCHED"
            ),
            "recovered_state_confirmed": reconcile_after.get("state") == "CONFIRMED",
            "same_external_reference": (
                reconcile_after.get("external_reference") == external_reference
                and reconcile_external.get("external_reference") == external_reference
            ),
            "redispatches_during_reconciliation": reconcile.get("dispatches"),
            "external_transfers_after_reconciliation": reconcile_external.get(
                "transfer_count"
            ),
            "repeat_dispatched_nothing": repeat.get("dispatches") == 0,
            "repeat_same_execution": repeat.get("execution_key") == execution_key,
            "repeat_same_external_reference": (
                repeat.get("external_reference") == external_reference
                and repeat_external.get("external_reference") == external_reference
            ),
        },
        "conservative_beat": conservative,
    }
    validate_artifact(artifact)
    return artifact


def validate_artifact(value: object) -> None:
    """Reject an artifact unless every advertised reconciliation fact holds."""
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported gate-reconciliation artifact")
    provenance = _record(value, "provenance")
    case = _record(value, "case")
    crash = _record(value, "crash")
    claims = _record(value, "claims")
    events = value.get("events")
    if (
        provenance.get("source") != "local-postgresql-reconciliation-proof"
        or provenance.get("label") != "LOCAL POSTGRESQL RECONCILIATION PROOF"
        or provenance.get("environment") != "SYNTHETIC_DEMO"
        or provenance.get("cloud_execution") is not False
        or provenance.get("real_funds") is not False
        or provenance.get("note") != _PROVENANCE_NOTE
        or not _nonempty(case.get("tenant_id"))
        or not _nonempty(case.get("case_id"))
        or crash.get("exit_code") != DIED_AFTER_EXTERNAL_EFFECT
        or not _nonempty(crash.get("execution_key"))
        or not _nonempty(crash.get("external_reference"))
        or not isinstance(events, list)
        or len(events) != 3
    ):
        raise ValueError("gate-reconciliation artifact identity or provenance is invalid")
    observe, reconcile, repeat = events
    if not all(isinstance(event, dict) for event in events):
        raise ValueError("gate-reconciliation events must be records")
    assert isinstance(observe, dict)
    assert isinstance(reconcile, dict)
    assert isinstance(repeat, dict)
    execution_key = crash.get("execution_key")
    process_ids = [event.get("process_id") for event in events]
    if (
        observe.get("phase") != "OBSERVE"
        or reconcile.get("phase") != "RECONCILE"
        or repeat.get("phase") != "REPEAT"
        or any(event.get("execution_key") != execution_key for event in events)
        or any(not isinstance(process_id, int) for process_id in process_ids)
        or len(set(process_ids)) != 3
    ):
        raise ValueError("gate-reconciliation event identity is inconsistent")
    boolean_claims = _boolean_claim_keys()
    if (
        set(claims) != set(boolean_claims) | set(_count_claim_keys())
        or any(claims.get(name) is not True for name in boolean_claims)
        or type(claims.get("redispatches_during_reconciliation")) is not int
        or claims.get("redispatches_during_reconciliation") != 0
        or type(claims.get("external_transfers_after_reconciliation")) is not int
        or claims.get("external_transfers_after_reconciliation") != 1
    ):
        raise ValueError("gate-reconciliation artifact does not establish every claim")
    _validate_conservative_beat(value.get("conservative_beat"))


def _validate_conservative_beat(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise ValueError("the conservative beat must be null or a record")
    crash = _record(value, "crash")
    claims = _record(value, "claims")
    events = value.get("events")
    if (
        crash.get("exit_code") != DIED_BEFORE_EXTERNAL_EFFECT
        or not _nonempty(crash.get("execution_key"))
        or not isinstance(events, list)
        or len(events) != 2
        or any(claim is not True for claim in claims.values())
    ):
        raise ValueError("the conservative beat does not establish its refusal to guess")
    reconcile, observe = events
    if (
        not isinstance(reconcile, dict)
        or not isinstance(observe, dict)
        or reconcile.get("phase") != "RECONCILE"
        or observe.get("phase") != "OBSERVE"
        or reconcile.get("execution_key") != crash.get("execution_key")
        or observe.get("execution_key") != crash.get("execution_key")
    ):
        raise ValueError("the conservative beat events are inconsistent")


def _human_narrative(artifact: dict[str, object]) -> str:
    """Render only values carried by the already-validated proof artifact."""
    validate_artifact(artifact)
    provenance = _record(artifact, "provenance")
    case = _record(artifact, "case")
    crash = _record(artifact, "crash")
    claims = _record(artifact, "claims")
    events = artifact.get("events")
    assert isinstance(events, list) and len(events) == 3
    observe = cast(dict[str, object], events[0])
    reconcile = cast(dict[str, object], events[1])
    repeat = cast(dict[str, object], events[2])
    gate_row = _record(observe, "gate_row")
    observed_external = _record(observe, "external")
    before = _record(reconcile, "before")
    after = _record(reconcile, "after")
    transfer_count = observed_external.get("transfer_count")
    external_transfer = "committed" if transfer_count == 1 else str(transfer_count)
    finalized_at = gate_row.get("finalized_at")
    gate_finalization = "missing" if finalized_at is None else str(finalized_at)

    # MUSTER runs no background reconciler.  The demonstration of that fact is
    # observational: a whole separate process used a read-only Gate entry point,
    # recorded zero dispatches, and found the row in the DISPATCHED state the
    # killed process left behind.  Any other observation is printed as a change
    # rather than being mislabeled as disabled retry behaviour.
    observed_state = gate_row.get("state")
    automatic_retry = (
        "disabled"
        if observe.get("dispatches") == 0 and observed_state == "DISPATCHED"
        else f"OBSERVED A CHANGE -- {observed_state}"
    )
    sandbox_status = (
        "NO REAL FUNDS TRANSFERRED"
        if provenance.get("real_funds") is False
        else "REAL FUNDS STATUS NOT PROVED"
    )
    lines = [
        "MUSTER -- DURABLE RECONCILIATION AFTER PROCESS DEATH",
        "",
        f"  SANDBOX: {sandbox_status}",
        "",
        _line("tenant", case.get("tenant_id")),
        _line("case", case.get("case_id")),
        _line("execution id", crash.get("execution_key")),
        "",
        "BEFORE CRASH",
        _line("Gate state", gate_row.get("state")),
        _line("External transfer", external_transfer),
        _line("Gate finalization", gate_finalization),
        "",
        "AFTER RESTART",
        _line("MUSTER finality", before.get("finality")),
        _line("Automatic retry", automatic_retry),
        "",
        "RECONCILIATION",
        _line("Executor inspection", reconcile.get("executor_inspection")),
        _line("Recovered state", after.get("state")),
        _line("Reconciled from", after.get("reconciled_from")),
        _line("Redispatches", claims.get("redispatches_during_reconciliation")),
        _line("External transfers", claims.get("external_transfers_after_reconciliation")),
        "",
        "EXACT REPEAT",
        _line("Same execution", _lower_boolean(claims.get("repeat_same_execution"))),
        _line(
            "Same external reference",
            _lower_boolean(claims.get("repeat_same_external_reference")),
        ),
        _line("Additional dispatches", repeat.get("dispatches")),
    ]
    conservative = artifact.get("conservative_beat")
    if isinstance(conservative, dict):
        conservative_events = conservative.get("events")
        assert isinstance(conservative_events, list) and len(conservative_events) == 2
        conservative_reconcile = cast(dict[str, object], conservative_events[0])
        conservative_observe = cast(dict[str, object], conservative_events[1])
        conservative_after = _record(conservative_reconcile, "after")
        conservative_external = _record(conservative_observe, "external")
        lines.extend(
            (
                "",
                "CONSERVATIVE CASE (process died before the external effect)",
                _line("External attempt", conservative_external.get("attempt")),
                _line("External transfer", conservative_external.get("transfer_count")),
                _line(
                    "Executor inspection",
                    conservative_reconcile.get("executor_inspection"),
                ),
                _line("Recovered state", conservative_after.get("state")),
                _line("MUSTER finality", conservative_after.get("finality")),
                _line("Redispatches", conservative_reconcile.get("dispatches")),
                "  The Gate refuses to guess.",
            )
        )
    return "\n".join(lines)


def _run_phase(
    phase: str,
    dsn: str,
    tenant_id: str,
    case_id: str,
    *arguments: str,
) -> dict[str, object]:
    environment = dict(os.environ)
    environment[DSN_ENVIRONMENT] = dsn
    process = subprocess.run(  # noqa: S603 - executable and argv shape are controlled here
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--tenant",
            tenant_id,
            "--case",
            case_id,
            phase,
            *arguments,
        ],
        cwd=REPOSITORY,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"reconciliation Ravi {phase} phase failed: {process.stderr.strip()}"
        )
    parsed: object = json.loads(process.stdout)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"reconciliation Ravi {phase} phase returned no proof record")
    return parsed


def _run_crash_phase(
    dsn: str,
    tenant_id: str,
    case_id: str,
    *,
    window: str,
    record: Path,
    expected_exit: int,
    require_external_reference: bool,
) -> tuple[dict[str, object], int]:
    environment = dict(os.environ)
    environment[DSN_ENVIRONMENT] = dsn
    process = subprocess.run(  # noqa: S603 - executable and argv shape are controlled here
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--tenant",
            tenant_id,
            "--case",
            case_id,
            "crash",
            "--window",
            window,
            "--record",
            str(record),
        ],
        cwd=REPOSITORY,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != expected_exit:
        raise RuntimeError(
            f"reconciliation Ravi {window} crash exited {process.returncode}, "
            f"expected {expected_exit}: {process.stderr.strip()}"
        )
    parsed: object = json.loads(record.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict) or not _nonempty(parsed.get("execution_key")):
        raise RuntimeError(f"reconciliation Ravi {window} crash wrote no execution key")
    if require_external_reference and not _nonempty(parsed.get("external_reference")):
        raise RuntimeError(f"reconciliation Ravi {window} crash wrote no external reference")
    return parsed, process.returncode


def _execution_record(
    result: Result[ExecutionRecord, GateRejection], operation: str
) -> ExecutionRecord:
    if isinstance(result, Err):
        raise InvariantViolation(
            f"reconciliation demo {operation} refused: "
            f"{result.error.failure.value}: {result.error.detail}"
        )
    return result.value


def _inspection_label(state: ExecutionState) -> str:
    match state:
        case ExecutionState.CONFIRMED:
            return "EXECUTED"
        case ExecutionState.FAILED:
            return "NOT_EXECUTED"
        case ExecutionState.UNCERTAIN:
            return "STILL_UNKNOWN"
        case ExecutionState.RESERVED | ExecutionState.DISPATCHED:
            raise InvariantViolation(
                "reconciliation did not produce an executor-inspection answer"
            )


def _lookup(execution_key_hex: str, case_id: str) -> ExecutionLookup:
    return ExecutionLookup(
        ExecutionKey(bytes.fromhex(execution_key_hex)),
        expected_case_id=case_id,
    )


def _record(value: object, key: str) -> dict[str, object]:
    if not isinstance(value, dict) or not isinstance(value.get(key), dict):
        raise ValueError(f"gate-reconciliation artifact requires record {key}")
    return cast(dict[str, object], value[key])


def _required_text(value: object, label: str) -> str:
    if not _nonempty(value):
        raise ValueError(f"{label} must be non-empty text")
    return cast(str, value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise InvariantViolation(f"{label} must be text")
    return value


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvariantViolation(f"{label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _integer(value, label)


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _boolean_claim_keys() -> tuple[str, ...]:
    return (
        "distinct_processes",
        "gate_row_was_dispatched_after_the_crash",
        "external_transfer_committed_before_the_crash",
        "gate_was_not_finalized_before_reconciliation",
        "finality_was_unknown_after_restart",
        "reconciled_from_dispatched",
        "recovered_state_confirmed",
        "same_external_reference",
        "repeat_dispatched_nothing",
        "repeat_same_execution",
        "repeat_same_external_reference",
    )


def _count_claim_keys() -> tuple[str, ...]:
    return (
        "redispatches_during_reconciliation",
        "external_transfers_after_reconciliation",
    )


def _line(label: str, value: object) -> str:
    return f"  {label:<26}{value}"


def _lower_boolean(value: object) -> str:
    if not isinstance(value, bool):
        raise ValueError("the narrative requires a boolean claim")
    return str(value).lower()


def _confirmation(tenant_id: str, case_id: str) -> str:
    return f"{tenant_id}/{case_id}"


def _dsn(argument: str | None) -> str:
    value = argument or os.environ.get(DSN_ENVIRONMENT, "")
    if not value:
        raise ValueError(f"PostgreSQL DSN required via --dsn or {DSN_ENVIRONMENT}")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument("--dsn", help=f"PostgreSQL DSN; defaults to {DSN_ENVIRONMENT}")
    parser.add_argument("--tenant", default=DEFAULT_TENANT)
    parser.add_argument("--case", default=DEFAULT_CASE)
    subparsers = parser.add_subparsers(dest="phase", required=True)
    crash = subparsers.add_parser("crash")
    crash.add_argument(
        "--window",
        choices=("after-external", "before-external"),
        required=True,
    )
    crash.add_argument("--record", type=Path, required=True)
    observe = subparsers.add_parser("observe")
    observe.add_argument("--execution", required=True)
    reconcile = subparsers.add_parser("reconcile")
    reconcile.add_argument("--execution", required=True)
    subparsers.add_parser("repeat")
    reset = subparsers.add_parser("reset")
    reset.add_argument("--confirm-demo-only-reset", required=True)
    proof = subparsers.add_parser("prove")
    proof.add_argument("--confirm-demo-only-reset", required=True)
    proof.add_argument("--output", type=Path)
    proof.add_argument("--json", action="store_true")
    proof.add_argument("--with-conservative-beat", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        dsn = _dsn(arguments.dsn)
        if arguments.phase == "crash":
            crash_phase(
                dsn,
                arguments.tenant,
                arguments.case,
                window=arguments.window,
                record=arguments.record,
            )
        if arguments.phase == "observe":
            result: object = observe_phase(
                dsn,
                arguments.tenant,
                arguments.case,
                arguments.execution,
            )
        elif arguments.phase == "reconcile":
            result = reconcile_phase(
                dsn,
                arguments.tenant,
                arguments.case,
                arguments.execution,
            )
        elif arguments.phase == "repeat":
            result = repeat_phase(dsn, arguments.tenant, arguments.case)
        elif arguments.phase == "reset":
            result = {
                "phase": "RESET",
                "case": {"tenant_id": arguments.tenant, "case_id": arguments.case},
                "deleted": reset_case(
                    dsn,
                    arguments.tenant,
                    arguments.case,
                    arguments.confirm_demo_only_reset,
                ),
            }
        else:
            result = prove(
                dsn,
                arguments.tenant,
                arguments.case,
                arguments.confirm_demo_only_reset,
                with_conservative_beat=arguments.with_conservative_beat,
            )
            if arguments.output is not None:
                arguments.output.parent.mkdir(parents=True, exist_ok=True)
                arguments.output.write_text(
                    json.dumps(result, indent=2) + "\n",
                    encoding="utf-8",
                )
            if not arguments.json:
                print(_human_narrative(result))
                return 0
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (InvariantViolation, RuntimeError, ValueError, psycopg.Error) as error:
        print(f"muster-reconcile-ravi: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
