"""The sanitized final Action Gate proof, as one immutable record.

This module is a *transcription boundary*, not a producer.  Nothing here runs,
decides, or re-derives anything: the five Cloud Run executions below already
happened, in a project this process cannot reach, from an image this worktree
is no longer at.  What a later reader needs is that the numbers on the judge's
screen are the numbers that were observed, so the observations live here once,
as named constants, and both the tracked UI artifact and the architecture
document are checked against them.

Two facts about provenance are load-bearing and are therefore separate fields
rather than one "commit":

``DEPLOYED_SOURCE_COMMIT``
    the commit the deployed image was built from.  It is the only commit that
    can honestly be said to have produced this proof.

``DOCUMENTATION_COMMIT``
    the later documentation-only head this repository sat at afterwards.  It
    built nothing and ran nothing, and writing it into the image provenance
    would be a quiet forgery of which code was proved.

The record is also explicit about four things it does **not** claim, because
each is a plausible misreading that the screen must be unable to produce:
these are sandbox observations, no real funds moved, this is a replay and not
live telemetry, and the Cloud Run process was never killed.  The proof is
*unknown after acceptance* -- the synthetic external system accepted the
action and its answer was deliberately lost.  The literal process-death proof
is a different, local one (``demo/reconcile_ravi.py``).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = "muster.action-gate-proof/v1"

REPOSITORY = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = (
    REPOSITORY
    / "packages"
    / "muster-ui"
    / "public"
    / "cases"
    / "ravi-cloud-gate-proof.json"
)

#  ---- provenance ----------------------------------------------------------

PROJECT_ID = "muster-agentic-2026-9177"
REGION = "asia-south1"
TENANT_ID = "BETA"
CASE_ID = "CASE-RAVI-SAT-CLOUD-GATE-FINAL-B-AF1359C"
EXECUTION_ID = "6e9de1415fb0056e7c2e41b4b3d1d15008a980e0b19a7afde70c86f0642d5b80"

#: The commit the deployed image was built from.  Not the current head.
DEPLOYED_SOURCE_COMMIT = "af1359c828d70e9e860f10ae076f225b006e5693"
#: The documentation-only head recorded afterwards.  It built no image.
DOCUMENTATION_COMMIT = "f03f6207f4911c33ec7342bcfb2b88471ef1c1b8"

CLOUD_BUILD_ID = "4f7f281f-5373-43db-addd-496cd2c546fe"
IMAGE_DIGEST = "sha256:77e0060833b982b471b7b7e272ee37eb438e3e551e79ba004cb41e94ca2e9d73"
CONTROL_PLANE_IMAGE = (
    f"{REGION}-docker.pkg.dev/{PROJECT_ID}/muster/muster-control-plane@{IMAGE_DIGEST}"
)

#: The synthetic external system's receipt.  It is derived from the execution
#: id, which is why the same string appears in every read that found a transfer.
EXTERNAL_REFERENCE = f"sandbox-pay-{EXECUTION_ID}"

#: The instant the synthetic rail recorded acceptance, and the instant the
#: durable row was reconciled -- the same value, read off the row.
RECONCILED_AT = 1760000000000000

#  ---- least privilege -----------------------------------------------------

LEAST_PRIVILEGE_EXECUTION = "muster-database-bootstrap-gs54f"
RUNTIME_ROLE = "muster_runtime"
RUNTIME_GRANTS = 20
PRIVILEGE_QUESTIONS = 126
PRIVILEGE_ANSWERS_WRONG = 0
MIGRATIONS_APPLIED = "none"
MIGRATIONS_CURRENT = (1, 2, 3, 4, 5, 6, 7)

#  ---- the five executions -------------------------------------------------

STAGE_UNKNOWN = "muster-control-plane-hero-z2m6k"
STAGE_PRE_READ = "muster-database-bootstrap-jkr7k"
STAGE_RECONCILE = "muster-control-plane-hero-hdfv2"
STAGE_IDEMPOTENT = "muster-control-plane-hero-pv2f2"
STAGE_FINAL_READ = "muster-database-bootstrap-kpz8p"


@dataclass(frozen=True, slots=True)
class ControlPlaneObservation:
    """One execution's report of the durable Gate row, field for field.

    A record rather than a long keyword list, so a transcription mistake is a
    named field in one place instead of an argument in the wrong position.
    """

    identifier: str
    ordinal: int
    execution: str
    state: str
    finality: str | None
    outcome_code: str | None
    external_reference: str | None
    reconciled_from: str | None
    reconciled_at: int | None
    dispatches: int
    inspections: int
    real_funds: bool | None


def _control_plane_stage(observed: ControlPlaneObservation) -> dict[str, object]:
    """One durable read of the Gate row, exactly as that execution reported it.

    A ``None`` never means "false" and never means "absent from the row": it
    means *this execution did not report that field*, and the viewer renders
    nothing for it.  The distinction matters most on the idempotency read,
    which reported a state and two counters and nothing else -- inventing a
    finality for it from the previous stage would be a fact nobody observed.
    """
    return {
        "id": observed.identifier,
        "ordinal": observed.ordinal,
        "kind": "control_plane",
        "cloud_run_execution": observed.execution,
        "state": observed.state,
        "finality": observed.finality,
        "outcome_code": observed.outcome_code,
        "external_reference": observed.external_reference,
        "reconciled_from": observed.reconciled_from,
        "reconciled_at": observed.reconciled_at,
        "dispatches": observed.dispatches,
        "inspections": observed.inspections,
        "real_funds": observed.real_funds,
    }


def _external_world_stage(
    *,
    identifier: str,
    ordinal: int,
    execution: str,
    attempt: str,
    transfer_present: bool,
    external_reference: str,
    transfer_count: int,
) -> dict[str, object]:
    """One read-only look at the synthetic external world.

    ``read_only`` is not a promise about intent.  Both of these executions
    reported, in their own output, that the simulated external world was read
    and nothing was written; that report is the field.
    """
    return {
        "id": identifier,
        "ordinal": ordinal,
        "kind": "external_world",
        "cloud_run_execution": execution,
        "attempt": attempt,
        "transfer_present": transfer_present,
        "external_reference": external_reference,
        "transfer_count": transfer_count,
        "read_only": True,
    }


def build_gate_proof() -> dict[str, object]:
    """Build the sanitized proof document from the observed constants above."""
    return {
        "schema_version": SCHEMA_VERSION,
        "provenance": {
            "project_id": PROJECT_ID,
            "region": REGION,
            "tenant_id": TENANT_ID,
            "case_id": CASE_ID,
            "execution_id": EXECUTION_ID,
            "deployed_source_commit": DEPLOYED_SOURCE_COMMIT,
            "documentation_commit": DOCUMENTATION_COMMIT,
            "cloud_build_id": CLOUD_BUILD_ID,
            "image_digest": IMAGE_DIGEST,
            "control_plane_image": CONTROL_PLANE_IMAGE,
        },
        "claims": {
            "sandbox_only": True,
            "real_funds": False,
            "live_telemetry": False,
            "cloud_run_process_death_claimed": False,
        },
        "action": {
            "kind": "PAY",
            "recipient": "RAVI",
            "amount": {
                "unit": "INR",
                "scale": 2,
                "minor": 510000,
                "display": "INR 5,100.00",
            },
        },
        "external_reference": EXTERNAL_REFERENCE,
        "least_privilege": {
            "cloud_run_execution": LEAST_PRIVILEGE_EXECUTION,
            "runtime_role": RUNTIME_ROLE,
            "runtime_grants": RUNTIME_GRANTS,
            "privilege_questions": PRIVILEGE_QUESTIONS,
            "privilege_answers_wrong": PRIVILEGE_ANSWERS_WRONG,
            "migrations_applied": MIGRATIONS_APPLIED,
            "migrations_current": list(MIGRATIONS_CURRENT),
        },
        "stages": [
            _control_plane_stage(
                ControlPlaneObservation(
                    identifier="unknown_after_acceptance",
                    ordinal=1,
                    execution=STAGE_UNKNOWN,
                    state="UNCERTAIN",
                    finality=None,
                    outcome_code="EXECUTOR_EXCEPTION",
                    external_reference=None,
                    reconciled_from=None,
                    reconciled_at=None,
                    dispatches=1,
                    inspections=0,
                    real_funds=False,
                )
            ),
            _external_world_stage(
                identifier="pre_reconciliation_external_read",
                ordinal=2,
                execution=STAGE_PRE_READ,
                attempt="ATTEMPTED",
                transfer_present=True,
                external_reference=EXTERNAL_REFERENCE,
                transfer_count=1,
            ),
            _control_plane_stage(
                ControlPlaneObservation(
                    identifier="reconciliation",
                    ordinal=3,
                    execution=STAGE_RECONCILE,
                    state="CONFIRMED",
                    finality="DEFINITELY_EXECUTED",
                    outcome_code="CONFIRMED",
                    external_reference=EXTERNAL_REFERENCE,
                    reconciled_from="UNCERTAIN",
                    reconciled_at=RECONCILED_AT,
                    dispatches=0,
                    inspections=1,
                    real_funds=False,
                )
            ),
            _control_plane_stage(
                ControlPlaneObservation(
                    identifier="exact_idempotency_read",
                    ordinal=4,
                    execution=STAGE_IDEMPOTENT,
                    state="CONFIRMED",
                    finality=None,
                    outcome_code=None,
                    external_reference=EXTERNAL_REFERENCE,
                    reconciled_from=None,
                    reconciled_at=None,
                    dispatches=0,
                    inspections=0,
                    real_funds=None,
                )
            ),
            _external_world_stage(
                identifier="final_external_read",
                ordinal=5,
                execution=STAGE_FINAL_READ,
                attempt="ATTEMPTED",
                transfer_present=True,
                external_reference=EXTERNAL_REFERENCE,
                transfer_count=1,
            ),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) > 1:
        print("usage: gate_proof_artifact.py [OUTPUT_FILE]", file=sys.stderr)
        return 2
    target = Path(args[0]) if args else DEFAULT_OUTPUT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_gate_proof(), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
