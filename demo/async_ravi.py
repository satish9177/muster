"""Local PostgreSQL proof that one Ravi case resumes in a later process.

This utility composes the existing casework commands and ``demo.durable_ravi``
keys.  It is deliberately not a workflow engine: each phase opens PostgreSQL,
performs one idempotent delivery step, prints a versioned proof record, and
exits.  ``prove`` launches the employer and site phases as separate Python
processes and combines their records for the static UI fixture.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, cast

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

from muster.core.analysis.outcomes import Invariant, outcome_class  # noqa: E402
from muster.core.evidence.relations import ClosedLowerBound, ExactValue  # noqa: E402
from muster.core.evidence.transcript import (  # noqa: E402
    Attestation,
    TranscriptEntry,
    entry_digest,
)
from muster.core.results import Err, InvariantViolation  # noqa: E402
from muster.core.values.scalars import VBool, VEnum, VInt, VScaled, render  # noqa: E402
from muster.domains.workforce.bundle import (  # noqa: E402
    on_site_duration,
    present_on_site,
    scheduled,
)
from muster.platform.adapters.sql.database import SqlDatabase  # noqa: E402
from muster.platform.adapters.sql.schema import migrate  # noqa: E402
from muster.platform.casework.advance import Casework  # noqa: E402
from muster.platform.casework.commands import (  # noqa: E402
    Appended,
    CaseReport,
    append_transcript_entry,
    case_status,
)
from support import ravi  # noqa: E402
from support.authority import WORKER  # noqa: E402

SCHEMA_VERSION = "muster.async-durability/v1"
DEFAULT_TENANT = "MUSTER-ASYNC-DEMO"
DEFAULT_CASE = "CASE-RAVI-ASYNC-DEMO"
DSN_ENVIRONMENT = "MUSTER_ASYNC_DSN"
# Synthetic local bound mirroring the verified Stage-90 cloud observation.
SITE_DURATION_FLOOR_MINUTES = 508


def employer_phase(dsn: str, tenant_id: str, case_id: str) -> dict[str, object]:
    """Persist the base case and employer evidence, safe to retry."""
    migrate(dsn)
    database = SqlDatabase(dsn)
    casework = durable_casework(database)
    case = durable_case(
        tenant_id,
        case_id,
        duration_floor_minutes=SITE_DURATION_FLOOR_MINUTES,
    )
    open_durable_case(casework, case)

    employer = _entry_for(case.entries, scheduled(WORKER, ravi.SATURDAY))
    phased = (*_base_entries(case.entries), employer)
    appended = tuple(_append(casework, tenant_id, case_id, entry) for entry in phased)
    report = _report(casework, tenant_id, case_id)
    members = _members(database, tenant_id, case_id)
    return {
        "phase": "EMPLOYER",
        "label": "T0",
        "process_id": os.getpid(),
        "case": {"tenant_id": tenant_id, "case_id": case_id},
        "authored_entries_created": sum(item.created for item in appended),
        "delivered": [_entry_model(employer)],
        "employer_entry_present": entry_digest(employer).hex in members,
        "state": _state_model(report, members),
    }


def resume_site_phase(dsn: str, tenant_id: str, case_id: str) -> dict[str, object]:
    """Load the durable phase-one head, append Site-A evidence, and advance it."""
    migrate(dsn)
    database = SqlDatabase(dsn)
    casework = durable_casework(database)
    case = durable_case(
        tenant_id,
        case_id,
        duration_floor_minutes=SITE_DURATION_FLOOR_MINUTES,
    )

    loaded = _report(casework, tenant_id, case_id)
    loaded_members = _members(database, tenant_id, case_id)
    employer = _entry_for(case.entries, scheduled(WORKER, ravi.SATURDAY))
    if entry_digest(employer).hex not in loaded_members:
        raise InvariantViolation("resume-site did not load the employer entry from phase one")

    site_entries = (
        _entry_for(case.entries, present_on_site(WORKER, ravi.SATURDAY)),
        _entry_for(case.entries, on_site_duration(WORKER, ravi.SATURDAY)),
    )
    appended = tuple(_append(casework, tenant_id, case_id, entry) for entry in site_entries)
    report = _report(casework, tenant_id, case_id)
    members = _members(database, tenant_id, case_id)
    return {
        "phase": "RESUME_SITE",
        "label": "LATER_EVENT",
        "process_id": os.getpid(),
        "case": {"tenant_id": tenant_id, "case_id": case_id},
        "loaded_state": _state_model(loaded, loaded_members),
        "authored_entries_created": sum(item.created for item in appended),
        "delivered": [_entry_model(entry) for entry in site_entries],
        "prior_employer_entry_preserved": entry_digest(employer).hex in members,
        "state": _state_model(report, members),
        "result": _result_model(report),
    }


def inspect_phase(dsn: str, tenant_id: str, case_id: str) -> dict[str, object]:
    """Read one case through a new database object without mutating it."""
    migrate(dsn)
    database = SqlDatabase(dsn)
    report = _report(durable_casework(database), tenant_id, case_id)
    members = _members(database, tenant_id, case_id)
    return {
        "phase": "INSPECT",
        "process_id": os.getpid(),
        "case": {"tenant_id": tenant_id, "case_id": case_id},
        "state": _state_model(report, members),
    }


def reset_case(dsn: str, tenant_id: str, case_id: str, confirmation: str) -> dict[str, int]:
    """Remove only this synthetic case's relational state; retain shared content."""
    expected = _confirmation(tenant_id, case_id)
    if confirmation != expected:
        raise ValueError(f"refusing reset: confirmation must exactly match {expected}")
    migrate(dsn)
    statements = (
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
        ("case_head", "DELETE FROM casework.case_head WHERE tenant_id=%s AND case_id=%s"),
    )
    deleted: dict[str, int] = {}
    with psycopg.connect(dsn) as connection, connection.transaction():
        for name, statement in statements:
            deleted[name] = connection.execute(statement, (tenant_id, case_id)).rowcount
    return deleted


def prove(
    dsn: str,
    tenant_id: str,
    case_id: str,
    confirmation: str,
) -> dict[str, object]:
    """Run the two delivery events in distinct subprocesses and validate continuity."""
    reset_case(dsn, tenant_id, case_id, confirmation)
    employer = _run_phase("employer", dsn, tenant_id, case_id)
    site = _run_phase("resume-site", dsn, tenant_id, case_id)
    employer_state = _record(employer, "state")
    loaded_state = _record(site, "loaded_state")
    site_state = _record(site, "state")
    artifact = {
        "schema_version": SCHEMA_VERSION,
        "provenance": {
            "source": "local-postgresql-durability-proof",
            "label": "LOCAL POSTGRESQL DURABILITY PROOF",
            "environment": "SYNTHETIC_DEMO",
            "cloud_execution": False,
            "note": (
                "The two evidence events ran in separate Python processes against the "
                "same local PostgreSQL case. No elapsed production time is claimed."
            ),
        },
        "case": {"tenant_id": tenant_id, "case_id": case_id},
        "events": [employer, site],
        "continuity": {
            "same_tenant_case": employer["case"] == site["case"],
            "different_processes": employer["process_id"] != site["process_id"],
            "loaded_phase_one_head": employer_state["head"] == loaded_state["head"],
            "loaded_phase_one_transcript": (
                employer_state["transcript_entry_count"]
                == loaded_state["transcript_entry_count"]
            ),
            "prior_employer_evidence_preserved": site["prior_employer_entry_preserved"],
            "revision_progressed": _revision_number(site_state) > _revision_number(employer_state),
        },
        "result": site["result"],
    }
    validate_artifact(artifact)
    return artifact


def validate_artifact(value: object) -> None:
    """Reject a durability artifact that does not prove every advertised transition."""
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported async-durability artifact")
    provenance = _record(value, "provenance")
    case = _record(value, "case")
    continuity = _record(value, "continuity")
    result = _record(value, "result")
    events = value.get("events")
    if (
        provenance.get("source") != "local-postgresql-durability-proof"
        or provenance.get("label") != "LOCAL POSTGRESQL DURABILITY PROOF"
        or provenance.get("environment") != "SYNTHETIC_DEMO"
        or provenance.get("cloud_execution") is not False
        or not _nonempty(case.get("tenant_id"))
        or not _nonempty(case.get("case_id"))
        or not isinstance(events, list)
        or len(events) != 2
        or any(continuity.get(key) is not True for key in _continuity_keys())
        or result.get("outcome") != "INVARIANT"
        or result.get("exact_duration_status") != "UNRESOLVED"
        or result.get("execution") != "NOT_EXECUTED"
    ):
        raise ValueError("async-durability artifact does not establish the required proof")
    employer, site = events
    if not isinstance(employer, dict) or not isinstance(site, dict):
        raise ValueError("async-durability events must be records")
    delivered = site.get("delivered")
    if (
        employer.get("phase") != "EMPLOYER"
        or site.get("phase") != "RESUME_SITE"
        or employer.get("case") != case
        or site.get("case") != case
        or employer.get("process_id") == site.get("process_id")
        or not isinstance(delivered, list)
        or not any(_is_duration_floor(item) for item in delivered)
    ):
        raise ValueError("async-durability event identity or evidence is inconsistent")


def _is_duration_floor(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    proposition = value.get("proposition")
    relation = value.get("relation")
    return (
        isinstance(proposition, dict)
        and proposition.get("predicate") == "on_site_duration"
        and isinstance(relation, dict)
        and relation.get("kind") == "CLOSED_LOWER_BOUND"
        and relation.get("display") == f">= {SITE_DURATION_FLOOR_MINUTES} minutes"
    )


def _run_phase(phase: str, dsn: str, tenant_id: str, case_id: str) -> dict[str, object]:
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
        ],
        cwd=Path(__file__).resolve().parent.parent,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise RuntimeError(f"async Ravi {phase} phase failed: {process.stderr.strip()}")
    parsed = json.loads(process.stdout)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"async Ravi {phase} phase returned no proof record")
    return parsed


def _base_entries(entries: tuple[TranscriptEntry, ...]) -> tuple[TranscriptEntry, ...]:
    acquired = {
        scheduled(WORKER, ravi.SATURDAY),
        present_on_site(WORKER, ravi.SATURDAY),
        on_site_duration(WORKER, ravi.SATURDAY),
    }
    return tuple(
        entry
        for entry in entries
        if not isinstance(entry, Attestation) or entry.receipt.payload.proposition not in acquired
    )


def _entry_for(entries: tuple[TranscriptEntry, ...], proposition: object) -> Attestation:
    matches = tuple(
        entry
        for entry in entries
        if isinstance(entry, Attestation) and entry.receipt.payload.proposition == proposition
    )
    if len(matches) != 1:
        raise InvariantViolation(f"expected one durable attestation for {proposition}")
    return matches[0]


def _append(
    casework: Casework, tenant_id: str, case_id: str, entry: TranscriptEntry
) -> Appended:
    appended = append_transcript_entry(
        casework,
        tenant_id=tenant_id,
        case_id=case_id,
        entry=entry,
        now=ravi.NOW,
    )
    if isinstance(appended, Err):
        raise InvariantViolation(
            f"async Ravi entry refused: {appended.error.failure.value}: {appended.error.detail}"
        )
    return appended.value


def _report(casework: Casework, tenant_id: str, case_id: str) -> CaseReport:
    reported = case_status(
        casework,
        tenant_id=tenant_id,
        case_id=case_id,
        now=ravi.NOW,
    )
    if isinstance(reported, Err):
        raise InvariantViolation(
            f"async Ravi case unavailable: {reported.error.failure.value}: {reported.error.detail}"
        )
    return reported.value


def _members(database: SqlDatabase, tenant_id: str, case_id: str) -> set[str]:
    with database.reading(tenant_id) as scope:
        members = scope.transcript.members(case_id)
    if isinstance(members, Err):
        raise InvariantViolation(
            f"async Ravi transcript unavailable: {members.error.failure.value}"
        )
    return {digest.hex for digest in members.value}


def _state_model(report: CaseReport, members: set[str]) -> dict[str, object]:
    analysis = report.analysis
    return {
        "status": report.status.value,
        "outcome": "UNANALYSED" if analysis is None else outcome_class(analysis.kernel.outcome),
        "head": {
            "revision_number": report.head.revision_number,
            "revision_digest": (
                None if report.head.revision_digest is None else report.head.revision_digest.hex
            ),
            "certificate_digest": (
                None
                if report.head.certificate_digest is None
                else report.head.certificate_digest.hex
            ),
            "transcript_prefix_digest": report.head.inputs.transcript_prefix_digest.hex,
        },
        "transcript_entry_count": len(members),
        "outstanding_request_count": len(report.outstanding),
        "certificate_reproduced": report.certificate_reproduced,
    }


def _result_model(report: CaseReport) -> dict[str, object]:
    analysis = report.analysis
    if analysis is None or not isinstance(analysis.kernel.outcome, Invariant):
        raise InvariantViolation("resume-site did not produce the invariant Ravi result")
    outcome = analysis.kernel.outcome
    fields = {field.name: field.value for field in outcome.action.consequential_fields}
    recipient = fields.get("recipient")
    amount = fields.get("amount")
    if not isinstance(recipient, VEnum) or not isinstance(amount, VScaled):
        raise InvariantViolation("the Ravi result does not carry the expected PAY fields")
    duration = on_site_duration(WORKER, ravi.SATURDAY)
    return {
        "status": report.status.value,
        "outcome": outcome_class(outcome),
        "exact_duration_status": (
            "UNRESOLVED" if duration in analysis.projected.unresolved() else "RESOLVED"
        ),
        "action": {
            "kind": outcome.action.kind,
            "recipient": recipient.member,
            "amount": {
                "unit": amount.unit_tag,
                "scale": amount.scale,
                "minor": amount.minor,
                "display": render(amount),
            },
            "display": outcome.action.render(),
        },
        "execution": "NOT_EXECUTED",
    }


def _entry_model(entry: Attestation) -> dict[str, object]:
    proposition = entry.receipt.payload.proposition
    relation = entry.receipt.payload.relation
    return {
        "entry_digest": entry_digest(entry).hex,
        "proposition": {
            "predicate": proposition.predicate_id,
            "args": list(proposition.args),
            "display": str(proposition),
        },
        "source_class": entry.receipt.payload.source_class,
        "authorization": "Q-12",
        "relation": _relation_model(relation),
    }


def _relation_model(relation: object) -> dict[str, object]:
    match relation:
        case ExactValue(VBool(flag)):
            return {"kind": "EXACT", "display": f"= {render(VBool(flag))}"}
        case ClosedLowerBound(VInt(number)):
            return {
                "kind": "CLOSED_LOWER_BOUND",
                "display": f">= {number} minutes",
            }
        case _:
            raise InvariantViolation("unsupported async Ravi evidence relation")


def _record(value: object, key: str) -> dict[str, object]:
    if not isinstance(value, dict) or not isinstance(value.get(key), dict):
        raise ValueError(f"async-durability artifact requires record {key}")
    return cast(dict[str, object], value[key])


def _revision_number(state: dict[str, object]) -> int:
    head = _record(state, "head")
    value = head.get("revision_number")
    if not isinstance(value, int):
        raise ValueError("async-durability head requires a revision number")
    return value


def _continuity_keys() -> tuple[str, ...]:
    return (
        "same_tenant_case",
        "different_processes",
        "loaded_phase_one_head",
        "loaded_phase_one_transcript",
        "prior_employer_evidence_preserved",
        "revision_progressed",
    )


def _confirmation(tenant_id: str, case_id: str) -> str:
    return f"{tenant_id}/{case_id}"


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value)


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
    subparsers.add_parser("employer")
    subparsers.add_parser("resume-site")
    subparsers.add_parser("inspect")
    reset = subparsers.add_parser("reset")
    reset.add_argument("--confirm-demo-only-reset", required=True)
    proof = subparsers.add_parser("prove")
    proof.add_argument("--confirm-demo-only-reset", required=True)
    proof.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        dsn = _dsn(arguments.dsn)
        if arguments.phase == "employer":
            result: object = employer_phase(dsn, arguments.tenant, arguments.case)
        elif arguments.phase == "resume-site":
            result = resume_site_phase(dsn, arguments.tenant, arguments.case)
        elif arguments.phase == "inspect":
            result = inspect_phase(dsn, arguments.tenant, arguments.case)
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
            )
            if arguments.output is not None:
                arguments.output.parent.mkdir(parents=True, exist_ok=True)
                arguments.output.write_text(
                    json.dumps(result, indent=2) + "\n", encoding="utf-8"
                )
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (InvariantViolation, RuntimeError, ValueError, psycopg.Error) as error:
        print(f"muster-async-ravi: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
