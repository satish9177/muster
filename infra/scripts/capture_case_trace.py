"""Capture one sanitized case-trace record from one exact execution log."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
from typing import cast

SCHEMA_VERSION = "muster.case-trace/v1"
RECORD_PREFIX = "MUSTER_CASE_TRACE_V1="
MAX_RECORD_BYTES = 128 * 1024

FORBIDDEN_KEYS = frozenset(
    {
        "access_token",
        "credentials",
        "private_key",
        "prompt",
        "raw_evidence",
        "raw_object",
        "secret",
        "signature",
    }
)


class CaptureError(ValueError):
    """The exact execution did not yield one admissible trace."""


def capture_case_trace(
    log_text: str,
    *,
    project_id: str,
    job_name: str,
    cloud_run_region: str,
    execution_name: str,
    executed_at: str,
    completed_at: str,
) -> dict[str, object]:
    """Extract, bind, and validate a single machine record."""

    candidates = [line for line in log_text.splitlines() if line.startswith(RECORD_PREFIX)]
    if len(candidates) != 1:
        raise CaptureError(f"expected one {RECORD_PREFIX} record, found {len(candidates)}")

    encoded = candidates[0].removeprefix(RECORD_PREFIX)
    try:
        octets = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise CaptureError("case trace record is not canonical base64") from error
    if not octets or len(octets) > MAX_RECORD_BYTES:
        raise CaptureError("case trace record has an unsafe size")
    try:
        parsed = cast(object, json.loads(octets.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CaptureError("case trace record is not UTF-8 JSON") from error

    artifact = _object(parsed, "artifact")
    _validate_envelope(
        artifact,
        project_id=project_id,
        job_name=job_name,
        cloud_run_region=cloud_run_region,
        execution_name=execution_name,
        executed_at=executed_at,
        completed_at=completed_at,
    )
    _audit_private_fields(artifact)
    return artifact


def canonical_json(artifact: dict[str, object]) -> str:
    return json.dumps(artifact, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def write_artifact(path: Path, content: str) -> None:
    """Replace one generated file only after its complete sibling is written."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _validate_envelope(
    artifact: dict[str, object],
    *,
    project_id: str,
    job_name: str,
    cloud_run_region: str,
    execution_name: str,
    executed_at: str,
    completed_at: str,
) -> None:
    if artifact.get("schema_version") != SCHEMA_VERSION:
        raise CaptureError("unknown case trace schema")
    for identifier in (
        project_id,
        job_name,
        cloud_run_region,
        execution_name,
        executed_at,
        completed_at,
    ):
        if not identifier:
            raise CaptureError("execution binding values must be non-empty")

    provenance = _object(artifact.get("provenance"), "provenance")
    if provenance != {"source": "verified-cloud-execution", "captured": False}:
        raise CaptureError("producer provenance is not an uncaptured cloud execution")

    execution = _object(artifact.get("execution"), "execution")
    if execution.get("project_id") != project_id:
        raise CaptureError("artifact project does not match the execution")
    if execution.get("job_name") != job_name:
        raise CaptureError("artifact job does not match the execution")
    if execution.get("cloud_run_region") != cloud_run_region:
        raise CaptureError("artifact region does not match the execution")
    if any(execution.get(field) is not None for field in _CAPTURED_EXECUTION_FIELDS):
        raise CaptureError("producer tried to assert capture-owned execution fields")

    _object(execution.get("model"), "execution.model")
    _object(artifact.get("claim"), "claim")
    _object(artifact.get("plan"), "plan")
    boundary = _object(artifact.get("security_boundary"), "security_boundary")
    result = _object(artifact.get("result"), "result")
    if boundary.get("result") != "DENIED" or boundary.get("http_status") != 403:
        raise CaptureError("artifact does not carry the observed IAM 403")
    if result.get("status") != "PROPOSED" or result.get("outcome") != "INVARIANT":
        raise CaptureError("artifact does not carry the completed proposed invariant")
    action = _object(result.get("action"), "result.action")
    _validate_action_execution(_object(action.get("execution"), "result.action.execution"))
    if not isinstance(artifact.get("attestations"), list):
        raise CaptureError("artifact attestations must be an array")

    provenance["captured"] = True
    execution["execution_name"] = execution_name
    execution["executed_at"] = executed_at
    execution["completed_at"] = completed_at


#: What a producer may claim about the Action Gate.  ``NOT_EXECUTED`` is the
#: analysis-only shape; the rest are the durable states the Gate's own machine
#: can reach.  ``RESERVED`` is deliberately absent: a reservation that never
#: crossed the executor boundary is unfinished work, not an execution, and an
#: artifact carrying one would be publishing a lifecycle mid-flight.
_EXECUTED_STATES = frozenset({"CONFIRMED", "DISPATCHED", "FAILED", "UNCERTAIN"})
_EXECUTION_KEY_OCTETS = 32


def _validate_action_execution(execution: dict[str, object]) -> None:
    """The one part of a captured trace that asserts something was *done*.

    Checked here as well as at the producer, because this is the boundary the
    published file crosses: everything above validates that a record describes
    the execution the capture is bound to, and this validates that the record
    does not describe a settlement it has no business describing.

    ``real_funds`` must be exactly ``False`` -- ``is not False``, not falsy --
    so a producer cannot satisfy it with ``0``, ``null`` or an empty string.
    """
    status = execution.get("status")
    if status == "NOT_EXECUTED":
        if set(execution) != {"status"}:
            raise CaptureError("an unexecuted action carries no execution fields")
        return
    if status not in _EXECUTED_STATES:
        raise CaptureError("result.action.execution names an unknown state")
    if set(execution) != {
        "status",
        "execution_key",
        "external_reference",
        "outcome_code",
        "real_funds",
        "reserved_at",
        "dispatched_at",
        "finalized_at",
    }:
        raise CaptureError("result.action.execution carries unexpected fields")
    if execution.get("real_funds") is not False:
        raise CaptureError("a captured case trace never carries a real-funds execution")
    _validate_lifecycle_instants(execution, status)

    key = execution.get("execution_key")
    if (
        not isinstance(key, str)
        or len(key) != _EXECUTION_KEY_OCTETS * 2
        or key != key.lower()
        or any(character not in "0123456789abcdef" for character in key)
    ):
        raise CaptureError("result.action.execution names no canonical execution key")
    #  DISPATCHED is the one published state with no result yet, so it is the
    #  one state whose outcome code must be absent rather than present.  The
    #  producer refuses the other reading too; this is the boundary where the
    #  row stops being a record and becomes a published file, and a captured
    #  ``outcome_code: "DISPATCHED"`` would be a state renamed as a result.
    outcome = execution.get("outcome_code")
    if status == "DISPATCHED":
        if outcome is not None:
            raise CaptureError("a dispatched execution has no outcome yet")
    elif not isinstance(outcome, str) or not outcome:
        raise CaptureError("a finalized execution carries an outcome code")

    reference = execution.get("external_reference")
    if status == "CONFIRMED":
        if not isinstance(reference, str) or not reference:
            raise CaptureError("a confirmed execution carries an external reference")
    elif reference is not None:
        raise CaptureError("an unconfirmed execution carries no external reference")


def _validate_lifecycle_instants(execution: dict[str, object], status: object) -> None:
    """The three durable instants, and the ordering the row is supposed to have.

    These are *measurements* the producer read off the execution row -- not a
    timeline reconstructed from the state machine -- so the capture checks them
    as measurements: each is a whole number, each of the ones a given state must
    carry is present, and they do not run backwards.

    ``bool`` is excluded explicitly because it is an ``int`` in Python, and an
    instant that arrived as ``true`` would otherwise pass every check below.
    """
    def instant(name: str) -> int | None:
        value = execution.get(name)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise CaptureError(f"result.action.execution.{name} is not a durable instant")
        return value

    reserved = instant("reserved_at")
    dispatched = instant("dispatched_at")
    finalized = instant("finalized_at")

    if reserved is None:
        raise CaptureError("an executed action carries a reservation instant")
    #  Every publishable status is at or past DISPATCHED, so a dispatch instant
    #  is not optional; the three final ones carry a finalization instant too.
    if dispatched is None:
        raise CaptureError("an executed action carries a dispatch instant")
    if status == "DISPATCHED":
        if finalized is not None:
            raise CaptureError("a dispatched execution has not been finalized")
    elif finalized is None:
        raise CaptureError("a final execution state carries a finalization instant")

    if dispatched < reserved:
        raise CaptureError("dispatch cannot precede reservation")
    if finalized is not None and finalized < dispatched:
        raise CaptureError("finalization cannot precede dispatch")


_CAPTURED_EXECUTION_FIELDS = ("execution_name", "executed_at", "completed_at")


def _audit_private_fields(value: object, path: str = "artifact") -> None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise CaptureError(f"{path} contains a non-string key")
            if raw_key.lower() in FORBIDDEN_KEYS:
                raise CaptureError(f"{path}.{raw_key} is forbidden in a case trace")
            _audit_private_fields(child, f"{path}.{raw_key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _audit_private_fields(child, f"{path}[{index}]")


def _object(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CaptureError(f"{name} must be an object")
    return cast(dict[str, object], value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--execution", required=True)
    parser.add_argument("--executed-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ui-output", type=Path, required=True)
    arguments = parser.parse_args()

    artifact = capture_case_trace(
        arguments.logs.read_text(encoding="utf-8"),
        project_id=arguments.project,
        job_name=arguments.job,
        cloud_run_region=arguments.region,
        execution_name=arguments.execution,
        executed_at=arguments.executed_at,
        completed_at=arguments.completed_at,
    )
    content = canonical_json(artifact)
    write_artifact(arguments.output, content)
    write_artifact(arguments.ui_output, content)
    print(f"  case trace {arguments.output}")
    print(f"  UI replay  {arguments.ui_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
