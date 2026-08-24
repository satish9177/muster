"""Generate the judge-facing Ravi evidence plan from the real demo path.

The producer drives ``demo.hero.run_hero`` with the deterministic interpreters,
then projects the plan, admitted relations, and final kernel result.  It does
not decide which evidence matters: the existing planner already did that.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from demo.hero import run_hero
elif __package__:
    from demo.hero import run_hero  # type: ignore[no-redef]
else:
    from hero import run_hero  # type: ignore[import-not-found,no-redef]

from agent_tests.support import fleet
from muster.core.analysis.outcomes import Divergent, ExactReachable, Invariant, outcome_class
from muster.core.evidence.relations import AcquisitionRelation, ClosedLowerBound, ExactValue
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled, render
from muster.core.values.symbols import SymbolRef
from muster.domains.workforce.bundle import (
    QUALIFYING_MINUTES,
    on_site_duration,
    present_on_site,
    scheduled,
)
from muster.platform.adapters.memory import MemoryDatabase
from support import ravi

SCHEMA_VERSION = "muster.evidence-plan/v1"
TENANT_ID = "MUSTER-DEMO"
CASE_ID = "CASE-RAVI-EVIDENCE-PLAN"
REPOSITORY = Path(__file__).resolve().parent.parent
DEFAULT_TRACE = (
    REPOSITORY
    / "packages"
    / "muster-ui"
    / "public"
    / "cases"
    / "ravi-cloud-execution.json"
)


def build_read_model(
    cloud_trace: dict[str, object] | None = None,
) -> dict[str, object]:
    """Project the stored cloud run and locally reproduced plan into a read model."""
    trace = _load_trace() if cloud_trace is None else cloud_trace
    transport = fleet.transport(
        {
            fleet.SITE_ENDPOINT: fleet.site(TENANT_ID),
            fleet.EMPLOYER_ENDPOINT: fleet.employer(TENANT_ID),
        }
    )
    run = run_hero(
        ravi.casework(MemoryDatabase()),
        transport,
        tenant_id=TENANT_ID,
        case_id=CASE_ID,
    )
    analysis = run.report.analysis
    if analysis is None:
        raise RuntimeError("the Ravi evidence plan requires a completed analysis")
    outcome = analysis.kernel.outcome
    if not isinstance(outcome, Invariant):
        raise RuntimeError("the Ravi evidence plan requires the invariant hero result")

    duration = on_site_duration(fleet.WORKER, fleet.SATURDAY)
    expected = {
        scheduled(fleet.WORKER, fleet.SATURDAY),
        present_on_site(fleet.WORKER, fleet.SATURDAY),
        duration,
    }
    requested = {target.proposition for target in run.solicited.targets}
    trace_requested = {
        _trace_proposition(item["proposition"])
        for item in _records(_record(trace, "plan"), "requirements")
    }
    admitted = {
        _trace_proposition(item["proposition"]): _trace_relation(item["relation"])
        for item in _records(trace, "attestations")
    }
    if requested != expected or trace_requested != expected or set(admitted) != expected:
        raise RuntimeError("the hero plan and admitted evidence no longer match the Ravi proof")
    if duration not in analysis.projected.unresolved():
        raise RuntimeError("the exact duration must remain unresolved in the invariant result")

    required = [
        _required_item(target.proposition, admitted[target.proposition])
        for target in run.solicited.targets
    ]
    action_fields: dict[str, dict[str, object]] = {
        field.name: _value_model(field.value) for field in outcome.action.consequential_fields
    }
    trace_result = _record(trace, "result")
    if trace_result.get("outcome") != outcome_class(outcome):
        raise RuntimeError("stored execution and deterministic kernel outcome disagree")
    if _trace_action_fields(trace_result) != action_fields:
        raise RuntimeError("stored execution and deterministic kernel action disagree")
    return {
        "schema_version": SCHEMA_VERSION,
        "case": {
            "tenant_id": _string(trace, "tenant_id"),
            "case_id": _string(trace, "case_id"),
        },
        "required_resolved": required,
        "not_required": [
            {
                "label": "Exact minute count — never established",
                "proposition": _proposition_model(duration),
                "status": "NOT_REQUIRED",
                "unresolved": True,
                "reason": (
                    "Every currently admissible exact duration produces the same "
                    "consequential action."
                ),
            }
        ],
        "summary": {
            "reachable_action_count": _reachable_action_count(outcome),
            "outcome": outcome_class(outcome),
            "exact_duration_status": "UNRESOLVED",
            "action": {
                "kind": outcome.action.kind,
                "fields": action_fields,
                "display": outcome.action.render(),
            },
            "explanation": (
                "Exact duration remains unresolved because resolving it cannot change "
                "the action."
            ),
        },
        "provenance": {
            "mode": "verified-cloud-execution-projection",
            "label": "VERIFIED CLOUD EXECUTION",
            "description": (
                "Projected from the stored verified Ravi execution and checked against "
                "the existing deterministic Hinge plan and kernel result."
            ),
            "basis": "This projection performed no new model call or cloud execution.",
        },
    }


def _load_trace() -> dict[str, object]:
    loaded: object = json.loads(DEFAULT_TRACE.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise RuntimeError("the Ravi cloud trace must be a JSON object")
    return loaded


def _record(value: dict[str, object], key: str) -> dict[str, object]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise RuntimeError(f"Ravi cloud trace field {key} must be an object")
    return item


def _records(value: dict[str, object], key: str) -> list[dict[str, object]]:
    items = value.get(key)
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise RuntimeError(f"Ravi cloud trace field {key} must be an object list")
    return items


def _string(value: dict[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise RuntimeError(f"Ravi cloud trace field {key} must be a string")
    return item


def _trace_proposition(value: object) -> SymbolRef:
    if not isinstance(value, dict):
        raise RuntimeError("trace proposition must be an object")
    predicate = _string(value, "predicate")
    args = value.get("args")
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise RuntimeError("trace proposition args must be strings")
    return SymbolRef(predicate, tuple(args))


def _trace_relation(value: object) -> AcquisitionRelation:
    if not isinstance(value, dict):
        raise RuntimeError("trace relation must be an object")
    wire_value = _record(value, "value")
    raw = wire_value.get("value")
    if wire_value.get("type") == "bool" and isinstance(raw, bool):
        parsed: Value = VBool(raw)
    elif wire_value.get("type") == "int" and isinstance(raw, int):
        parsed = VInt(raw)
    else:
        raise RuntimeError("unsupported trace relation value")
    if value.get("kind") == "EXACT":
        return ExactValue(parsed)
    if value.get("kind") == "CLOSED_LOWER_BOUND":
        return ClosedLowerBound(parsed)
    raise RuntimeError("unsupported trace relation kind")


def _trace_action_fields(result: dict[str, object]) -> dict[str, dict[str, object]]:
    action = _record(result, "action")
    fields: dict[str, dict[str, object]] = {}
    for field in _records(action, "fields"):
        name = _string(field, "name")
        value = _record(field, "value")
        if value.get("type") == "enum":
            parsed: Value = VEnum(_string(value, "enum_id"), _string(value, "value"))
        elif value.get("type") == "scaled":
            unit = _string(value, "unit")
            scale = value.get("scale")
            minor = value.get("minor")
            if not isinstance(scale, int) or not isinstance(minor, int):
                raise RuntimeError("scaled action fields require integer scale and minor")
            parsed = VScaled(unit, scale, minor)
        else:
            raise RuntimeError("unsupported trace action field")
        fields[name] = _value_model(parsed)
    return fields


def _required_item(reference: SymbolRef, relation: AcquisitionRelation) -> dict[str, object]:
    duration = on_site_duration(fleet.WORKER, fleet.SATURDAY)
    schedule = scheduled(fleet.WORKER, fleet.SATURDAY)
    presence = present_on_site(fleet.WORKER, fleet.SATURDAY)
    if reference == schedule:
        label = "Scheduled for Saturday"
        reason = "Schedule eligibility can change the consequential action."
        requirement = "Required by the deterministic evidence plan."
    elif reference == presence:
        label = "Present on site"
        reason = "Site presence can change the consequential action."
        requirement = "Required by the deterministic evidence plan."
    elif reference == duration:
        label = "On-site duration — threshold only"
        reason = "The pinned policy's qualifying-duration threshold can change the action."
        requirement = f"At least {QUALIFYING_MINUTES} minutes under pinned policy."
    else:  # pragma: no cover - the exact requested set is checked by the caller
        raise RuntimeError(f"unexpected Ravi evidence target: {reference}")
    return {
        "label": label,
        "proposition": _proposition_model(reference),
        "status": "RESOLVED",
        "requirement": requirement,
        "established": _relation_display(relation),
        "reason": reason,
    }


def _relation_display(relation: AcquisitionRelation) -> str:
    match relation:
        case ExactValue(value):
            return f"Authorized evidence establishes = {render(value)}."
        case ClosedLowerBound(VInt(number)):
            return f"Authorized evidence establishes at least {number} minutes."
        case _:
            raise RuntimeError(f"unsupported Ravi evidence relation: {type(relation).__name__}")


def _proposition_model(reference: SymbolRef) -> dict[str, object]:
    return {
        "predicate": reference.predicate_id,
        "args": list(reference.args),
        "display": str(reference),
    }


def _value_model(value: Value) -> dict[str, object]:
    match value:
        case VBool(flag):
            return {"type": "bool", "value": flag, "display": render(value)}
        case VInt(number):
            return {"type": "int", "value": number, "display": render(value)}
        case VScaled(unit_tag, scale, minor):
            return {
                "type": "scaled",
                "unit": unit_tag,
                "scale": scale,
                "minor": minor,
                "display": render(value),
            }
        case VEnum(enum_id, member):
            return {
                "type": "enum",
                "enum_id": enum_id,
                "value": member,
                "display": render(value),
            }


def _reachable_action_count(outcome: Invariant | Divergent) -> int:
    if isinstance(outcome, Invariant):
        return 1
    if isinstance(outcome.reachable, ExactReachable):
        return len(outcome.reachable.actions)
    raise RuntimeError("the evidence-plan read model requires an exact reachable-action set")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: evidence_plan.py OUTPUT_FILE", file=sys.stderr)
        return 2
    target = Path(args[0])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_read_model(), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
