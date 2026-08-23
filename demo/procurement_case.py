"""Build the compact procurement read models from deterministic kernel output."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.core.actions import Action, ConsequentialAction
from muster.core.analysis.outcomes import Divergent, ExactReachable, Invariant, outcome_class
from muster.core.analysis.planning import EvidenceRequested, NoActionRequired
from muster.core.case.revision import CaseRevision
from muster.core.results import Ok
from muster.core.values.scalars import VEnum, VInt, VScaled
from muster.domains.procurement.bundle import (
    ACCEPTANCE_THRESHOLD,
    CURRENCY,
    FIELD_AMOUNT,
    FIELD_RECIPIENT,
    FIXED_AMOUNT_MINOR,
    PER_UNIT_RATE_MINOR,
    SOURCE_PROCUREMENT_PO,
    SOURCE_WAREHOUSE,
    ProcurementPolicy,
    delivered_quantity,
    procurement_bundle,
)
from muster.domains.procurement.scenario import (
    ORDERED_QUANTITY,
    RELATION_CLAIM_ONLY,
    WAREHOUSE_QUANTITY,
    case_fixture,
    revision,
)
from muster.hinge.prepare import EngineLimits
from muster.policy.program import evaluate_program
from muster.solve.reference.bounded import BoundedEnumerationBackend


def analysis(
    policy: ProcurementPolicy, case_revision: CaseRevision | None = None
) -> CaseAnalysis:
    bundle = procurement_bundle(policy)
    produced = analyse_revision(
        revision(policy) if case_revision is None else case_revision,
        bundle,
        BoundedEnumerationBackend(50_000),
        EngineLimits(max_unresolved=4, reachable_action_cap=10),
    )
    if not isinstance(produced, Ok):
        raise RuntimeError(f"procurement analysis failed: {produced.error}")
    return produced.value


def _action_fields(action: Action | ConsequentialAction) -> tuple[Any, ...]:
    if isinstance(action, Action):
        return action.fields
    return action.consequential_fields


def _action_model(action: Action | ConsequentialAction) -> dict[str, Any]:
    fields = {field.name: field.value for field in _action_fields(action)}
    recipient = fields.get(FIELD_RECIPIENT)
    amount = fields.get(FIELD_AMOUNT)
    if not isinstance(recipient, VEnum) or not isinstance(amount, VScaled):
        raise RuntimeError("a procurement PAY action must carry recipient and scaled amount")
    return {
        "kind": action.kind,
        "recipient": recipient.member,
        "currency": amount.unit_tag,
        "amount_minor": amount.minor,
    }


def _alternative(policy: ProcurementPolicy, quantity: int) -> dict[str, Any]:
    bundle = procurement_bundle(policy)
    world = revision(policy).known()
    world[delivered_quantity()] = VInt(quantity)
    evaluated = evaluate_program(bundle.program, bundle.action_schema, world)
    if not isinstance(evaluated, Ok):
        raise RuntimeError(f"procurement alternative did not evaluate: {evaluated.error}")
    return {"quantity": quantity, "action": _action_model(evaluated.value)}


def _display_inr(minor: int) -> str:
    return f"₹{minor // 100:,}"


def build_read_model(policy: ProcurementPolicy) -> dict[str, Any]:
    fixture = case_fixture()
    bundle = procurement_bundle(policy)
    produced = analysis(policy)
    outcome = produced.kernel.outcome
    planning = produced.planning.record.planning_outcome

    if isinstance(outcome, Invariant):
        proposed_action: dict[str, Any] | None = _action_model(outcome.action)
        result_explanation = (
            f"MUSTER stops here because resolving {WAREHOUSE_QUANTITY} vs "
            f"{ORDERED_QUANTITY} cannot change the action."
        )
        exact_quantity_relevance = "IRRELEVANT TO THIS ACTION"
    else:
        proposed_action = None
        result_explanation = (
            "The same uncertainty now changes the action, so MUSTER asks for proof."
        )
        exact_quantity_relevance = "ACTION-SENSITIVE"

    if isinstance(planning, EvidenceRequested):
        target = planning.request.targets[0]
        evidence: dict[str, Any] = {
            "status": "REQUIRED",
            "display_status": "REQUIRED",
            "reason": "ACTION_SENSITIVE_UNCERTAINTY",
            "hinge": {
                "predicate": target.proposition.predicate_id,
                "label": "delivered quantity",
                "permitted_source_classes": list(target.permitted_source_classes),
            },
        }
    elif isinstance(planning, NoActionRequired):
        evidence = {
            "status": "NONE_REQUIRED",
            "display_status": "NONE REQUIRED",
            "reason": planning.reason.value,
            "hinge": None,
        }
    else:
        raise RuntimeError(f"unexpected procurement planning outcome: {type(planning).__name__}")

    records = fixture.records[:2]
    quantities = [record.value.value for record in records if isinstance(record.value, VInt)]
    if len(quantities) != 2 or quantities[0] == quantities[1]:
        raise RuntimeError("the procurement fixture must retain two disagreeing quantities")

    return {
        "schema_version": "muster.procurement-case/v1",
        "case": {
            "tenant_id": fixture.tenant_id,
            "case_id": fixture.case_id,
            "po_id": fixture.po_id,
            "supplier": fixture.supplier,
            "title": "Supplier Delivery",
        },
        "sources": [
            {
                "label": record.label,
                "source_class": record.source_class,
                "quantity": record.value.value,
                "relation": (
                    "CLAIM" if record.relation == RELATION_CLAIM_ONLY else "LOWER_BOUND"
                ),
            }
            for record in records
            if isinstance(record.value, VInt)
        ],
        "uncertainty": {
            "predicate": delivered_quantity().predicate_id,
            "status": "UNRESOLVED",
            "admissible_min": WAREHOUSE_QUANTITY,
            "admissible_max": ORDERED_QUANTITY,
            "lower_bound": {
                "quantity": WAREHOUSE_QUANTITY,
                "source_class": SOURCE_WAREHOUSE,
                "semantics": "CLOSED_LOWER_BOUND",
            },
            "upper_bound": {
                "quantity": ORDERED_QUANTITY,
                "source_class": SOURCE_PROCUREMENT_PO,
                "semantics": "CLOSED_UPPER_BOUND",
            },
        },
        "policy": {
            "key": policy.value,
            "display_name": (
                "Fixed contract"
                if policy is ProcurementPolicy.FIXED_TOLERANCE
                else "Per-unit contract"
            ),
            "display_rule": (
                f"Acceptable if quantity ≥ {ACCEPTANCE_THRESHOLD}"
                if policy is ProcurementPolicy.FIXED_TOLERANCE
                else f"{_display_inr(PER_UNIT_RATE_MINOR)} / unit"
            ),
            "display_note": (
                f"Fixed payment {_display_inr(FIXED_AMOUNT_MINOR)}"
                if policy is ProcurementPolicy.FIXED_TOLERANCE
                else f"Rate pinned at {_display_inr(PER_UNIT_RATE_MINOR)} per unit"
            ),
            "policy_id": bundle.manifest.policy_id,
            "version": bundle.manifest.human_version,
            "manifest_digest": bundle.digest().hex,
            "acceptance_minimum": ACCEPTANCE_THRESHOLD,
            "fixed_amount_minor": FIXED_AMOUNT_MINOR,
            "per_unit_rate_minor": PER_UNIT_RATE_MINOR,
            "currency": CURRENCY,
        },
        "alternatives": [
            _alternative(policy, quantity)
            for quantity in range(WAREHOUSE_QUANTITY, ORDERED_QUANTITY + 1)
        ],
        "result": {
            "outcome": outcome_class(outcome),
            "proposed_action": proposed_action,
            "additional_evidence": evidence,
            "exact_quantity_relevance": exact_quantity_relevance,
            "explanation": result_explanation,
            "reachable_action_count": (
                len(outcome.reachable.actions)
                if isinstance(outcome, Divergent) and isinstance(outcome.reachable, ExactReachable)
                else 1
            ),
        },
        "provenance": {
            "mode": "deterministic-local-replay",
            "description": "Derived from the pinned procurement bundle by the MUSTER kernel.",
            "basis": "No model or cloud execution is used for this procurement proof.",
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: procurement_case.py OUTPUT_DIRECTORY", file=sys.stderr)
        return 2
    output = Path(args[0])
    output.mkdir(parents=True, exist_ok=True)
    for policy, name in (
        (ProcurementPolicy.FIXED_TOLERANCE, "procurement-fixed.json"),
        (ProcurementPolicy.PER_UNIT, "procurement-per-unit.json"),
    ):
        (output / name).write_text(
            json.dumps(build_read_model(policy), indent=2) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
