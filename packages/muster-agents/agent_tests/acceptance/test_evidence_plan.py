"""The judge-facing plan is a projection of existing proof, not a second planner."""

from __future__ import annotations

import json
from pathlib import Path

from demo.evidence_plan import DEFAULT_TRACE, build_read_model

from muster.domains.workforce.bundle import QUALIFYING_MINUTES

REPOSITORY = Path(__file__).resolve().parents[4]
ARTIFACT = REPOSITORY / "packages/muster-ui/public/cases/ravi-evidence-plan.json"
COMPONENT = REPOSITORY / "packages/muster-ui/src/components/EvidencePlanner.tsx"


def test_generated_evidence_plan_is_current_and_consequence_sensitive() -> None:
    stored: object = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert stored == build_read_model()
    assert isinstance(stored, dict)
    required = stored["required_resolved"]
    assert isinstance(required, list)
    duration = next(
        item
        for item in required
        if item["proposition"]["predicate"] == "on_site_duration"
    )
    assert duration["label"] == "On-site duration — threshold only"
    assert str(QUALIFYING_MINUTES) in duration["requirement"]
    assert "508" in duration["established"]
    assert stored["not_required"][0]["label"] == "Exact minute count — never established"
    assert stored["not_required"][0]["unresolved"] is True
    assert stored["summary"]["reachable_action_count"] == 1
    assert stored["summary"]["outcome"] == "INVARIANT"
    assert stored["summary"]["exact_duration_status"] == "UNRESOLVED"
    assert stored["summary"]["action"]["fields"]["amount"]["display"] == "INR 5,100.00"


def test_evidence_plan_projects_the_stored_verified_execution() -> None:
    trace: object = json.loads(DEFAULT_TRACE.read_text(encoding="utf-8"))
    assert isinstance(trace, dict)
    model = build_read_model(trace)
    assert model["case"] == {
        "tenant_id": trace["tenant_id"],
        "case_id": trace["case_id"],
    }
    provenance = model["provenance"]
    assert isinstance(provenance, dict)
    assert provenance["label"] == "VERIFIED CLOUD EXECUTION"


def test_react_contains_no_ravi_policy_values_or_proposition_names() -> None:
    source = COMPONENT.read_text(encoding="utf-8")
    for forbidden in ("240", "508", "510000", "on_site_duration", "scheduled(RAVI"):
        assert forbidden not in source
