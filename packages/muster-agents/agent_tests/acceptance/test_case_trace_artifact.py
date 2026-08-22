"""The UI artifact is a projection of the worked run, not a second demo."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from demo.case_trace_artifact import (
    ARTIFACT_SCHEMA_VERSION,
    ArtifactContext,
    CaseTraceArtifact,
    build_case_trace_artifact,
)
from demo.cloud_hero import CloudHeroRun, RawAccess, RawAttempt, cloud_case
from infra.scripts.capture_case_trace import (
    SCHEMA_VERSION as CAPTURE_SCHEMA_VERSION,
)
from infra.scripts.capture_case_trace import (
    CaptureError,
    capture_case_trace,
)

from agent_tests.support import cloud

REPOSITORY = Path(__file__).resolve().parents[4]
TYPESCRIPT_CONSUMER = REPOSITORY / "packages/muster-ui/src/data/caseTraceArtifact.ts"
STAGE_90 = REPOSITORY / "infra/scripts/90-hero-job.sh"
CONTROL_PLANE_DOCKERFILE = REPOSITORY / "infra/docker/control-plane.Dockerfile"


@pytest.fixture
def artifact(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> CaseTraceArtifact:
    observed = replace(
        cloud_run,
        raw_access=RawAttempt(
            RawAccess.DENIED,
            "gs://private-site-source/B-4471-NORTH-TURNSTILE-2.txt",
            403,
        ),
    )
    return build_case_trace_artifact(
        observed,
        cloud_case(cloud.configuration(tenant_id, case_id)),
        ArtifactContext(
            source="verified-cloud-execution",
            project_id="muster-project",
            job_name="muster-control-plane-hero",
            cloud_run_region="asia-south1",
            model_name="gemini-3.7-flash",
            model_location="global",
            control_plane_id="muster-control-plane",
            model_interpretation=True,
        ),
    )


def test_structured_run_maps_to_the_narrow_case_trace(artifact: CaseTraceArtifact) -> None:
    document = artifact.to_document()
    plan = document["plan"]
    boundary = document["security_boundary"]
    attestations = document["attestations"]
    result = document["result"]
    assert isinstance(plan, dict)
    assert isinstance(boundary, dict)
    assert isinstance(attestations, list)
    assert isinstance(result, dict)

    requirements = plan["requirements"]
    assert isinstance(requirements, list)
    assert {item["proposition"]["predicate"] for item in requirements} == {
        "scheduled",
        "present_on_site",
        "on_site_duration",
    }
    assert boundary["result"] == "DENIED"
    assert boundary["http_status"] == 403
    assert {item["agent_id"] for item in attestations} == {
        "agent-hr-payroll",
        "agent-site-a",
    }
    assert all(
        item["authorization"] == {"check": "Q-12", "status": "PASSED"}
        for item in attestations
    )
    assert result["status"] == "PROPOSED"
    assert result["outcome"] == "INVARIANT"
    assert result["action"] == {
        "kind": "PAY",
        "fields": [
            {
                "name": "recipient",
                "value": {"type": "enum", "enum_id": "party_id", "value": "RAVI"},
            },
            {
                "name": "amount",
                "value": {"type": "scaled", "unit": "INR", "scale": 2, "minor": 510000},
            },
        ],
        "execution": {"status": "NOT_EXECUTED"},
    }
    assert {item["predicate"] for item in result["unresolved"]} == {
        "on_site_duration",
        "shift_payable_under_policy",
    }


def test_private_source_material_and_secret_bearing_fields_never_enter_artifact(
    artifact: CaseTraceArtifact,
) -> None:
    serialized = artifact.canonical_json()
    for forbidden in (
        "B-4471",
        "NORTH-TURNSTILE-2",
        "raw_object",
        "raw_evidence",
        "nonce",
        "signature",
        "private_key",
        "access_token",
        "credentials",
        "prompt",
    ):
        assert forbidden not in serialized


def test_serialization_is_deterministic_and_machine_framed(artifact: CaseTraceArtifact) -> None:
    assert artifact.canonical_json() == artifact.canonical_json()
    assert artifact.machine_record().startswith("MUSTER_CASE_TRACE_V1=")
    assert "\n" not in artifact.machine_record()


def test_capture_binds_the_exact_execution_and_preserves_observed_status(
    artifact: CaseTraceArtifact,
) -> None:
    captured = capture_case_trace(
        f"unrelated log line\n{artifact.machine_record()}\njob complete\n",
        project_id="muster-project",
        job_name="muster-control-plane-hero",
        cloud_run_region="asia-south1",
        execution_name="muster-control-plane-hero-abcde",
        executed_at="2026-08-22T10:00:00Z",
        completed_at="2026-08-22T10:01:00Z",
    )
    assert captured["provenance"] == {
        "source": "verified-cloud-execution",
        "captured": True,
    }
    execution = captured["execution"]
    boundary = captured["security_boundary"]
    assert isinstance(execution, dict)
    assert isinstance(boundary, dict)
    assert execution["execution_name"] == "muster-control-plane-hero-abcde"
    assert execution["executed_at"] == "2026-08-22T10:00:00Z"
    assert boundary["http_status"] == 403


def test_capture_fails_closed_on_ambiguous_or_private_records(
    artifact: CaseTraceArtifact,
) -> None:
    arguments = {
        "project_id": "muster-project",
        "job_name": "muster-control-plane-hero",
        "cloud_run_region": "asia-south1",
        "execution_name": "muster-control-plane-hero-abcde",
        "executed_at": "2026-08-22T10:00:00Z",
        "completed_at": "2026-08-22T10:01:00Z",
    }
    with pytest.raises(CaptureError, match="expected one"):
        capture_case_trace(
            f"{artifact.machine_record()}\n{artifact.machine_record()}\n", **arguments
        )

    encoded = CaseTraceArtifact(
        schema_version=artifact.schema_version,
        case_id=artifact.case_id,
        tenant_id=artifact.tenant_id,
        provenance=artifact.provenance,
        execution=artifact.execution,
        policy=artifact.policy,
        claim=artifact.claim,
        plan=artifact.plan,
        security_boundary=artifact.security_boundary,
        attestations=artifact.attestations,
        result={**artifact.result, "raw_object": "gs://private/source"},
    ).machine_record()
    with pytest.raises(CaptureError, match="forbidden"):
        capture_case_trace(encoded, **arguments)
    assert json.loads(artifact.canonical_json()) == artifact.to_document()


def test_schema_version_agrees_across_producer_capture_and_consumer() -> None:
    consumer = TYPESCRIPT_CONSUMER.read_text(encoding="utf-8")
    assert ARTIFACT_SCHEMA_VERSION == CAPTURE_SCHEMA_VERSION
    assert f'CASE_TRACE_SCHEMA_VERSION = "{ARTIFACT_SCHEMA_VERSION}"' in consumer


def test_stage_90_captures_the_machine_record_for_its_exact_execution() -> None:
    stage = STAGE_90.read_text(encoding="utf-8")
    image = CONTROL_PLANE_DOCKERFILE.read_text(encoding="utf-8")
    assert 'muster::execution_output "${HERO_JOB}" "${execution}" > "${trace_logs}"' in stage
    assert 'artifact_output="${EVIDENCE_DIR}/case-traces/${execution}.json"' in stage
    assert '--execution "${execution}"' in stage
    assert 'public/cases/ravi-cloud-execution.json' in stage
    assert 'COPY demo/case_trace_artifact.py /app/demo/case_trace_artifact.py' in image
