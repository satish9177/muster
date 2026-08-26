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
from demo.cloud_hero import (
    CLOUD_EXECUTOR_ID,
    CLOUD_GATE_ID,
    CloudGateExecution,
    CloudHeroRun,
    RawAccess,
    RawAttempt,
    cloud_case,
)
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


#  ---- the U2 half: an artifact that carries an execution -------------------


EXECUTION_KEY = "7c" * 32
ACTION_DIGEST = "1d" * 32
#: A durable instant, in the same units the execution row stores.  Written out
#: as one value with the others derived from it so the ordering the record
#: enforces -- reserve, then dispatch, then finalize -- is visible here rather
#: than being three numbers a reader has to compare.
RESERVED_AT = 1_755_849_600


def _execution(**overrides: object) -> CloudGateExecution:
    """A lifecycle in exactly the shape the deployed Gate produces one."""
    fields: dict[str, object] = {
        "state": "CONFIRMED",
        "execution_key": EXECUTION_KEY,
        "external_reference": f"sandbox-pay-{EXECUTION_KEY[:24]}",
        "outcome_code": "CONFIRMED",
        "real_funds": False,
        "gate_id": CLOUD_GATE_ID,
        "executor_id": CLOUD_EXECUTOR_ID,
        "principal_id": "muster-control-plane@muster-project.iam.gserviceaccount.com",
        "reserved_at": RESERVED_AT,
        "dispatched_at": RESERVED_AT + 1,
        "finalized_at": RESERVED_AT + 2,
        "action_digest": ACTION_DIGEST,
        "dispatch_count": 1,
        "execution_count": 1,
    }
    fields.update(overrides)
    return CloudGateExecution(**fields)  # type: ignore[arg-type]


@pytest.fixture
def executed_artifact(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> CaseTraceArtifact:
    return _built(cloud_run, tenant_id, case_id, execution=_execution())


def _built(
    cloud_run: CloudHeroRun,
    tenant_id: str,
    case_id: str,
    *,
    execution: CloudGateExecution | None,
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
        execution=execution,
    )


def test_an_analysis_only_run_still_publishes_the_unexecuted_shape(
    artifact: CaseTraceArtifact,
) -> None:
    """The U1 artifact is unchanged, field for field.

    A milestone that quietly widened the published record would make every
    already-captured trace a different document than the one that was reviewed.
    """
    result = artifact.to_document()["result"]
    assert isinstance(result, dict)
    action = result["action"]
    assert isinstance(action, dict)
    assert action["execution"] == {"status": "NOT_EXECUTED"}


def test_a_gate_run_publishes_exactly_the_fields_it_produced(
    executed_artifact: CaseTraceArtifact,
) -> None:
    """Eight, and no ninth.

    Every one of them is a value the producer *read* -- five off the durable
    lifecycle and three instants off the same row.  There is still no per-step
    event here: that a CONFIRMED row passed through RESERVED and DISPATCHED is
    a property of the state machine, and a viewer may draw it as one, but this
    artifact carries only what the database recorded.  A trace that invented a
    timeline would be the demo asserting a sequence nothing observed.
    """
    result = executed_artifact.to_document()["result"]
    assert isinstance(result, dict)
    action = result["action"]
    assert isinstance(action, dict)
    assert action["execution"] == {
        "status": "CONFIRMED",
        "execution_key": EXECUTION_KEY,
        "external_reference": f"sandbox-pay-{EXECUTION_KEY[:24]}",
        "outcome_code": "CONFIRMED",
        "real_funds": False,
        "reserved_at": RESERVED_AT,
        "dispatched_at": RESERVED_AT + 1,
        "finalized_at": RESERVED_AT + 2,
    }
    #  The analysis is still a proposal.  Executing does not move the case.
    assert result["status"] == "PROPOSED"
    assert result["outcome"] == "INVARIANT"


def test_the_producer_refuses_to_publish_a_real_funds_execution(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    """The one field in this artifact nobody downstream could check for itself."""
    with pytest.raises(ValueError, match="real-funds"):
        _built(cloud_run, tenant_id, case_id, execution=_execution(real_funds=True))


def test_the_producer_refuses_to_publish_a_reservation(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    """A reservation that never dispatched is unfinished work, not an outcome.

    ``ActionGate.execute`` cannot return one today.  The refusal is here so
    that the artifact staying free of mid-flight lifecycles does not rest on
    that remaining true after a later change to the service.
    """
    with pytest.raises(ValueError, match="RESERVED"):
        _built(
            cloud_run,
            tenant_id,
            case_id,
            execution=_execution(state="RESERVED", external_reference=None),
        )


def test_the_producer_refuses_a_settlement_claim_with_no_receipt_behind_it(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    with pytest.raises(ValueError, match="external reference"):
        _built(cloud_run, tenant_id, case_id, execution=_execution(external_reference=None))


def test_the_producer_refuses_a_reference_on_an_unconfirmed_execution(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    with pytest.raises(ValueError, match="no external reference"):
        _built(cloud_run, tenant_id, case_id, execution=_execution(state="UNCERTAIN"))


def test_the_producer_refuses_an_execution_missing_a_lifecycle_instant(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    """A published state implies instants, and absent ones are not filled in.

    Every state the artifact publishes is at or past the dispatch boundary, so
    a dispatch instant is not optional; the three final states carry a
    finalization instant as well.  Refused rather than emitted as ``null``,
    because a null in a field the screen presents as a recorded moment is a
    question the viewer would have to answer by guessing.
    """
    with pytest.raises(ValueError, match="dispatch instant"):
        _built(cloud_run, tenant_id, case_id, execution=_execution(dispatched_at=None))
    with pytest.raises(ValueError, match="finalization instant"):
        _built(cloud_run, tenant_id, case_id, execution=_execution(finalized_at=None))


def _dispatched(**overrides: object) -> CloudGateExecution:
    """A truthful DISPATCHED row: crossed the boundary, no answer back.

    This is what the durable record looks like between ``executor.dispatch``
    and the outcome that finalizes it -- three nulls, and every one of them
    load-bearing.  There is no receipt, because nothing settled; no outcome
    code, because no outcome exists; and no finalization instant, because the
    lifecycle has not finalized.  The producer, the capture and the viewer all
    have to be able to publish this shape, or the only way to show a dispatched
    execution is to make something up about it.
    """
    fields: dict[str, object] = {
        "state": "DISPATCHED",
        "external_reference": None,
        "outcome_code": None,
        "finalized_at": None,
    }
    fields.update(overrides)
    return _execution(**fields)


def test_a_dispatched_run_publishes_the_shape_a_dispatched_row_actually_has(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    """The same eight fields, three of them null, none of them invented."""
    published = _built(cloud_run, tenant_id, case_id, execution=_dispatched())
    result = published.to_document()["result"]
    assert isinstance(result, dict)
    action = result["action"]
    assert isinstance(action, dict)
    assert action["execution"] == {
        "status": "DISPATCHED",
        "execution_key": EXECUTION_KEY,
        "external_reference": None,
        "outcome_code": None,
        "real_funds": False,
        "reserved_at": RESERVED_AT,
        "dispatched_at": RESERVED_AT + 1,
        "finalized_at": None,
    }


def test_the_producer_refuses_a_dispatched_execution_that_claims_finality(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    """DISPATCHED means the outcome is not known, and a finalization says otherwise."""
    with pytest.raises(ValueError, match="not been finalized"):
        _built(
            cloud_run,
            tenant_id,
            case_id,
            execution=_dispatched(finalized_at=RESERVED_AT + 2),
        )


def test_the_producer_refuses_an_outcome_code_on_a_dispatched_execution(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    """An outcome code is a result, and a dispatched execution has no result yet.

    ``"DISPATCHED"`` is used deliberately as the mutation: it is the code a
    producer reaches for when the shape demands one and none exists, and it is
    a lifecycle state wearing a result's name.
    """
    with pytest.raises(ValueError, match="no outcome yet"):
        _built(cloud_run, tenant_id, case_id, execution=_dispatched(outcome_code="DISPATCHED"))


def test_the_producer_refuses_a_finalized_execution_with_no_outcome_code(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    """Relaxing the rule for DISPATCHED does not relax it for the states that finalized."""
    for state in ("CONFIRMED", "FAILED", "UNCERTAIN"):
        reference = f"sandbox-pay-{EXECUTION_KEY[:24]}" if state == "CONFIRMED" else None
        with pytest.raises(ValueError, match="an outcome code"):
            _built(
                cloud_run,
                tenant_id,
                case_id,
                execution=_execution(
                    state=state, external_reference=reference, outcome_code=None
                ),
            )


def test_the_capture_binds_a_gate_execution_the_same_way_it_binds_the_run(
    executed_artifact: CaseTraceArtifact,
) -> None:
    captured = capture_case_trace(
        f"{executed_artifact.machine_record()}\n",
        project_id="muster-project",
        job_name="muster-control-plane-hero",
        cloud_run_region="asia-south1",
        execution_name="muster-control-plane-hero-abcde",
        executed_at="2026-08-22T10:00:00Z",
        completed_at="2026-08-22T10:01:00Z",
    )
    result = captured["result"]
    assert isinstance(result, dict)
    action = result["action"]
    assert isinstance(action, dict)
    execution = action["execution"]
    assert isinstance(execution, dict)
    assert execution["status"] == "CONFIRMED"
    assert execution["real_funds"] is False
    assert execution["external_reference"] == f"sandbox-pay-{EXECUTION_KEY[:24]}"


def _captured(artifact: CaseTraceArtifact) -> dict[str, object]:
    captured = capture_case_trace(
        f"{artifact.machine_record()}\n",
        project_id="muster-project",
        job_name="muster-control-plane-hero",
        cloud_run_region="asia-south1",
        execution_name="muster-control-plane-hero-abcde",
        executed_at="2026-08-22T10:00:00Z",
        completed_at="2026-08-22T10:01:00Z",
    )
    result = captured["result"]
    assert isinstance(result, dict)
    action = result["action"]
    assert isinstance(action, dict)
    execution = action["execution"]
    assert isinstance(execution, dict)
    return execution


def test_the_capture_publishes_a_truthful_dispatched_execution(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    """The shape a real dispatched row has survives the second gate too.

    The capture is an independent check on what reaches the browser, so the
    row the Gate can actually be sitting on mid-flight has to pass it -- with
    its three nulls intact rather than filled in on the way out.
    """
    execution = _captured(_built(cloud_run, tenant_id, case_id, execution=_dispatched()))

    assert execution == {
        "status": "DISPATCHED",
        "execution_key": EXECUTION_KEY,
        "external_reference": None,
        "outcome_code": None,
        "real_funds": False,
        "reserved_at": RESERVED_AT,
        "dispatched_at": RESERVED_AT + 1,
        "finalized_at": None,
    }


def test_the_capture_refuses_an_outcome_code_on_a_dispatched_execution(
    cloud_run: CloudHeroRun, tenant_id: str, case_id: str
) -> None:
    """Manufactured at the producer or added afterwards, it is refused here too."""
    dispatched = _built(cloud_run, tenant_id, case_id, execution=_dispatched())
    result = dict(dispatched.result)
    action = dict(result["action"])  # type: ignore[call-overload]
    action["execution"] = {**action["execution"], "outcome_code": "DISPATCHED"}
    result["action"] = action

    with pytest.raises(CaptureError, match="no outcome yet"):
        _captured(replace(dispatched, result=result))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"real_funds": True}, "real-funds"),
        ({"real_funds": 0}, "real-funds"),
        ({"real_funds": None}, "real-funds"),
        ({"status": "RESERVED"}, "unknown state"),
        ({"status": "SETTLED"}, "unknown state"),
        ({"execution_key": EXECUTION_KEY.upper()}, "canonical execution key"),
        ({"execution_key": "7c" * 31}, "canonical execution key"),
        ({"outcome_code": ""}, "outcome code"),
        ({"outcome_code": None}, "outcome code"),
        ({"external_reference": None}, "external reference"),
        ({"gate_id": CLOUD_GATE_ID}, "unexpected fields"),
    ],
)
def test_the_capture_refuses_an_unsafe_execution_claim(
    executed_artifact: CaseTraceArtifact, mutation: dict[str, object], message: str
) -> None:
    """The capture is a second, independent gate on what gets published.

    The producer already refuses most of these, and that is the point of
    checking them again here: the file this writes is the one a browser loads,
    and it must not depend on the producer having been the only thing between a
    log line and a published settlement claim.
    """
    result = dict(executed_artifact.result)
    action = dict(result["action"])  # type: ignore[call-overload]
    action["execution"] = {**action["execution"], **mutation}
    result["action"] = action
    encoded = replace(executed_artifact, result=result).machine_record()

    with pytest.raises(CaptureError, match=message):
        capture_case_trace(
            encoded,
            project_id="muster-project",
            job_name="muster-control-plane-hero",
            cloud_run_region="asia-south1",
            execution_name="muster-control-plane-hero-abcde",
            executed_at="2026-08-22T10:00:00Z",
            completed_at="2026-08-22T10:01:00Z",
        )


def test_the_capture_refuses_an_unexecuted_action_carrying_execution_fields(
    artifact: CaseTraceArtifact,
) -> None:
    """"NOT_EXECUTED plus an execution key" is a claim with two answers."""
    result = dict(artifact.result)
    action = dict(result["action"])  # type: ignore[call-overload]
    action["execution"] = {"status": "NOT_EXECUTED", "execution_key": EXECUTION_KEY}
    result["action"] = action
    encoded = replace(artifact, result=result).machine_record()

    with pytest.raises(CaptureError, match="no execution fields"):
        capture_case_trace(
            encoded,
            project_id="muster-project",
            job_name="muster-control-plane-hero",
            cloud_run_region="asia-south1",
            execution_name="muster-control-plane-hero-abcde",
            executed_at="2026-08-22T10:00:00Z",
            completed_at="2026-08-22T10:01:00Z",
        )


def test_the_consumer_and_the_capture_agree_on_the_execution_states() -> None:
    """One vocabulary across the producer, the capture and the viewer.

    RESERVED is absent from all three, deliberately: a reservation that never
    crossed the executor boundary is unfinished work, not a published outcome.
    """
    from infra.scripts.capture_case_trace import _EXECUTED_STATES

    consumer = TYPESCRIPT_CONSUMER.read_text(encoding="utf-8")
    read_model = (REPOSITORY / "packages/muster-ui/src/data/readModel.ts").read_text(
        encoding="utf-8"
    )
    assert {"CONFIRMED", "DISPATCHED", "FAILED", "UNCERTAIN"} == _EXECUTED_STATES
    for state in sorted(_EXECUTED_STATES):
        assert f'"{state}"' in read_model, state
    assert '"RESERVED"' not in read_model
    assert "ArtifactActionExecution" in consumer
