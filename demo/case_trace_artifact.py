"""Sanitized replay artifact projected from one completed hero run.

This module is intentionally a projection boundary.  It reads the structured
values the control plane already produced and emits a small, versioned record;
it does not parse narration and it does not re-decide any policy question.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from muster.core.analysis.outcomes import Invariant, outcome_class
from muster.core.authority.grants import AuthorityGrant
from muster.core.evidence.relations import (
    AcquisitionRelation,
    ClosedLowerBound,
    ClosedUpperBound,
    EnumSubset,
    ExactValue,
)
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled
from muster.core.values.symbols import SymbolRef
from muster.platform.dispatch.acquire import Answered

if TYPE_CHECKING:
    from demo.cloud_hero import CloudHeroRun

    from support.ravi import RaviCase


ARTIFACT_SCHEMA_VERSION = "muster.case-trace/v1"
ARTIFACT_RECORD_PREFIX = "MUSTER_CASE_TRACE_V1="

VERIFIED_CLOUD_EXECUTION: Literal["verified-cloud-execution"] = "verified-cloud-execution"
DETERMINISTIC_LOCAL_REPLAY: Literal["deterministic-local-replay"] = (
    "deterministic-local-replay"
)
CURATED_EXAMPLE: Literal["curated-example"] = "curated-example"

type ProvenanceSource = Literal[
    "verified-cloud-execution", "deterministic-local-replay", "curated-example"
]


@dataclass(frozen=True, slots=True)
class ArtifactContext:
    source: ProvenanceSource
    project_id: str
    job_name: str
    cloud_run_region: str
    model_name: str
    model_location: str
    control_plane_id: str
    model_interpretation: bool


@dataclass(frozen=True, slots=True)
class CaseTraceArtifact:
    """A typed wrapper whose document is the sole serialized representation."""

    schema_version: str
    case_id: str
    tenant_id: str
    provenance: dict[str, object]
    execution: dict[str, object]
    policy: dict[str, object]
    claim: dict[str, object]
    plan: dict[str, object]
    security_boundary: dict[str, object]
    attestations: tuple[dict[str, object], ...]
    result: dict[str, object]

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "tenant_id": self.tenant_id,
            "provenance": self.provenance,
            "execution": self.execution,
            "policy": self.policy,
            "claim": self.claim,
            "plan": self.plan,
            "security_boundary": self.security_boundary,
            "attestations": list(self.attestations),
            "result": self.result,
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.to_document(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )

    def machine_record(self) -> str:
        encoded = base64.b64encode(self.canonical_json().encode("utf-8")).decode("ascii")
        return f"{ARTIFACT_RECORD_PREFIX}{encoded}"


def cloud_artifact_context_from_environment(
    source: ProvenanceSource = VERIFIED_CLOUD_EXECUTION,
) -> ArtifactContext:
    """Read only safe execution labels; secret-bearing configuration is absent."""

    def required(name: str) -> str:
        value = os.environ.get(name, "").strip()
        if not value:
            raise ValueError(f"case trace configuration is missing {name}")
        return value

    return ArtifactContext(
        source=source,
        project_id=required("MUSTER_TRACE_PROJECT_ID"),
        job_name=required("MUSTER_TRACE_JOB_NAME"),
        cloud_run_region=required("MUSTER_TRACE_CLOUD_RUN_REGION"),
        model_name=required("MUSTER_TRACE_MODEL"),
        model_location=required("MUSTER_TRACE_MODEL_LOCATION"),
        control_plane_id=required("MUSTER_TRACE_CONTROL_PLANE_ID"),
        model_interpretation=True,
    )


def build_case_trace_artifact(
    run: CloudHeroRun, case: RaviCase, context: ArtifactContext
) -> CaseTraceArtifact:
    """Project one successful run, refusing to manufacture missing proof."""

    report = run.report
    if report is None or report.analysis is None:
        raise ValueError("a case trace requires a completed analysis")
    analysis = report.analysis
    invariant = analysis.kernel.outcome
    if not isinstance(invariant, Invariant):
        raise ValueError("a case trace requires an invariant outcome")
    if run.raw_access.outcome.value != "DENIED" or run.raw_access.status != 403:
        raise ValueError("a verified case trace requires the observed IAM 403")
    if report.status.value != "PROPOSED":
        raise ValueError("a verified case trace requires a proposed case")
    if len(run.claims) != 1:
        raise ValueError("the worked trace requires exactly one worker claim")

    claim = run.claims[0]
    requirements = tuple(
        {
            "proposition": _proposition(target.proposition),
            "permitted_source_classes": list(target.permitted_source_classes),
        }
        for target in run.solicited.targets
    )

    attestations: list[dict[str, object]] = []
    for acquisition_report in run.reports:
        for exchange in acquisition_report.exchanges:
            if not isinstance(exchange.result, Answered):
                continue
            for admitted in exchange.result.admitted:
                payload = admitted.payload
                target = exchange.assignment.target_for(payload.proposition)
                if target is None:  # pragma: no cover - admission already enforces this
                    raise ValueError(f"admitted unassigned proposition {payload.proposition}")
                grant = _grant_for(case, payload.signer_key_ref, payload.source_class)
                attestations.append(
                    {
                        "agent_id": exchange.assignment.agent_id,
                        "source_class": payload.source_class,
                        "source_id": grant.principal_id,
                        "proposition": _proposition(payload.proposition),
                        "relation": _relation(payload.relation),
                        "signer_key_ref": payload.signer_key_ref,
                        "entry_digest": admitted.entry_digest.hex,
                        "authorization": {"check": "Q-12", "status": "PASSED"},
                        "disclosure_class": target.layer.value,
                        "model_interpretation": context.model_interpretation,
                    }
                )

    if not attestations:
        raise ValueError("a case trace requires admitted attestations")

    action = invariant.action
    return CaseTraceArtifact(
        schema_version=ARTIFACT_SCHEMA_VERSION,
        case_id=case.case_id,
        tenant_id=case.tenant_id,
        provenance={"source": context.source, "captured": False},
        execution={
            "project_id": context.project_id,
            "job_name": context.job_name,
            "execution_name": None,
            "executed_at": None,
            "completed_at": None,
            "cloud_run_region": context.cloud_run_region,
            "model": {"name": context.model_name, "location": context.model_location},
        },
        policy={
            "policy_id": case.policy_id,
            "bundle_digest": analysis.revision.bundle_pin.hex,
        },
        claim={
            "claimant": claim.claimant,
            "role": claim.role_in_case,
            "proposition": _proposition(claim.proposition),
            "asserted_value": _value(claim.asserted_value),
            "authority": "CLAIM_ONLY",
        },
        plan={
            "request_id": run.solicited.digest().hex,
            "requirements": list(requirements),
        },
        security_boundary={
            "actor": context.control_plane_id,
            "operation": "storage.objects.get",
            "target_class": "site-evidence",
            "result": run.raw_access.outcome.value,
            "http_status": run.raw_access.status,
            "enforcement": "GCP IAM",
        },
        attestations=tuple(attestations),
        result={
            "status": report.status.value,
            "outcome": outcome_class(invariant),
            "rebuild": {
                "processor": analysis.kernel.determinism_class.value,
                "certificate_reproduced": report.certificate_reproduced,
            },
            "action": {
                "kind": action.kind,
                "fields": [
                    {"name": field.name, "value": _value(field.value)}
                    for field in action.consequential_fields
                ],
                "execution": {"status": "NOT_EXECUTED"},
            },
            "unresolved": [
                _proposition(reference) for reference in analysis.projected.unresolved()
            ],
        },
    )


def _grant_for(case: RaviCase, key_ref: str, source_class: str) -> AuthorityGrant:
    matches = tuple(
        grant
        for grant in case.authority_snapshot.grants
        if grant.key_ref == key_ref and grant.source_class == source_class
    )
    if len(matches) != 1:
        raise ValueError(f"expected one authority grant for {key_ref}/{source_class}")
    return matches[0]


def _proposition(reference: SymbolRef) -> dict[str, object]:
    return {"predicate": reference.predicate_id, "args": list(reference.args)}


def _value(value: Value) -> dict[str, object]:
    match value:
        case VBool(flag):
            return {"type": "bool", "value": flag}
        case VInt(number):
            return {"type": "int", "value": number}
        case VScaled(unit_tag, scale, minor):
            return {"type": "scaled", "unit": unit_tag, "scale": scale, "minor": minor}
        case VEnum(enum_id, member):
            return {"type": "enum", "enum_id": enum_id, "value": member}


def _relation(relation: AcquisitionRelation) -> dict[str, object]:
    match relation:
        case ExactValue(value):
            return {"kind": "EXACT", "value": _value(value)}
        case ClosedLowerBound(bound):
            return {"kind": "CLOSED_LOWER_BOUND", "value": _value(bound)}
        case ClosedUpperBound(bound):
            return {"kind": "CLOSED_UPPER_BOUND", "value": _value(bound)}
        case EnumSubset(allowed):
            return {"kind": "ENUM_SUBSET", "values": [_value(value) for value in allowed]}
        case _:
            raise ValueError(f"unsupported acquisition relation {type(relation).__name__}")
