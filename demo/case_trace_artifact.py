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
    from demo.cloud_hero import CloudGateExecution, CloudHeroRun

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
    run: CloudHeroRun,
    case: RaviCase,
    context: ArtifactContext,
    *,
    execution: CloudGateExecution | None = None,
) -> CaseTraceArtifact:
    """Project one successful run, refusing to manufacture missing proof.

    ``execution`` is the deployed Action Gate's durable lifecycle, and it is
    ``None`` for every analysis-only run -- which keeps the artifact an
    analysis-only deployment emits byte-identical in shape to the U1 one.  When
    it is present, what is projected are the fields the Gate actually produced
    and nothing that would have to be invented.

    That now includes the three lifecycle instants, and they are read rather
    than derived.  ``reserved_at`` is always a stored value; ``dispatched_at``
    and ``finalized_at`` are ``null`` for exactly the states whose rows have
    not reached them.  There is still no per-step *event* here: that a CONFIRMED
    row passed through RESERVED and DISPATCHED is a property of the state
    machine, and a viewer may draw it as one -- but the moments below are
    measurements, and the artifact keeps the two apart by carrying only the
    measurements.
    """

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
                "execution": _execution(execution),
            },
            "unresolved": [
                _proposition(reference) for reference in analysis.projected.unresolved()
            ],
        },
    )


#: The durable states a *published* lifecycle may be in.  RESERVED is absent:
#: a reservation that never crossed the executor boundary is unfinished work,
#: and an artifact carrying one would publish a payment mid-flight.  The Gate
#: cannot return a RESERVED record from ``execute`` today; this is here so that
#: it staying unpublishable does not depend on that remaining true.
_PUBLISHABLE_STATES = frozenset({"CONFIRMED", "DISPATCHED", "FAILED", "UNCERTAIN"})


def _execution(execution: CloudGateExecution | None) -> dict[str, object]:
    """The Gate's durable lifecycle, or the honest absence of one.

    Refusals rather than assumptions, one per way this projection could publish
    something it cannot support.  ``real_funds: false`` printed for an executor
    that said otherwise would be the one field in this artifact nobody
    downstream could check; a CONFIRMED state with no external reference would
    be a settlement claim with no receipt behind it; an unconfirmed state
    carrying one would be the reverse; and a state outside the published
    vocabulary would be a lifecycle the capture and the viewer have no reading
    for.  The durable row already refuses most of these -- ``ExecutionRecord``
    and the table's own CHECK constraint both say so -- and this says it again
    at the boundary where the value stops being a database row and becomes a
    published fact.
    """
    if execution is None:
        return {"status": "NOT_EXECUTED"}
    if execution.real_funds:
        raise ValueError("a published case trace never carries a real-funds execution")
    if execution.state not in _PUBLISHABLE_STATES:
        raise ValueError(f"a case trace does not publish a {execution.state} execution")
    if execution.state == "CONFIRMED" and not execution.external_reference:
        raise ValueError("a confirmed execution carries an external reference")
    if execution.state != "CONFIRMED" and execution.external_reference:
        raise ValueError("an unconfirmed execution carries no external reference")
    #  An outcome code is a *result*, and DISPATCHED is precisely the state in
    #  which no result exists yet: the executor boundary has been crossed and
    #  the executor has not answered.  A truthful dispatched row therefore
    #  carries a null outcome code, a null external reference and a null
    #  finalized-at.  Requiring a code from every published state made that row
    #  unpublishable, which is an invitation to manufacture one -- and
    #  ``outcome_code: "DISPATCHED"`` would be a lifecycle state wearing a
    #  result's name, which is the single worst thing this projection could
    #  publish about an action that may still settle.
    if execution.state == "DISPATCHED":
        if execution.outcome_code is not None:
            raise ValueError("a dispatched execution has no outcome yet")
    elif not execution.outcome_code:
        raise ValueError("a finalized execution carries an outcome code")
    #  The instants a published state must already carry.  Every state in
    #  ``_PUBLISHABLE_STATES`` is at or past DISPATCHED, so a dispatched-at is
    #  not optional here, and the three final states carry a finalized-at as
    #  well.  ``ExecutionRecord`` refuses rows that disagree; this refuses to
    #  publish one that somehow did, rather than emitting a null a viewer would
    #  have to interpret.
    if execution.dispatched_at is None:
        raise ValueError(f"a {execution.state} execution carries a dispatch instant")
    if execution.state != "DISPATCHED" and execution.finalized_at is None:
        raise ValueError(f"a {execution.state} execution carries a finalization instant")
    if execution.state == "DISPATCHED" and execution.finalized_at is not None:
        raise ValueError("a dispatched execution has not been finalized")
    return {
        "status": execution.state,
        "execution_key": execution.execution_key,
        "external_reference": execution.external_reference,
        "outcome_code": execution.outcome_code,
        "real_funds": execution.real_funds,
        #  Measurements, not a reconstructed timeline.  See the docstring above.
        "reserved_at": execution.reserved_at,
        "dispatched_at": execution.dispatched_at,
        "finalized_at": execution.finalized_at,
    }


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
