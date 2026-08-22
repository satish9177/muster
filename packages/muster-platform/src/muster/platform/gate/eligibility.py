"""Pure validation that turns the current authoritative proposal into an intent."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.analysis.outcomes import Invariant
from muster.core.results import Err, Ok, Result
from muster.platform.casework.commands import CaseReport
from muster.platform.gate.model import ActionIntent, ExecuteProposal
from muster.platform.orchestration.status import CaseStatus


class EligibilityFailure(Enum):
    NOT_PROPOSED = "NOT_PROPOSED"
    NOT_INVARIANT = "NOT_INVARIANT"
    PROPOSAL_NOT_CURRENT = "PROPOSAL_NOT_CURRENT"
    CERTIFICATE_NOT_REPRODUCED = "CERTIFICATE_NOT_REPRODUCED"
    CERTIFICATE_BINDING_MISMATCH = "CERTIFICATE_BINDING_MISMATCH"
    POLICY_BINDING_MISMATCH = "POLICY_BINDING_MISMATCH"
    ACTION_BINDING_MISMATCH = "ACTION_BINDING_MISMATCH"


@dataclass(frozen=True, slots=True)
class EligibilityError:
    failure: EligibilityFailure
    detail: str


def current_action_intent(
    report: CaseReport,
    request: ExecuteProposal,
    *,
    tenant_id: str,
    gate_id: str,
    executor_id: str,
) -> Result[ActionIntent, EligibilityError]:
    """Validate the current head and derive every imperative field server-side."""
    head = report.head
    if report.status is not CaseStatus.PROPOSED or report.analysis is None:
        return Err(
            EligibilityError(
                EligibilityFailure.NOT_PROPOSED,
                f"current case status is {report.status.value}",
            )
        )
    if head.inputs.tenant_id != tenant_id or head.case_id != request.case_id:
        return Err(
            EligibilityError(
                EligibilityFailure.PROPOSAL_NOT_CURRENT,
                "the loaded head names a different tenant or case",
            )
        )
    if (
        head.revision_digest != request.revision_digest
        or head.certificate_digest != request.certificate_digest
    ):
        return Err(
            EligibilityError(
                EligibilityFailure.PROPOSAL_NOT_CURRENT,
                "the requested revision/certificate is not the current case head",
            )
        )
    if not report.certificate_reproduced:
        return Err(
            EligibilityError(
                EligibilityFailure.CERTIFICATE_NOT_REPRODUCED,
                "the current deterministic replay does not reproduce the head certificate",
            )
        )

    analysis = report.analysis
    revision = analysis.revision
    certificate = analysis.certificate
    if (
        revision.digest() != head.revision_digest
        or certificate.digest() != head.certificate_digest
        or certificate.revision_semantic_digest != revision.digest()
        or (certificate.tenant_id, certificate.case_id) != (tenant_id, request.case_id)
    ):
        return Err(
            EligibilityError(
                EligibilityFailure.CERTIFICATE_BINDING_MISMATCH,
                "the current revision, certificate, and case head do not bind one result",
            )
        )
    if (
        revision.bundle_pin != head.inputs.bundle_manifest_digest
        or certificate.bundle_manifest_digest != head.inputs.bundle_manifest_digest
        or revision.authorization_context_digest != head.inputs.authorization_context_digest
    ):
        return Err(
            EligibilityError(
                EligibilityFailure.POLICY_BINDING_MISMATCH,
                "the result does not bind the head's policy and authority snapshots",
            )
        )

    outcome = analysis.kernel.outcome
    if not isinstance(outcome, Invariant):
        return Err(
            EligibilityError(
                EligibilityFailure.NOT_INVARIANT,
                "only an invariant consequential action may enter the Gate",
            )
        )
    action = outcome.action
    if (
        action.digest() != request.action_digest
        or action.action_schema_digest != analysis.projected.action_schema.digest()
    ):
        return Err(
            EligibilityError(
                EligibilityFailure.ACTION_BINDING_MISMATCH,
                "the requested action digest is not the current policy-projected action",
            )
        )

    return Ok(
        ActionIntent(
            tenant_id=tenant_id,
            case_id=request.case_id,
            revision_number=head.revision_number,
            revision_digest=revision.digest(),
            certificate_digest=certificate.digest(),
            kernel_result_digest=analysis.kernel.digest(),
            bundle_manifest_digest=head.inputs.bundle_manifest_digest,
            authorization_context_digest=head.inputs.authorization_context_digest,
            gate_id=gate_id,
            executor_id=executor_id,
            action_schema_digest=action.action_schema_digest,
            action_digest=action.digest(),
            action=action,
        )
    )
