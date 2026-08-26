"""Who a deployed Gate will accept as its caller, and where that answer comes from.

The local Gate's ``GateCaller`` arrives from a trusted in-process application
boundary, which is honest for a demo API composed in one process and useless
in a cloud.  A deployed control plane has an identity, the runtime knows what
it is, and the deployment knows which one it provisioned -- so this module
turns those three facts into exactly one :class:`ExecutionGrant` and refuses
whenever they disagree.

**The principal is observed, never offered.**  Nothing here reads a request
field, a header, a browser value or a model's output.  The only input is a
:class:`RuntimePrincipal`, whose one implementation asks the Google metadata
server what identity *this* workload is running as -- a question answered on
the basis of where the request came from, so there is no value a caller can
supply that changes it.  A control plane that took its own principal from its
caller would be a control plane whose authority list decided nothing.

**Configuration is the other half, and it is exact.**  The deployment names
the principal it expects, the tenant, the action kind, the gate and the
executor.  There is no wildcard, no prefix match and no "any tenant" form to
misconfigure: the grant this module builds is a single frozen tuple of
equalities, and :class:`LocalExecutionAuthority` compares it by value.

**This is not Q-12 and cannot become it.**  Q-12 decides whether a *source
statement* may justify a consequence, against a signed authority snapshot this
module has never seen.  What is decided here is whether an authenticated
caller may ask this Gate and this executor to perform one action kind for one
tenant.  Neither implies the other, and collapsing them would mean a cloud IAM
identity could widen what a case is allowed to conclude.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from muster.core.results import Err, Ok, Result
from muster.platform.gate.authority import ExecutionGrant, GateCaller, LocalExecutionAuthority


class CloudPrincipalFailure(Enum):
    #: The runtime identity boundary did not answer.  Not on Google Cloud, or
    #: the metadata server is unreachable -- either way this process cannot say
    #: who it is, and a Gate that guessed would be a Gate with no caller.
    RUNTIME_IDENTITY_UNAVAILABLE = "RUNTIME_IDENTITY_UNAVAILABLE"
    #: It answered with something that is not a service-account identity.
    RUNTIME_IDENTITY_MALFORMED = "RUNTIME_IDENTITY_MALFORMED"
    #: It answered, and the answer is not the principal this deployment
    #: provisioned.  The commonest real cause is a job deployed under the wrong
    #: service account, which is exactly the case that must not execute.
    PRINCIPAL_MISMATCH = "PRINCIPAL_MISMATCH"
    #: The deployment's own execution-authority configuration is absent or
    #: incomplete.  Refused rather than defaulted: a default grant is a grant
    #: nobody decided.
    AUTHORITY_NOT_CONFIGURED = "AUTHORITY_NOT_CONFIGURED"


@dataclass(frozen=True, slots=True)
class CloudPrincipalError:
    failure: CloudPrincipalFailure
    detail: str


class RuntimePrincipal(Protocol):
    """The workload's own identity, as the runtime reports it."""

    def principal_id(self) -> Result[str, CloudPrincipalError]: ...


@dataclass(frozen=True, slots=True)
class CloudExecutionAuthorityConfiguration:
    """The single grant a deployment provisioned, stated field by field.

    Every field is required and none of them may be empty.  ``ExecutionGrant``
    already refuses an empty field; this refuses *before* one is constructed,
    so a deployment with a missing variable is told which decision it did not
    make rather than being handed a ``ValueError`` from two layers down.
    """

    expected_principal_id: str
    tenant_id: str
    action_kind: str
    gate_id: str
    executor_id: str

    def missing(self) -> tuple[str, ...]:
        return tuple(
            name
            for name, value in (
                ("expected_principal_id", self.expected_principal_id),
                ("tenant_id", self.tenant_id),
                ("action_kind", self.action_kind),
                ("gate_id", self.gate_id),
                ("executor_id", self.executor_id),
            )
            if not value.strip()
        )


@dataclass(frozen=True, slots=True)
class CloudGateAuthority:
    """One authenticated caller and the one grant that caller holds."""

    caller: GateCaller
    authority: LocalExecutionAuthority


def resolve_cloud_gate_authority(
    runtime: RuntimePrincipal, configuration: CloudExecutionAuthorityConfiguration
) -> Result[CloudGateAuthority, CloudPrincipalError]:
    """Bind the observed runtime identity to the configured grant, or refuse.

    The equality below is the whole check, and it is deliberately an equality
    rather than a membership test: a deployment that provisioned one service
    account has one principal, and a list here would be a place for a second
    one to be added without a reviewer noticing which.

    The returned caller carries the *observed* principal, not the configured
    one.  They are equal by the time this returns, and using the observed value
    keeps that true rather than assumed: if the comparison were ever relaxed,
    the grant would still be checked against what the runtime actually said.
    """
    absent = configuration.missing()
    if absent:
        return Err(
            CloudPrincipalError(
                CloudPrincipalFailure.AUTHORITY_NOT_CONFIGURED,
                ", ".join(absent),
            )
        )

    observed = runtime.principal_id()
    if isinstance(observed, Err):
        return observed
    principal = observed.value.strip()
    if not principal or "@" not in principal:
        return Err(
            CloudPrincipalError(
                CloudPrincipalFailure.RUNTIME_IDENTITY_MALFORMED,
                "the runtime identity is not a service-account identity",
            )
        )
    if principal != configuration.expected_principal_id.strip():
        #  The observed principal is named and the expected one is not.  Both
        #  are service-account identities rather than secrets, and naming the
        #  one that actually ran is what an operator needs; restating the
        #  configured value would only confirm what their own deployment says.
        return Err(
            CloudPrincipalError(
                CloudPrincipalFailure.PRINCIPAL_MISMATCH,
                f"this workload runs as {principal!r}, "
                "which is not the principal this Gate was provisioned for",
            )
        )

    caller = GateCaller(principal)
    return Ok(
        CloudGateAuthority(
            caller=caller,
            authority=LocalExecutionAuthority(
                (
                    ExecutionGrant(
                        principal_id=caller.principal_id,
                        tenant_id=configuration.tenant_id,
                        action_kind=configuration.action_kind,
                        gate_id=configuration.gate_id,
                        executor_id=configuration.executor_id,
                    ),
                )
            ),
        )
    )
