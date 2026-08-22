"""A narrow, explicit local authority to invoke the Action Gate.

This is not source authority and it is not a cloud IAM assertion.  A trusted
local application boundary supplies the authenticated principal, and this
closed set decides whether that exact principal may ask this exact gate and
sandbox executor to perform one action kind for one tenant.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.results import InvariantViolation


@dataclass(frozen=True, slots=True)
class GateCaller:
    principal_id: str

    def __post_init__(self) -> None:
        if not self.principal_id:
            raise InvariantViolation("a Gate caller has an authenticated principal id")


@dataclass(frozen=True, slots=True)
class ExecutionGrant:
    principal_id: str
    tenant_id: str
    action_kind: str
    gate_id: str
    executor_id: str

    def __post_init__(self) -> None:
        if not all(
            (
                self.principal_id,
                self.tenant_id,
                self.action_kind,
                self.gate_id,
                self.executor_id,
            )
        ):
            raise InvariantViolation("an execution grant contains no wildcard or empty field")


@dataclass(frozen=True, slots=True)
class LocalExecutionAuthority:
    grants: tuple[ExecutionGrant, ...]

    def may_invoke(
        self, caller: GateCaller, *, tenant_id: str, gate_id: str, executor_id: str
    ) -> bool:
        """Fail before loading a case when no exact local grant can apply."""
        return any(
            grant.principal_id == caller.principal_id
            and grant.tenant_id == tenant_id
            and grant.gate_id == gate_id
            and grant.executor_id == executor_id
            for grant in self.grants
        )

    def permits(
        self,
        caller: GateCaller,
        *,
        tenant_id: str,
        action_kind: str,
        gate_id: str,
        executor_id: str,
    ) -> bool:
        return ExecutionGrant(
            principal_id=caller.principal_id,
            tenant_id=tenant_id,
            action_kind=action_kind,
            gate_id=gate_id,
            executor_id=executor_id,
        ) in self.grants
