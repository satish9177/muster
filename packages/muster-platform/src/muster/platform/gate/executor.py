"""The executor contract and a synthetic, idempotent sandbox payment adapter."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from muster.core.values.scalars import VEnum, VScaled
from muster.platform.gate.model import ActionIntent


@dataclass(frozen=True, slots=True)
class ExecutorDispatch:
    """The exact authorized value at the one imperative boundary."""

    intent: ActionIntent
    idempotency_key: str
    gate_id: str


@dataclass(frozen=True, slots=True)
class Confirmed:
    external_reference: str
    duplicate: bool = False


@dataclass(frozen=True, slots=True)
class DefiniteFailure:
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class UnknownOutcome:
    code: str
    detail: str


type ExecutorOutcome = Confirmed | DefiniteFailure | UnknownOutcome


class ActionExecutor(Protocol):
    @property
    def executor_id(self) -> str: ...

    @property
    def trusted_gate_id(self) -> str: ...

    def dispatch(self, request: ExecutorDispatch) -> ExecutorOutcome: ...


class SandboxMode(Enum):
    SUCCESS = "SUCCESS"
    DEFINITE_PRE_DISPATCH_FAILURE = "DEFINITE_PRE_DISPATCH_FAILURE"
    UNKNOWN_AFTER_DISPATCH = "UNKNOWN_AFTER_DISPATCH"
    CONFIRMED_DUPLICATE = "CONFIRMED_DUPLICATE"


class SandboxPaymentExecutor:
    """No payment rail: only deterministic synthetic transaction references."""

    def __init__(
        self,
        *,
        executor_id: str = "sandbox-payment/v1",
        trusted_gate_id: str = "local-action-gate/v1",
        mode: SandboxMode = SandboxMode.SUCCESS,
    ) -> None:
        self._executor_id = executor_id
        self._trusted_gate_id = trusted_gate_id
        self.mode = mode
        self._confirmed: dict[str, str] = {}
        self._dispatch_count = 0
        self._execution_count = 0
        # This protects the sandbox adapter's synthetic idempotency dictionary.
        # Gate correctness rests on the durable reservation, never on this lock.
        self._lock = threading.Lock()

    @property
    def executor_id(self) -> str:
        return self._executor_id

    @property
    def trusted_gate_id(self) -> str:
        return self._trusted_gate_id

    @property
    def dispatch_count(self) -> int:
        return self._dispatch_count

    @property
    def execution_count(self) -> int:
        return self._execution_count

    def dispatch(self, request: ExecutorDispatch) -> ExecutorOutcome:
        with self._lock:
            self._dispatch_count += 1
            refused = self._validate(request)
            if refused is not None:
                return refused

            existing = self._confirmed.get(request.idempotency_key)
            if existing is not None:
                return Confirmed(existing, duplicate=True)

            reference = f"sandbox-pay-{request.idempotency_key[:24]}"
            match self.mode:
                case SandboxMode.DEFINITE_PRE_DISPATCH_FAILURE:
                    return DefiniteFailure(
                        "SANDBOX_PRE_DISPATCH_FAILURE",
                        "the sandbox rejected the request before any synthetic execution",
                    )
                case SandboxMode.UNKNOWN_AFTER_DISPATCH:
                    return UnknownOutcome(
                        "SANDBOX_TIMEOUT_AFTER_DISPATCH",
                        "the sandbox outcome is intentionally unknown",
                    )
                case SandboxMode.CONFIRMED_DUPLICATE:
                    self._confirmed[request.idempotency_key] = reference
                    return Confirmed(reference, duplicate=True)
                case SandboxMode.SUCCESS:
                    self._confirmed[request.idempotency_key] = reference
                    self._execution_count += 1
                    return Confirmed(reference)

    def _validate(self, request: ExecutorDispatch) -> DefiniteFailure | None:
        intent = request.intent
        if request.gate_id != self.trusted_gate_id or intent.gate_id != self.trusted_gate_id:
            return DefiniteFailure(
                "UNTRUSTED_GATE",
                "the sandbox accepts dispatch only from its configured local Gate identity",
            )
        if intent.executor_id != self.executor_id:
            return DefiniteFailure("WRONG_EXECUTOR", "the intent names another executor")
        if request.idempotency_key != intent.execution_key().hex:
            return DefiniteFailure(
                "IDEMPOTENCY_MISMATCH",
                "the executor key is not the key of the exact authorized intent",
            )
        if intent.action.kind != "PAY":
            return DefiniteFailure("UNSUPPORTED_ACTION", "the sandbox supports PAY only")

        fields = {field.name: field.value for field in intent.action.consequential_fields}
        recipient = fields.get("recipient")
        amount = fields.get("amount")
        if not isinstance(recipient, VEnum) or not recipient.member:
            return DefiniteFailure("INVALID_RECIPIENT", "PAY requires an exact enum recipient")
        if not isinstance(amount, VScaled) or amount.minor < 0:
            return DefiniteFailure("INVALID_AMOUNT", "PAY requires a non-negative scaled amount")
        return None
