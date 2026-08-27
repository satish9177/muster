"""The executor contract and a synthetic, idempotent sandbox payment adapter."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from muster.core.values.scalars import VEnum, VScaled
from muster.platform.gate.model import ActionIntent


@dataclass(frozen=True, slots=True)
class ExecutorDispatch:
    """The exact authorized value at the one imperative boundary."""

    intent: ActionIntent
    idempotency_key: str
    gate_id: str


@dataclass(frozen=True, slots=True)
class ExecutorInquiry:
    """A read-only question about the exact execution the Gate already dispatched."""

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


@dataclass(frozen=True, slots=True)
class ExecutedAs:
    external_reference: str


@dataclass(frozen=True, slots=True)
class NotExecuted:
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class StillUnknown:
    code: str
    detail: str


type ReconciliationAnswer = ExecutedAs | NotExecuted | StillUnknown


class ActionExecutor(Protocol):
    @property
    def executor_id(self) -> str: ...

    @property
    def trusted_gate_id(self) -> str: ...

    @property
    def transfers_real_funds(self) -> bool:
        """Whether a confirmation from this executor moved money that exists.

        Part of the contract rather than a label a demo prints, because the
        one thing an audience of a payment demo must be able to check is which
        answer this is -- and a projection that asserted ``false`` on its own
        authority would be asserting it about whichever executor happened to be
        composed, not about the one that ran.
        """
        ...

    def dispatch(self, request: ExecutorDispatch) -> ExecutorOutcome: ...


@runtime_checkable
class ReconcilableExecutor(Protocol):
    """An executor able to reconcile one prior execution without dispatching.

    The inquiry repeats the stored intent, its exact execution key and the Gate
    binding so only the executor named by that intent can answer.  ``inspect``
    must never create the requested effect.  An external protocol may atomically
    seal a never-attempted idempotency key with durable negative evidence so a
    later dispatch is refused; that is an observation/exclusion operation, not
    an execution or redispatch.

    ``runtime_checkable`` intentionally establishes only method presence; the
    Gate already checks the stored executor and Gate identities before making
    the observational call.
    """

    def inspect(self, inquiry: ExecutorInquiry) -> ReconciliationAnswer: ...


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
    def transfers_real_funds(self) -> bool:
        """Never.  There is no payment rail here and no credential for one."""
        return False

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
        return validate_sandbox_payment(
            request,
            executor_id=self.executor_id,
            trusted_gate_id=self.trusted_gate_id,
        )


def validate_sandbox_payment(
    request: ExecutorDispatch, *, executor_id: str, trusted_gate_id: str
) -> DefiniteFailure | None:
    """Validate a dispatch accepted by either simulated sandbox executor.

    This is validation for a simulated external system only.  It does not
    describe a payment rail, hold payment credentials, or move real funds.
    Keeping the validation here lets the in-memory and durable simulations
    enforce one exact boundary without making the Gate import an adapter.
    """
    intent = request.intent
    if request.gate_id != trusted_gate_id or intent.gate_id != trusted_gate_id:
        return DefiniteFailure(
            "UNTRUSTED_GATE",
            "the sandbox accepts dispatch only from its configured local Gate identity",
        )
    if intent.executor_id != executor_id:
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
