"""Canonical action intent, exact binding, and the Gate state machine.

Nothing in this module performs I/O.  An ``ActionIntent`` is the exact value
the Gate authorizes and the executor receives; its key is also the durable
reservation and idempotency identity.  There is no intermediate value that
authorizes an abstract action kind and fills its consequential fields later.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from muster.core.actions import ConsequentialAction, read_consequential_action
from muster.core.results import InvariantViolation
from muster.core.values.times import Instant
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import NAtom, NInt, Node, NRec
from muster.core.wire.shape import read_atom, read_digest, read_int, read_rec

TAG_ACTION_INTENT = "ActionIntent/v1"

# This is an operational idempotency namespace, not a MUSTER semantic digest
# domain.  Keeping it outside ``muster/v1/`` avoids widening the frozen kernel
# digest namespace with a database reservation key.
_EXECUTION_KEY_PREFIX = b"muster-action-gate/idempotency/v1\x00"


@dataclass(frozen=True, slots=True)
class ExecutionKey:
    """The 32-octet reservation and executor idempotency identity."""

    octets: bytes

    def __post_init__(self) -> None:
        if len(self.octets) != 32:
            raise InvariantViolation(f"an execution key is 32 octets, found {len(self.octets)}")

    @property
    def hex(self) -> str:
        return self.octets.hex()

    def __str__(self) -> str:
        return self.hex


@dataclass(frozen=True, slots=True)
class ExecuteProposal:
    """The application-facing command: proposal identities, never payment fields."""

    case_id: str
    revision_digest: Digest
    certificate_digest: Digest
    action_digest: Digest

    def __post_init__(self) -> None:
        if not self.case_id:
            raise InvariantViolation("an execution request names a case")


@dataclass(frozen=True, slots=True)
class ExecutionLookup:
    """The durable identity of one already-authorized execution, and nothing more.

    This is what an *idempotency read* is allowed to present.  It is
    deliberately not an :class:`ExecuteProposal`: a proposal is a request to
    validate a case and act, while a lookup is a request to be told what a
    previous authorization already durably did.  Neither carries a recipient,
    an amount, a currency or an action kind -- those are read back from the
    stored canonical ``ActionIntent``, which stays the authority for what was
    actually reserved.

    **The identity is the execution key, and that choice is the whole point.**
    An :class:`ExecutionKey` is ``sha256`` over the canonical octets of the
    exact ``ActionIntent`` that was authorized, and it is the durable primary
    key of the row those octets live in.  So it names *one historical
    execution* rather than "whatever the case currently proposes": the row
    stays addressable by it for as long as the row exists, however far the case
    head has since advanced.  An identity derived from the current head would
    have made a confirmed payment un-lookupable the moment somebody appended
    one more transcript entry -- and "the retry has to happen before the case
    moves" is not a property a duplicate-prevention story can be built on.

    It is also not a value anybody can usefully invent.  A caller who does not
    already hold the octets cannot compute the key, and one who holds them has
    the intent anyway; guessing it is guessing a 256-bit digest.  What the key
    does *not* do is authorize: the read still authenticates the caller, still
    demands an exact grant for the stored action kind, and still refuses a row
    another Gate authorized.

    ``expected_case_id`` is an optional caller-visible narrowing, not part of
    the identity.  A caller that knows which case it is asking about can say
    so, and a key belonging to another case is then refused rather than
    answered -- which turns a configuration mix-up between two deployed cases
    into a refusal instead of a confident report about the wrong one.  Omitting
    it asks the narrower question "what did this execution do", which is
    already exact.
    """

    execution_key: ExecutionKey
    expected_case_id: str | None = None

    def __post_init__(self) -> None:
        if self.expected_case_id is not None and not self.expected_case_id:
            raise InvariantViolation(
                "an execution lookup either names a case or does not constrain one"
            )

    def mismatches(self, intent: ActionIntent) -> tuple[str, ...]:
        """Name every field a stored intent disagrees with.

        Applied to the row a store returns, so that "the query matched" and
        "the stored canonical value agrees" stay two checks rather than one.  A
        store answers from its primary key; this answers from the octets that
        key is supposed to be the hash of.
        """
        return tuple(
            name
            for name, offered, stored in (
                ("execution_key", self.execution_key, intent.execution_key()),
                (
                    "case_id",
                    self.expected_case_id,
                    None if self.expected_case_id is None else intent.case_id,
                ),
            )
            if offered != stored
        )


@dataclass(frozen=True, slots=True)
class ActionIntent:
    """Every fact authorization is bound to and dispatch acts upon."""

    tenant_id: str
    case_id: str
    revision_number: int
    revision_digest: Digest
    certificate_digest: Digest
    kernel_result_digest: Digest
    bundle_manifest_digest: Digest
    authorization_context_digest: Digest
    gate_id: str
    executor_id: str
    action_schema_digest: Digest
    action_digest: Digest
    action: ConsequentialAction

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("case_id", self.case_id),
            ("gate_id", self.gate_id),
            ("executor_id", self.executor_id),
        ):
            if not value:
                raise InvariantViolation(f"an action intent names {name}")
        if self.revision_number < 1:
            raise InvariantViolation(
                f"an executable proposal has a positive revision number: {self.revision_number}"
            )
        if self.action.action_schema_digest != self.action_schema_digest:
            raise InvariantViolation("the action and intent name different action schemas")
        if self.action.digest() != self.action_digest:
            raise InvariantViolation("the action digest is not the digest of the bound action")

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACTION_INTENT,
            (
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                NInt(self.revision_number),
                self.revision_digest.to_node(),
                self.certificate_digest.to_node(),
                self.kernel_result_digest.to_node(),
                self.bundle_manifest_digest.to_node(),
                self.authorization_context_digest.to_node(),
                NAtom(self.gate_id),
                NAtom(self.executor_id),
                self.action_schema_digest.to_node(),
                self.action_digest.to_node(),
                self.action.to_node(),
            ),
        )

    def canonical_octets(self) -> bytes:
        return encode(self.to_node())

    def execution_key(self) -> ExecutionKey:
        return ExecutionKey(
            hashlib.sha256(_EXECUTION_KEY_PREFIX + self.canonical_octets()).digest()
        )


def read_action_intent(node: Node) -> ActionIntent:
    """Read the exact canonical value stored beside a reservation."""
    (
        tenant,
        case,
        revision_number,
        revision,
        certificate,
        kernel_result,
        bundle,
        authorization,
        gate,
        executor,
        action_schema,
        action_digest,
        action,
    ) = read_rec(node, TAG_ACTION_INTENT, 13)
    return ActionIntent(
        tenant_id=read_atom(tenant),
        case_id=read_atom(case),
        revision_number=read_int(revision_number),
        revision_digest=read_digest(revision),
        certificate_digest=read_digest(certificate),
        kernel_result_digest=read_digest(kernel_result),
        bundle_manifest_digest=read_digest(bundle),
        authorization_context_digest=read_digest(authorization),
        gate_id=read_atom(gate),
        executor_id=read_atom(executor),
        action_schema_digest=read_digest(action_schema),
        action_digest=read_digest(action_digest),
        action=read_consequential_action(action),
    )


def binding_mismatches(expected: ActionIntent, offered: ActionIntent) -> tuple[str, ...]:
    """Name every exact binding an offered intent substituted.

    The public command never accepts an intent, recipient, amount, or currency;
    it accepts only proposal digests.  This comparison remains the pure guard at
    every internal boundary that does exchange a complete intent, including a
    durable row read back before dispatch.
    """
    mismatches: list[str] = []
    scalar_fields = (
        "tenant_id",
        "case_id",
        "revision_number",
        "revision_digest",
        "certificate_digest",
        "kernel_result_digest",
        "bundle_manifest_digest",
        "authorization_context_digest",
        "gate_id",
        "executor_id",
        "action_schema_digest",
        "action_digest",
    )
    for name in scalar_fields:
        if getattr(expected, name) != getattr(offered, name):
            mismatches.append(name)

    if expected.action.kind != offered.action.kind:
        mismatches.append("action.kind")
    expected_fields = {field.name: field.value for field in expected.action.consequential_fields}
    offered_fields = {field.name: field.value for field in offered.action.consequential_fields}
    for name in sorted(set(expected_fields) | set(offered_fields)):
        if expected_fields.get(name) != offered_fields.get(name):
            mismatches.append(f"action.fields.{name}")
    return tuple(mismatches)


class ExecutionState(Enum):
    RESERVED = "RESERVED"
    DISPATCHED = "DISPATCHED"
    CONFIRMED = "CONFIRMED"
    FAILED = "FAILED"
    UNCERTAIN = "UNCERTAIN"


class Finality(Enum):
    DEFINITELY_NOT_EXECUTED = "DEFINITELY_NOT_EXECUTED"
    DEFINITELY_EXECUTED = "DEFINITELY_EXECUTED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


def finality(state: ExecutionState) -> Finality:
    match state:
        case ExecutionState.RESERVED | ExecutionState.FAILED:
            return Finality.DEFINITELY_NOT_EXECUTED
        case ExecutionState.CONFIRMED:
            return Finality.DEFINITELY_EXECUTED
        case ExecutionState.DISPATCHED | ExecutionState.UNCERTAIN:
            return Finality.OUTCOME_UNKNOWN


def transition_is_legal(before: ExecutionState, after: ExecutionState) -> bool:
    return (before, after) in {
        (ExecutionState.RESERVED, ExecutionState.DISPATCHED),
        (ExecutionState.DISPATCHED, ExecutionState.CONFIRMED),
        (ExecutionState.DISPATCHED, ExecutionState.FAILED),
        (ExecutionState.DISPATCHED, ExecutionState.UNCERTAIN),
    }


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    """The durable lifecycle and its safe execution proof."""

    intent: ActionIntent
    state: ExecutionState
    requested_by: str
    reserved_at: Instant
    dispatched_at: Instant | None = None
    finalized_at: Instant | None = None
    external_reference: str | None = None
    outcome_code: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if not self.requested_by:
            raise InvariantViolation("an execution record names its requesting principal")
        if self.state is ExecutionState.RESERVED:
            if any(
                value is not None
                for value in (
                    self.dispatched_at,
                    self.finalized_at,
                    self.external_reference,
                    self.outcome_code,
                    self.detail,
                )
            ):
                raise InvariantViolation("a reservation carries no dispatch or outcome")
        elif self.state is ExecutionState.DISPATCHED:
            if self.dispatched_at is None or any(
                value is not None
                for value in (
                    self.finalized_at,
                    self.external_reference,
                    self.outcome_code,
                    self.detail,
                )
            ):
                raise InvariantViolation("a dispatched execution has no final outcome")
        else:
            if self.dispatched_at is None or self.finalized_at is None or not self.outcome_code:
                raise InvariantViolation("a final execution state carries dispatch and outcome")
            if self.state is ExecutionState.CONFIRMED:
                if not self.external_reference:
                    raise InvariantViolation("a confirmed execution carries an external reference")
            elif self.external_reference is not None:
                raise InvariantViolation(
                    "an unconfirmed execution carries no transaction reference"
                )

        if self.dispatched_at is not None and self.dispatched_at < self.reserved_at:
            raise InvariantViolation("dispatch cannot precede reservation")
        if self.finalized_at is not None and (
            self.dispatched_at is None or self.finalized_at < self.dispatched_at
        ):
            raise InvariantViolation("finalization cannot precede dispatch")

    @property
    def execution_key(self) -> ExecutionKey:
        return self.intent.execution_key()

    @property
    def finality(self) -> Finality:
        return finality(self.state)


class GateReadState(Enum):
    AUTHORIZED = "AUTHORIZED"
    EXECUTED = "EXECUTED"
    UNCERTAIN = "UNCERTAIN"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class GateReadModel:
    execution_id: str
    state: GateReadState
    durable_state: ExecutionState
    finality: Finality
    external_reference: str | None


def read_model(record: ExecutionRecord) -> GateReadModel:
    state = {
        ExecutionState.RESERVED: GateReadState.AUTHORIZED,
        ExecutionState.DISPATCHED: GateReadState.UNCERTAIN,
        ExecutionState.CONFIRMED: GateReadState.EXECUTED,
        ExecutionState.FAILED: GateReadState.FAILED,
        ExecutionState.UNCERTAIN: GateReadState.UNCERTAIN,
    }[record.state]
    return GateReadModel(
        execution_id=record.execution_key.hex,
        state=state,
        durable_state=record.state,
        finality=record.finality,
        external_reference=record.external_reference,
    )
