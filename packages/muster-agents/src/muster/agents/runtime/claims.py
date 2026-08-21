"""The worker's account, interpreted into a claim that moves nothing.

This module is a deliberate near-duplicate of the acquisition runtime, and the
duplication is the design rather than a cost somebody failed to factor out.

An attestation and a claim are different wire variants with different digest
kinds and different signing bodies, and the property that matters most in this
distribution is that **the worker agent has no code path to the first one**.
A shared "emit" abstraction with a flag would make that property conditional on
a boolean; two separate pipelines make it structural.  So this file has its own
tools, its own validator and its own constructor, it never imports the receipt
builder, and the worker profile holds no source signer at all.

What a claim is, stated plainly because the demo depends on understanding it:

    Ravi says he was there.  MUSTER records that he said it, and records why it
    does not matter.  A ``Statement`` is not a ``Justification`` variant, no
    rule converts one, and the only trace it leaves at rebuild is a recorded
    non-effect naming the descriptor that refused it.  It cannot become a fact
    by being correct, by being confident, or by being the only thing anybody
    said.

**A claim's authenticity is deliberately unverified.**  The admission path
verifies attestation signatures and does not verify statements, because a
statement can never move a value and adding a signing body for one would widen
the frozen signing surface for no security gain.  The marker below says so out
loud rather than presenting an empty signature as a real one.

**A model cannot name what is claimed.**  Exactly as in the acquisition
runtime, the model names a *label* drawn from the brief and a value spelled as
the pinned sort requires.  The worker can say "I was there on Saturday" in any
words; what leaves is one declared proposition and one value inside its
declared domain, or nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from muster.agents.runtime.observations import (
    ObservationError,
    ObservationFailure,
    label_for,
    parse_value,
)
from muster.core.evidence.transcript import StatementRecord
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.scalars import Value, value_in_domain
from muster.core.values.sorts import Domain, Sort
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import Instant
from muster.core.wire.signature import Signature

#: What a statement carries where an attestation carries a signature.  The
#: identical marker the ratified case fixtures use, restated here rather than
#: imported because the composition layer that defines it is not something an
#: agent distribution may depend on -- and asserted equal to it by an
#: architecture test, so the two copies cannot drift apart in silence.
UNVERIFIED = Signature("UNSIGNED-LOCAL-DEVELOPMENT", b"")


@dataclass(frozen=True, slots=True)
class ClaimTarget:
    """One proposition a party may say something about.

    Deliberately *not* an ``AcquisitionTargetSpec``.  That type carries
    permitted source classes and a resource scope, which are authority
    coordinates -- and a claim has no authority coordinates at all, because a
    claim confers nothing.  Reusing it would put an authority-shaped field on
    the one artifact in the system whose whole point is that it has none.
    """

    proposition: SymbolRef
    value_sort: Sort
    domain: Domain
    #: What a person would call this, in the party's own terms.  Prose for a
    #: brief, read by nothing.
    description: str

    def __post_init__(self) -> None:
        if not self.description:
            raise InvariantViolation(f"a claim target describes itself: {self.proposition}")


@dataclass(frozen=True, slots=True)
class ClaimBrief:
    """What a party is being invited to say something about.

    ``claimant`` and ``role_in_case`` come from the officer-signed construction
    record by way of the caller, never from the party.  A claimant who could
    name their own role could claim to be the site.
    """

    tenant_id: str
    case_id: str
    claimant: str
    role_in_case: str
    signer_key_ref: str
    targets: tuple[ClaimTarget, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant", self.tenant_id),
            ("case", self.case_id),
            ("claimant", self.claimant),
            ("role", self.role_in_case),
            ("key", self.signer_key_ref),
        ):
            if not value:
                raise InvariantViolation(f"a claim brief names a {name}")
        if not self.targets:
            raise InvariantViolation("a claim brief names at least one target")

    def labelled(self) -> dict[str, ClaimTarget]:
        return {label_for(index): target for index, target in enumerate(self.targets)}


@dataclass(frozen=True, slots=True)
class CandidateClaim:
    """Exactly what the model said the party asserted.  Two untrusted strings."""

    label: str
    value: str


@dataclass(slots=True)
class ClaimRecorder:
    """One worker turn, as data.  Per invocation, and discarded with it."""

    candidates: list[CandidateClaim] = field(default_factory=list)
    declines: list[tuple[str, str]] = field(default_factory=list)


class ClaimDecline(Enum):
    """Why a party's account produced no claim."""

    NOTHING_ASSERTED = "nothing_asserted"
    UNCLEAR = "unclear"
    OUT_OF_SCOPE = "out_of_scope"


CLAIM_DECLINE_REASONS: tuple[str, ...] = tuple(member.value for member in ClaimDecline)


@dataclass(frozen=True, slots=True)
class ValidatedClaim:
    proposition: SymbolRef
    value: Value
    value_sort: Sort


def validate_claims(
    candidates: tuple[CandidateClaim, ...], *, targets: dict[str, ClaimTarget]
) -> Result[tuple[ValidatedClaim, ...], ObservationError]:
    """Every candidate claim, or the first refusal.

    The same gate the acquisition runtime applies, minus the relation: a party
    asserts a value, not a bound.  ``ExactValue`` is the only shape a claim has,
    which is why ``StatementRecord`` carries a value rather than a relation --
    and why a claim cannot express "at least four hours" even when that is what
    the party means.  It would not matter if it could: the claim is inert.
    """
    validated: list[ValidatedClaim] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.label in seen:
            return Err(
                ObservationError(
                    ObservationFailure.DUPLICATE_TARGET,
                    f"{candidate.label!r} was asserted more than once",
                )
            )
        seen.add(candidate.label)
        target = targets.get(candidate.label)
        if target is None:
            return Err(
                ObservationError(
                    ObservationFailure.UNKNOWN_TARGET,
                    f"{candidate.label!r} is not a target of this brief",
                )
            )
        parsed = parse_value(candidate.value, target.value_sort)
        if isinstance(parsed, Err):
            return Err(parsed.error)
        if not value_in_domain(parsed.value, target.domain):
            return Err(
                ObservationError(
                    ObservationFailure.VALUE_OUT_OF_DOMAIN,
                    f"{candidate.value} is outside {target.domain}",
                )
            )
        validated.append(ValidatedClaim(target.proposition, parsed.value, target.value_sort))
    return Ok(tuple(validated))


def build_statements(
    claims: tuple[ValidatedClaim, ...], *, brief: ClaimBrief, stated_at: Instant
) -> tuple[StatementRecord, ...]:
    """One statement per validated claim.  Total: nothing here can fail.

    ``statement_time`` is the agent's clock and never the model's.  A model
    asked when something was said will answer, and the answer would be the one
    field of a claim that a model had authored unchecked -- for a record whose
    only remaining job is to be provenance.

    ``supersedes`` is ``None``.  A party correcting an earlier claim is a real
    operation and it is the *party's* act, expressed by naming the entry being
    replaced; a model deciding that this claim replaces that one would be a
    model editing the transcript.
    """
    return tuple(
        StatementRecord(
            tenant_id=brief.tenant_id,
            case_id=brief.case_id,
            claimant=brief.claimant,
            role_in_case=brief.role_in_case,
            proposition=claim.proposition,
            asserted_value=claim.value,
            value_sort=claim.value_sort,
            measurement_procedure_id=None,
            statement_time=stated_at,
            supersedes=None,
            signer_key_ref=brief.signer_key_ref,
            signature=UNVERIFIED,
        )
        for claim in claims
    )
