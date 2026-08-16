"""Interpreting admissibility descriptors over a transcript snapshot.

Rules run over a canonically ordered snapshot and return a typed, ordered set of
facts, constraints and **recorded non-effects**.  The non-effects are not
bookkeeping: "supplier says 100" producing no constraint has to leave a trace
saying *why*, because silence is indistinguishable from a rule that never ran.

Milestone A interprets three descriptors:

* ``AttestedRelation``   -- a validated relation from a permitted source class
  becomes a fact or a constraint, by the ordered lowering table.
* ``SelfServingClaimIsInert`` -- a party's claim becomes nothing at all, and
  says so.  This is the rule that stops "he says he was there" from moving a
  payment, and it fires even when the claim later turns out to be correct.
* ``StructuralDomainBound`` -- a declared domain restated as a constraint, for
  the variables that are still open.

A rejected attestation is a recorded non-effect, not a fatal error: evidence
that fails validation must have no effect, and the record must say that it
arrived and was refused.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.case.constraints import (
    AttestedRelationDeriv,
    Constraint,
    NonEffect,
    StructuralDeriv,
)
from muster.core.case.facts import AttestedBy, EstablishedFact
from muster.core.case.labels import constraint_label
from muster.core.evidence.relations import (
    LoweredConstraint,
    LoweredFact,
    LoweredNonEffect,
    PredicateInfo,
    lower_relation,
    validate_relation,
)
from muster.core.evidence.transcript import (
    Attestation,
    Statement,
    TranscriptEntry,
    VerificationReceipt,
)
from muster.core.expr.domains import domain_formula
from muster.core.expr.ir import Leaf
from muster.core.results import Err, Ok, Result
from muster.core.values.classification import EvidenceLayer
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import Instant
from muster.core.wire.codec import canonical_order, encode
from muster.core.wire.digests import Digest
from muster.policy.artifacts import AdmissibilityDescriptor, AdmissibilityDescriptors
from muster.policy.predicates import PredicateSchema

RULE_ATTESTED_RELATION = "AttestedRelation"
RULE_SELF_SERVING_CLAIM_IS_INERT = "SelfServingClaimIsInert"
RULE_STRUCTURAL_DOMAIN_BOUND = "StructuralDomainBound"

LABEL_PREFIX_ATTESTED = "C-ATT"
LABEL_PREFIX_DOMAIN = "C-DOM"

REASON_CLAIM_INERT = "ADVERSE_INTEREST_ABSENT"
REASON_RECEIPT_EXPIRED = "ReceiptNotValidAtAsOf"
REASON_PROCEDURE_NOT_ADMISSIBLE = "MeasurementProcedureNotAdmissible"

#  The rules this build interprets. A descriptor outside this set is refused
#  rather than skipped.
INTERPRETED_RULES: tuple[str, ...] = (
    RULE_ATTESTED_RELATION,
    RULE_SELF_SERVING_CLAIM_IS_INERT,
    RULE_STRUCTURAL_DOMAIN_BOUND,
)

#  A descriptor setting whose semantics this build does not implement must
#  not carry a meaning-bearing value: a declared field that no code reads is
#  how an authenticated setting comes to authorize nothing.
_EXPECTED_RULE_KIND = {
    RULE_ATTESTED_RELATION: "ATTESTED_RELATION",
    RULE_SELF_SERVING_CLAIM_IS_INERT: "NON_EFFECT",
    RULE_STRUCTURAL_DOMAIN_BOUND: "STRUCTURAL",
}
_EXPECTED_GROUPING_KEY = {
    RULE_ATTESTED_RELATION: "PROPOSITION",
    RULE_SELF_SERVING_CLAIM_IS_INERT: "CLAIMANT",
    RULE_STRUCTURAL_DOMAIN_BOUND: "PROPOSITION",
}


class DerivationFailure(Enum):
    MISSING_DESCRIPTOR = "MISSING_DESCRIPTOR"
    UNINTERPRETABLE_DESCRIPTOR = "UNINTERPRETABLE_DESCRIPTOR"
    UNDECLARED_PROPOSITION = "UNDECLARED_PROPOSITION"
    CROSS_TENANT_ARTIFACT = "CrossTenantArtifact"
    CASE_MISMATCH = "CASE_MISMATCH"
    PREDICATE_SCHEMA_MISMATCH = "PredicateSchemaMismatch"


@dataclass(frozen=True, slots=True)
class DerivationError:
    failure: DerivationFailure
    detail: str


@dataclass(frozen=True, slots=True)
class AdmissibilitySnapshot:
    """Everything the rules read, in canonical order.

    Ordered by entry digest rather than by arrival, so the same set of entries
    produces the same derivation regardless of the order they turned up in.

    ``as_of`` is here because receipt validity is decided against it and
    against nothing else -- never against a clock. That is what makes the
    derivation replayable: the same transcript at the same ``as_of`` admits
    the same receipts a year from now.
    """

    tenant_id: str
    case_id: str
    as_of: Instant
    declared: tuple[SymbolRef, ...]
    entries: tuple[TranscriptEntry, ...]


@dataclass(frozen=True, slots=True)
class DerivationOutcome:
    facts: tuple[EstablishedFact, ...]
    constraints: tuple[Constraint, ...]
    non_effects: tuple[NonEffect, ...]


def derive(
    snapshot: AdmissibilitySnapshot,
    descriptors: AdmissibilityDescriptors,
    schema: PredicateSchema,
    pinned_schema_digest: Digest,
) -> Result[DerivationOutcome, DerivationError]:
    """Run every descriptor Milestone A interprets, in a fixed order."""
    for rule_id in INTERPRETED_RULES:
        if descriptors.descriptor(rule_id) is None:
            #  The bundle owns the rules as data; a rule this module needs but
            #  the bundle does not declare means the two disagree about what
            #  admissibility is, and guessing is how that becomes invisible.
            return Err(DerivationError(DerivationFailure.MISSING_DESCRIPTOR, rule_id))

    for descriptor in descriptors.descriptors:
        if descriptor.rule_id not in INTERPRETED_RULES:
            #  The bundle declares a rule this build does not implement.
            #  Ignoring it would apply the pinned admissibility only in part
            #  while the certificate cites the manifest whole -- and a later
            #  build that does implement it would derive a different revision
            #  from the same inputs, breaking replay silently.
            return Err(
                DerivationError(DerivationFailure.UNINTERPRETABLE_DESCRIPTOR, descriptor.rule_id)
            )
        unsupported = _unsupported_settings(descriptor)
        if unsupported is not None:
            return Err(DerivationError(DerivationFailure.UNINTERPRETABLE_DESCRIPTOR, unsupported))

    declared = set(snapshot.declared)
    facts: list[EstablishedFact] = []
    constraints: list[Constraint] = []
    non_effects: list[NonEffect] = []

    for entry in snapshot.entries:
        match entry:
            case Attestation(receipt):
                produced = _attested_relation(
                    receipt=receipt,
                    snapshot=snapshot,
                    declared=declared,
                    schema=schema,
                    pinned_schema_digest=pinned_schema_digest,
                    descriptors=descriptors,
                )
                if isinstance(produced, Err):
                    return produced
                facts.extend(produced.value.facts)
                constraints.extend(produced.value.constraints)
                non_effects.extend(produced.value.non_effects)
            case Statement(record):
                if record.tenant_id != snapshot.tenant_id:
                    return Err(
                        DerivationError(DerivationFailure.CROSS_TENANT_ARTIFACT, record.tenant_id)
                    )
                #  A claim is not a justification, so there is nothing to weigh
                #  and nothing to record except that it moved nothing.
                version = _version(descriptors, RULE_SELF_SERVING_CLAIM_IS_INERT)
                non_effects.append(
                    NonEffect(
                        RULE_SELF_SERVING_CLAIM_IS_INERT,
                        version,
                        record.claimant,
                        REASON_CLAIM_INERT,
                    )
                )

    return Ok(
        DerivationOutcome(
            _ordered_facts(facts), _ordered_constraints(constraints), _deduplicate(non_effects)
        )
    )


def structural_domain_bounds(
    open_refs: tuple[SymbolRef, ...],
    schema: PredicateSchema,
    pinned_schema_digest: Digest,
) -> tuple[Constraint, ...]:
    """The declared domain of every still-open, non-normative variable.

    Two restrictions, both deliberate.

    *Open variables only*, and computed after the facts are settled: a domain
    constraint on a variable whose value is already established is vacuous, and
    prepare has already checked that value against the same domain.

    *Non-normative only*.  A normative variable's domain is already asserted
    from its declaration when the query is built, so a structural constraint on
    one would add nothing -- while making the layer-flow rule say "a normative
    variable may be mentioned by a policy entailment **or** by a structural
    bound".  The tighter rule is the one worth having: **the only constraint
    that may mention a normative variable is a byte-reproducible output of the
    pinned bundle's entailment compiler.**  Nothing is lost, and the check that
    enforces it needs no exceptions.
    """
    produced: list[Constraint] = []
    for ref in open_refs:
        spec = schema.spec_for(ref)
        if spec is None:  # pragma: no cover - prepare rejects this first
            continue
        if spec.layer is EvidenceLayer.NORMATIVE:
            continue
        produced.append(
            Constraint(
                constraint_label(LABEL_PREFIX_DOMAIN, ref),
                domain_formula(Leaf(ref), spec.value_sort, spec.domain),
                StructuralDeriv(pinned_schema_digest),
            )
        )
    return _ordered_constraints(produced)


def _attested_relation(
    *,
    receipt: VerificationReceipt,
    snapshot: AdmissibilitySnapshot,
    declared: set[SymbolRef],
    schema: PredicateSchema,
    pinned_schema_digest: Digest,
    descriptors: AdmissibilityDescriptors,
) -> Result[DerivationOutcome, DerivationError]:
    payload = receipt.payload
    version = _version(descriptors, RULE_ATTESTED_RELATION)

    #  Q-10 then Q-9: the tenant and the schema pin are meaningless to check
    #  after the content, and checking them first makes the rejection the same
    #  one every conforming implementation reports.
    if payload.tenant_id != snapshot.tenant_id:
        return Err(DerivationError(DerivationFailure.CROSS_TENANT_ARTIFACT, payload.tenant_id))
    if payload.case_id != snapshot.case_id:
        return Err(DerivationError(DerivationFailure.CASE_MISMATCH, payload.case_id))
    if payload.predicate_schema_digest != pinned_schema_digest:
        return Ok(
            _only_non_effect(
                version, payload.proposition, DerivationFailure.PREDICATE_SCHEMA_MISMATCH.value
            )
        )

    #  A receipt is admissible only inside the window it was signed for,
    #  judged against the revision's ``as_of`` and never against a clock. A
    #  receipt expiring at an instant is admitted at the microsecond before
    #  it and refused at it, and that decision replays identically forever.
    if not payload.validity.contains(snapshot.as_of):
        return Ok(_only_non_effect(version, payload.proposition, REASON_RECEIPT_EXPIRED))

    ref = payload.proposition
    if ref not in declared:
        return Err(DerivationError(DerivationFailure.UNDECLARED_PROPOSITION, str(ref)))

    spec = schema.spec_for(ref)
    if spec is None:
        return Err(DerivationError(DerivationFailure.PREDICATE_SCHEMA_MISMATCH, str(ref)))

    info = PredicateInfo(
        value_sort=spec.value_sort,
        domain=spec.domain,
        layer=spec.layer,
        permitted_source_classes=frozenset(spec.permitted_source_classes),
    )
    #  The descriptor names the measurement procedures the bundle admits and the
    #  predicate schema names the procedure a predicate is measured by. A
    #  declared list nothing compares against is not a control.
    admitted_procedures = descriptors.descriptor(RULE_ATTESTED_RELATION)
    if (
        admitted_procedures is not None
        and spec.measurement_class is not None
        and spec.measurement_class not in admitted_procedures.admissible_procedures
    ):
        return Ok(_only_non_effect(version, ref, REASON_PROCEDURE_NOT_ADMISSIBLE))

    validated = validate_relation(payload.relation, payload.value_sort, info, payload.source_class)
    if isinstance(validated, Err):
        return Ok(_only_non_effect(version, ref, validated.error.failure.value))

    lowered = lower_relation(payload.relation, ref, spec.domain)
    receipt_digest = receipt.digest()
    match lowered:
        case LoweredFact(value):
            return Ok(
                DerivationOutcome(
                    (EstablishedFact(ref, value, AttestedBy(receipt_digest)),), (), ()
                )
            )
        case LoweredConstraint(formula):
            return Ok(
                DerivationOutcome(
                    (),
                    (
                        Constraint(
                            #  One receipt per constraint, so the label carries
                            #  the receipt: two sources bounding one proposition
                            #  -- a lower bound and an upper bound -- must not
                            #  collide on a label the revision requires to be
                            #  unique. The entailment channel already does this
                            #  for rules; the attested channel did not.
                            constraint_label(
                                f"{LABEL_PREFIX_ATTESTED}-{receipt_digest.hex[:12]}", ref
                            ),
                            formula,
                            AttestedRelationDeriv(version, receipt_digest),
                        ),
                    ),
                    (),
                )
            )
        case LoweredNonEffect(reason):
            return Ok(_only_non_effect(version, ref, reason))


def _only_non_effect(version: int, ref: SymbolRef, reason: str) -> DerivationOutcome:
    return DerivationOutcome(
        (), (), (NonEffect(f"{RULE_ATTESTED_RELATION}:{reason}", version, str(ref), reason),)
    )


def _unsupported_settings(descriptor: AdmissibilityDescriptor) -> str | None:
    """A descriptor setting this build would otherwise silently ignore.

    ``rule_kind`` and ``grouping_key`` are checked for coherence with the rule
    they describe; ``max_temporal_gap`` must be zero, because contemporaneity
    grouping is not implemented here and a bundle may not declare a bound this
    build would not enforce.
    """
    if descriptor.rule_kind != _EXPECTED_RULE_KIND[descriptor.rule_id]:
        return f"{descriptor.rule_id}.rule_kind={descriptor.rule_kind}"
    if descriptor.grouping_key != _EXPECTED_GROUPING_KEY[descriptor.rule_id]:
        return f"{descriptor.rule_id}.grouping_key={descriptor.grouping_key}"
    if descriptor.max_temporal_gap != 0:
        return f"{descriptor.rule_id}.max_temporal_gap={descriptor.max_temporal_gap}"
    return None


def _version(descriptors: AdmissibilityDescriptors, rule_id: str) -> int:
    descriptor = descriptors.descriptor(rule_id)
    return descriptor.rule_version if descriptor is not None else 0


def _ordered_facts(facts: list[EstablishedFact]) -> tuple[EstablishedFact, ...]:
    return canonical_order(facts, lambda fact: fact.to_node())


def _ordered_constraints(constraints: list[Constraint]) -> tuple[Constraint, ...]:
    return canonical_order(constraints, lambda item: item.to_node())


def _deduplicate(non_effects: list[NonEffect]) -> tuple[NonEffect, ...]:
    """Identical non-effects are one non-effect; the collection is a set."""
    unique = {encode(item.to_node()): item for item in non_effects}
    return canonical_order(unique.values(), lambda item: item.to_node())
