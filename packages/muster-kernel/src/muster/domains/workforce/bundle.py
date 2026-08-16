"""The synthetic workforce bundle.

Everything here is **synthetic policy data**: the qualifying duration, the daily
rate, the source classes and the action schema are declared by this bundle and
are not claims about any real payroll practice.

The predicate that matters is the one that is *not* here.  MUSTER has no
``worked`` predicate, and this bundle does not define one: no policy authority
is the authority on whether a person worked, since remote work, off-badge work
and reassignment refute any enumeration.  What a policy authority *is* the
authority on is what its own policy pays for, so the ratified conclusion is

    shift_payable_under_policy(W, D)
        <->  scheduled(W, D)
         and present_on_site(W, D)
         and on_site_duration(W, D) >= 240 minutes

and that biconditional is a stipulative definition inside a signed bundle --
the only kind of biconditional a ratifier can honestly sign.  ``240`` is a
declared policy constant, not a discovered fact.

The bundle is a value: adding a domain means adding one of these, not changing
anything under ``core``, ``policy``, ``solve``, ``hinge`` or ``evidence``.
"""

from __future__ import annotations

from muster.core.actions import (
    ActionKindSpec,
    ActionSchema,
    Consequentiality,
    FieldSpec,
)
from muster.core.evidence.transcript import Signature
from muster.core.expr.ir import Binary, BinaryOp, Ite, Leaf, LitInt, NAry, NAryOp, freevars
from muster.core.expr.terms import Term, literal, term_digest
from muster.core.results import Err, InvariantViolation
from muster.core.values.classification import AcquisitionClass, EvidenceLayer
from muster.core.values.scalars import VEnum, VScaled
from muster.core.values.sorts import (
    BoolDomain,
    BoolSort,
    EnumDomain,
    EnumSort,
    IntRange,
    IntSort,
    ScaledRange,
    ScaledSort,
)
from muster.core.values.symbols import SymbolRef, SymbolRefTemplate
from muster.core.values.times import HalfOpenInterval
from muster.core.wire.codec import canonical_order
from muster.policy.artifacts import (
    AdmissibilityDescriptor,
    AdmissibilityDescriptors,
    DisclosureEntry,
    DisclosurePolicy,
    RatificationRecord,
    RatificationSet,
)
from muster.policy.entailment import DefinitionRule, EntailmentRules
from muster.policy.manifest import (
    SUPPORTED_INTERPRETER_VERSION,
    SUPPORTED_IR_SCHEMA_VERSION,
    BundleManifest,
    LoadedBundle,
    SignedManifest,
    load_bundle,
)
from muster.policy.predicates import PredicateSchema, PredicateSpec
from muster.policy.program import ActionTerm, DecisionProgram, FieldTerm

POLICY_ID = "workforce-demo"
HUMAN_VERSION = "1.2.0"

#  Synthetic policy constants.
QUALIFYING_MINUTES = 240
MINUTES_IN_A_DAY = 1440
CURRENCY = "INR"
CURRENCY_SCALE = 2
MAX_DAILY_RATE_MINOR = 10_000_00
MAX_PAYMENT_MINOR = 100_000_00

WORKING_DAYS: tuple[str, ...] = ("MON", "TUE", "WED", "THU", "FRI", "SAT")

PREDICATE_DAILY_RATE = "daily_rate"
PREDICATE_SCHEDULED = "scheduled"
PREDICATE_PRESENT = "present_on_site"
PREDICATE_DURATION = "on_site_duration"
PREDICATE_PAYABLE = "shift_payable_under_policy"

SOURCE_PAYROLL = "HR_PAYROLL_SYSTEM"
SOURCE_SITE_ACCESS = "SITE_ACCESS_CONTROL"

ACTION_SCHEMA_ID = "workforce-actions"
ACTION_PAY = "PAY"
FIELD_RECIPIENT = "recipient"
FIELD_AMOUNT = "amount"
FIELD_BASIS = "basis_code"
ENUM_PARTY = "party_id"
ENUM_BASIS = "payment_basis"
BASIS_WEEKLY_SHIFT_TOTAL = "WEEKLY_SHIFT_TOTAL"

RULE_SHIFT_PAYABLE = "R-SHIFT-PAYABLE-1"
RATIFICATION_SHIFT_PAYABLE = "RAT-SHIFT-PAYABLE-1"

BINDER_WORKER = "W"
BINDER_DAY = "D"

#  Milestone A holds no keyring and verifies nothing.  The algorithm name says
#  so out loud, so a carried signature cannot be mistaken for a verified one.
UNSIGNED = Signature("UNSIGNED-LOCAL-DEVELOPMENT", b"")

EFFECTIVE_FROM = 1_700_000_000_000_000
RATIFIED_AT = 1_700_000_000_000_000
RATIFIED_BY = "policy-authority-1"
SIGNER_KEY = "key-policy-authority-1"


def money(minor: int) -> VScaled:
    return VScaled(CURRENCY, CURRENCY_SCALE, minor)


def daily_rate(worker: str) -> SymbolRef:
    return SymbolRef(PREDICATE_DAILY_RATE, (worker,))


def scheduled(worker: str, day: str) -> SymbolRef:
    return SymbolRef(PREDICATE_SCHEDULED, (worker, day))


def present_on_site(worker: str, day: str) -> SymbolRef:
    return SymbolRef(PREDICATE_PRESENT, (worker, day))


def on_site_duration(worker: str, day: str) -> SymbolRef:
    return SymbolRef(PREDICATE_DURATION, (worker, day))


def shift_payable(worker: str, day: str) -> SymbolRef:
    return SymbolRef(PREDICATE_PAYABLE, (worker, day))


def declared_instances(worker: str) -> tuple[SymbolRef, ...]:
    """Every proposition instance a case about one worker's week declares."""
    instances = [daily_rate(worker)]
    for day in WORKING_DAYS:
        instances.extend(
            (
                scheduled(worker, day),
                present_on_site(worker, day),
                on_site_duration(worker, day),
                shift_payable(worker, day),
            )
        )
    return tuple(instances)


def predicate_schema() -> PredicateSchema:
    return PredicateSchema(
        schema_version=1,
        predicates=(
            PredicateSpec(
                predicate_id=PREDICATE_DAILY_RATE,
                arg_kinds=("WORKER",),
                value_sort=ScaledSort(CURRENCY, CURRENCY_SCALE),
                domain=ScaledRange(0, MAX_DAILY_RATE_MINOR),
                layer=EvidenceLayer.RECORD,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_PAYROLL,),
                measurement_class="PAYROLL_RECORD",
            ),
            PredicateSpec(
                predicate_id=PREDICATE_SCHEDULED,
                arg_kinds=("WORKER", "DAY"),
                value_sort=BoolSort(),
                domain=BoolDomain(),
                layer=EvidenceLayer.RECORD,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_PAYROLL,),
                measurement_class="ROSTER_RECORD",
            ),
            PredicateSpec(
                predicate_id=PREDICATE_PRESENT,
                arg_kinds=("WORKER", "DAY"),
                value_sort=BoolSort(),
                domain=BoolDomain(),
                layer=EvidenceLayer.OBSERVATION,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_SITE_ACCESS,),
                measurement_class="SITE_ACCESS_EVENT",
            ),
            PredicateSpec(
                predicate_id=PREDICATE_DURATION,
                arg_kinds=("WORKER", "DAY"),
                value_sort=IntSort(),
                domain=IntRange(0, MINUTES_IN_A_DAY),
                layer=EvidenceLayer.OBSERVATION,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_SITE_ACCESS,),
                measurement_class="SITE_ACCESS_DURATION_MINUTES",
            ),
            PredicateSpec(
                predicate_id=PREDICATE_PAYABLE,
                arg_kinds=("WORKER", "DAY"),
                value_sort=BoolSort(),
                domain=BoolDomain(),
                layer=EvidenceLayer.NORMATIVE,
                #  DERIVED, and therefore not attestable by anyone: no evidence
                #  target can name it and no receipt can carry it.
                acquisition=AcquisitionClass.DERIVED,
                permitted_source_classes=(),
                measurement_class=None,
            ),
        ),
    )


def action_schema() -> ActionSchema:
    return ActionSchema(
        schema_id=ACTION_SCHEMA_ID,
        schema_version=1,
        kinds=(
            ActionKindSpec(
                kind=ACTION_PAY,
                fields=(
                    FieldSpec(
                        name=FIELD_RECIPIENT,
                        sort=EnumSort(ENUM_PARTY),
                        bounds=EnumDomain(("RAVI",)),
                        consequentiality=Consequentiality.CONSEQUENTIAL,
                        required=True,
                    ),
                    FieldSpec(
                        name=FIELD_AMOUNT,
                        sort=ScaledSort(CURRENCY, CURRENCY_SCALE),
                        bounds=ScaledRange(0, MAX_PAYMENT_MINOR),
                        consequentiality=Consequentiality.CONSEQUENTIAL,
                        required=True,
                    ),
                    FieldSpec(
                        name=FIELD_BASIS,
                        sort=EnumSort(ENUM_BASIS),
                        bounds=EnumDomain((BASIS_WEEKLY_SHIFT_TOTAL,)),
                        #  Diagnostic: the executor ignores it, so two actions
                        #  differing only here are the same action.
                        consequentiality=Consequentiality.DIAGNOSTIC,
                        required=False,
                        default=VEnum(ENUM_BASIS, BASIS_WEEKLY_SHIFT_TOTAL),
                    ),
                ),
            ),
        ),
    )


def payable_premise(worker: str, day: str) -> Term:
    """The ratified criteria, instantiated for one worker and one day."""
    return NAry(
        NAryOp.AND,
        (
            Leaf(scheduled(worker, day)),
            Leaf(present_on_site(worker, day)),
            Binary(BinaryOp.GE, Leaf(on_site_duration(worker, day)), LitInt(QUALIFYING_MINUTES)),
        ),
    )


def entailment_rules() -> EntailmentRules:
    return EntailmentRules(
        schema_version=1,
        rules=(
            DefinitionRule(
                rule_id=RULE_SHIFT_PAYABLE,
                binder_args=(BINDER_WORKER, BINDER_DAY),
                conclusion=SymbolRefTemplate(PREDICATE_PAYABLE, (BINDER_WORKER, BINDER_DAY)),
                premise=payable_premise(BINDER_WORKER, BINDER_DAY),
                exhaustiveness_ratification_ref=ratifications().records[0].digest(),
            ),
        ),
    )


def ratifications() -> RatificationSet:
    """The human decision that makes the biconditional legitimate.

    Its subject is the *premise term* -- the exact criteria being ratified as
    exhaustive -- so a ratification cannot be reused for a rule whose criteria
    were changed afterwards.
    """
    return RatificationSet(
        schema_version=1,
        records=(
            RatificationRecord(
                ratification_id=RATIFICATION_SHIFT_PAYABLE,
                tenant_scope=None,
                subject_kind="ENTAILMENT_PREMISE_EXHAUSTIVENESS",
                subject_ref=term_digest(payable_premise(BINDER_WORKER, BINDER_DAY)),
                ratified_at=RATIFIED_AT,
                signer_key_ref=SIGNER_KEY,
                signature=UNSIGNED,
            ),
        ),
    )


def decision_program(worker: str) -> DecisionProgram:
    """``PAY(worker, sum over the week of the daily rate on payable days)``.

    No guard: the program is total in form, and what varies is the amount.  The
    week's total is a bounded sum over a literal index set, which keeps the
    fragment linear and the query decidable.
    """
    zero: Term = literal(money(0))
    contributions = tuple(
        Ite(Leaf(shift_payable(worker, day)), Leaf(daily_rate(worker)), zero)
        for day in WORKING_DAYS
    )
    if len(contributions) < 2:  # pragma: no cover - the week has six days
        raise InvariantViolation("the sum needs at least two days")
    amount = NAry(NAryOp.ADD, contributions)
    action = ActionTerm(
        kind=ACTION_PAY,
        fields=(
            FieldTerm(FIELD_RECIPIENT, literal(VEnum(ENUM_PARTY, worker))),
            FieldTerm(FIELD_AMOUNT, amount),
        ),
    )
    inputs = canonical_order(
        {ref for contribution in contributions for ref in freevars(contribution)},
        lambda ref: ref.to_node(),
    )
    return DecisionProgram(inputs=inputs, rules=(), otherwise=action)


def admissibility_descriptors() -> AdmissibilityDescriptors:
    return AdmissibilityDescriptors(
        schema_version=1,
        descriptors=(
            AdmissibilityDescriptor(
                rule_id="AttestedRelation",
                rule_version=1,
                rule_kind="ATTESTED_RELATION",
                grouping_key="PROPOSITION",
                admissible_procedures=(
                    "PAYROLL_RECORD",
                    "ROSTER_RECORD",
                    "SITE_ACCESS_EVENT",
                    "SITE_ACCESS_DURATION_MINUTES",
                ),
                max_temporal_gap=0,
            ),
            AdmissibilityDescriptor(
                rule_id="SelfServingClaimIsInert",
                rule_version=1,
                rule_kind="NON_EFFECT",
                grouping_key="CLAIMANT",
                admissible_procedures=("PARTY_STATEMENT",),
                max_temporal_gap=0,
            ),
            AdmissibilityDescriptor(
                rule_id="StructuralDomainBound",
                rule_version=1,
                rule_kind="STRUCTURAL",
                grouping_key="PROPOSITION",
                admissible_procedures=("PREDICATE_SCHEMA",),
                max_temporal_gap=0,
            ),
        ),
    )


def disclosure_policy() -> DisclosurePolicy:
    """Carried because the manifest commits to its digest.

    Milestone A publishes no views; redaction is milestone D.  The entries exist
    so that the signed tuple is complete, not so that anything reads them.
    """
    return DisclosurePolicy(
        schema_version=1,
        entries=(
            DisclosureEntry(
                outcome_class="DIVERGENT",
                action_kind=None,
                audience_class="WORKER",
                disclosure_context="NOTIFICATION",
                reveals_sensitive_input=False,
                inference_acknowledgement_ref=None,
                permitted_paths=("case.tenant_id", "case.case_id", "kernel.outcome.tag"),
            ),
            DisclosureEntry(
                outcome_class="INVARIANT",
                action_kind=ACTION_PAY,
                audience_class="WORKER",
                disclosure_context="NOTIFICATION",
                reveals_sensitive_input=False,
                inference_acknowledgement_ref=None,
                permitted_paths=(
                    "case.tenant_id",
                    "case.case_id",
                    "kernel.outcome.tag",
                    "kernel.outcome.action",
                ),
            ),
        ),
    )


def workforce_bundle(worker: str = "RAVI") -> LoadedBundle:
    """Assemble and validate the bundle. Raises only on a defect in this module."""
    program = decision_program(worker)
    rules = entailment_rules()
    schema = predicate_schema()
    actions = action_schema()
    descriptors = admissibility_descriptors()
    disclosure = disclosure_policy()
    ratified = ratifications()

    manifest = BundleManifest(
        manifest_schema_version=1,
        tenant_scope=None,
        policy_id=POLICY_ID,
        human_version=HUMAN_VERSION,
        effective_interval=HalfOpenInterval(EFFECTIVE_FROM, None),
        decision_program_digest=program.digest(),
        entailment_rules_digest=rules.digest(),
        admissibility_descriptors_digest=descriptors.digest(),
        predicate_schema_digest=schema.digest(),
        action_schema_digest=actions.digest(),
        disclosure_policy_digest=disclosure.digest(),
        ratification_records_digest=ratified.digest(),
        ir_schema_version=SUPPORTED_IR_SCHEMA_VERSION,
        interpreter_version=SUPPORTED_INTERPRETER_VERSION,
        ratified_by=RATIFIED_BY,
        ratified_at=RATIFIED_AT,
        signer_key_ref=SIGNER_KEY,
    )
    loaded = load_bundle(
        signed_manifest=SignedManifest(manifest, UNSIGNED),
        program=program,
        entailment_rules=rules,
        predicate_schema=schema,
        action_schema=actions,
        admissibility_descriptors=descriptors,
        disclosure_policy=disclosure,
        ratifications=ratified,
    )
    if isinstance(loaded, Err):  # pragma: no cover - a defect in this module
        raise InvariantViolation(f"the workforce bundle does not load: {loaded.error}")
    return loaded.value
