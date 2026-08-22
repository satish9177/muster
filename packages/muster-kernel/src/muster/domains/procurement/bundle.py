"""Pinned synthetic procurement policies over one disputed delivery quantity.

The domain package supplies vocabulary and policy data only.  Invariance,
divergence, consequential-action comparison, and evidence planning remain the
generic kernel's work.
"""

from __future__ import annotations

from enum import Enum

from muster.core.actions import (
    ActionKindSpec,
    ActionSchema,
    Consequentiality,
    FieldSpec,
)
from muster.core.expr.ir import Binary, BinaryOp, Leaf, LitEnum, LitInt, Scale
from muster.core.expr.terms import Term
from muster.core.results import Err, InvariantViolation
from muster.core.values.classification import AcquisitionClass, EvidenceLayer
from muster.core.values.scalars import VEnum, VScaled
from muster.core.values.sorts import (
    EnumDomain,
    EnumSort,
    IntRange,
    IntSort,
    ScaledRange,
    ScaledSort,
)
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import HalfOpenInterval
from muster.core.wire.codec import canonical_order
from muster.core.wire.signature import Signature
from muster.policy.artifacts import (
    AdmissibilityDescriptor,
    AdmissibilityDescriptors,
    DisclosurePolicy,
    RatificationSet,
)
from muster.policy.entailment import EntailmentRules
from muster.policy.manifest import (
    SUPPORTED_INTERPRETER_VERSION,
    SUPPORTED_IR_SCHEMA_VERSION,
    BundleManifest,
    LoadedBundle,
    SignedManifest,
    load_bundle,
)
from muster.policy.predicates import PredicateSchema, PredicateSpec
from muster.policy.program import ActionTerm, DecisionProgram, FieldTerm, ProgramRule

TENANT = "MUSTER-DEMO"
CASE_ID = "PROCUREMENT-PO-4821"
PO_ID = "PO-4821"
SUPPLIER = "SUPPLIER-ORION"

# A schema safety bound, deliberately wider than PO-4821's admissible envelope.
# The case-specific ceiling must therefore be supplied by the purchase order.
MAX_SUPPORTED_QUANTITY = 200
ACCEPTANCE_THRESHOLD = 97

CURRENCY = "INR"
CURRENCY_SCALE = 2
FIXED_AMOUNT_MINOR = 6_300_000
PER_UNIT_RATE_MINOR = 63_000
MAX_PAYMENT_MINOR = FIXED_AMOUNT_MINOR

PREDICATE_SUPPLIER_DECLARED = "supplier_declared_quantity"
PREDICATE_WAREHOUSE_RECEIVED = "warehouse_received_quantity"
PREDICATE_ORDERED_QUANTITY = "ordered_quantity"
PREDICATE_DELIVERED = "delivered_quantity"
PREDICATE_FIXED_AMOUNT = "fixed_contract_amount"
PREDICATE_PER_UNIT_RATE = "per_unit_rate"

SOURCE_SUPPLIER = "SUPPLIER_DECLARATION"
SOURCE_WAREHOUSE = "WAREHOUSE_RECEIVING"
SOURCE_PROCUREMENT_PO = "PROCUREMENT_PO"
SCOPE_PURCHASE_ORDER = "PURCHASE_ORDER"

ACTION_PAY = "PAY"
ACTION_HOLD = "HOLD"
FIELD_RECIPIENT = "recipient"
FIELD_AMOUNT = "amount"
FIELD_PO = "purchase_order"
ENUM_SUPPLIER = "procurement_supplier"
ENUM_PO = "purchase_order_id"
ACTION_SCHEMA_ID = "procurement-actions"

UNSIGNED = Signature("UNSIGNED-LOCAL-DEVELOPMENT", b"")
EFFECTIVE_FROM = 1_700_000_000_000_000
RATIFIED_AT = 1_700_000_000_000_000
RATIFIED_BY = "procurement-policy-authority"
SIGNER_KEY = "key-procurement-policy-authority"


class ProcurementPolicy(Enum):
    FIXED_TOLERANCE = "FIXED_TOLERANCE"
    PER_UNIT = "PER_UNIT"


def money(minor: int) -> VScaled:
    return VScaled(CURRENCY, CURRENCY_SCALE, minor)


def supplier_declared_quantity(po_id: str = PO_ID) -> SymbolRef:
    return SymbolRef(PREDICATE_SUPPLIER_DECLARED, (po_id,))


def warehouse_received_quantity(po_id: str = PO_ID) -> SymbolRef:
    return SymbolRef(PREDICATE_WAREHOUSE_RECEIVED, (po_id,))


def ordered_quantity(po_id: str = PO_ID) -> SymbolRef:
    return SymbolRef(PREDICATE_ORDERED_QUANTITY, (po_id,))


def delivered_quantity(po_id: str = PO_ID) -> SymbolRef:
    return SymbolRef(PREDICATE_DELIVERED, (po_id,))


def fixed_contract_amount(po_id: str = PO_ID) -> SymbolRef:
    return SymbolRef(PREDICATE_FIXED_AMOUNT, (po_id,))


def per_unit_rate(po_id: str = PO_ID) -> SymbolRef:
    return SymbolRef(PREDICATE_PER_UNIT_RATE, (po_id,))


def declared_instances(po_id: str = PO_ID) -> tuple[SymbolRef, ...]:
    return canonical_order(
        (
            supplier_declared_quantity(po_id),
            warehouse_received_quantity(po_id),
            ordered_quantity(po_id),
            delivered_quantity(po_id),
            fixed_contract_amount(po_id),
            per_unit_rate(po_id),
        ),
        lambda ref: ref.to_node(),
    )


def predicate_schema() -> PredicateSchema:
    return PredicateSchema(
        schema_version=1,
        predicates=(
            PredicateSpec(
                predicate_id=PREDICATE_SUPPLIER_DECLARED,
                arg_kinds=(SCOPE_PURCHASE_ORDER,),
                value_sort=IntSort(),
                domain=IntRange(0, MAX_SUPPORTED_QUANTITY),
                layer=EvidenceLayer.RECORD,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_SUPPLIER,),
                resource_scope_kinds=(SCOPE_PURCHASE_ORDER,),
                measurement_class="SUPPLIER_DELIVERY_STATEMENT",
            ),
            PredicateSpec(
                predicate_id=PREDICATE_WAREHOUSE_RECEIVED,
                arg_kinds=(SCOPE_PURCHASE_ORDER,),
                value_sort=IntSort(),
                domain=IntRange(0, MAX_SUPPORTED_QUANTITY),
                layer=EvidenceLayer.OBSERVATION,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_WAREHOUSE,),
                resource_scope_kinds=(SCOPE_PURCHASE_ORDER,),
                measurement_class="WAREHOUSE_RECEIPT_COUNT",
            ),
            PredicateSpec(
                predicate_id=PREDICATE_ORDERED_QUANTITY,
                arg_kinds=(SCOPE_PURCHASE_ORDER,),
                value_sort=IntSort(),
                domain=IntRange(0, MAX_SUPPORTED_QUANTITY),
                layer=EvidenceLayer.RECORD,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_PROCUREMENT_PO,),
                resource_scope_kinds=(SCOPE_PURCHASE_ORDER,),
                measurement_class="PURCHASE_ORDER_ORDERED_QUANTITY",
            ),
            PredicateSpec(
                predicate_id=PREDICATE_DELIVERED,
                arg_kinds=(SCOPE_PURCHASE_ORDER,),
                value_sort=IntSort(),
                domain=IntRange(0, MAX_SUPPORTED_QUANTITY),
                layer=EvidenceLayer.OBSERVATION,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_WAREHOUSE,),
                resource_scope_kinds=(SCOPE_PURCHASE_ORDER,),
                measurement_class="AUTHORITATIVE_DELIVERY_QUANTITY",
            ),
            PredicateSpec(
                predicate_id=PREDICATE_FIXED_AMOUNT,
                arg_kinds=(SCOPE_PURCHASE_ORDER,),
                value_sort=ScaledSort(CURRENCY, CURRENCY_SCALE),
                domain=ScaledRange(FIXED_AMOUNT_MINOR, FIXED_AMOUNT_MINOR),
                layer=EvidenceLayer.RECORD,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_PROCUREMENT_PO,),
                resource_scope_kinds=(SCOPE_PURCHASE_ORDER,),
                measurement_class="PURCHASE_ORDER_FIXED_AMOUNT",
            ),
            PredicateSpec(
                predicate_id=PREDICATE_PER_UNIT_RATE,
                arg_kinds=(SCOPE_PURCHASE_ORDER,),
                value_sort=ScaledSort(CURRENCY, CURRENCY_SCALE),
                domain=ScaledRange(PER_UNIT_RATE_MINOR, PER_UNIT_RATE_MINOR),
                layer=EvidenceLayer.RECORD,
                acquisition=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=(SOURCE_PROCUREMENT_PO,),
                resource_scope_kinds=(SCOPE_PURCHASE_ORDER,),
                measurement_class="PURCHASE_ORDER_UNIT_RATE",
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
                        sort=EnumSort(ENUM_SUPPLIER),
                        bounds=EnumDomain((SUPPLIER,)),
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
                ),
            ),
            ActionKindSpec(
                kind=ACTION_HOLD,
                fields=(
                    FieldSpec(
                        name=FIELD_PO,
                        sort=EnumSort(ENUM_PO),
                        bounds=EnumDomain((PO_ID,)),
                        consequentiality=Consequentiality.CONSEQUENTIAL,
                        required=True,
                    ),
                ),
            ),
        ),
    )


def _pay(amount: Term) -> ActionTerm:
    return ActionTerm(
        ACTION_PAY,
        (
            FieldTerm(FIELD_RECIPIENT, LitEnum(VEnum(ENUM_SUPPLIER, SUPPLIER))),
            FieldTerm(FIELD_AMOUNT, amount),
        ),
    )


def decision_program(policy: ProcurementPolicy, po_id: str = PO_ID) -> DecisionProgram:
    quantity = delivered_quantity(po_id)
    amount: Term
    if policy is ProcurementPolicy.FIXED_TOLERANCE:
        amount = Leaf(fixed_contract_amount(po_id))
    else:
        amount = Scale(
            Leaf(quantity),
            PER_UNIT_RATE_MINOR,
            ScaledSort(CURRENCY, CURRENCY_SCALE),
        )

    rule = ProgramRule(
        guard=Binary(BinaryOp.GE, Leaf(quantity), LitInt(ACCEPTANCE_THRESHOLD)),
        action=_pay(amount),
    )
    otherwise = ActionTerm(
        ACTION_HOLD,
        (FieldTerm(FIELD_PO, LitEnum(VEnum(ENUM_PO, po_id))),),
    )
    draft = DecisionProgram(inputs=(), rules=(rule,), otherwise=otherwise)
    inputs = canonical_order(draft.free_symbols(), lambda ref: ref.to_node())
    return DecisionProgram(inputs=inputs, rules=draft.rules, otherwise=draft.otherwise)
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
                    "AUTHORITATIVE_DELIVERY_QUANTITY",
                    "PURCHASE_ORDER_ORDERED_QUANTITY",
                    "PURCHASE_ORDER_FIXED_AMOUNT",
                    "PURCHASE_ORDER_UNIT_RATE",
                    "SUPPLIER_DELIVERY_STATEMENT",
                    "WAREHOUSE_RECEIPT_COUNT",
                ),
                max_temporal_gap=0,
            ),
            AdmissibilityDescriptor(
                rule_id="SelfServingClaimIsInert",
                rule_version=1,
                rule_kind="NON_EFFECT",
                grouping_key="CLAIMANT",
                admissible_procedures=("SUPPLIER_DELIVERY_STATEMENT",),
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


def procurement_bundle(policy: ProcurementPolicy, po_id: str = PO_ID) -> LoadedBundle:
    program = decision_program(policy, po_id)
    rules = EntailmentRules(schema_version=1, rules=())
    schema = predicate_schema()
    actions = action_schema()
    descriptors = admissibility_descriptors()
    disclosure = DisclosurePolicy(schema_version=1, entries=())
    ratified = RatificationSet(schema_version=1, records=())

    manifest = BundleManifest(
        manifest_schema_version=1,
        tenant_scope=TENANT,
        policy_id=f"procurement-{policy.value.lower().replace('_', '-')}",
        human_version="1.0.0",
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
    if isinstance(loaded, Err):
        raise InvariantViolation(f"the procurement bundle does not load: {loaded.error}")
    return loaded.value
