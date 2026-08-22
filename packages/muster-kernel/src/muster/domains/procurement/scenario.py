"""The shared PO-4821 evidence fixture for either pinned policy."""

from __future__ import annotations

from dataclasses import dataclass, replace

from muster.core.case.constraints import AttestedRelationDeriv, Constraint, NonEffect
from muster.core.case.facts import AttestedBy, EstablishedFact
from muster.core.case.revision import (
    Authorizability,
    CaseRevision,
    RebuildMode,
    canonical_constraints,
    canonical_declared,
    canonical_facts,
    canonical_non_effects,
)
from muster.core.expr.ir import Binary, BinaryOp, Leaf
from muster.core.values.scalars import VInt, VScaled
from muster.core.values.symbols import SymbolRef
from muster.core.wire.digests import Digest
from muster.domains.procurement.bundle import (
    CASE_ID,
    FIXED_AMOUNT_MINOR,
    PER_UNIT_RATE_MINOR,
    PO_ID,
    SOURCE_PROCUREMENT_PO,
    SOURCE_SUPPLIER,
    SOURCE_WAREHOUSE,
    SUPPLIER,
    TENANT,
    ProcurementPolicy,
    declared_instances,
    delivered_quantity,
    fixed_contract_amount,
    money,
    ordered_quantity,
    per_unit_rate,
    procurement_bundle,
    supplier_declared_quantity,
    warehouse_received_quantity,
)

SUPPLIER_QUANTITY = 100
WAREHOUSE_QUANTITY = 97
ORDERED_QUANTITY = 100

RELATION_CLAIM_ONLY = "CLAIM_ONLY"
RELATION_CLOSED_LOWER_BOUND = "CLOSED_LOWER_BOUND"
RELATION_CLOSED_UPPER_BOUND = "CLOSED_UPPER_BOUND"
RELATION_CONTRACT_TERM = "CONTRACT_TERM"

SUPPLIER_RECEIPT = Digest(bytes((11,)) * 32)
WAREHOUSE_RECEIPT = Digest(bytes((12,)) * 32)
ORDERED_QUANTITY_RECEIPT = Digest(bytes((13,)) * 32)
FIXED_AMOUNT_RECEIPT = Digest(bytes((14,)) * 32)
PER_UNIT_RATE_RECEIPT = Digest(bytes((15,)) * 32)
EXACT_WAREHOUSE_RECEIPT = Digest(bytes((16,)) * 32)


@dataclass(frozen=True, slots=True)
class ProcurementSourceRecord:
    source_class: str
    label: str
    proposition: SymbolRef
    value: VInt | VScaled
    relation: str


@dataclass(frozen=True, slots=True)
class ProcurementCase:
    tenant_id: str
    case_id: str
    po_id: str
    supplier: str
    fixed_amount: VScaled
    per_unit_rate: VScaled
    records: tuple[ProcurementSourceRecord, ...]


def case_fixture() -> ProcurementCase:
    return ProcurementCase(
        tenant_id=TENANT,
        case_id=CASE_ID,
        po_id=PO_ID,
        supplier=SUPPLIER,
        fixed_amount=money(FIXED_AMOUNT_MINOR),
        per_unit_rate=money(PER_UNIT_RATE_MINOR),
        records=(
            ProcurementSourceRecord(
                SOURCE_SUPPLIER,
                "Supplier declaration",
                supplier_declared_quantity(),
                VInt(SUPPLIER_QUANTITY),
                RELATION_CLAIM_ONLY,
            ),
            ProcurementSourceRecord(
                SOURCE_WAREHOUSE,
                "Warehouse receiving",
                warehouse_received_quantity(),
                VInt(WAREHOUSE_QUANTITY),
                RELATION_CLOSED_LOWER_BOUND,
            ),
            ProcurementSourceRecord(
                SOURCE_PROCUREMENT_PO,
                "Purchase order ceiling",
                ordered_quantity(),
                VInt(ORDERED_QUANTITY),
                RELATION_CLOSED_UPPER_BOUND,
            ),
            ProcurementSourceRecord(
                SOURCE_PROCUREMENT_PO,
                "Fixed contract amount",
                fixed_contract_amount(),
                money(FIXED_AMOUNT_MINOR),
                RELATION_CONTRACT_TERM,
            ),
            ProcurementSourceRecord(
                SOURCE_PROCUREMENT_PO,
                "Per-unit rate",
                per_unit_rate(),
                money(PER_UNIT_RATE_MINOR),
                RELATION_CONTRACT_TERM,
            ),
        ),
    )


def _placeholder(octet: int) -> Digest:
    return Digest(bytes((octet,)) * 32)


def base_revision() -> CaseRevision:
    fixture = case_fixture()
    receipt_digests = (
        SUPPLIER_RECEIPT,
        WAREHOUSE_RECEIPT,
        ORDERED_QUANTITY_RECEIPT,
        FIXED_AMOUNT_RECEIPT,
        PER_UNIT_RATE_RECEIPT,
    )
    facts = canonical_facts(
        EstablishedFact(record.proposition, record.value, AttestedBy(receipt))
        for record, receipt in zip(fixture.records, receipt_digests, strict=True)
    )
    return CaseRevision(
        tenant_id=fixture.tenant_id,
        case_id=fixture.case_id,
        construction_digest=_placeholder(1),
        transcript_prefix_digest=_placeholder(2),
        bundle_pin=_placeholder(3),
        as_of=1_785_000_000_000_000,
        mode=RebuildMode.COUNTERFACTUAL,
        authorization_context_digest=_placeholder(4),
        authorizability=Authorizability.NEVER_AUTHORIZABLE,
        declared=canonical_declared(declared_instances()),
        established=facts,
        constraints=canonical_constraints(
            (
                Constraint(
                    "WAREHOUSE-CONFIRMED-LOWER-BOUND",
                    Binary(
                        BinaryOp.GE,
                        Leaf(delivered_quantity()),
                        Leaf(warehouse_received_quantity()),
                    ),
                    AttestedRelationDeriv(1, WAREHOUSE_RECEIPT),
                ),
                Constraint(
                    "PO-ORDERED-QUANTITY-CEILING",
                    Binary(
                        BinaryOp.LE,
                        Leaf(delivered_quantity()),
                        Leaf(ordered_quantity()),
                    ),
                    AttestedRelationDeriv(1, ORDERED_QUANTITY_RECEIPT),
                ),
            )
        ),
        non_effects=canonical_non_effects(
            (
                NonEffect(
                    "SelfServingClaimIsInert",
                    1,
                    str(supplier_declared_quantity()),
                    (
                        "supplier declaration records a claim but establishes no "
                        "delivered-quantity bound"
                    ),
                ),
            )
        ),
    )


def revision(policy: ProcurementPolicy) -> CaseRevision:
    return replace(base_revision(), bundle_pin=procurement_bundle(policy).digest())


def revision_with_exact_quantity(
    policy: ProcurementPolicy, quantity: int = WAREHOUSE_QUANTITY
) -> CaseRevision:
    """Admit a final authoritative warehouse adjudication for the exact quantity."""
    current = revision(policy)
    exact = EstablishedFact(
        delivered_quantity(), VInt(quantity), AttestedBy(EXACT_WAREHOUSE_RECEIPT)
    )
    return replace(current, established=canonical_facts((*current.established, exact)))
