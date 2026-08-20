"""The end-to-end worked scenario every golden vector is drawn from.

NON-PRODUCTION SPECIFICATION MATERIAL.

ALPHA / PO-4471.  A goods-receipt system attests `accepted_quantity >= 99`.
The policy pays Rs 63,000.00 at >= 100 and Rs 62,370.00 otherwise, so the
attested lower bound leaves the action DIVERGENT -- which is the honest answer,
and the one the disclosure machinery then has to redact correctly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Hashable

from . import fixtures as F
from .digests import commitment, digest_node
from .disclosure import build_participant_view, resolve_entry, validate_policy
from .hinge import Val, val_to_node
from .merkle import Tree, build_tree
from .nodes import (
    Atom,
    Bool,
    Bytes,
    Digest,
    Int,
    Node,
    Rec,
    Seq,
    SetV,
    Tagged,
    Unit,
    encode,
    none,
    some,
)
from .paths import CERTIFICATE_SCHEMA_VERSION, extract
from .selfcomp import Case, concrete_action, project, reference_invariant, symbol
from .signing import Keyring, sign_record
from .registry import REG

# --------------------------------------------------------------------------
# ratifications and policy bundle
# --------------------------------------------------------------------------


def ratification(rid: str, subject_kind: str, subject: Digest) -> Rec:
    unsigned = Rec(
        "RatificationRecord/v1",
        [
            Atom(rid),
            none(),  # shared across tenants
            Atom(subject_kind),
            subject,
            Int(F.T_2026_01_01),
            Atom("key-rat-1"),
            Rec("Signature/v1", [Atom("PLACEHOLDER"), Bytes(b"")]),
        ],
    )
    return sign_record(REG, F.KEYRING, unsigned, "RatificationRecord")


INFERENCE_ACK = ratification(
    "ratif-inference-1",
    "INFERENCE_ACKNOWLEDGEMENT",
    digest_node("DISCLOSURE_POLICY", Atom("procurement-demo")),
)

RATIFICATION_SET = Rec("RatificationSet/v1", [Int(1), Seq([INFERENCE_ACK])])
RATIFICATION_SET_DIGEST = digest_node("RATIFICATION_SET", RATIFICATION_SET)
INFERENCE_ACK_DIGEST = digest_node("RATIFICATION_RECORD", INFERENCE_ACK)


def disclosure_entry(
    outcome_class: str,
    action_kind: str | None,
    audience: str,
    context: str,
    permitted: list[str],
    reveals_sensitive: bool = False,
    ack: Digest | None = None,
) -> Rec:
    return Rec(
        "DisclosureEntry/v1",
        [
            Atom(outcome_class),
            none() if action_kind is None else some(Atom(action_kind)),
            Atom(audience),
            Atom(context),
            Bool(reveals_sensitive),
            none() if ack is None else some(ack),
            Seq([Atom(p) for p in permitted]),
        ],
    )


#: The WAREHOUSE participant sees that a case exists and which policy governed it.
#: It does NOT see the outcome tag, the action, the quantity or any witness.
WAREHOUSE_DIVERGENT = disclosure_entry(
    "DIVERGENT",
    None,
    "WAREHOUSE",
    "NOTIFICATION",
    ["case.tenant_id", "case.case_id", "bundle.manifest_digest", "revision.bundle_pin"],
)

#: The SUPPLIER, on an invariant outcome, sees the action it is owed -- and the
#: disclosure policy records that this determines a sensitive input by inference.
SUPPLIER_INVARIANT = disclosure_entry(
    "INVARIANT",
    "PAY",
    "SUPPLIER",
    "NOTIFICATION",
    ["case.tenant_id", "case.case_id", "kernel.outcome.tag", "kernel.outcome.action"],
    reveals_sensitive=True,
    ack=INFERENCE_ACK_DIGEST,
)

AUDITOR_DIVERGENT = disclosure_entry(
    "DIVERGENT",
    None,
    "AUDITOR",
    "AUDIT",
    [
        "case.tenant_id",
        "case.case_id",
        "certificate.schema_version",
        "bundle.manifest_digest",
        "revision.bundle_pin",
        "revision.as_of",
        "revision.mode",
        "revision.authorizability",
        "kernel.outcome.tag",
        "kernel.outcome.reachable",
        "kernel.determinism_class",
    ],
)

DISCLOSURE_POLICY = Rec(
    "DisclosurePolicy/v1",
    [Int(1), Seq([WAREHOUSE_DIVERGENT, SUPPLIER_INVARIANT, AUDITOR_DIVERGENT])],
)
DISCLOSURE_POLICY_DIGEST = digest_node("DISCLOSURE_POLICY", DISCLOSURE_POLICY)

ENTAILMENT_RULES = Rec("EntailmentRules/v1", [Int(1), Seq([])])
ADMISSIBILITY_DESCRIPTORS = Rec("AdmissibilityDescriptors/v1", [Int(1), Seq([])])

BUNDLE_MANIFEST = Rec(
    "BundleManifest/v1",
    [
        Int(1),
        none(),
        Atom("procurement-demo"),
        Atom("2.0.0"),
        F.interval(F.T_2026_01_01),
        digest_node("POLICY_PROGRAM", F.DECISION_PROGRAM),
        digest_node("ENTAILMENT_RULES", ENTAILMENT_RULES),
        digest_node("ADMISSIBILITY_DESCRIPTORS", ADMISSIBILITY_DESCRIPTORS),
        F.PREDICATE_SCHEMA_DIGEST,
        F.ACTION_SCHEMA_DIGEST,
        DISCLOSURE_POLICY_DIGEST,
        RATIFICATION_SET_DIGEST,
        Int(1),
        Int(1),
        Atom("ratifier-1"),
        Int(F.T_2026_01_01),
        Atom("key-rat-1"),
    ],
)
MANIFEST_DIGEST = digest_node("MANIFEST", BUNDLE_MANIFEST)
SIGNED_MANIFEST = sign_record(
    REG,
    F.KEYRING,
    Rec("SignedManifest/v1", [BUNDLE_MANIFEST, Rec("Signature/v1", [Atom("P"), Bytes(b"")])]),
    "SignedManifest",
)


# --------------------------------------------------------------------------
# evidence
# --------------------------------------------------------------------------

EVIDENCE_REQUEST = Rec(
    "EvidenceRequest/v1",
    [
        Atom(F.TENANT),
        Atom(F.CASE_ID),
        digest_node("CASE_REVISION", Atom("bootstrap")),
        Seq(
            [
                Rec(
                    "EvidenceTarget/v1",
                    [F.Q_REF, Atom("ATTESTABLE"), SetV([Atom("GOODS_RECEIPT_SYSTEM")])],
                )
            ]
        ),
    ],
)
REQUEST_ID = digest_node("EVIDENCE_REQUEST", EVIDENCE_REQUEST)

ACQUISITION_PAYLOAD = Rec(
    "AcquisitionPayload/v1",
    [
        Atom(F.TENANT),
        Atom(F.CASE_ID),
        Atom("PO-4471"),
        F.Q_REF,
        Tagged("ClosedLowerBound", Rec("ClosedLowerBound/v1", [Tagged("VInt", Int(99))])),
        F.SORT_INT,
        F.PREDICATE_SCHEMA_DIGEST,
        Int(F.T_2026_06_01),
        Int(F.T_2026_06_01 + 60_000_000),
        F.interval(F.T_2026_06_01, F.T_2026_06_01 + 86_400_000_000),
        Bytes(F.NONCE),
        Atom("GOODS_RECEIPT_SYSTEM"),
        Atom("key-gr-1"),
        Int(3),
        REQUEST_ID,
    ],
)

VERIFICATION_RECEIPT = sign_record(
    REG,
    F.KEYRING,
    Rec(
        "VerificationReceipt/v1",
        [ACQUISITION_PAYLOAD, Rec("Signature/v1", [Atom("PLACEHOLDER"), Bytes(b"")])],
    ),
    "VerificationReceipt",
)
RECEIPT_DIGEST = digest_node("VERIFICATION_RECEIPT", VERIFICATION_RECEIPT)

INTEREST_ASSESSMENT = sign_record(
    REG,
    F.KEYRING,
    Rec(
        "InterestAssessment/v1",
        [
            Atom(F.TENANT),
            Atom(F.CASE_ID),
            F.Q_REF,
            Atom("SUP-12"),
            Atom("QUANTITY"),
            Atom("UPWARD"),
            F.interval(F.T_2026_01_01),
            Atom("case-officer-1"),
            none(),
            Atom("key-case-1"),
            Rec("Signature/v1", [Atom("PLACEHOLDER"), Bytes(b"")]),
        ],
    ),
    "InterestAssessment",
)

CASE_CONSTRUCTION = sign_record(
    REG,
    F.KEYRING,
    Rec(
        "CaseConstructionRecord/v1",
        [
            Atom(F.TENANT),
            Atom(F.CASE_ID),
            Int(F.T_2026_06_01 - 3_600_000_000),
            Seq([Atom("PO-4471")]),
            some(Atom("CONTRACT-88")),
            Seq(
                [
                    Rec(
                        "PartyRecord/v1",
                        [Atom(F.TENANT), Atom("SUP-12"), Atom("SUPPLIER"), SetV([Atom("DELIVERY")])],
                    ),
                    Rec(
                        "PartyRecord/v1",
                        [Atom(F.TENANT), Atom("WH-1"), Atom("WAREHOUSE"), SetV([Atom("COUNT")])],
                    ),
                ]
            ),
            Seq([F.Q_REF]),
            #  [G1] Where this case is, signed by the officer who opened it.
            #  accepted_quantity carries its own purchase order in an argument,
            #  so this coordinate is not what Q-12(d) resolves for *that*
            #  predicate -- it is what a case-level predicate would resolve
            #  against, and it is here so the record can carry one at all.
            SetV([Rec("ResourceScope/v1", [Atom("cost_centre"), Atom("CC-7")])]),
            Atom("key-case-1"),
            Rec("Signature/v1", [Atom("PLACEHOLDER"), Bytes(b"")]),
        ],
    ),
    "CaseConstructionRecord",
)
CONSTRUCTION_DIGEST = digest_node("CASE_CONSTRUCTION", CASE_CONSTRUCTION)

TRANSCRIPT_ENTRIES = [Tagged("Attestation", VERIFICATION_RECEIPT)]
TRANSCRIPT_PREFIX = Rec(
    "TranscriptPrefix/v1",
    [
        Atom(F.TENANT),
        Atom(F.CASE_ID),
        Seq(sorted((digest_node("TRANSCRIPT_ENTRY", e) for e in TRANSCRIPT_ENTRIES), key=encode)),
    ],
)
TRANSCRIPT_PREFIX_DIGEST = digest_node("TRANSCRIPT_PREFIX", TRANSCRIPT_PREFIX)

#  [G1] The authority the worked scenario is decided under.
#
#  One grant, and it is deliberately narrow: the goods-receipt system's key may
#  attest exactly ``accepted_quantity``, for exactly ``PO-4471``, in exactly
#  this tenant, under exactly authorization-policy version 3.  Every clause of
#  Q-12 has something to check, and the two ratified adversarial requirements
#  are refusals *against this snapshot*: a worker key resolves no grant at all
#  (Q-12(b)), and a key granted a different purchase order resolves one that
#  fails on scope alone (Q-12(d)).
AUTHORITY_GRANT = Rec(
    "AuthorityGrant/v1",
    [
        Atom("key-gr-1"),
        Atom("WH-1"),
        Atom(F.TENANT),
        Atom("GOODS_RECEIPT_SYSTEM"),
        SetV([Atom("accepted_quantity")]),
        SetV([Rec("ResourceScope/v1", [Atom("purchase_order"), Atom("PO-4471")])]),
        F.interval(F.T_2026_01_01, F.T_2026_06_01 + 365 * 86_400_000_000),
        Int(3),
    ],
)

AUTHORITY_REGISTRY_SNAPSHOT = Rec(
    "AuthorityRegistrySnapshot/v1",
    [
        Atom("authority-registry-1"),
        Atom(F.TENANT),
        Int(3),
        Seq([AUTHORITY_GRANT]),
        Int(F.T_2026_01_01),
    ],
)
AUTHORITY_REGISTRY_SNAPSHOT_DIGEST = digest_node(
    "AUTHORITY_REGISTRY_SNAPSHOT", AUTHORITY_REGISTRY_SNAPSHOT
)

SIGNED_AUTHORITY_REGISTRY_SNAPSHOT = sign_record(
    REG,
    F.KEYRING,
    Rec(
        "SignedAuthorityRegistrySnapshot/v1",
        [
            Rec(
                "AuthorityRegistrySnapshotBody/v1",
                [AUTHORITY_REGISTRY_SNAPSHOT, Atom("key-authority-publisher-1")],
            ),
            Rec("Signature/v1", [Atom("PLACEHOLDER"), Bytes(b"")]),
        ],
    ),
    "SignedAuthorityRegistrySnapshot",
)

REVOCATION_SNAPSHOT = Rec(
    "RevocationSnapshot/v1",
    [
        Atom("revocation-registry-1"),
        Atom(F.TENANT),
        SetV([]),
        Int(F.T_2026_01_01),
    ],
)
REVOCATION_SNAPSHOT_DIGEST = digest_node("REVOCATION_SNAPSHOT", REVOCATION_SNAPSHOT)

#  [E] The fleet, published against that authority snapshot and granting
#  nothing.  The profile advertises exactly the acquisition the grant permits,
#  which is what makes the separation testable rather than accidental: a
#  catalog that could only ever agree with the registry would prove nothing.
AGENT_CATALOG_SNAPSHOT = Rec(
    "AgentCatalogSnapshot/v1",
    [
        Atom("agent-catalog-1"),
        Atom(F.TENANT),
        Seq(
            [
                Rec(
                    "AgentProfile/v1",
                    [
                        Atom("agent-goods-receipt"),
                        Int(1),
                        Atom(F.TENANT),
                        Atom("WH-1"),
                        Atom("GOODS_RECEIPT_SYSTEM"),
                        SetV([Atom("accepted_quantity")]),
                        SetV(
                            [Rec("ResourceScope/v1", [Atom("purchase_order"), Atom("PO-4471")])]
                        ),
                        Atom("local://agent-goods-receipt"),
                        Atom("ACTIVE"),
                    ],
                )
            ]
        ),
        Int(F.T_2026_01_01),
        AUTHORITY_REGISTRY_SNAPSHOT_DIGEST,
    ],
)
AGENT_CATALOG_SNAPSHOT_DIGEST = digest_node("AGENT_CATALOG_SNAPSHOT", AGENT_CATALOG_SNAPSHOT)

AUTHORIZATION_CONTEXT = Rec(
    "AuthorizationContext/v1",
    [
        Int(3),
        AUTHORITY_REGISTRY_SNAPSHOT_DIGEST,
        REVOCATION_SNAPSHOT_DIGEST,
        F.interval(F.T_2026_06_01, F.T_2026_06_01 + 30 * 86_400_000_000),
    ],
)
AUTHORIZATION_CONTEXT_DIGEST = digest_node("AUTHORIZATION_CONTEXT", AUTHORIZATION_CONTEXT)

REBUILD_INPUTS = Rec(
    "RebuildInputs/v1",
    [
        Atom(F.TENANT),
        Atom(F.CASE_ID),
        CONSTRUCTION_DIGEST,
        TRANSCRIPT_PREFIX_DIGEST,
        MANIFEST_DIGEST,
        Int(F.AS_OF),
        Atom("OPERATIONAL"),
        AUTHORIZATION_CONTEXT_DIGEST,
    ],
)


# --------------------------------------------------------------------------
# revision -- what stage 4 of the rebuild produces from the receipt above
# --------------------------------------------------------------------------

CONSTRAINT_ATT = Rec(
    "Constraint/v1",
    [
        Atom("C-ATT-1"),
        F.T.ge(F.T.var(F.Q_REF), F.T.lit(("int", 99))),
        Tagged("AttestedRelation", Rec("AttestedRelationDeriv/v1", [Int(1), RECEIPT_DIGEST])),
    ],
)
CONSTRAINT_DOM = Rec(
    "Constraint/v1",
    [
        Atom("C-DOM-1"),
        F.T.and_(
            F.T.ge(F.T.var(F.Q_REF), F.T.lit(("int", 0))),
            F.T.le(F.T.var(F.Q_REF), F.T.lit(("int", 120))),
        ),
        Tagged("Structural", Rec("StructuralDeriv/v1", [F.PREDICATE_SCHEMA_DIGEST])),
    ],
)
NON_EFFECT = Rec(
    "NonEffect/v1",
    [Atom("SelfServingClaimIsInert"), Int(1), Atom("SUP-12"), Atom("ADVERSE_INTEREST_ABSENT")],
)


def build_revision() -> Rec:
    return Rec(
        "CaseRevision/v1",
        [
            Atom(F.TENANT),
            Atom(F.CASE_ID),
            CONSTRUCTION_DIGEST,
            TRANSCRIPT_PREFIX_DIGEST,
            MANIFEST_DIGEST,
            Int(F.AS_OF),
            Atom("OPERATIONAL"),
            AUTHORIZATION_CONTEXT_DIGEST,
            Atom("AUTHORIZABLE"),
            Seq([F.Q_REF]),
            Seq([]),
            Seq(sorted([CONSTRAINT_ATT, CONSTRAINT_DOM], key=encode)),
            Seq([NON_EFFECT]),
        ],
    )


CASE_REVISION = build_revision()
REVISION_SEMANTIC_DIGEST = digest_node("CASE_REVISION", CASE_REVISION)

REVISION_LINEAGE = sign_record(
    REG,
    F.KEYRING,
    Rec(
        "RevisionLineage/v1",
        [
            Atom(F.TENANT),
            Atom(F.CASE_ID),
            REVISION_SEMANTIC_DIGEST,
            Int(8),
            some(digest_node("CASE_REVISION", Atom("parent"))),
            Int(F.AS_OF + 1_000_000),
            Atom("key-muster-1"),
            Rec("Signature/v1", [Atom("PLACEHOLDER"), Bytes(b"")]),
        ],
    ),
    "RevisionLineage",
)


# --------------------------------------------------------------------------
# analysis
# --------------------------------------------------------------------------

CASE = F.procurement_case(99)

LOGICAL_CASE = Rec(
    "LogicalCase/v1",
    [
        Seq([F.Q_REF]),
        Seq([]),
        Seq(sorted([CONSTRAINT_ATT, CONSTRAINT_DOM], key=encode)),
        digest_node("POLICY_PROGRAM", F.DECISION_PROGRAM),
        F.ACTION_SCHEMA_DIGEST,
        F.PREDICATE_SCHEMA_DIGEST,
    ],
)
LOGICAL_CASE_DIGEST = digest_node("LOGICAL_CASE", LOGICAL_CASE)


def world_node(case: Case, world: dict[Hashable, Val]) -> Rec:
    bindings = []
    for spec in list(case.universe) + [v for v, _ in case.known]:
        if spec.key in world:
            bindings.append(Rec("Binding/v1", [spec.ref, val_to_node(world[spec.key])]))
    return Rec("World/v1", [Seq(sorted(bindings, key=encode))])


def build_kernel_record() -> tuple[Rec, Tagged]:
    verdict, payload = reference_invariant(CASE)
    if verdict == "Divergent":
        left, right = payload  # type: ignore[misc]
        reachable = SetV(
            [project(CASE, concrete_action(CASE, w)) for w in _distinct_worlds()]
        )
        outcome = Tagged(
            "Divergent",
            Rec(
                "DivergentOutcome/v1",
                [
                    Tagged("Exact", reachable),
                    world_node(CASE, left),
                    world_node(CASE, right),
                ],
            ),
        )
    else:  # pragma: no cover - the fixture is divergent by construction
        raise AssertionError(f"unexpected verdict {verdict}")
    kernel = Rec(
        "KernelAnalysisRecord/v1",
        [
            LOGICAL_CASE_DIGEST,
            outcome,
            Seq([digest_node("SOLVER_QUERY", Atom("invariance-q1"))]),
            Rec(
                "SolverFingerprint/v1",
                [Atom("reference-bounded"), Atom("0.8.0"), Int(0), Atom("QF_LIA"), Int(0)],
            ),
            Atom("DETERMINISTIC"),
        ],
    )
    return kernel, outcome


def _distinct_worlds() -> list[dict[Hashable, Val]]:
    from .selfcomp import feasible_worlds

    seen: dict[bytes, dict[Hashable, Val]] = {}
    for w in feasible_worlds(CASE):
        proj = encode(project(CASE, concrete_action(CASE, w)))
        seen.setdefault(proj, w)
    return list(seen.values())


KERNEL_RECORD, OUTCOME = build_kernel_record()

PLANNING_RECORD = Rec(
    "PlanningRecord/v1",
    [
        Tagged("EvidenceRequested", EVIDENCE_REQUEST),
        none(),
    ],
)

DIAGNOSTIC_ANNEX = Rec(
    "DiagnosticAnnex/v1",
    [
        Seq([Atom("bounded-reference-enumeration")]),
        Seq([digest_node("SOLVER_QUERY", Atom("invariance-q1"))]),
        none(),
    ],
)

ANALYSIS_CERTIFICATE = Rec(
    "AnalysisCertificate/v1",
    [
        Int(CERTIFICATE_SCHEMA_VERSION),
        Atom(F.TENANT),
        Atom(F.CASE_ID),
        REVISION_SEMANTIC_DIGEST,
        MANIFEST_DIGEST,
        KERNEL_RECORD,
        PLANNING_RECORD,
        some(digest_node("DIAGNOSTIC_ANNEX", DIAGNOSTIC_ANNEX)),
    ],
)

INTERNAL_RECORD = Rec(
    "InternalAnalysisRecord/v1",
    [ANALYSIS_CERTIFICATE, CASE_REVISION, none(), Bytes(F.SALT_CASE)],
)


# --------------------------------------------------------------------------
# commitments and views
# --------------------------------------------------------------------------

CASE_COMMITMENT = commitment(F.SALT_CASE, "CASE_COMMITMENT", CONSTRUCTION_DIGEST)
REVISION_COMMITMENT = commitment(F.SALT_CASE, "REVISION_COMMITMENT", REVISION_SEMANTIC_DIGEST)

COMMITTED = extract(INTERNAL_RECORD)

TREE: Tree = build_tree(
    F.TENANT,
    F.CASE_ID,
    CASE_COMMITMENT,
    REVISION_COMMITMENT,
    MANIFEST_DIGEST,
    CERTIFICATE_SCHEMA_VERSION,
    F.SALT_CASE,
    COMMITTED,
)

COMMITMENT_ENVELOPE = Rec(
    "CommitmentEnvelope/v1",
    [
        Atom(F.TENANT),
        Atom(F.CASE_ID),
        CASE_COMMITMENT,
        REVISION_COMMITMENT,
        MANIFEST_DIGEST,
        DISCLOSURE_POLICY_DIGEST,
        Int(CERTIFICATE_SCHEMA_VERSION),
        Int(len(TREE.leaves)),
        Bytes(TREE.root),
        Atom("key-muster-1"),
    ],
)

SIGNED_ENVELOPE = sign_record(
    REG,
    F.KEYRING,
    Rec(
        "SignedCommitmentEnvelope/v1",
        [COMMITMENT_ENVELOPE, Rec("Signature/v1", [Atom("PLACEHOLDER"), Bytes(b"")])],
    ),
    "SignedCommitmentEnvelope",
)


def participant_view(audience: str, context: str = "NOTIFICATION") -> Rec:
    entry = resolve_entry(DISCLOSURE_POLICY, OUTCOME, audience, context)
    notice = None
    if entry.fields[4].value is True:  # type: ignore[union-attr]
        notice = "DISCLOSED_ACTION_DETERMINES_A_SENSITIVE_INPUT"
    return build_participant_view(TREE, SIGNED_ENVELOPE, entry, audience, context, notice)


WAREHOUSE_VIEW = participant_view("WAREHOUSE")
AUDITOR_VIEW = participant_view("AUDITOR", "AUDIT")
