"""The Phase-1 wire type registry -- the single source of truth.

NON-PRODUCTION SPECIFICATION MATERIAL.

Every tag table, arity table, digest-kind table, signing-body table and type
inventory in the Phase 0.8 report is generated from this file.  Nothing is
maintained in parallel by hand.

Phase 0.8 is the FIRST freeze.  No `/v1` tag drafted in Phase 0.5-0.7 was ever
produced by any implementation, so the definitions here are the initial
definitions, not incompatible redefinitions.
"""

from __future__ import annotations

from .schema import (
    ATOM,
    BOOL,
    BYTES,
    DIGEST,
    INT,
    UNIT,
    AtomIn,
    AtomMax,
    BytesLen,
    FieldDecl,
    OptOf,
    Ref,
    Registry,
    SELF_BODY,
    SeqOf,
    SetOf,
    SigningSpec,
    TypeDecl,
    TypeExpr,
)

REG = Registry()

CERTIFICATE_SCHEMA_VERSION = 1

MODALITIES = ("IMPLICATION", "DEFINITION")
DERIVATION_MODES = ("RULE_FIRED", "FULL_EVALUATION", "WITNESS_DISJUNCT")
LAYERS = ("OBSERVATION", "RECORD", "NORMATIVE")
ACQUISITION_CLASSES = ("ATTESTABLE", "DERIVED")
CONSEQUENTIALITY = ("CONSEQUENTIAL", "DIAGNOSTIC")
WORLD_SIDES = ("S", "L", "R")
QUERY_KINDS = ("FEASIBILITY", "INVARIANCE", "SUFFICIENCY")
REBUILD_MODES = ("OPERATIONAL", "COUNTERFACTUAL")
AUTHORIZABILITY = ("AUTHORIZABLE", "NEVER_AUTHORIZABLE")
OUTCOME_CLASSES = ("INVARIANT", "DIVERGENT", "INFEASIBLE", "INDETERMINATE")
PROOF_SIDES = ("L", "R")


def _f(name: str, type_: TypeExpr, note: str = "") -> FieldDecl:
    return FieldDecl(name, type_, note)


def record(
    name: str,
    tag: str,
    fields: list[FieldDecl],
    *,
    digest_kind: str | None = None,
    persistence: str = "embedded",
    signing: SigningSpec | None = None,
    commitment_eligible: bool = False,
    unique_by: tuple[tuple[str, tuple[str, ...]], ...] = (),
    note: str = "",
) -> TypeDecl:
    return REG.add(
        TypeDecl(
            name=name,
            kind="record",
            tag=tag,
            fields=tuple(fields),
            digest_kind=digest_kind,
            persistence=persistence,
            signing=signing,
            commitment_eligible=commitment_eligible,
            unique_by=unique_by,
            note=note,
        )
    )


def union(
    name: str,
    variants: list[tuple[str, TypeExpr]],
    *,
    digest_kind: str | None = None,
    persistence: str = "embedded",
    note: str = "",
) -> TypeDecl:
    return REG.add(
        TypeDecl(
            name=name,
            kind="union",
            variants=tuple(variants),
            digest_kind=digest_kind,
            persistence=persistence,
            note=note,
        )
    )


def alias(name: str, of: TypeExpr, note: str = "") -> TypeDecl:
    return REG.add(TypeDecl(name=name, kind="alias", alias_of=of, note=note))


# ==========================================================================
# 1. foundation
# ==========================================================================

alias("Instant", INT, "signed microseconds since 1970-01-01T00:00:00Z (R-7)")

record(
    "Signature",
    "Signature/v1",
    [
        _f("alg", ATOM, "signature algorithm identifier"),
        _f("sig", BYTES, "raw signature octets"),
    ],
    note=(
        "[N4b] Carries NO signer_key_ref.  The single authoritative key reference "
        "for every signed artifact lives inside that artifact's signed body, so "
        "payload and wrapper cannot disagree."
    ),
)

record(
    "HalfOpenInterval",
    "HalfOpen/v1",
    [_f("start", Ref("Instant")), _f("end", OptOf(Ref("Instant")))],
)

record(
    "SymbolRef",
    "SymbolRef/v1",
    [_f("predicate_id", ATOM), _f("args", SeqOf(ATOM))],
    digest_kind="SYMBOL_REF",
)

record(
    "SymbolRefTemplate",
    "SymbolRefTemplate/v1",
    [_f("predicate_id", ATOM), _f("args_or_binders", SeqOf(ATOM))],
)

record("ScaledSort", "ScaledSort/v1", [_f("unit_tag", ATOM), _f("scale", INT)])
record("EnumSort", "EnumSort/v1", [_f("enum_id", ATOM)])

union(
    "Sort",
    [
        ("Bool", UNIT),
        ("Int", UNIT),
        ("Scaled", Ref("ScaledSort")),
        ("Enum", Ref("EnumSort")),
    ],
)

record("IntRange", "IntRange/v1", [_f("lo", INT), _f("hi", INT)])
record("ScaledRange", "ScaledRange/v1", [_f("lo", INT), _f("hi", INT)])
record("EnumDomain", "EnumDomain/v1", [_f("members", SeqOf(ATOM, min_count=1))])

union(
    "Domain",
    [
        ("BoolDomain", UNIT),
        ("IntRange", Ref("IntRange")),
        ("ScaledRange", Ref("ScaledRange")),
        ("EnumDomain", Ref("EnumDomain")),
    ],
)

record("VScaled", "VScaled/v1", [_f("unit_tag", ATOM), _f("scale", INT), _f("minor", INT)])
record("VEnum", "VEnum/v1", [_f("enum_id", ATOM), _f("member", ATOM)])

union(
    "Value",
    [
        ("VBool", BOOL),
        ("VInt", INT),
        ("VScaled", Ref("VScaled")),
        ("VEnum", Ref("VEnum")),
    ],
)


# ==========================================================================
# 2. expression families -- Term (domain/policy) and QTerm (solver query)
# ==========================================================================
#
# [A1] The two families are variant-name isomorphic and differ in exactly one
# place: the leaf.  `Term` has `Var(SymbolRef)` and knows nothing about worlds.
# `QTerm` has `QVar(QueryVar)` where QueryVar = (WorldSide, SymbolRef).  Their
# composite records carry distinct tags (`Bin/v1` vs `QBin/v1`, ...) so the two
# families are distinguishable at the octet level, not merely by convention.
#
# The isomorphism is machine-checked (checks.CHK_TERM_FAMILY_ISOMORPHIC), so the
# families cannot drift.

record(
    "QueryVar",
    "QueryVar/v1",
    [
        _f("side", AtomIn(WORLD_SIDES), "S = shared/known, L = left world, R = right world"),
        _f("ref", Ref("SymbolRef")),
    ],
)

#: (variant name, payload shape).  ``"@self"`` denotes the family's own type,
#: ``("@rec", suffix, [(field, shape), ...])`` an auxiliary record whose tag is
#: prefixed per family.
TERM_SHAPE: list[tuple[str, object]] = [
    ("Var", "@leaf"),
    ("LitBool", BOOL),
    ("LitInt", INT),
    ("LitScaled", Ref("VScaled")),
    ("LitEnum", Ref("VEnum")),
    ("Not", "@self"),
    ("Neg", "@self"),
    ("And", ("@seq", 2)),
    ("Or", ("@seq", 2)),
    ("Add", ("@seq", 2)),
    ("Implies", ("@rec", "Bin", ["left", "right"])),
    ("Iff", ("@rec", "Bin", ["left", "right"])),
    ("Sub", ("@rec", "Bin", ["left", "right"])),
    ("Eq", ("@rec", "Bin", ["left", "right"])),
    ("Ne", ("@rec", "Bin", ["left", "right"])),
    ("Lt", ("@rec", "Bin", ["left", "right"])),
    ("Le", ("@rec", "Bin", ["left", "right"])),
    ("Gt", ("@rec", "Bin", ["left", "right"])),
    ("Ge", ("@rec", "Bin", ["left", "right"])),
    ("MulConst", ("@mulconst", None, None)),
    ("Scale", ("@scale", None, None)),
    ("Rescale", ("@rescale", None, None)),
    ("Ite", ("@rec", "Ite", ["cond", "if_true", "if_false"])),
    ("EnumTable", ("@enumtable", None, None)),
]


#: Members of each expression family, recorded by the builder so the checks can
#: tell "a QTerm node inside the QTerm grammar" (legitimate) from "a QTerm node
#: reachable from a policy or case structure" (the [A1] defect).
TERM_FAMILY_MEMBERS: dict[str, set[str]] = {"Term": set(), "QTerm": set()}


def _build_term_family(family: str, prefix: str, leaf: TypeExpr) -> None:
    self_ref = Ref(family)
    variants: list[tuple[str, TypeExpr]] = []
    made: set[str] = set()
    members = TERM_FAMILY_MEMBERS[family]
    members.add(family)
    if prefix == "Q":
        members.add("QueryVar")

    def mk(suffix: str, fields: list[FieldDecl]) -> Ref:
        name = f"{prefix}{suffix}"
        if name not in made:
            record(name, f"{prefix}{suffix}/v1", fields)
            made.add(name)
            members.add(name)
        return Ref(name)

    for vname, shape in TERM_SHAPE:
        if isinstance(shape, TypeExpr):
            # A payload that is world-agnostic (literals) is shared verbatim.
            variants.append((vname, shape))
        elif shape == "@leaf":
            variants.append(("QVar" if prefix == "Q" else "Var", leaf))
        elif shape == "@self":
            variants.append((vname, self_ref))
        elif isinstance(shape, tuple) and shape[0] == "@seq":
            variants.append((vname, SeqOf(self_ref, min_count=shape[1])))
        elif isinstance(shape, tuple) and shape[0] == "@rec":
            _, suffix, names = shape
            variants.append((vname, mk(suffix, [_f(n, self_ref) for n in names])))
        elif isinstance(shape, tuple) and shape[0] == "@mulconst":
            variants.append((vname, mk("MulConst", [_f("k", INT), _f("a", self_ref)])))
        elif isinstance(shape, tuple) and shape[0] == "@scale":
            variants.append(
                (vname, mk("Scale", [_f("a", self_ref), _f("k", INT), _f("to", Ref("Sort"))]))
            )
        elif isinstance(shape, tuple) and shape[0] == "@rescale":
            variants.append((vname, mk("Rescale", [_f("a", self_ref), _f("to_scale", INT)])))
        elif isinstance(shape, tuple) and shape[0] == "@enumtable":
            arm = mk("Arm", [_f("member", ATOM), _f("term", self_ref)])
            variants.append(
                (
                    vname,
                    mk(
                        "EnumTable",
                        [_f("scrutinee", self_ref), _f("arms", SeqOf(arm, min_count=1))],
                    ),
                )
            )
        else:  # pragma: no cover
            raise AssertionError(f"unhandled shape {shape!r}")

    union(family, variants, digest_kind="TERM" if prefix == "" else "QUERY_TERM")


_build_term_family("Term", "", Ref("SymbolRef"))
_build_term_family("QTerm", "Q", Ref("QueryVar"))


# ==========================================================================
# 3. actions
# ==========================================================================

record("ActionField", "ActionField/v1", [_f("name", ATOM), _f("value", Ref("Value"))])

record(
    "Action",
    "Action/v1",
    [_f("kind", ATOM), _f("fields", SeqOf(Ref("ActionField")))],
    digest_kind="ACTION",
    persistence="persisted",
    commitment_eligible=True,
    unique_by=(("fields", ("name",)),),
    note=(
        "[N2] The complete deterministic policy result: EVERY field declared for "
        "`kind`, consequential and diagnostic alike, in ActionSchema declaration "
        "order.  A declared optional field that the program does not compute takes "
        "its declared `default` if Some, else its derived filler -- so absence has "
        "no representation and cannot be encoded two ways."
    ),
)

record(
    "ConsequentialAction",
    "ConsequentialAction/v1",
    [
        _f("action_schema_digest", DIGEST),
        _f("kind", ATOM),
        _f("consequential_fields", SeqOf(Ref("ActionField"))),
    ],
    digest_kind="CONSEQUENTIAL_ACTION",
    persistence="persisted",
    commitment_eligible=True,
    unique_by=(("consequential_fields", ("name",)),),
    note="[N2] The exact projection.  ONLY this type participates in Hinge equality.",
)


# ==========================================================================
# 4. schemas
# ==========================================================================

record(
    "FieldSpec",
    "FieldSpec/v1",
    [
        _f("name", ATOM),
        _f("sort", Ref("Sort")),
        _f("bounds", Ref("Domain")),
        _f("consequentiality", AtomIn(CONSEQUENTIALITY)),
        _f("required", BOOL),
        _f("default", OptOf(Ref("Value"))),
    ],
)

record(
    "ActionKindSpec",
    "ActionKindSpec/v1",
    [_f("kind", ATOM), _f("fields", SeqOf(Ref("FieldSpec")))],
    unique_by=(("fields", ("name",)),),
)

record(
    "ActionSchema",
    "ActionSchema/v1",
    [
        _f("schema_id", ATOM),
        _f("schema_version", INT),
        _f("kinds", SeqOf(Ref("ActionKindSpec"), min_count=1)),
    ],
    digest_kind="ACTION_SCHEMA",
    persistence="persisted",
    unique_by=(("kinds", ("kind",)),),
    note="[N2] `kind` is unique.  Two ActionKindSpec entries for PAY is a load error.",
)

record(
    "PredicateSpec",
    "PredicateSpec/v1",
    [
        _f("predicate_id", ATOM),
        _f("arg_kinds", SeqOf(ATOM)),
        _f("value_sort", Ref("Sort")),
        _f("domain", Ref("Domain")),
        _f("layer", AtomIn(LAYERS)),
        _f("acquisition", AtomIn(ACQUISITION_CLASSES)),
        _f("permitted_source_classes", SetOf(ATOM)),
        _f("measurement_class", OptOf(ATOM)),
    ],
)

record(
    "PredicateSchema",
    "PredicateSchema/v1",
    [_f("schema_version", INT), _f("predicates", SeqOf(Ref("PredicateSpec")))],
    digest_kind="PREDICATE_SCHEMA",
    persistence="persisted",
    unique_by=(("predicates", ("predicate_id",)),),
)


# ==========================================================================
# 5. policy artifacts
# ==========================================================================

record("FieldTerm", "FieldTerm/v1", [_f("name", ATOM), _f("term", Ref("Term"))])
record(
    "ActionTerm",
    "ActionTerm/v1",
    [_f("kind", ATOM), _f("fields", SeqOf(Ref("FieldTerm")))],
    unique_by=(("fields", ("name",)),),
)
record("ProgramRule", "ProgramRule/v1", [_f("guard", Ref("Term")), _f("action", Ref("ActionTerm"))])
record(
    "DecisionProgram",
    "DecisionProgram/v1",
    [
        _f("inputs", SeqOf(Ref("SymbolRef"))),
        _f("rules", SeqOf(Ref("ProgramRule"))),
        _f("otherwise", Ref("ActionTerm")),
    ],
    digest_kind="POLICY_PROGRAM",
    persistence="persisted",
)

record(
    "ImplicationRule",
    "ImplicationRule/v1",
    [
        _f("rule_id", ATOM),
        _f("binder_args", SeqOf(ATOM)),
        _f("conclusion", Ref("SymbolRefTemplate")),
        _f("premise", Ref("Term")),
        _f("conclusion_value", Ref("Term")),
    ],
)
record(
    "DefinitionRule",
    "DefinitionRule/v1",
    [
        _f("rule_id", ATOM),
        _f("binder_args", SeqOf(ATOM)),
        _f("conclusion", Ref("SymbolRefTemplate")),
        _f("premise", Ref("Term")),
        _f("exhaustiveness_ratification_ref", DIGEST),
    ],
)
union(
    "EntailmentRule",
    [("Implication", Ref("ImplicationRule")), ("Definition", Ref("DefinitionRule"))],
)
record(
    "EntailmentRules",
    "EntailmentRules/v1",
    [_f("schema_version", INT), _f("rules", SeqOf(Ref("EntailmentRule")))],
    digest_kind="ENTAILMENT_RULES",
    persistence="persisted",
    unique_by=(("rules", ("rule_id",)),),
)

record(
    "AdmissibilityDescriptor",
    "AdmissibilityDescriptor/v1",
    [
        _f("rule_id", ATOM),
        _f("rule_version", INT),
        _f("rule_kind", ATOM),
        _f("grouping_key", ATOM),
        _f("admissible_procedures", SetOf(ATOM)),
        _f("max_temporal_gap", INT),
        _f("ratification_ref", OptOf(DIGEST)),
    ],
    digest_kind="ADMISSIBILITY_DESCRIPTOR",
)
record(
    "AdmissibilityDescriptors",
    "AdmissibilityDescriptors/v1",
    [_f("schema_version", INT), _f("descriptors", SeqOf(Ref("AdmissibilityDescriptor")))],
    digest_kind="ADMISSIBILITY_DESCRIPTORS",
    persistence="persisted",
    unique_by=(("descriptors", ("rule_id",)),),
)

record(
    "DisclosureEntry",
    "DisclosureEntry/v1",
    [
        _f("outcome_class", AtomIn(OUTCOME_CLASSES), "[N1b] total over AnalysisOutcome"),
        _f("action_kind", OptOf(ATOM), "[N1b] Some iff outcome_class = INVARIANT"),
        _f("audience_class", ATOM),
        _f("disclosure_context", ATOM),
        _f("reveals_sensitive_input", BOOL),
        _f("inference_acknowledgement_ref", OptOf(DIGEST)),
        _f("permitted_paths", SeqOf(ATOM)),
    ],
    digest_kind="DISCLOSURE_ENTRY",
    note=(
        "[N1a] `action_disclosable` is REMOVED.  `permitted_paths` is the sole "
        "authority on what may be disclosed, so a flag and a path list can no "
        "longer contradict each other."
    ),
)
record(
    "DisclosurePolicy",
    "DisclosurePolicy/v1",
    [_f("schema_version", INT), _f("entries", SeqOf(Ref("DisclosureEntry")))],
    digest_kind="DISCLOSURE_POLICY",
    persistence="persisted",
    unique_by=(
        (
            "entries",
            ("outcome_class", "action_kind", "audience_class", "disclosure_context"),
        ),
    ),
)

record(
    "RatificationRecord",
    "RatificationRecord/v1",
    [
        _f("ratification_id", ATOM),
        _f("tenant_scope", OptOf(ATOM), "[N4c] None = shared across tenants"),
        _f("subject_kind", ATOM),
        _f("subject_ref", DIGEST),
        _f("ratified_at", Ref("Instant")),
        _f("signer_key_ref", ATOM),
        _f("signature", Ref("Signature")),
    ],
    digest_kind="RATIFICATION_RECORD",
    persistence="persisted",
    signing=SigningSpec("signature", SELF_BODY, "signer_key_ref", "RATIFICATION_RECORD_BODY"),
)
record(
    "RatificationSet",
    "RatificationSet/v1",
    [_f("schema_version", INT), _f("records", SeqOf(Ref("RatificationRecord")))],
    digest_kind="RATIFICATION_SET",
    persistence="persisted",
    unique_by=(("records", ("ratification_id",)),),
    note="[B9] The aggregate named by BundleManifest.ratification_records_digest.",
)

record(
    "BundleManifest",
    "BundleManifest/v1",
    [
        _f("manifest_schema_version", INT),
        _f("tenant_scope", OptOf(ATOM), "None = shared across tenants"),
        _f("policy_id", ATOM),
        _f("human_version", ATOM, "DISPLAY ONLY -- never resolves anything"),
        _f("effective_interval", Ref("HalfOpenInterval")),
        _f("decision_program_digest", DIGEST),
        _f("entailment_rules_digest", DIGEST),
        _f("admissibility_descriptors_digest", DIGEST),
        _f("predicate_schema_digest", DIGEST),
        _f("action_schema_digest", DIGEST),
        _f("disclosure_policy_digest", DIGEST),
        _f("ratification_records_digest", DIGEST),
        _f("ir_schema_version", INT),
        _f("interpreter_version", INT),
        _f("ratified_by", ATOM),
        _f("ratified_at", Ref("Instant")),
        _f("signer_key_ref", ATOM),
    ],
    digest_kind="MANIFEST",
    persistence="persisted",
)
record(
    "SignedManifest",
    "SignedManifest/v1",
    [_f("manifest", Ref("BundleManifest")), _f("signature", Ref("Signature"))],
    persistence="persisted",
    signing=SigningSpec("signature", "manifest", "manifest.signer_key_ref", "MANIFEST"),
)


# ==========================================================================
# 6. evidence
# ==========================================================================

record("ExactValue", "ExactValue/v1", [_f("value", Ref("Value"))])
record("ClosedLowerBound", "ClosedLowerBound/v1", [_f("bound", Ref("Value"))])
record("ClosedUpperBound", "ClosedUpperBound/v1", [_f("bound", Ref("Value"))])
record("EnumSubset", "EnumSubset/v1", [_f("allowed", SetOf(Ref("Value"), min_count=1))])

union(
    "AcquisitionRelation",
    [
        ("ExactValue", Ref("ExactValue")),
        ("ClosedLowerBound", Ref("ClosedLowerBound")),
        ("ClosedUpperBound", Ref("ClosedUpperBound")),
        ("EnumSubset", Ref("EnumSubset")),
    ],
    note=(
        "[A4] Phase-1 relation algebra, closed.  Bounds are CLOSED only -- there is "
        "no `inclusive` field because strict bounds are not supported.  `allowed` "
        "has min_count 1, so |A| = 0 is unrepresentable rather than merely rejected."
    ),
)

record(
    "AcquisitionPayload",
    "AcquisitionPayload/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("subject", ATOM),
        _f("proposition", Ref("SymbolRef")),
        _f("relation", Ref("AcquisitionRelation")),
        _f("value_sort", Ref("Sort")),
        _f("predicate_schema_digest", DIGEST),
        _f("observed_at", Ref("Instant")),
        _f("issued_at", Ref("Instant")),
        _f("validity", Ref("HalfOpenInterval")),
        _f("nonce", BytesLen(16)),
        _f("source_class", ATOM),
        _f("signer_key_ref", ATOM),
        _f("authorization_policy_version", INT),
        _f("request_id", DIGEST),
    ],
    digest_kind="ATTESTATION_PAYLOAD",
)

record(
    "VerificationReceipt",
    "VerificationReceipt/v1",
    [_f("payload", Ref("AcquisitionPayload")), _f("signature", Ref("Signature"))],
    digest_kind="VERIFICATION_RECEIPT",
    persistence="persisted",
    signing=SigningSpec("signature", "payload", "payload.signer_key_ref", "ATTESTATION_PAYLOAD"),
    note=(
        "[N4a] `revocation_snapshot` is REMOVED from the receipt.  It was an "
        "unsigned field beside a signature, so it could be swapped without "
        "invalidating anything.  Revocation is now pinned once per rebuild in "
        "AuthorizationContext, which IS inside the semantic revision."
    ),
)

record(
    "StatementRecord",
    "StatementRecord/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("claimant", ATOM),
        _f("role_in_case", ATOM),
        _f("proposition", Ref("SymbolRef")),
        _f("asserted_value", Ref("Value")),
        _f("value_sort", Ref("Sort")),
        _f("measurement_procedure_id", OptOf(ATOM)),
        _f("statement_time", Ref("Instant")),
        _f("supersedes", OptOf(DIGEST)),
        _f("signer_key_ref", ATOM),
        _f("signature", Ref("Signature")),
    ],
    digest_kind="STATEMENT",
    persistence="persisted",
    signing=SigningSpec("signature", SELF_BODY, "signer_key_ref", "STATEMENT_BODY"),
)

record(
    "InterestAssessment",
    "InterestAssessment/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("proposition", Ref("SymbolRef")),
        _f("principal_id", ATOM),
        _f("scope", ATOM),
        _f("direction", ATOM),
        _f("validity", Ref("HalfOpenInterval")),
        _f("issuer", ATOM),
        _f("supersedes", OptOf(DIGEST)),
        _f("signer_key_ref", ATOM),
        _f("signature", Ref("Signature")),
    ],
    digest_kind="INTEREST_ASSESSMENT",
    persistence="persisted",
    signing=SigningSpec("signature", SELF_BODY, "signer_key_ref", "INTEREST_ASSESSMENT_BODY"),
)

record(
    "PartyRecord",
    "PartyRecord/v1",
    [
        _f("tenant_id", ATOM),
        _f("principal_id", ATOM),
        _f("role_in_case", ATOM),
        _f("competences", SetOf(ATOM)),
    ],
)

record(
    "CaseConstructionRecord",
    "CaseConstructionRecord/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("created_at", Ref("Instant")),
        _f("subject_refs", SeqOf(ATOM)),
        _f("contract_ref", OptOf(ATOM)),
        _f("parties", SeqOf(Ref("PartyRecord"))),
        _f("declared_instances", SeqOf(Ref("SymbolRef"))),
        _f("signer_key_ref", ATOM),
        _f("signature", Ref("Signature")),
    ],
    digest_kind="CASE_CONSTRUCTION",
    persistence="persisted",
    signing=SigningSpec("signature", SELF_BODY, "signer_key_ref", "CASE_CONSTRUCTION_BODY"),
    unique_by=(("parties", ("principal_id",)),),
)

record(
    "Retraction",
    "Retraction/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM, "[N4d] without this an ALPHA/case-A retraction replays into case B"),
        _f("target", DIGEST),
        _f("at", Ref("Instant")),
        _f("signer_key_ref", ATOM),
        _f("signature", Ref("Signature")),
    ],
    signing=SigningSpec("signature", SELF_BODY, "signer_key_ref", "RETRACTION_BODY"),
)

record(
    "Declaration",
    "Declaration/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM, "[N4d]"),
        _f("instances", SeqOf(Ref("SymbolRef"), min_count=1)),
        _f("at", Ref("Instant")),
        _f("signer_key_ref", ATOM),
        _f("signature", Ref("Signature")),
    ],
    signing=SigningSpec("signature", SELF_BODY, "signer_key_ref", "DECLARATION_BODY"),
)

record(
    "TranscriptPrefix",
    "TranscriptPrefix/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("entry_digests", SeqOf(DIGEST), "ascending by digest octets, never by arrival"),
    ],
    digest_kind="TRANSCRIPT_PREFIX",
    persistence="derived",
    note=(
        "[B9] Gives TRANSCRIPT_PREFIX a declared preimage.  Phase 0.7 named the "
        "digest kind but described its input only in prose, so the ordering rule "
        "and the tenant/case binding were not part of anything checkable."
    ),
)

union(
    "TranscriptEntry",
    [
        ("Attestation", Ref("VerificationReceipt")),
        ("Statement", Ref("StatementRecord")),
        ("Retraction", Ref("Retraction")),
        ("Declaration", Ref("Declaration")),
    ],
    digest_kind="TRANSCRIPT_ENTRY",
    persistence="persisted",
)


# ==========================================================================
# 7. case state
# ==========================================================================

record("AttestedBy", "AttestedBy/v1", [_f("receipt_digest", DIGEST)])
record(
    "EntailedBy",
    "EntailedBy/v1",
    [
        _f("manifest_digest", DIGEST),
        _f("modality", AtomIn(MODALITIES)),
        _f("derivation_mode", AtomIn(DERIVATION_MODES), "[A2] selects the E-5 check"),
        _f("rule_ids", SeqOf(ATOM, min_count=1), "[B4c] ALL cited rules, canonical order"),
        _f("premise_digests", SeqOf(DIGEST), "[A2] digests of the EstablishedFacts read"),
    ],
)
union("Justification", [("AttestedBy", Ref("AttestedBy")), ("EntailedBy", Ref("EntailedBy"))])

record(
    "EstablishedFact",
    "EstablishedFact/v1",
    [
        _f("ref", Ref("SymbolRef")),
        _f("value", Ref("Value")),
        _f("justification", Ref("Justification")),
    ],
    digest_kind="ESTABLISHED_FACT",
    commitment_eligible=True,
    note="[A2] Digested so EntailedBy.premise_digests has a defined preimage.",
)

record("StructuralDeriv", "StructuralDeriv/v1", [_f("predicate_schema_digest", DIGEST)])
record(
    "AdverseDeriv",
    "AdverseDeriv/v1",
    [
        _f("rule_version", INT),
        _f("sources", SeqOf(DIGEST)),
        _f("dependencies", SeqOf(DIGEST)),
        _f("descriptor_digest", DIGEST),
    ],
)
record(
    "BracketDeriv",
    "BracketDeriv/v1",
    [
        _f("rule_version", INT),
        _f("sources", SeqOf(DIGEST)),
        _f("dependencies", SeqOf(DIGEST)),
        _f("descriptor_digest", DIGEST),
    ],
)
record(
    "StipulationDeriv",
    "StipulationDeriv/v1",
    [_f("rule_version", INT), _f("statement_digests", SeqOf(DIGEST, min_count=1))],
)
record(
    "AttestedRelationDeriv",
    "AttestedRelationDeriv/v1",
    [_f("rule_version", INT), _f("receipt_digest", DIGEST)],
)
record(
    "PolicyEntailmentDeriv",
    "PolicyEntailmentDeriv/v1",
    [
        _f("manifest_digest", DIGEST),
        _f("modality", AtomIn(MODALITIES)),
        _f("rule_ids", SeqOf(ATOM, min_count=1)),
        _f("ratification_ref", OptOf(DIGEST)),
    ],
)
union(
    "ConstraintDerivation",
    [
        ("Structural", Ref("StructuralDeriv")),
        ("InterestAdverseBound", Ref("AdverseDeriv")),
        ("OpposedBracket", Ref("BracketDeriv")),
        ("PartyStipulation", Ref("StipulationDeriv")),
        ("AttestedRelation", Ref("AttestedRelationDeriv")),
        ("PolicyEntailment", Ref("PolicyEntailmentDeriv")),
    ],
)

record(
    "Constraint",
    "Constraint/v1",
    [
        _f(
            "label",
            AtomMax(100),
            "embedded in the derived assertion label \"C:\" || label || \":L\", which "
            "must itself be a valid ATOM",
        ),
        _f("formula", Ref("Term"), "[A1] Term, never QTerm -- no world qualification here"),
        _f("derivation", Ref("ConstraintDerivation")),
    ],
    digest_kind="CONSTRAINT",
    commitment_eligible=True,
)

record(
    "NonEffect",
    "NonEffect/v1",
    [
        _f("rule_id", ATOM),
        _f("rule_version", INT),
        _f("subject", ATOM),
        _f("reason", ATOM),
    ],
    commitment_eligible=True,
)

record(
    "AuthorizationContext",
    "AuthorizationContext/v1",
    [
        _f("authorization_policy_version", INT),
        _f("key_registry_snapshot_digest", DIGEST),
        _f("revocation_snapshot_digest", DIGEST),
        _f("context_validity", Ref("HalfOpenInterval")),
    ],
    digest_kind="AUTHORIZATION_CONTEXT",
    persistence="persisted",
    note=(
        "[A3/N4a] The external, mutable authority state that rebuild consults, "
        "pinned by digest so rebuild is a pure function of its declared inputs."
    ),
)

record(
    "RebuildInputs",
    "RebuildInputs/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("construction_digest", DIGEST),
        _f("transcript_prefix_digest", DIGEST),
        _f("bundle_manifest_digest", DIGEST),
        _f("as_of", Ref("Instant")),
        _f("mode", AtomIn(REBUILD_MODES)),
        _f("authorization_context_digest", DIGEST),
    ],
    digest_kind="REBUILD_INPUTS",
    persistence="derived",
    note="[A3] The COMPLETE semantic input tuple.  rebuild(RebuildInputs, store) is pure.",
)

record(
    "CaseRevision",
    "CaseRevision/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("construction_digest", DIGEST),
        _f("transcript_prefix_digest", DIGEST),
        _f("bundle_pin", DIGEST),
        _f("as_of", Ref("Instant")),
        _f("mode", AtomIn(REBUILD_MODES), "[A3] semantic: effectivity differs by mode"),
        _f("authorization_context_digest", DIGEST, "[A3] semantic: revocation changes results"),
        _f("authorizability", AtomIn(AUTHORIZABILITY)),
        _f("declared", SeqOf(Ref("SymbolRef"))),
        _f("established", SeqOf(Ref("EstablishedFact"))),
        _f("constraints", SeqOf(Ref("Constraint"))),
        _f("non_effects", SeqOf(Ref("NonEffect"))),
    ],
    digest_kind="CASE_REVISION",
    persistence="persisted",
    unique_by=(
        # Each key here MUST match paths.DYNAMIC_SOURCES: a dynamic commitment
        # path is injective only if its source collection is unique by exactly
        # the fields the path segment digests.
        ("established", ("ref",)),
        ("constraints", ("label",)),
        ("non_effects", ("rule_id", "subject")),
    ),
)

record(
    "RevisionLineage",
    "RevisionLineage/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("revision_semantic_digest", DIGEST),
        _f("revision_number", INT),
        _f("parent_digest", OptOf(DIGEST)),
        _f("published_at", Ref("Instant")),
        _f("signer_key_ref", ATOM),
        _f("signature", Ref("Signature")),
    ],
    digest_kind="REVISION_LINEAGE",
    persistence="persisted",
    signing=SigningSpec("signature", SELF_BODY, "signer_key_ref", "REVISION_LINEAGE_BODY"),
    note=(
        "Not semantic -- excluded from CASE_REVISION bytes -- but authenticated, so "
        "the chronology cannot be rewritten while the semantic digest stays valid."
    ),
)


# ==========================================================================
# 8. analysis
# ==========================================================================

record("Binding", "Binding/v1", [_f("ref", Ref("SymbolRef")), _f("value", Ref("Value"))])
record(
    "World",
    "World/v1",
    [_f("bindings", SeqOf(Ref("Binding")))],
    digest_kind="WORLD",
    commitment_eligible=True,
    unique_by=(("bindings", ("ref",)),),
)

record(
    "QueryDecl",
    "QueryDecl/v1",
    [
        _f("side", AtomIn(WORLD_SIDES)),
        _f("ref", Ref("SymbolRef")),
        _f("sort", Ref("Sort")),
        _f("domain", Ref("Domain")),
    ],
)
record(
    "LabeledAssertion",
    "LabeledAssertion/v1",
    [_f("label", AtomMax(120)), _f("formula", Ref("QTerm"))],
    note=(
        "[A1] `side` is REMOVED.  A whole-formula side label cannot express a "
        "cross-world assertion; world qualification now lives on the leaf."
    ),
)
record(
    "EnumDeclaration",
    "EnumDeclaration/v1",
    [_f("enum_id", ATOM), _f("members", SeqOf(ATOM, min_count=1))],
    note=(
        "[A1] Every enum a query mentions -- in a declared sort or in any LitEnum -- "
        "must appear here.  Without it an enum literal has no canonical index, so "
        "two conforming backends can disagree about what the same octets denote, or "
        "fail to lower them at all."
    ),
)

record(
    "SolverQuery",
    "SolverQuery/v1",
    [
        _f("kind", AtomIn(QUERY_KINDS)),
        _f("logical_case_digest", DIGEST),
        _f("enums", SeqOf(Ref("EnumDeclaration"))),
        _f("declarations", SeqOf(Ref("QueryDecl"))),
        _f("assertions", SeqOf(Ref("LabeledAssertion"))),
    ],
    digest_kind="SOLVER_QUERY",
    persistence="derived",
    unique_by=(
        ("enums", ("enum_id",)),
        ("declarations", ("side", "ref")),
        ("assertions", ("label",)),
    ),
)

record(
    "SolverFingerprint",
    "SolverFingerprint/v1",
    [
        _f("backend", ATOM),
        _f("version", ATOM),
        _f("seed", INT),
        _f("logic", ATOM),
        _f("budget", INT),
    ],
)

record(
    "TruncatedReachable",
    "TruncatedReachable/v1",
    [_f("sample", SetOf(Ref("ConsequentialAction"))), _f("cap", INT)],
)
union(
    "ReachableActions",
    [
        ("Exact", SetOf(Ref("ConsequentialAction"))),
        ("Truncated", Ref("TruncatedReachable")),
        ("NotComputed", ATOM),
    ],
)

record(
    "DeletionWitness",
    "DeletionWitness/v1",
    [_f("member", Ref("SymbolRef")), _f("left", Ref("World")), _f("right", Ref("World"))],
)
record(
    "ProvenSupport",
    "ProvenSupport/v1",
    [
        _f("members", SeqOf(Ref("SymbolRef"))),
        _f("sufficiency_handle", DIGEST),
        _f("deletion_witnesses", SeqOf(Ref("DeletionWitness"))),
    ],
)
record(
    "UnprovenSupport",
    "UnprovenSupport/v1",
    [
        _f("members", SeqOf(Ref("SymbolRef"))),
        _f("inconclusive", SeqOf(Ref("SymbolRef"))),
        _f("reasons", SeqOf(ATOM)),
    ],
)
union(
    "SupportResult",
    [
        ("ProvenIrredundantSupport", Ref("ProvenSupport")),
        ("SufficientSupportIrredundanceUnproved", Ref("UnprovenSupport")),
    ],
)

record(
    "InvariantOutcome",
    "InvariantOutcome/v1",
    [
        _f("action", Ref("ConsequentialAction")),
        _f("witness", Ref("World")),
        _f("invariance_query_digest", DIGEST),
    ],
)
record(
    "DivergentOutcome",
    "DivergentOutcome/v1",
    [
        _f("reachable", Ref("ReachableActions")),
        _f("left", Ref("World")),
        _f("right", Ref("World")),
    ],
)
record("InfeasibleOutcome", "InfeasibleOutcome/v1", [_f("contributing", SeqOf(ATOM))])
record("IndeterminateOutcome", "IndeterminateOutcome/v1", [_f("reason", ATOM)])
union(
    "AnalysisOutcome",
    [
        ("Invariant", Ref("InvariantOutcome")),
        ("Divergent", Ref("DivergentOutcome")),
        ("Infeasible", Ref("InfeasibleOutcome")),
        ("Indeterminate", Ref("IndeterminateOutcome")),
    ],
)

record(
    "LogicalCase",
    "LogicalCase/v1",
    [
        _f("universe", SeqOf(Ref("SymbolRef"))),
        _f("known", SeqOf(Ref("EstablishedFact"))),
        _f("constraints", SeqOf(Ref("Constraint"))),
        _f("decision_program_digest", DIGEST),
        _f("action_schema_digest", DIGEST),
        _f("predicate_schema_digest", DIGEST),
    ],
    digest_kind="LOGICAL_CASE",
    persistence="derived",
    note="[B9] The object KernelAnalysisRecord.logical_case_digest names.",
)

record(
    "KernelAnalysisRecord",
    "KernelAnalysisRecord/v1",
    [
        _f("logical_case_digest", DIGEST),
        _f("outcome", Ref("AnalysisOutcome")),
        _f("query_digests", SeqOf(DIGEST)),
        _f("fingerprint", Ref("SolverFingerprint")),
        _f("determinism_class", ATOM),
    ],
    digest_kind="KERNEL_ANALYSIS_RECORD",
    persistence="persisted",
)

record(
    "EvidenceTarget",
    "EvidenceTarget/v1",
    [
        _f("proposition", Ref("SymbolRef")),
        _f("acquisition_class", AtomIn(ACQUISITION_CLASSES)),
        _f("permitted_source_classes", SetOf(ATOM, min_count=1)),
    ],
)
record(
    "EvidenceRequest",
    "EvidenceRequest/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("revision_semantic_digest", DIGEST),
        _f("targets", SeqOf(Ref("EvidenceTarget"), min_count=1)),
    ],
    digest_kind="EVIDENCE_REQUEST",
    persistence="persisted",
    unique_by=(("targets", ("proposition",)),),
    note="[B9] request_id in AcquisitionPayload is digest(EVIDENCE_REQUEST, canonical(this)).",
)
record(
    "HumanEscalation",
    "HumanEscalation/v1",
    [_f("reason", ATOM), _f("unacquirable", SeqOf(Ref("SymbolRef"), min_count=1))],
)
union(
    "PlanningOutcome",
    [
        ("NoActionRequired", UNIT),
        ("EvidenceRequested", Ref("EvidenceRequest")),
        ("NoSufficientSetAcquirable", Ref("HumanEscalation")),
        ("PlanningIndeterminate", ATOM),
    ],
    note="[B9] The variants PlanningRecord.planning_outcome may take.  H9 escalation included.",
)
record(
    "PlanningRecord",
    "PlanningRecord/v1",
    [
        _f("planning_outcome", Ref("PlanningOutcome")),
        _f("support", OptOf(Ref("SupportResult"))),
    ],
)

record(
    "DiagnosticAnnex",
    "DiagnosticAnnex/v1",
    [
        _f("notes", SeqOf(ATOM)),
        _f("query_digests", SeqOf(DIGEST)),
        _f("solver_log_ref", OptOf(ATOM)),
    ],
    digest_kind="DIAGNOSTIC_ANNEX",
    persistence="persisted",
    note="[B9] Diagnostic only.  Never read by any decision or authorisation path (D1).",
)

record(
    "AnalysisCertificate",
    "AnalysisCertificate/v1",
    [
        _f("certificate_schema_version", INT),
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("revision_semantic_digest", DIGEST),
        _f("bundle_manifest_digest", DIGEST),
        _f("kernel", Ref("KernelAnalysisRecord")),
        _f("planning", Ref("PlanningRecord")),
        _f("diagnostic_annex_digest", OptOf(DIGEST)),
    ],
    digest_kind="ANALYSIS_CERTIFICATE",
    persistence="persisted",
)

record(
    "InternalAnalysisRecord",
    "InternalAnalysisRecord/v1",
    [
        _f("certificate", Ref("AnalysisCertificate")),
        _f("revision", Ref("CaseRevision")),
        _f("full_action", OptOf(Ref("Action"))),
        _f("salt_case", BytesLen(32)),
    ],
    digest_kind="INTERNAL_ANALYSIS_RECORD",
    persistence="persisted",
    note="Never crosses the trust boundary.  salt_case never leaves it at all.",
)


# ==========================================================================
# 9. commitments and disclosure
# ==========================================================================

record(
    "CommitmentLeaf",
    "CommitmentLeaf/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_commitment", DIGEST, "[B11] SALTED -- not the raw case digest"),
        _f("revision_commitment", DIGEST, "[B11] SALTED -- not revision_semantic_digest"),
        _f("certificate_schema_version", INT),
        _f("path", ATOM),
        _f("salt", BytesLen(32)),
        _f("value_bytes", BYTES, "canonical encoding of ANY registry type"),
    ],
    digest_kind="MERKLE_LEAF",
    persistence="derived",
)

record(
    "CommitmentRoot",
    "CommitmentRoot/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("revision_commitment", DIGEST),
        _f("bundle_manifest_digest", DIGEST),
        _f("certificate_schema_version", INT),
        _f("leaf_count", INT),
        _f("merkle", BytesLen(32)),
    ],
    digest_kind="MERKLE_ROOT",
    persistence="derived",
)

record("ProofStep", "ProofStep/v1", [_f("side", AtomIn(PROOF_SIDES)), _f("sibling", BytesLen(32))])

record(
    "CommitmentEnvelope",
    "CommitmentEnvelope/v1",
    [
        _f("tenant_id", ATOM),
        _f("case_id", ATOM),
        _f("case_commitment", DIGEST),
        _f("revision_commitment", DIGEST),
        _f("bundle_manifest_digest", DIGEST),
        _f("disclosure_policy_digest", DIGEST),
        _f("certificate_schema_version", INT),
        _f("leaf_count", INT),
        _f("root", BytesLen(32)),
        _f("signer_key_ref", ATOM),
    ],
    digest_kind="COMMITMENT_ENVELOPE",
    persistence="persisted",
)
record(
    "SignedCommitmentEnvelope",
    "SignedCommitmentEnvelope/v1",
    [_f("envelope", Ref("CommitmentEnvelope")), _f("signature", Ref("Signature"))],
    persistence="persisted",
    signing=SigningSpec("signature", "envelope", "envelope.signer_key_ref", "COMMITMENT_ENVELOPE"),
    note=(
        "[B8] Restores authenticity.  Merkle consistency alone proves only that a "
        "view is internally consistent, not that MUSTER produced it."
    ),
)

record(
    "Disclosure",
    "Disclosure/v1",
    [
        _f("path", ATOM),
        _f("value_bytes", BYTES),
        _f("salt", BytesLen(32)),
        _f("proof", SeqOf(Ref("ProofStep"))),
    ],
)

record(
    "ParticipantView",
    "ParticipantView/v1",
    [
        _f("envelope", Ref("SignedCommitmentEnvelope")),
        _f("audience_class", ATOM),
        _f("disclosure_context", ATOM),
        _f("disclosure_entry_digest", DIGEST),
        _f("disclosures", SeqOf(Ref("Disclosure"))),
        _f("inference_notice", OptOf(ATOM)),
    ],
    digest_kind="PARTICIPANT_VIEW",
    persistence="persisted",
    unique_by=(("disclosures", ("path",)),),
)

record(
    "AuditorView",
    "AuditorView/v1",
    [
        _f("envelope", Ref("SignedCommitmentEnvelope")),
        _f("audience_class", ATOM),
        _f("disclosure_context", ATOM),
        _f("disclosure_entry_digest", DIGEST),
        _f("disclosures", SeqOf(Ref("Disclosure"))),
    ],
    digest_kind="AUDITOR_VIEW",
    persistence="persisted",
    unique_by=(("disclosures", ("path",)),),
)


# ==========================================================================
# 10. generated signing-body types
# ==========================================================================
#
# [B5] Every artifact whose signature covers "the record itself" gets an
# explicitly declared body type, generated here from the parent declaration by
# deleting exactly the signature field.  The body has its own record tag and its
# own digest kind, so the signed preimage is a first-class, inspectable type
# rather than an informal "the record minus the signature" convention -- and an
# implementation cannot quietly disagree about what was covered.

def _generate_signing_bodies() -> None:
    pending = [d for d in REG if d.signing is not None and d.signing.body == SELF_BODY]
    for decl in pending:
        spec = decl.signing
        assert spec is not None
        assert decl.tag is not None
        base = decl.tag.split("/")[0]
        record(
            f"{decl.name}Body",
            f"{base}Body/v1",
            [_f(f.name, f.type, f.note) for f in decl.fields if f.name != spec.signature_field],
            digest_kind=spec.domain,
            persistence="derived",
            unique_by=decl.unique_by,
            note=f"Signed preimage of {decl.name}.  Generated: {decl.name} minus `{spec.signature_field}`.",
        )


_generate_signing_bodies()
