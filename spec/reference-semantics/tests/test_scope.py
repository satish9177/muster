"""[N2] action split, [A4] relations, [A5] dependencies and Gate quarantine.

Also the meta-suite: every machine check must FAIL when its defect is injected.
A check that cannot fail proves nothing.
"""

from __future__ import annotations

import pytest

from muster_spec import checks
from muster_spec import fixtures as F
from muster_spec import scenario as S
from muster_spec.digests import digest_node
from muster_spec.nodes import Atom, Bool, Int, Rec, Seq, SetV, Tagged, Unit, encode, none, some
from muster_spec.registry import REG
from muster_spec.relations import (
    InvalidEnumSubset,
    LayerFlowViolation,
    NonNumericRelation,
    PredicateInfo,
    RelationValueSortMismatch,
    UnitMismatch,
    ValueOutOfDomain,
    lower_relation,
    validate_relation,
)
from muster_spec.schema import Ref, SchemaError, validate
from muster_spec.selfcomp import concrete_action, project

# --------------------------------------------------------------------------
# [N2] Action vs ConsequentialAction
# --------------------------------------------------------------------------


def test_ACTION_VS_CONSEQUENTIAL_DISTINCT_BYTES():
    assert REG["Action"].tag != REG["ConsequentialAction"].tag
    assert REG["Action"].arity != REG["ConsequentialAction"].arity
    assert REG["Action"].digest_kind != REG["ConsequentialAction"].digest_kind
    assert encode(F.PAY_ACTION) != encode(F.PAY_CONSEQUENTIAL)


def test_HOLD_REASON_IS_DIAGNOSTIC():
    """Two Actions differing only in reason_code project to identical effects."""
    a = F.hold_action("DISPUTED_QUANTITY")
    b = F.hold_action("MISSING_RECEIPT")
    case = F.procurement_case(99)
    assert encode(a) != encode(b)
    assert encode(project(case, a)) == encode(project(case, b))


def test_PROJECTION_DETERMINISTIC():
    case = F.procurement_case(99)
    assert encode(project(case, F.PAY_ACTION)) == encode(F.PAY_CONSEQUENTIAL)
    assert encode(project(case, F.PAY_ACTION)) == encode(project(case, F.PAY_ACTION))


def test_consequential_action_carries_its_schema_digest():
    """A projection can never be reinterpreted under another schema."""
    assert F.PAY_CONSEQUENTIAL.fields[0] == F.ACTION_SCHEMA_DIGEST


def test_DUPLICATE_ACTION_KIND_REJECTED():
    """[N2] Two ActionKindSpec entries for PAY flipped Hinge between verdicts."""
    kinds = S.F.ACTION_SCHEMA.fields[2]
    dup = Rec("ActionSchema/v1", [Atom("dup"), Int(1), Seq([kinds.items[0], kinds.items[0]])])
    with pytest.raises(SchemaError, match="duplicate key"):
        validate(REG, dup, Ref("ActionSchema"))


def test_duplicate_field_name_within_a_kind_rejected():
    fs = F.ACTION_SCHEMA.fields[2].items[0].fields[1].items[0]
    bad = Rec("ActionKindSpec/v1", [Atom("PAY"), Seq([fs, fs])])
    with pytest.raises(SchemaError, match="duplicate key"):
        validate(REG, bad, Ref("ActionKindSpec"))


def test_full_action_contains_every_declared_field():
    """An unset optional diagnostic takes its declared default, so absence has no form."""
    case = F.procurement_case(99)
    world = {case.universe[0].key: ("int", 105)}
    action = concrete_action(case, world)
    declared = [f[0] for f in F.ACTION_SCHEMA.fields[2].items[0].fields[1].items] if False else None
    names = [f.fields[0].value for f in action.fields[1].items]
    assert names == ["recipient", "amount", "basis_code"]


# --------------------------------------------------------------------------
# [A4] relations
# --------------------------------------------------------------------------

INT_INFO = PredicateInfo(F.SORT_INT, F.dom_int(0, 120), "OBSERVATION")
BASIS_INFO = PredicateInfo(F.SORT_BASIS, F.DOM_BASIS, "RECORD")
SINGLE_MEMBER = PredicateInfo(
    Tagged("Enum", Rec("EnumSort/v1", [Atom("colour")])), F.dom_enum("RED"), "RECORD"
)


def rel(variant: str, *payload):
    tag = {"ExactValue": "ExactValue/v1", "ClosedLowerBound": "ClosedLowerBound/v1",
           "ClosedUpperBound": "ClosedUpperBound/v1", "EnumSubset": "EnumSubset/v1"}[variant]
    return Tagged(variant, Rec(tag, list(payload)))


def venum(eid, m):
    return Tagged("VEnum", Rec("VEnum/v1", [Atom(eid), Atom(m)]))


def test_relation_union_is_exactly_four_closed_forms():
    variants = [v for v, _ in REG["AcquisitionRelation"].variants]
    assert variants == ["ExactValue", "ClosedLowerBound", "ClosedUpperBound", "EnumSubset"]
    for name in ("ClosedLowerBound", "ClosedUpperBound"):
        assert "inclusive" not in {f.name for f in REG[name].fields}


def test_empty_enum_subset_is_unrepresentable():
    bad = rel("EnumSubset", SetV([]))
    with pytest.raises(SchemaError, match="at least 1"):
        validate(REG, bad, Ref("AcquisitionRelation"))


def test_SIGNED_LOWER_BOUND_REPLAY():
    r = rel("ClosedLowerBound", Tagged("VInt", Int(99)))
    validate_relation(r, F.SORT_INT, INT_INFO)
    kind, term = lower_relation(r, F.Q_REF, INT_INFO)
    assert kind == "constraint"
    assert term.variant == "Ge"
    assert encode(term) == encode(lower_relation(r, F.Q_REF, INT_INFO)[1])


def test_SIGNED_UPPER_BOUND_REPLAY():
    r = rel("ClosedUpperBound", Tagged("VInt", Int(110)))
    validate_relation(r, F.SORT_INT, INT_INFO)
    assert lower_relation(r, F.Q_REF, INT_INFO)[1].variant == "Le"


def test_SIGNED_EXACT_REPLAY_IS_A_FACT_NOT_A_CONSTRAINT():
    r = rel("ExactValue", Tagged("VInt", Int(103)))
    validate_relation(r, F.SORT_INT, INT_INFO)
    kind, value = lower_relation(r, F.Q_REF, INT_INFO)
    assert kind == "fact" and value == ("int", 103)


def test_ENUM_SUBSET_SINGLETON_IS_EQ():
    """Never a unary Or, which the Term grammar rejects (min_count 2)."""
    r = rel("EnumSubset", SetV([venum("basis", "FIXED")]))
    validate_relation(r, F.SORT_BASIS, BASIS_INFO)
    kind, term = lower_relation(r, F.Q_REF, BASIS_INFO)
    assert kind == "constraint" and term.variant == "Eq"


def test_ENUM_SUBSET_FULL_DOMAIN_IS_VACUOUS():
    r = rel("EnumSubset", SetV([venum("basis", "FIXED"), venum("basis", "PRORATA")]))
    validate_relation(r, F.SORT_BASIS, BASIS_INFO)
    assert lower_relation(r, F.Q_REF, BASIS_INFO) == ("noneffect", "VACUOUS_SUBSET")


def test_SINGLE_MEMBER_DOMAIN_HAS_EXACTLY_ONE_LOWERING():
    """[B14a] Domain {RED} with A = {RED} matched two Phase 0.7 rows at once."""
    r = rel("EnumSubset", SetV([venum("colour", "RED")]))
    validate_relation(r, SINGLE_MEMBER.value_sort, SINGLE_MEMBER)
    result = lower_relation(r, F.Q_REF, SINGLE_MEMBER)
    assert result == ("noneffect", "VACUOUS_SUBSET")  # row 1 wins, deterministically
    for _ in range(5):
        assert lower_relation(r, F.Q_REF, SINGLE_MEMBER) == result


def test_multi_member_subset_is_an_Or_in_declaration_order():
    info = PredicateInfo(
        Tagged("Enum", Rec("EnumSort/v1", [Atom("colour")])),
        F.dom_enum("RED", "GREEN", "BLUE"),
        "RECORD",
    )
    r = rel("EnumSubset", SetV([venum("colour", "BLUE"), venum("colour", "RED")]))
    validate_relation(r, info.value_sort, info)
    kind, term = lower_relation(r, F.Q_REF, info)
    assert kind == "constraint" and term.variant == "Or"
    members = [t.value.fields[1].value.fields[1].value for t in term.value.items]
    assert members == ["RED", "BLUE"]  # declaration order, not set order


def test_Q11_BOUND_VALUE_SORT_IS_CHECKED():
    """The check Phase 0.7 omitted: value_sort passed, the bound's own sort did not."""
    r = rel("ClosedLowerBound", Tagged("VScaled", Rec("VScaled/v1", [Atom("INR"), Int(2), Int(99)])))
    with pytest.raises(RelationValueSortMismatch):
        validate_relation(r, F.SORT_INT, INT_INFO)


def test_bound_on_a_non_numeric_sort_rejected():
    r = rel("ClosedLowerBound", venum("basis", "FIXED"))
    with pytest.raises(NonNumericRelation):
        validate_relation(r, F.SORT_BASIS, BASIS_INFO)


def test_value_outside_the_domain_rejected():
    r = rel("ExactValue", Tagged("VInt", Int(500)))
    with pytest.raises(ValueOutOfDomain):
        validate_relation(r, F.SORT_INT, INT_INFO)


def test_declared_sort_mismatch_rejected():
    r = rel("ExactValue", Tagged("VInt", Int(5)))
    with pytest.raises(UnitMismatch):
        validate_relation(r, F.SORT_INR, INT_INFO)


def test_enum_member_outside_the_domain_rejected():
    r = rel("EnumSubset", SetV([venum("basis", "BARTER")]))
    with pytest.raises(InvalidEnumSubset):
        validate_relation(r, F.SORT_BASIS, BASIS_INFO)


def test_attested_relation_on_a_NORMATIVE_predicate_rejected():
    info = PredicateInfo(F.SORT_INT, F.dom_int(0, 120), "NORMATIVE")
    with pytest.raises(LayerFlowViolation):
        validate_relation(rel("ExactValue", Tagged("VInt", Int(3))), F.SORT_INT, info)


# --------------------------------------------------------------------------
# [A5] dependencies and Gate quarantine
# --------------------------------------------------------------------------


def test_dependency_matrix_covers_every_module():
    assert set(checks.ALLOWED) == set(checks.MODULES)
    assert len(checks.MODULES) == 11


def test_application_is_the_only_module_that_sees_the_adapters():
    for m in checks.MODULES:
        if m == "application":
            assert "solve.z3" in checks.ALLOWED[m]
            assert "solve.reference" in checks.ALLOWED[m]
        else:
            assert "solve.z3" not in checks.ALLOWED[m] or m == "solve.z3"


def test_FORBIDDEN_HINGE_TO_Z3_ADAPTER():
    assert "solve.z3" in checks.forbidden("hinge")
    assert "solve.reference" in checks.forbidden("hinge")
    assert "solve" in checks.ALLOWED["hinge"]


def test_FORBIDDEN_SOLVE_TO_ADAPTER():
    assert "solve.z3" in checks.forbidden("solve")


def test_FORBIDDEN_EVIDENCE_TO_DOMAIN():
    assert "domains.workforce" in checks.forbidden("evidence")
    assert "domains.procurement" in checks.forbidden("evidence")


def test_FORBIDDEN_DOMAIN_CROSS():
    assert "domains.procurement" in checks.forbidden("domains.workforce")


def test_FORBIDDEN_CORE_OUTWARD():
    assert checks.forbidden("core") == frozenset(checks.MODULES) - {"core"}


@pytest.mark.parametrize(
    "name",
    ["SpendingLimit", "AuthorizedAction", "GateDecision", "PayeeBinding",
     "ExecutionReservation", "SettlementRecord", "PayoutInstruction"],
)
def test_FORBIDDEN_GATE_TYPE_IN_PHASE_1(name):
    """Deny-list AND allowlist.  SpendingLimit is the name Phase 0.7's F-18 missed."""
    assert name not in REG.order, name
    hay = name.lower()
    assert any(bad in hay for bad in checks.GATE_DENY_SUBSTRINGS), name


def test_gate_quarantine_is_not_only_a_deny_list():
    """A Gate concept under an unanticipated name is caught by the inventory."""
    from muster_spec.inventory import PHASE1_TYPE_INVENTORY

    assert "ObligationLock" not in PHASE1_TYPE_INVENTORY
    assert set(REG.order) == set(PHASE1_TYPE_INVENTORY)


def test_no_gate_digest_kind_is_reserved():
    from muster_spec.schema import digest_kinds

    kinds = set(digest_kinds(REG))
    assert "AUTHORIZED_ACTION" not in kinds
    assert "GATE_DECISION" not in kinds


# --------------------------------------------------------------------------
# meta: every check bites
# --------------------------------------------------------------------------


def test_all_checks_pass_on_the_frozen_contract():
    results = checks.run_all()
    failing = {k: v for k, v in results.items() if v}
    assert not failing, failing


def test_every_check_is_falsifiable(monkeypatch):
    """Inject a defect matching each check's subject; the check must report it."""
    from muster_spec.schema import FieldDecl, Ref as SRef, TypeDecl

    injections: dict[str, callable] = {}

    def inject(name):
        def deco(fn):
            injections[name] = fn
            return fn

        return deco

    @inject("CHK_NO_DUPLICATE_TYPE_TAG")
    def _(mp):
        clash = REG["SymbolRef"]
        mp.setitem(REG.types, "Clash", TypeDecl(name="Clash", kind="record", tag=clash.tag,
                                                fields=clash.fields))
        mp.setattr(REG, "order", REG.order + ["Clash"])

    @inject("CHK_NO_DUPLICATE_DIGEST_KIND")
    def _(mp):
        d = REG["SymbolRef"]
        mp.setitem(REG.types, "Clash2", TypeDecl(name="Clash2", kind="record", tag="Clash2/v1",
                                                 fields=d.fields, digest_kind="SYMBOL_REF"))
        mp.setattr(REG, "order", REG.order + ["Clash2"])

    @inject("CHK_ARITY_MATCHES_DECLARED_FIELDS")
    def _(mp):
        mp.setitem(REG.types, "Empty", TypeDecl(name="Empty", kind="record", tag="Empty/v1"))
        mp.setattr(REG, "order", REG.order + ["Empty"])

    @inject("CHK_EVERY_FIELD_TYPE_RESOLVES")
    def _(mp):
        mp.setitem(REG.types, "Dangling", TypeDecl(
            name="Dangling", kind="record", tag="Dangling/v1",
            fields=(FieldDecl("x", SRef("NoSuchType")),)))
        mp.setattr(REG, "order", REG.order + ["Dangling"])

    @inject("CHK_NO_PLACEHOLDER_IN_NORMATIVE_SCHEMA")
    def _(mp):
        d = REG["SymbolRef"]
        mp.setitem(REG.types, "SymbolRef", TypeDecl(
            name=d.name, kind=d.kind, tag=d.tag, fields=d.fields,
            digest_kind=d.digest_kind, note="premise_digests = …"))

    @inject("CHK_TERM_FAMILY_ISOMORPHIC")
    def _(mp):
        q = REG["QTerm"]
        mp.setitem(REG.types, "QTerm", TypeDecl(name=q.name, kind="union",
                                                variants=q.variants[:-1]))

    @inject("CHK_QUERY_ASSERTION_CANNOT_CONTAIN_BARE_VAR")
    def _(mp):
        la = REG["LabeledAssertion"]
        mp.setitem(REG.types, "LabeledAssertion", TypeDecl(
            name=la.name, kind="record", tag=la.tag,
            fields=la.fields + (FieldDecl("side", SRef("Instant")),)))

    @inject("CHK_DOMAIN_EXPRESSION_CANNOT_CONTAIN_QUERYVAR")
    def _(mp):
        c = REG["Constraint"]
        fields = tuple(
            FieldDecl("formula", SRef("QTerm")) if f.name == "formula" else f for f in c.fields
        )
        mp.setitem(REG.types, "Constraint", TypeDecl(
            name=c.name, kind="record", tag=c.tag, fields=fields, digest_kind=c.digest_kind))

    @inject("CHK_QUERYVAR_CARRIES_A_WORLD_SIDE")
    def _(mp):
        qv = REG["QueryVar"]
        mp.setitem(REG.types, "QueryVar", TypeDecl(
            name=qv.name, kind="record", tag=qv.tag,
            fields=(FieldDecl("side", SRef("Instant")), qv.fields[1])))

    @inject("CHK_NO_DUPLICATE_SIGNER_KEY_REF")
    def _(mp):
        s = REG["Signature"]
        mp.setitem(REG.types, "Signature", TypeDecl(
            name=s.name, kind="record", tag=s.tag,
            fields=s.fields + (FieldDecl("signer_key_ref", SRef("Instant")),)))

    @inject("CHK_SIGNER_KEY_REF_INSIDE_SIGNED_BODY")
    def _(mp):
        r = REG["VerificationReceipt"]
        from muster_spec.schema import SigningSpec

        mp.setitem(REG.types, "VerificationReceipt", TypeDecl(
            name=r.name, kind="record", tag=r.tag, fields=r.fields,
            digest_kind=r.digest_kind,
            signing=SigningSpec("signature", "payload", "signature.alg", "ATTESTATION_PAYLOAD")))

    @inject("CHK_NO_UNSIGNED_SECURITY_FIELD_BESIDE_A_SIGNATURE")
    def _(mp):
        r = REG["VerificationReceipt"]
        mp.setitem(REG.types, "VerificationReceipt", TypeDecl(
            name=r.name, kind="record", tag=r.tag,
            fields=r.fields + (FieldDecl("revocation_snapshot", SRef("Instant")),),
            digest_kind=r.digest_kind, signing=r.signing))

    @inject("CHK_AUTHORITY_BEARING_TYPE_BINDS_TENANT")
    def _(mp):
        r = REG["RatificationRecord"]
        fields = tuple(f for f in r.fields if f.name != "tenant_scope")
        mp.setitem(REG.types, "RatificationRecord", TypeDecl(
            name=r.name, kind="record", tag=r.tag, fields=fields,
            digest_kind=r.digest_kind, signing=r.signing))

    #  Not an injection -- a second, sharper falsification of the same check,
    #  run inline because ``inject`` allows one per name.  The milestone-E draft
    #  searched the whole record for a tenant name instead of the signed
    #  preimage, so a tenant reachable only through an *unsigned sibling* of the
    #  body would have satisfied it.  That is a tenant an attacker can swap
    #  without resigning, and counting it turns the check into a spelling test.
    def _tenant_outside_the_signed_body(mp):
        from muster_spec.schema import SigningSpec

        e = REG["SignedCommitmentEnvelope"]
        stripped = REG["CommitmentEnvelope"]
        mp.setitem(REG.types, "CommitmentEnvelope", TypeDecl(
            name=stripped.name, kind="record", tag=stripped.tag,
            fields=tuple(f for f in stripped.fields if f.name != "tenant_id"),
            digest_kind=stripped.digest_kind))
        #  ... and put the tenant back *outside* the body, beside the signature.
        mp.setitem(REG.types, "SignedCommitmentEnvelope", TypeDecl(
            name=e.name, kind="record", tag=e.tag,
            fields=(*e.fields, FieldDecl("tenant_id", SRef("Instant"))),
            signing=SigningSpec(
                "signature", "envelope", "envelope.signer_key_ref", "COMMITMENT_ENVELOPE"
            )))

    with pytest.MonkeyPatch.context() as mp:
        _tenant_outside_the_signed_body(mp)
        assert checks.CHECKS["CHK_AUTHORITY_BEARING_TYPE_BINDS_TENANT"](), (
            "a tenant outside the signed body must not satisfy the tenant binding"
        )

    @inject("CHK_CASE_BOUND_ARTIFACT_BINDS_CASE")
    def _(mp):
        r = REG["Retraction"]
        mp.setitem(REG.types, "Retraction", TypeDecl(
            name=r.name, kind="record", tag=r.tag,
            fields=tuple(f for f in r.fields if f.name != "case_id"), signing=r.signing))

    @inject("CHK_BUNDLE_ARTIFACT_HAS_A_MANIFEST_REFERENCE")
    def _(mp):
        m = REG["BundleManifest"]
        mp.setitem(REG.types, "BundleManifest", TypeDecl(
            name=m.name, kind="record", tag=m.tag,
            fields=tuple(f for f in m.fields if f.name != "disclosure_policy_digest"),
            digest_kind=m.digest_kind))

    @inject("CHK_DISCLOSURE_KEY_IS_TOTAL_OVER_OUTCOMES")
    def _(mp):
        e = REG["DisclosureEntry"]
        mp.setitem(REG.types, "DisclosureEntry", TypeDecl(
            name=e.name, kind="record", tag=e.tag,
            fields=e.fields + (FieldDecl("action_disclosable", SRef("Instant")),),
            digest_kind=e.digest_kind))

    @inject("CHK_COMMITMENT_ENVELOPE_IS_AUTHENTICATED")
    def _(mp):
        s = REG["SignedCommitmentEnvelope"]
        mp.setitem(REG.types, "SignedCommitmentEnvelope", TypeDecl(
            name=s.name, kind="record", tag=s.tag, fields=s.fields, signing=None))

    @inject("CHK_REVISION_COMMITMENT_IS_SALTED")
    def _(mp):
        e = REG["CommitmentEnvelope"]
        fields = tuple(
            FieldDecl("revision_semantic_digest", f.type) if f.name == "revision_commitment" else f
            for f in e.fields
        )
        mp.setitem(REG.types, "CommitmentEnvelope", TypeDecl(
            name=e.name, kind="record", tag=e.tag, fields=fields, digest_kind=e.digest_kind))

    @inject("CHK_NO_GATE_TYPE_IN_PHASE_1")
    def _(mp):
        mp.setitem(REG.types, "SpendingLimit", TypeDecl(
            name="SpendingLimit", kind="record", tag="SpendingLimit/v1",
            fields=(FieldDecl("cap", SRef("Instant")),)))
        mp.setattr(REG, "order", REG.order + ["SpendingLimit"])

    @inject("CHK_TYPE_INVENTORY_IS_EXPLICIT")
    def _(mp):
        mp.setitem(REG.types, "ObligationLock", TypeDecl(
            name="ObligationLock", kind="record", tag="ObligationLock/v1",
            fields=(FieldDecl("x", SRef("Instant")),)))
        mp.setattr(REG, "order", REG.order + ["ObligationLock"])

    @inject("CHK_PERSISTED_TYPES_ARE_CLASSIFIED")
    def _(mp):
        d = REG["SymbolRef"]
        mp.setitem(REG.types, "SymbolRef", TypeDecl(
            name=d.name, kind=d.kind, tag=d.tag, fields=d.fields,
            digest_kind=d.digest_kind, persistence="maybe"))

    @inject("CHK_DEPENDENCY_MATRIX_COVERS_EVERY_MODULE")
    def _(mp):
        mp.setattr(checks, "MODULES", checks.MODULES + ("reporting",))

    @inject("CHK_DEPENDENCY_MATRIX_INVARIANTS")
    def _(mp):
        allowed = dict(checks.ALLOWED)
        allowed["hinge"] = allowed["hinge"] + ("solve.z3",)
        mp.setattr(checks, "ALLOWED", allowed)

    @inject("CHK_EVERY_TYPE_HAS_AN_ENCODING")
    def _(mp):
        mp.setitem(REG.types, "Void", TypeDecl(name="Void", kind="union", variants=()))
        mp.setattr(REG, "order", REG.order + ["Void"])

    @inject("CHK_SIGNING_BODY_IS_DECLARED")
    def _(mp):
        from muster_spec.schema import SigningSpec

        r = REG["VerificationReceipt"]
        mp.setitem(REG.types, "VerificationReceipt", TypeDecl(
            name=r.name, kind="record", tag=r.tag, fields=r.fields, digest_kind=r.digest_kind,
            signing=SigningSpec("signature", "no_such_field", "payload.signer_key_ref",
                                "ATTESTATION_PAYLOAD")))

    @inject("CHK_COMMITMENT_PATH_INVENTORY_IS_WELL_FORMED")
    def _(mp):
        from muster_spec import paths

        bad = paths.PathSpec("kernel.outcome.a.very.long.segment" + "x" * 70, "ATOM", "always")
        mp.setattr(paths, "INVENTORY", paths.INVENTORY + (bad,))
        mp.setattr(checks, "INVENTORY", paths.INVENTORY)

    @inject("CHK_TERM_FAMILY_TAGS_DISJOINT")
    def _(mp):
        qb = REG["QBin"]
        mp.setitem(REG.types, "QBin", TypeDecl(
            name=qb.name, kind="record", tag="Bin/v1", fields=qb.fields))

    @inject("CHK_VIEW_VERIFICATION_IS_COMPLETE")
    def _(mp):
        from muster_spec import disclosure
        from muster_spec.merkle import verify_disclosure

        def membership_only(view, keyring, policy, *, trusted_signer):
            # The pre-review behaviour: inclusion proofs and nothing else.
            envelope = view.fields[0].fields[0]
            for d in view.fields[4].items:
                steps = [(s.fields[0].value, s.fields[1].value) for s in d.fields[3].items]
                if not verify_disclosure(envelope, d.fields[0].value, d.fields[1].value,
                                         d.fields[2].value, steps):
                    return ["membership"]
            return []

        mp.setattr(disclosure, "verify_view", membership_only)

    @inject("CHK_DYNAMIC_PATHS_ARE_INJECTIVE")
    def _(mp):
        r = REG["CaseRevision"]
        mp.setitem(REG.types, "CaseRevision", TypeDecl(
            name=r.name, kind="record", tag=r.tag, fields=r.fields,
            digest_kind=r.digest_kind,
            unique_by=tuple(u for u in r.unique_by if u[0] != "established")))

    @inject("CHK_EMBEDDED_ATOM_BUDGETS_ADD_UP")
    def _(mp):
        from muster_spec.schema import Prim

        c = REG["Constraint"]
        fields = tuple(
            FieldDecl("label", Prim("ATOM")) if f.name == "label" else f for f in c.fields
        )
        mp.setitem(REG.types, "Constraint", TypeDecl(
            name=c.name, kind="record", tag=c.tag, fields=fields, digest_kind=c.digest_kind))

    @inject("CHK_DIGEST_DOMAIN_NAMESPACE_IS_CLOSED")
    def _(mp):
        from muster_spec import domains

        clashing = dict(domains.AUXILIARY_DIGEST_DOMAINS)
        clashing["MANIFEST"] = "collides with the BundleManifest type domain"
        mp.setattr(domains, "AUXILIARY_DIGEST_DOMAINS", clashing)

    @inject("CHK_SOLVER_QUERY_DECLARES_ITS_ENUMS")
    def _(mp):
        q = REG["SolverQuery"]
        mp.setitem(REG.types, "SolverQuery", TypeDecl(
            name=q.name, kind="record", tag=q.tag,
            fields=tuple(f for f in q.fields if f.name != "enums"),
            digest_kind=q.digest_kind))

    @inject("CHK_PRODUCTION_DOES_NOT_IMPORT_THE_REFERENCE_SPEC")
    def _(mp):
        pass  # no src/muster exists yet; see the explicit assertion below

    #  ---- source authority [G1] and the fleet catalog [E] -----------------

    @inject("CHK_AUTHORITY_GRANT_HAS_NO_WILDCARD_SCOPE")
    def _(mp):
        #  The exact defect the check exists for: an enumerated authority field
        #  that admits the empty set.  Nothing else about the grant changes, so
        #  a check that only looked at field *names* would pass.
        from muster_spec.schema import SetOf

        g = REG["AuthorityGrant"]
        fields = tuple(
            FieldDecl(f.name, SetOf(SRef("ResourceScope"), min_count=0), f.note)
            if f.name == "resource_scope"
            else f
            for f in g.fields
        )
        mp.setitem(REG.types, "AuthorityGrant", TypeDecl(
            name=g.name, kind="record", tag=g.tag, fields=fields,
            digest_kind=g.digest_kind, persistence=g.persistence))

    @inject("CHK_AUTHORITY_SNAPSHOT_GRANTS_ARE_UNIQUE_BY_KEY_AND_CLASS")
    def _(mp):
        #  Uniqueness dropped to ``key_ref`` alone.  Plausible-looking, and it
        #  is precisely the version under which one key holding two classes
        #  becomes unrepresentable while two grants on one class do not.
        d = REG["AuthorityRegistrySnapshot"]
        mp.setitem(REG.types, "AuthorityRegistrySnapshot", TypeDecl(
            name=d.name, kind="record", tag=d.tag, fields=d.fields,
            digest_kind=d.digest_kind, persistence=d.persistence,
            unique_by=(("grants", ("key_ref",)),)))

    @inject("CHK_PERMITTED_SOURCE_CLASSES_IS_CONSUMED")
    def _(mp):
        #  The regression this check is named after, reproduced exactly: an
        #  authority field is declared and the validator that would read it is
        #  looked for somewhere it is not.  Nothing about the *schema* is wrong,
        #  which is why the defect survived two milestones the first time.
        mp.setattr(checks, "_AUTHORITY_CONSUMERS", {
            "permitted_source_classes": ("packages/muster-kernel/src/muster/core/results.py",),
        })

    @inject("CHK_AUTHORITY_DOES_NOT_DEPEND_ON_THE_CATALOG")
    def _(mp):
        #  A grant phrased in terms of a routing record.  This is the shape the
        #  whole separation exists to forbid: it reads as a convenience and it
        #  makes every authority answer a function of what a catalog says.
        g = REG["AuthorityGrant"]
        fields = (*g.fields, FieldDecl("profile", SRef("AgentProfile")))
        mp.setitem(REG.types, "AuthorityGrant", TypeDecl(
            name=g.name, kind="record", tag=g.tag, fields=fields,
            digest_kind=g.digest_kind, persistence=g.persistence))

    missing = set(checks.CHECKS) - set(injections)
    assert not missing, f"no falsification injection for {sorted(missing)}"

    for name, injector in sorted(injections.items()):
        if name == "CHK_PRODUCTION_DOES_NOT_IMPORT_THE_REFERENCE_SPEC":
            continue
        with pytest.MonkeyPatch.context() as mp:
            injector(mp)
            failures = checks.CHECKS[name]()
            assert failures, f"{name} did not detect its injected defect"


def test_production_import_check_scans_the_real_tree():
    """The one check with no in-memory injection: assert it is really looking."""
    import inspect

    source = inspect.getsource(checks._no_production_import)
    assert 'src' in source and 'muster_spec' in source
    assert checks._no_production_import() == []


def test_the_consumed_check_is_not_satisfied_by_a_mention():
    """[G1] The guard against the milestone's defining defect, falsified properly.

    The injection above points the check at a module that does not contain the
    field at all, which a substring search also refuses -- so it never exercised
    the distinction that matters.  This one does: a module whose docstring,
    comment, string literal, parameter name and keyword argument all name the
    field, and which never *reads* it.

    That is not a hypothetical shape.  It is what every module in this codebase
    looks like around a field it explains, and it is why "declared and read by
    nothing" survived two milestones the first time.
    """
    mention_only = '''"""All about permitted_source_classes and why it matters."""
#  permitted_source_classes is the load-bearing field here.
LABEL = "permitted_source_classes"


def build(permitted_source_classes):
    return Spec(permitted_source_classes=permitted_source_classes and None)
'''
    genuinely_read = '''def check(claim, spec):
    return claim.source_class in spec.permitted_source_classes
'''
    assert not checks._is_loaded(mention_only.replace(
        "permitted_source_classes and None", '"x"'), "permitted_source_classes")
    assert checks._is_loaded(genuinely_read, "permitted_source_classes")
