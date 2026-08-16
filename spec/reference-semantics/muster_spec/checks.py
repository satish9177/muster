"""Machine checks over the frozen contract.

NON-PRODUCTION SPECIFICATION MATERIAL.

Each check returns a list of failure strings.  An empty list is a pass.  The
suite is the mechanical replacement for prose review of the wire surface: the
defect family B9/B10/B11/N1/N2/N4 survived two hand-written correction rounds
precisely because arity, preimage, coverage and uniqueness properties are not
things prose review reliably catches.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Iterable

from .nodes import ATOM_RE, Atom, Node, Rec, Seq, Tagged, encode
from .paths import DYNAMIC_SOURCES, INVENTORY, SEGMENT_RE, path_in_inventory
from .registry import REG, TERM_SHAPE
from .schema import (
    AtomIn,
    AtomMax,
    BytesLen,
    OptOf,
    Prim,
    Ref,
    Registry,
    SELF_BODY,
    SeqOf,
    SetOf,
    TypeDecl,
    TypeExpr,
    digest_kinds,
    render_grammar,
    render_type,
)

Check = Callable[[], list[str]]
CHECKS: dict[str, Check] = {}


def check(name: str) -> Callable[[Check], Check]:
    def wrap(fn: Check) -> Check:
        CHECKS[name] = fn
        return fn

    return wrap


# --------------------------------------------------------------------------
# structural integrity of the registry
# --------------------------------------------------------------------------


@check("CHK_NO_DUPLICATE_TYPE_TAG")
def _dup_tags() -> list[str]:
    seen: dict[str, str] = {}
    out = []
    for d in REG:
        if d.kind != "record":
            continue
        assert d.tag is not None
        if d.tag in seen:
            out.append(f"tag {d.tag!r} claimed by {seen[d.tag]} and {d.name}")
        seen[d.tag] = d.name
    return out


@check("CHK_NO_DUPLICATE_DIGEST_KIND")
def _dup_digest_kinds() -> list[str]:
    seen: dict[str, str] = {}
    out = []
    for d in REG:
        if not d.digest_kind:
            continue
        if d.digest_kind in seen:
            out.append(f"digest kind {d.digest_kind} claimed by {seen[d.digest_kind]} and {d.name}")
        seen[d.digest_kind] = d.name
    return out


@check("CHK_EVERY_TYPE_HAS_AN_ENCODING")
def _every_type_encodable() -> list[str]:
    out = []
    for d in REG:
        if d.kind == "record" and not d.tag:
            out.append(f"{d.name}: record without a tag")
        if d.kind == "union" and not d.variants:
            out.append(f"{d.name}: union without variants")
        if d.kind == "alias" and d.alias_of is None:
            out.append(f"{d.name}: alias without a target")
    return out


@check("CHK_EVERY_FIELD_TYPE_RESOLVES")
def _fields_resolve() -> list[str]:
    out = []

    def walk(expr: TypeExpr, where: str) -> None:
        if isinstance(expr, Ref):
            if expr.name not in REG:
                out.append(f"{where}: unknown type {expr.name!r}")
        elif isinstance(expr, (SeqOf, SetOf, OptOf)):
            walk(expr.element, where)
        elif isinstance(expr, AtomIn):
            if not expr.vocabulary:
                out.append(f"{where}: empty ATOM vocabulary")
            for v in expr.vocabulary:
                if not ATOM_RE.match(v):
                    out.append(f"{where}: vocabulary member {v!r} violates the ATOM alphabet")
        elif isinstance(expr, AtomMax):
            if not (1 <= expr.max_length <= 128):
                out.append(f"{where}: ATOM maximum {expr.max_length} outside 1..128")
        elif isinstance(expr, BytesLen):
            if expr.length <= 0:
                out.append(f"{where}: non-positive BYTES length")
        elif not isinstance(expr, Prim):
            out.append(f"{where}: unrecognised type expression {expr!r}")

    for d in REG:
        for f in d.fields:
            walk(f.type, f"{d.name}.{f.name}")
        for vname, vtype in d.variants:
            walk(vtype, f"{d.name}<{vname}>")
        if d.alias_of is not None:
            walk(d.alias_of, d.name)
    return out


@check("CHK_ARITY_MATCHES_DECLARED_FIELDS")
def _arity() -> list[str]:
    out = []
    for d in REG:
        if d.kind != "record":
            continue
        if d.arity != len(d.fields):
            out.append(f"{d.name}: declared arity {d.arity} != {len(d.fields)} fields")
        if d.arity == 0:
            out.append(f"{d.name}: zero-arity record -- use UNIT instead")
        names = [f.name for f in d.fields]
        if len(set(names)) != len(names):
            out.append(f"{d.name}: duplicate field names {names}")
    return out


PLACEHOLDER_PATTERNS = (
    "…",  # horizontal ellipsis
    "...",
    "TBD",
    "TODO",
    "implementation-defined",
    "implementation defined",
    "equivalent representation",
    "or similar",
    "etc.",
)
ANGLE_PLACEHOLDER = re.compile(r"<[a-z_]+>")


@check("CHK_NO_PLACEHOLDER_IN_NORMATIVE_SCHEMA")
def _no_placeholders() -> list[str]:
    out = []
    surface = [("grammar", render_grammar(REG))]
    for d in REG:
        surface.append((f"{d.name}.note", d.note))
        for f in d.fields:
            surface.append((f"{d.name}.{f.name}.note", f.note))
    for where, text in surface:
        for pat in PLACEHOLDER_PATTERNS:
            if pat in text:
                out.append(f"{where}: contains placeholder {pat!r}")
        m = ANGLE_PLACEHOLDER.search(text)
        if m:
            out.append(f"{where}: contains angle placeholder {m.group(0)!r}")
    return out


# --------------------------------------------------------------------------
# [A1] world qualification
# --------------------------------------------------------------------------


@check("CHK_TERM_FAMILY_ISOMORPHIC")
def _term_iso() -> list[str]:
    t = [v for v, _ in REG["Term"].variants]
    q = [v for v, _ in REG["QTerm"].variants]
    out = []
    if len(t) != len(q):
        out.append(f"Term has {len(t)} variants, QTerm has {len(q)}")
    for a, b in zip(t, q):
        if a != b and not (a == "Var" and b == "QVar"):
            out.append(f"variant mismatch: Term.{a} vs QTerm.{b}")
    if t[0] != "Var" or q[0] != "QVar":
        out.append("the leaf variant must be Term.Var / QTerm.QVar")
    return out


@check("CHK_TERM_FAMILY_TAGS_DISJOINT")
def _term_tags_disjoint() -> list[str]:
    """Policy IR and query IR must be distinguishable at the octet level."""
    out = []
    for name in REG.order:
        d = REG[name]
        if d.kind != "record" or not d.tag:
            continue
        if name.startswith("Q") and f"{name[1:]}" in REG:
            twin = REG[name[1:]]
            if twin.kind == "record" and twin.tag == d.tag:
                out.append(f"{name} and {twin.name} share the record tag {d.tag!r}")
    return out


@check("CHK_DOMAIN_EXPRESSION_CANNOT_CONTAIN_QUERYVAR")
def _no_qvar_in_term() -> list[str]:
    out = []
    term_variants = {v for v, _ in REG["Term"].variants}
    if "QVar" in term_variants:
        out.append("Term declares a QVar variant: policy IR must not know worlds")
    # QTerm may appear inside its own grammar and in exactly one other place:
    # LabeledAssertion.formula.  Anywhere else means world qualification has
    # leaked into a policy, case or evidence structure.
    from .registry import TERM_FAMILY_MEMBERS

    q_family = TERM_FAMILY_MEMBERS["QTerm"]
    for d in REG:
        if d.name in q_family:
            continue
        for f in d.fields:
            if isinstance(f.type, Ref) and f.type.name in ("QTerm", "QueryVar"):
                if (d.name, f.name) != ("LabeledAssertion", "formula"):
                    out.append(f"{d.name}.{f.name}: {f.type.name} outside a SolverQuery assertion")
        for vname, vtype in d.variants:
            if isinstance(vtype, Ref) and vtype.name in ("QTerm", "QueryVar"):
                out.append(f"{d.name}<{vname}>: {vtype.name} outside the query grammar")
    return out


@check("CHK_QUERY_ASSERTION_CANNOT_CONTAIN_BARE_VAR")
def _no_var_in_qterm() -> list[str]:
    out = []
    q_variants = {v for v, _ in REG["QTerm"].variants}
    if "Var" in q_variants:
        out.append("QTerm declares a bare Var variant: query leaves must be world-qualified")
    la = REG["LabeledAssertion"]
    ftypes = {f.name: f.type for f in la.fields}
    if not (isinstance(ftypes.get("formula"), Ref) and ftypes["formula"].name == "QTerm"):
        out.append("LabeledAssertion.formula must be QTerm")
    if "side" in ftypes:
        out.append(
            "LabeledAssertion still carries a whole-formula `side`: a cross-world "
            "assertion cannot be expressed that way"
        )
    return out


@check("CHK_QUERYVAR_CARRIES_A_WORLD_SIDE")
def _qvar_side() -> list[str]:
    qv = REG["QueryVar"]
    out = []
    names = [f.name for f in qv.fields]
    if names != ["side", "ref"]:
        out.append(f"QueryVar fields must be (side, ref), got {names}")
    side = qv.fields[0].type
    if not isinstance(side, AtomIn) or set(side.vocabulary) != {"S", "L", "R"}:
        out.append("QueryVar.side must be a closed vocabulary {S, L, R}")
    return out


@check("CHK_VIEW_VERIFICATION_IS_COMPLETE")
def _view_verification_complete() -> list[str]:
    """Reader-side verification must check provenance and redaction, not only membership.

    Found by adversarial review.  The earlier `verify_view` checked inclusion
    proofs alone, so it accepted (a) a view whose envelope signature was invalid,
    and (b) a view disclosing seven paths beyond the entry it named, including
    `kernel.outcome.tag` and `kernel.outcome.reachable` to a WAREHOUSE audience.
    Every leaf proved membership, so nothing objected.

    This is BEHAVIOURAL: it builds both counterexamples and requires rejection.
    """
    from . import fixtures as F
    from . import scenario as S
    from .digests import digest_node
    from .disclosure import build_participant_view, resolve_entry, verify_view
    from .nodes import Atom, Bytes, Rec, Seq, none

    out: list[str] = []
    trust = dict(keyring=F.KEYRING, policy=S.DISCLOSURE_POLICY)

    def check_view(v: Rec) -> list[str]:
        return verify_view(v, trust["keyring"], trust["policy"], trusted_signer="key-muster-1")

    if check_view(S.WAREHOUSE_VIEW):
        out.append("an honest view is rejected")

    forged = Rec(
        "SignedCommitmentEnvelope/v1",
        [S.COMMITMENT_ENVELOPE, Rec("Signature/v1", [Atom("HMAC-SHA256-SPEC-STANDIN"), Bytes(bytes(32))])],
    )
    if not check_view(Rec("ParticipantView/v1", [forged, *S.WAREHOUSE_VIEW.fields[1:]])):
        out.append("an unauthenticated envelope is accepted: membership is not provenance")

    wh = resolve_entry(S.DISCLOSURE_POLICY, S.OUTCOME, "WAREHOUSE", "NOTIFICATION")
    over = build_participant_view(
        S.TREE, S.SIGNED_ENVELOPE, S.AUDITOR_DIVERGENT, "WAREHOUSE", "NOTIFICATION", None
    )
    mislabelled = Rec(
        "ParticipantView/v1",
        [over.fields[0], Atom("WAREHOUSE"), Atom("NOTIFICATION"),
         digest_node("DISCLOSURE_ENTRY", wh), over.fields[4], none()],
    )
    if not check_view(mislabelled):
        out.append("over-disclosure beyond the named entry is accepted")
    return out


@check("CHK_DYNAMIC_PATHS_ARE_INJECTIVE")
def _dynamic_paths_injective() -> list[str]:
    """A dynamic commitment path is only injective if its source collection is.

    `CaseRevision.established` and `.non_effects` carried no uniqueness rule, so
    two schema-valid members mapped to one path.  The extractor built a dict, so
    one leaf was silently dropped: the tree committed to less than the whole
    authoritative record while `leaf_count` stayed internally consistent, and
    nothing detected it.

    Checking the two known cases is not enough -- this asserts the general
    property, so a NEW dynamic path cannot reintroduce the same defect.
    """
    out = []
    prefixes = {spec.path for spec in INVENTORY if spec.dynamic}

    for prefix in sorted(prefixes):
        if prefix not in DYNAMIC_SOURCES:
            out.append(f"dynamic path {prefix!r} declares no source collection")
    for prefix in sorted(DYNAMIC_SOURCES):
        if prefix not in prefixes:
            out.append(f"DYNAMIC_SOURCES names {prefix!r}, which is not a dynamic inventory path")

    for prefix, (owner, coll, keys, domain) in sorted(DYNAMIC_SOURCES.items()):
        if owner not in REG:
            out.append(f"{prefix}: unknown owning type {owner}")
            continue
        decl = REG[owner]
        if coll not in {f.name for f in decl.fields}:
            out.append(f"{prefix}: {owner} has no field {coll!r}")
            continue
        declared_keys = dict(decl.unique_by).get(coll)
        if declared_keys is None:
            out.append(
                f"{prefix}: {owner}.{coll} declares NO uniqueness constraint, so two "
                f"members can share one commitment path and a leaf is silently dropped"
            )
        elif tuple(declared_keys) != tuple(keys):
            out.append(
                f"{prefix}: path segment digests {keys} but {owner}.{coll} is unique "
                f"by {tuple(declared_keys)} -- the two must be identical"
            )
        member_type = None
        for f in decl.fields:
            if f.name == coll and isinstance(f.type, (SeqOf, SetOf)):
                inner = f.type.element
                if isinstance(inner, Ref):
                    member_type = REG[inner.name]
        if member_type is None:
            out.append(f"{prefix}: cannot resolve the member type of {owner}.{coll}")
        else:
            names = {f.name for f in member_type.fields}
            for k in keys:
                if k not in names:
                    out.append(f"{prefix}: key field {k!r} is not a field of {member_type.name}")
        if domain not in set(digest_kinds(REG)) | set(_aux_domains()):
            out.append(f"{prefix}: segment domain {domain} is not declared")
    return out


def _aux_domains() -> set[str]:
    from .domains import AUXILIARY_DIGEST_DOMAINS

    return set(AUXILIARY_DIGEST_DOMAINS)


@check("CHK_EMBEDDED_ATOM_BUDGETS_ADD_UP")
def _atom_budgets() -> list[str]:
    """An atom that is embedded in a longer atom must leave room for the wrapper.

    `Constraint.label` was a plain ATOM, so a legal 128-character label produced
    the 132-character assertion label `"C:" || label || ":L"` -- a valid input
    that the encoder cannot represent.
    """
    out = []
    constraint_label = next(f for f in REG["Constraint"].fields if f.name == "label")
    assertion_label = next(f for f in REG["LabeledAssertion"].fields if f.name == "label")
    if not isinstance(constraint_label.type, AtomMax):
        out.append("Constraint.label is unbounded but is embedded in an assertion label")
        return out
    if not isinstance(assertion_label.type, AtomMax):
        out.append("LabeledAssertion.label is unbounded")
        return out
    # "C:" + label + ":L"
    if constraint_label.type.max_length + 4 > assertion_label.type.max_length:
        out.append(
            f"C-label budget: {constraint_label.type.max_length} + 4 exceeds "
            f"LabeledAssertion.label maximum {assertion_label.type.max_length}"
        )
    # "DOM:S:" + 64 hex, "FIX:" + 64 hex, "K:" + 64 hex
    for prefix, width in (("DOM:S:", 64), ("FIX:", 64), ("K:", 64)):
        if len(prefix) + width > assertion_label.type.max_length:
            out.append(f"{prefix} label exceeds the assertion-label maximum")
    if assertion_label.type.max_length > 128:
        out.append("LabeledAssertion.label maximum exceeds the ATOM limit of 128")
    return out


@check("CHK_DIGEST_DOMAIN_NAMESPACE_IS_CLOSED")
def _digest_namespace_closed() -> list[str]:
    """Domain separation is worthless unless the namespace is closed.

    Seven domains -- MERKLE_NODE, CASE_COMMITMENT, REVISION_COMMITMENT,
    KEY_REGISTRY_SNAPSHOT, REVOCATION_SNAPSHOT, TRANSCRIPT_PREFIX and the tooling
    corpus domain -- were in use while only type-owned kinds were declared, so
    nothing prevented an auxiliary domain from colliding with a type domain.
    """
    import re

    from .domains import AUXILIARY_DIGEST_DOMAINS

    type_kinds = set(digest_kinds(REG))
    aux = set(AUXILIARY_DIGEST_DOMAINS)
    out = []

    overlap = type_kinds & aux
    if overlap:
        out.append(f"domains claimed by both a type and AUXILIARY: {sorted(overlap)}")

    for name, preimage in AUXILIARY_DIGEST_DOMAINS.items():
        if not preimage.strip():
            out.append(f"auxiliary domain {name} documents no preimage")

    declared = type_kinds | aux
    pattern = re.compile(
        r'(?:digest|digest_bytes|digest_node|commitment|dynamic_segment)\(\s*"([A-Z_0-9]+)"'
    )
    for src in sorted(Path(__file__).resolve().parent.glob("*.py")):
        for m in pattern.finditer(src.read_text(encoding="utf-8")):
            if m.group(1) not in declared:
                out.append(f"{src.name}: undeclared digest domain {m.group(1)!r}")
    return out


@check("CHK_SOLVER_QUERY_DECLARES_ITS_ENUMS")
def _query_enums() -> list[str]:
    """An enum literal has no canonical index unless the query binds the order.

    Surfaced by the Z3 lowering: `LitEnum(party_id, SUP-12)` appears in the action
    disequality of a query whose only declared variable is an Int, so nothing in
    the octets said what integer SUP-12 denotes.  Two conforming backends could
    have disagreed, or -- as here -- failed to lower it at all.
    """
    q = REG["SolverQuery"]
    names = [f.name for f in q.fields]
    out = []
    if "enums" not in names:
        out.append("SolverQuery does not bind the member order of the enums it mentions")
        return out
    if "EnumDeclaration" not in REG:
        out.append("no EnumDeclaration type")
        return out
    keys = dict(q.unique_by)
    if keys.get("enums") != ("enum_id",):
        out.append("SolverQuery.enums is not unique by enum_id")
    members = next(f for f in REG["EnumDeclaration"].fields if f.name == "members")
    if not isinstance(members.type, SeqOf) or members.type.min_count < 1:
        out.append("EnumDeclaration.members may be empty")
    return out


# --------------------------------------------------------------------------
# [B5] signing
# --------------------------------------------------------------------------

SECURITY_CRITICAL = ("tenant_id", "case_id", "signer_key_ref", "nonce", "validity")


@check("CHK_SIGNING_BODY_IS_DECLARED")
def _signing_body_declared() -> list[str]:
    out = []
    kinds = digest_kinds(REG)
    for d in REG:
        spec = d.signing
        if spec is None:
            continue
        names = [f.name for f in d.fields]
        if spec.signature_field not in names:
            out.append(f"{d.name}: signature field {spec.signature_field!r} does not exist")
        if spec.domain not in kinds:
            out.append(f"{d.name}: signing domain {spec.domain} is not a declared digest kind")
        if spec.body == SELF_BODY:
            body_name = f"{d.name}Body"
            if body_name not in REG:
                out.append(f"{d.name}: no generated body type {body_name}")
            else:
                body = REG[body_name]
                expected = [n for n in names if n != spec.signature_field]
                got = [f.name for f in body.fields]
                if expected != got:
                    out.append(f"{body_name}: fields {got} != parent minus signature {expected}")
        elif spec.body not in names:
            out.append(f"{d.name}: signing body field {spec.body!r} does not exist")
    return out


@check("CHK_SIGNER_KEY_REF_INSIDE_SIGNED_BODY")
def _key_inside_body() -> list[str]:
    out = []
    for d in REG:
        spec = d.signing
        if spec is None:
            continue
        head = spec.key_ref_path.split(".")[0]
        if spec.body == SELF_BODY:
            if head == spec.signature_field:
                out.append(f"{d.name}: signer key reference lives inside the signature wrapper")
        elif head != spec.body:
            out.append(
                f"{d.name}: signer key reference {spec.key_ref_path!r} is outside the "
                f"signed body {spec.body!r}"
            )
    return out


@check("CHK_NO_DUPLICATE_SIGNER_KEY_REF")
def _no_dup_key_ref() -> list[str]:
    """[N4b] Signature must not restate an identity the body already binds."""
    sig = REG["Signature"]
    return [
        f"Signature.{f.name}: the wrapper must not carry signer identity"
        for f in sig.fields
        if "key" in f.name or "signer" in f.name
    ]


@check("CHK_NO_UNSIGNED_SECURITY_FIELD_BESIDE_A_SIGNATURE")
def _no_unsigned_security_field() -> list[str]:
    """[N4a] A security field outside the signed body is swappable."""
    out = []
    for d in REG:
        spec = d.signing
        if spec is None or spec.body == SELF_BODY:
            continue
        for f in d.fields:
            if f.name in (spec.signature_field, spec.body):
                continue
            if any(k in f.name for k in ("tenant", "revocation", "signer", "nonce", "key")):
                out.append(
                    f"{d.name}.{f.name}: security-critical field sits outside the "
                    f"signed body {spec.body!r} and can be swapped without resigning"
                )
    return out


@check("CHK_AUTHORITY_BEARING_TYPE_BINDS_TENANT")
def _tenant_binding() -> list[str]:
    out = []
    for d in REG:
        if d.signing is None:
            continue
        names = {f.name for f in d.fields}
        if d.signing.body != SELF_BODY:
            inner = REG[d.signing.body] if d.signing.body in REG else None
            body_type = next(
                (f.type for f in d.fields if f.name == d.signing.body), None
            )
            if isinstance(body_type, Ref):
                names |= {f.name for f in REG[body_type.name].fields}
        if not ({"tenant_id", "tenant_scope"} & names):
            out.append(f"{d.name}: signed artifact binds no tenant")
    return out


@check("CHK_CASE_BOUND_ARTIFACT_BINDS_CASE")
def _case_binding() -> list[str]:
    """[N4d] A case-scoped signed artifact without case_id replays across cases."""
    case_scoped = ("Retraction", "Declaration", "StatementRecord", "InterestAssessment")
    out = []
    for name in case_scoped:
        names = {f.name for f in REG[name].fields}
        if "case_id" not in names:
            out.append(f"{name}: case-scoped signed artifact carries no case_id")
    return out


# --------------------------------------------------------------------------
# bundles, disclosure, commitments
# --------------------------------------------------------------------------


@check("CHK_BUNDLE_ARTIFACT_HAS_A_MANIFEST_REFERENCE")
def _bundle_refs() -> list[str]:
    manifest = REG["BundleManifest"]
    referenced = {f.name for f in manifest.fields if f.name.endswith("_digest")}
    required = {
        "decision_program_digest",
        "entailment_rules_digest",
        "admissibility_descriptors_digest",
        "predicate_schema_digest",
        "action_schema_digest",
        "disclosure_policy_digest",
        "ratification_records_digest",
    }
    return [f"BundleManifest is missing {m}" for m in sorted(required - referenced)]


@check("CHK_DISCLOSURE_KEY_IS_TOTAL_OVER_OUTCOMES")
def _disclosure_key_total() -> list[str]:
    entry = REG["DisclosureEntry"]
    out = []
    names = [f.name for f in entry.fields]
    if "action_disclosable" in names:
        out.append("DisclosureEntry.action_disclosable can contradict permitted_paths")
    oc = entry.fields[0].type
    outcomes = {v for v, _ in REG["AnalysisOutcome"].variants}
    expected = {"INVARIANT", "DIVERGENT", "INFEASIBLE", "INDETERMINATE"}
    if not isinstance(oc, AtomIn) or set(oc.vocabulary) != expected:
        out.append(f"DisclosureEntry.outcome_class must cover exactly {sorted(expected)}")
    if len(outcomes) != len(expected):
        out.append("AnalysisOutcome variants and outcome_class vocabulary disagree in size")
    if not REG["DisclosurePolicy"].unique_by:
        out.append("DisclosurePolicy declares no uniqueness constraint")
    return out


@check("CHK_COMMITMENT_PATH_INVENTORY_IS_WELL_FORMED")
def _path_inventory() -> list[str]:
    out = []
    seen = set()
    for spec in INVENTORY:
        if spec.path in seen:
            out.append(f"duplicate inventory path {spec.path!r}")
        seen.add(spec.path)
        for seg in spec.path.split("."):
            if not SEGMENT_RE.match(seg):
                out.append(f"illegal segment {seg!r} in {spec.path!r}")
        if not spec.type_name:
            out.append(f"{spec.path}: no declared type")
        if spec.presence not in ("always", "INVARIANT", "DIVERGENT", "INFEASIBLE", "INDETERMINATE"):
            out.append(f"{spec.path}: unknown presence {spec.presence!r}")
    for variant in ("INVARIANT", "DIVERGENT", "INFEASIBLE", "INDETERMINATE"):
        if not any(s.presence == variant for s in INVENTORY):
            out.append(f"no committed path is specific to {variant}")
    return out


@check("CHK_COMMITMENT_ENVELOPE_IS_AUTHENTICATED")
def _envelope_signed() -> list[str]:
    out = []
    signed = REG["SignedCommitmentEnvelope"]
    if signed.signing is None:
        out.append("[B8] CommitmentEnvelope has no signature: internal consistency is not authenticity")
    env = {f.name for f in REG["CommitmentEnvelope"].fields}
    for required in ("tenant_id", "case_id", "case_commitment", "revision_commitment",
                     "bundle_manifest_digest", "disclosure_policy_digest",
                     "certificate_schema_version", "leaf_count", "root", "signer_key_ref"):
        if required not in env:
            out.append(f"CommitmentEnvelope is missing {required}")
    return out


@check("CHK_REVISION_COMMITMENT_IS_SALTED")
def _revision_salted() -> list[str]:
    """[B11] A raw semantic digest in a participant-visible field is an oracle."""
    out = []
    for name in ("CommitmentEnvelope", "CommitmentLeaf"):
        names = {f.name for f in REG[name].fields}
        if "revision_semantic_digest" in names:
            out.append(
                f"{name}.revision_semantic_digest is unsalted: a participant who can "
                f"enumerate candidate inputs can rebuild and compare"
            )
        if "revision_commitment" not in names:
            out.append(f"{name} does not bind a revision commitment")
    return out


# --------------------------------------------------------------------------
# scope: no Gate types
# --------------------------------------------------------------------------

GATE_DENY_SUBSTRINGS = (
    "authorizedaction",
    "gatedecision",
    "holddisposition",
    "payeebinding",
    "payeeregistry",
    "authorization_id",
    "authorizationid",
    "reservation",
    "settlement",
    "spendinglimit",
    "spending_limit",
    "executionreservation",
    "finality",
    "disbursement",
    "payout",
)


@check("CHK_NO_GATE_TYPE_IN_PHASE_1")
def _no_gate_types() -> list[str]:
    out = []
    for d in REG:
        hay = d.name.lower()
        for bad in GATE_DENY_SUBSTRINGS:
            if bad in hay:
                out.append(f"type {d.name} matches Gate-quarantine term {bad!r}")
        for f in d.fields:
            fh = f.name.lower()
            for bad in GATE_DENY_SUBSTRINGS:
                if bad in fh:
                    out.append(f"field {d.name}.{f.name} matches Gate-quarantine term {bad!r}")
    for kind in digest_kinds(REG):
        for bad in GATE_DENY_SUBSTRINGS:
            if bad in kind.lower().replace("_", ""):
                out.append(f"digest kind {kind} matches Gate-quarantine term {bad!r}")
    return out


@check("CHK_TYPE_INVENTORY_IS_EXPLICIT")
def _inventory_allowlist() -> list[str]:
    """[A5] Allowlisting, not just a deny-list.

    A regex deny-list cannot stop a Gate concept entering under a name nobody
    thought of.  An explicit inventory can: every registry type must appear in it,
    so a new type is a deliberate, reviewable edit rather than a silent addition.
    """
    from .inventory import PHASE1_TYPE_INVENTORY

    declared = set(REG.order)
    inventory = set(PHASE1_TYPE_INVENTORY)
    out = []
    for extra in sorted(declared - inventory):
        out.append(f"type {extra} is declared but absent from PHASE1_TYPE_INVENTORY")
    for missing in sorted(inventory - declared):
        out.append(f"PHASE1_TYPE_INVENTORY lists {missing}, which no longer exists")
    return out


@check("CHK_PERSISTED_TYPES_ARE_CLASSIFIED")
def _persistence() -> list[str]:
    ok = {"persisted", "embedded", "derived", "transient"}
    return [
        f"{d.name}: unknown persistence class {d.persistence!r}"
        for d in REG
        if d.persistence not in ok
    ]


# --------------------------------------------------------------------------
# dependency matrix  [A5]
# --------------------------------------------------------------------------

MODULES = (
    "core",
    "policy",
    "solve",
    "solve.z3",
    "solve.reference",
    "admissibility",
    "hinge",
    "evidence",
    "domains.workforce",
    "domains.procurement",
    "application",
)

ALLOWED: dict[str, tuple[str, ...]] = {
    "core": (),
    "policy": ("core",),
    "solve": ("core",),
    "solve.z3": ("core", "solve"),
    "solve.reference": ("core", "solve"),
    "admissibility": ("core", "policy"),
    "hinge": ("core", "policy", "solve"),
    "evidence": ("core", "hinge"),
    "domains.workforce": ("core", "policy"),
    "domains.procurement": ("core", "policy"),
    # [A5] The composition root -- and ONLY the composition root -- may see the
    # concrete adapters.  Phase 0.7 omitted this row entirely, which both left
    # F-17's coverage claim false and made `Z3Backend` unconstructible.
    "application": (
        "core",
        "policy",
        "solve",
        "solve.z3",
        "solve.reference",
        "admissibility",
        "hinge",
        "evidence",
        "domains.workforce",
        "domains.procurement",
    ),
}


def forbidden(module: str) -> frozenset[str]:
    return frozenset(MODULES) - {module} - set(ALLOWED[module])


@check("CHK_DEPENDENCY_MATRIX_COVERS_EVERY_MODULE")
def _matrix_coverage() -> list[str]:
    out = []
    for m in MODULES:
        if m not in ALLOWED:
            out.append(f"module {m} has no allowlist row")
    for m in ALLOWED:
        if m not in MODULES:
            out.append(f"allowlist row {m} names an undeclared module")
    return out


@check("CHK_DEPENDENCY_MATRIX_INVARIANTS")
def _matrix_invariants() -> list[str]:
    out = []
    if "solve.z3" in ALLOWED["hinge"] or "solve.reference" in ALLOWED["hinge"]:
        out.append("hinge may not import a concrete solver adapter")
    if "solve.z3" in ALLOWED["solve"] or "solve.reference" in ALLOWED["solve"]:
        out.append("solve must not import its own adapters")
    if "solve.z3" not in ALLOWED["application"]:
        out.append("nothing may construct Z3Backend: the composition root cannot see it")
    for a, b in (("domains.workforce", "domains.procurement"), ("domains.procurement", "domains.workforce")):
        if b in ALLOWED[a]:
            out.append(f"{a} must be independent of {b}")
    if ALLOWED["core"]:
        out.append("core must import nothing in muster")
    if "domains.workforce" in ALLOWED["evidence"] or "domains.procurement" in ALLOWED["evidence"]:
        out.append("evidence must not import a domain")
    # acyclicity
    def reach(m: str, seen: frozenset[str] = frozenset()) -> frozenset[str]:
        if m in seen:
            return seen
        seen = seen | {m}
        for n in ALLOWED[m]:
            seen = reach(n, seen)
        return seen

    for m in MODULES:
        for n in ALLOWED[m]:
            if m in reach(n):
                out.append(f"dependency cycle through {m} -> {n}")
    return out


@check("CHK_PRODUCTION_DOES_NOT_IMPORT_THE_REFERENCE_SPEC")
def _no_production_import() -> list[str]:
    root = Path(__file__).resolve().parents[3]
    src = root / "src" / "muster"
    if not src.exists():
        return []
    out = []
    for py in src.rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="replace")
        if "muster_spec" in text or "reference_semantics" in text or "reference-semantics" in text:
            out.append(f"{py}: production module imports the Phase 0.8 reference specification")
    return out


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------


def run_all() -> dict[str, list[str]]:
    return {name: fn() for name, fn in sorted(CHECKS.items())}


def summarise(results: dict[str, list[str]]) -> tuple[int, int]:
    passed = sum(1 for v in results.values() if not v)
    return passed, len(results)
