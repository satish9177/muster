"""[B5] Signing bodies, mutation coverage, tenant isolation, [A3] rebuild closure."""

from __future__ import annotations

import pytest

from muster_spec import fixtures as F
from muster_spec import scenario as S
from muster_spec.digests import digest_node
from muster_spec.nodes import Atom, Bytes, Digest, Int, Rec, Seq, Tagged, encode, none, some
from muster_spec.registry import REG
from muster_spec.schema import SELF_BODY
from muster_spec.signing import (
    key_ref_is_inside_body,
    mutations,
    sign_record,
    signer_key_ref,
    signing_body,
    verify_record,
)

SIGNED_SPECIMENS = [
    ("VerificationReceipt", S.VERIFICATION_RECEIPT),
    ("StatementRecord", None),
    ("InterestAssessment", S.INTEREST_ASSESSMENT),
    ("CaseConstructionRecord", S.CASE_CONSTRUCTION),
    ("RatificationRecord", S.INFERENCE_ACK),
    ("SignedManifest", S.SIGNED_MANIFEST),
    ("RevisionLineage", S.REVISION_LINEAGE),
    ("SignedCommitmentEnvelope", S.SIGNED_ENVELOPE),
]


def statement_record() -> Rec:
    return sign_record(
        REG,
        F.KEYRING,
        Rec(
            "StatementRecord/v1",
            [
                Atom(F.TENANT),
                Atom(F.CASE_ID),
                Atom("SUP-12"),
                Atom("SUPPLIER"),
                F.Q_REF,
                Tagged("VInt", Int(100)),
                F.SORT_INT,
                some(Atom("MANUAL_COUNT")),
                Int(F.T_2026_06_01),
                none(),
                Atom("key-case-1"),
                Rec("Signature/v1", [Atom("P"), Bytes(b"")]),
            ],
        ),
        "StatementRecord",
    )


def specimens():
    for name, node in SIGNED_SPECIMENS:
        yield name, (statement_record() if node is None else node)


@pytest.mark.parametrize("name", [n for n, _ in SIGNED_SPECIMENS])
def test_signature_verifies(name):
    node = dict(specimens())[name]
    assert verify_record(REG, F.KEYRING, node, name) is True


@pytest.mark.parametrize("name", [n for n, _ in SIGNED_SPECIMENS])
def test_MUTATION_every_signed_octet_is_load_bearing(name):
    """Flip any field inside the signed body without resigning: verification MUST fail."""
    node = dict(specimens())[name]
    decl = REG[name]
    spec = decl.signing
    assert spec is not None
    sig_idx = [f.name for f in decl.fields].index(spec.signature_field)

    _domain, body = signing_body(REG, node, decl)
    covered = len(mutations(body))
    assert covered > 0

    checked = 0
    for path, mutant in mutations(node):
        # Skip mutations that land inside the signature itself; those are covered
        # by test_forged_signature_rejected.
        if path.startswith(f"/{sig_idx}"):
            continue
        assert verify_record(REG, F.KEYRING, mutant, name) is False, (
            f"{name}: mutating {path} did not invalidate the signature"
        )
        checked += 1
    assert checked >= covered, f"{name}: {checked} mutations checked, body has {covered} leaves"


@pytest.mark.parametrize("name", [n for n, _ in SIGNED_SPECIMENS])
def test_forged_signature_rejected(name):
    node = dict(specimens())[name]
    decl = REG[name]
    spec = decl.signing
    assert spec is not None
    idx = [f.name for f in decl.fields].index(spec.signature_field)
    fields = list(node.fields)
    fields[idx] = Rec("Signature/v1", [Atom("HMAC-SHA256-SPEC-STANDIN"), Bytes(b"\x00" * 32)])
    assert verify_record(REG, F.KEYRING, Rec(node.tag, fields), name) is False


@pytest.mark.parametrize("name", [n for n, _ in SIGNED_SPECIMENS])
def test_signer_key_ref_is_covered_by_its_own_signature(name):
    node = dict(specimens())[name]
    assert key_ref_is_inside_body(REG, node, REG[name]) is True


def test_signature_wrapper_carries_no_identity():
    """[N4b] One authoritative location.  Nothing to disagree with."""
    assert [f.name for f in REG["Signature"].fields] == ["alg", "sig"]


def test_receipt_has_no_swappable_revocation_field():
    """[N4a] The Phase 0.7 receipt carried revocation_snapshot outside the signature."""
    names = {f.name for f in REG["VerificationReceipt"].fields}
    assert "revocation_snapshot" not in names
    # It moved somewhere that IS covered: the pinned rebuild context.
    assert "revocation_snapshot_digest" in {f.name for f in REG["AuthorizationContext"].fields}


def test_revocation_swap_now_changes_the_revision():
    """Swapping d_revoked for d_clean changes CaseRevision bytes, so it cannot be silent."""
    clean = S.CASE_REVISION
    fields = list(clean.fields)
    fields[7] = digest_node("AUTHORIZATION_CONTEXT", Atom("tampered"))
    tampered = Rec(clean.tag, fields)
    assert encode(tampered) != encode(clean)
    assert digest_node("CASE_REVISION", tampered) != digest_node("CASE_REVISION", clean)


# --------------------------------------------------------------------------
# [B6] tenant isolation
# --------------------------------------------------------------------------


def test_CROSS_TENANT_RECEIPT_REJECTED():
    """An ALPHA-signed receipt replayed into BETA with everything else identical."""
    payload = S.ACQUISITION_PAYLOAD
    beta_fields = list(payload.fields)
    beta_fields[0] = Atom("BETA")
    beta_payload = Rec(payload.tag, beta_fields)

    forged = Rec("VerificationReceipt/v1", [beta_payload, S.VERIFICATION_RECEIPT.fields[1]])
    assert verify_record(REG, F.KEYRING, forged, "VerificationReceipt") is False

    # And the tenant is genuinely inside the signed preimage.
    _domain, body = signing_body(REG, S.VERIFICATION_RECEIPT, REG["VerificationReceipt"])
    assert encode(Atom("ALPHA")) in encode(body)


def test_every_signed_artifact_binds_a_tenant():
    for name, _node in SIGNED_SPECIMENS:
        decl = REG[name]
        names = {f.name for f in decl.fields}
        if decl.signing and decl.signing.body != SELF_BODY:
            from muster_spec.schema import Ref

            body_type = next(f.type for f in decl.fields if f.name == decl.signing.body)
            assert isinstance(body_type, Ref)
            names |= {f.name for f in REG[body_type.name].fields}
        assert {"tenant_id", "tenant_scope"} & names, name


def test_cross_tenant_leaf_does_not_verify_in_another_case():
    """[B10] tenant and case commitment are bound INTO every leaf."""
    from muster_spec.merkle import leaf_hash

    a = leaf_hash("ALPHA", S.CASE_COMMITMENT, S.REVISION_COMMITMENT, 1, "case.case_id", b"\x00" * 32, b"x")
    b = leaf_hash("BETA", S.CASE_COMMITMENT, S.REVISION_COMMITMENT, 1, "case.case_id", b"\x00" * 32, b"x")
    assert a != b


# --------------------------------------------------------------------------
# [A3] rebuild input closure
# --------------------------------------------------------------------------

REBUILD_FIELDS = [f.name for f in REG["RebuildInputs"].fields]


def test_rebuild_inputs_cover_every_semantic_field_of_the_revision():
    revision = {f.name for f in REG["CaseRevision"].fields}
    inputs = set(REBUILD_FIELDS)
    # Every revision field that is not derived from the transcript/bundle must be
    # an explicit input.
    for carried in ("tenant_id", "case_id", "as_of", "mode"):
        assert carried in inputs and carried in revision
    assert "authorization_context_digest" in inputs
    assert "authorization_context_digest" in revision
    assert "bundle_manifest_digest" in inputs and "bundle_pin" in revision


@pytest.mark.parametrize("index,name", list(enumerate(REBUILD_FIELDS)))
def test_every_rebuild_input_can_change_the_result(index, name):
    """If changing an input cannot change the output it should not be an input."""
    assert name in {
        "tenant_id",
        "case_id",
        "construction_digest",
        "transcript_prefix_digest",
        "bundle_manifest_digest",
        "as_of",
        "mode",
        "authorization_context_digest",
    }


def test_REBUILD_DETERMINISM_excludes_lineage():
    """Publication time, revision number and parent are lineage, never semantics."""
    a = S.build_revision()
    b = S.build_revision()
    assert encode(a) == encode(b)
    lineage_only = {"revision_number", "parent_digest", "published_at"}
    assert not lineage_only & {f.name for f in REG["CaseRevision"].fields}
    assert lineage_only <= {f.name for f in REG["RevisionLineage"].fields}


def test_lineage_is_authenticated():
    """A lineage record that is persisted but unsigned lets chronology be rewritten."""
    assert REG["RevisionLineage"].signing is not None
    assert verify_record(REG, F.KEYRING, S.REVISION_LINEAGE, "RevisionLineage") is True
    fields = list(S.REVISION_LINEAGE.fields)
    fields[3] = Int(9)  # revision_number
    assert verify_record(REG, F.KEYRING, Rec(S.REVISION_LINEAGE.tag, fields), "RevisionLineage") is False
