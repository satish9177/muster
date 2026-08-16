"""[B7/B8/B11] Merkle shape, proofs, envelope authenticity, salted commitments."""

from __future__ import annotations

import hashlib

import pytest

from muster_spec import fixtures as F
from muster_spec import scenario as S
from muster_spec.digests import PREFIX, commitment, field_salt
from muster_spec.merkle import (
    build_tree,
    empty_hash,
    fold_proof,
    inclusion_proof,
    leaf_hash,
    levels,
    merkle,
    node_hash,
    verify_disclosure,
)
from muster_spec.nodes import Atom, Bytes, Rec, encode
from muster_spec.paths import extract, path_in_inventory
from muster_spec.registry import REG
from muster_spec.signing import verify_record

L = [bytes([i]) * 32 for i in range(8)]


def test_MERKLE_EMPTY_IS_A_FIXED_CONSTANT():
    assert merkle([]) == empty_hash()
    assert merkle([]) == hashlib.sha256(PREFIX + b"MERKLE_EMPTY\x00").digest()


def test_MERKLE_ONE_LEAF_IS_NOT_HASHED_AGAIN():
    assert merkle([L[0]]) == L[0]


def test_MERKLE_TWO_LEAF():
    assert merkle(L[:2]) == node_hash(L[0], L[1])


def test_MERKLE_THREE_LEAF_CANONICAL_PROMOTION_NOT_DUPLICATION():
    promoted = node_hash(node_hash(L[0], L[1]), L[2])
    duplicated = node_hash(node_hash(L[0], L[1]), node_hash(L[2], L[2]))
    assert merkle(L[:3]) == promoted
    assert merkle(L[:3]) != duplicated


def test_MERKLE_FOUR_LEAF():
    assert merkle(L[:4]) == node_hash(node_hash(L[0], L[1]), node_hash(L[2], L[3]))


def test_leaf_and_node_domains_are_disjoint():
    """No leaf hash can be reinterpreted as an internal node."""
    same_input = b"\x00" * 32
    assert node_hash(same_input, same_input) != hashlib.sha256(
        PREFIX + b"MERKLE_LEAF\x00" + same_input + same_input
    ).digest()


@pytest.mark.parametrize("size", list(range(1, 9)))
def test_proofs_verify_at_every_size(size):
    leaves = L[:size]
    root = merkle(leaves)
    for i in range(size):
        assert fold_proof(leaves[i], inclusion_proof(leaves, i)) == root


@pytest.mark.parametrize("size", list(range(1, 9)))
def test_proof_for_the_wrong_leaf_fails(size):
    leaves = L[:size]
    root = merkle(leaves)
    for i in range(size):
        wrong = bytes([0xFF]) * 32
        assert fold_proof(wrong, inclusion_proof(leaves, i)) != root


def test_leaf_count_is_committed():
    node = S.TREE.root_node
    assert node.fields[5].value == len(S.TREE.leaves)
    fields = list(node.fields)
    fields[5] = type(node.fields[5])(len(S.TREE.leaves) + 1)
    from muster_spec.merkle import root_hash

    assert root_hash(Rec(node.tag, fields)) != S.TREE.root


def test_DUPLICATE_PATH_REJECTED():
    """A dict cannot hold a duplicate key, so the leaf set is duplicate-free by type."""
    committed = dict(S.COMMITTED)
    assert len(committed) == len(S.TREE.paths)
    assert len(set(S.TREE.paths)) == len(S.TREE.paths)


def test_MERKLE_CROSS_CASE_TRANSPLANT_REJECTED():
    other_salt = bytes([0xAA]) * 32
    other_case_commitment = commitment(other_salt, "CASE_COMMITMENT", S.CONSTRUCTION_DIGEST)
    other = build_tree(
        F.TENANT,
        "PO-9999",
        other_case_commitment,
        S.REVISION_COMMITMENT,
        S.MANIFEST_DIGEST,
        1,
        other_salt,
        S.COMMITTED,
    )
    path = "case.case_id"
    i = other.index_of(path)
    steps = other.proof(path)
    # A leaf and proof from case PO-9999 offered against the PO-4471 envelope.
    assert (
        verify_disclosure(
            S.COMMITMENT_ENVELOPE, path, other.values[i], other.salts[i], steps
        )
        is False
    )


def test_path_salts_are_distinct_and_key_dependent():
    a = field_salt(F.SALT_CASE, "case.case_id")
    b = field_salt(F.SALT_CASE, "case.tenant_id")
    c = field_salt(bytes([1]) * 32, "case.case_id")
    assert len({a, b, c}) == 3


def test_every_committed_path_is_in_the_frozen_inventory():
    for p in S.TREE.paths:
        assert path_in_inventory(p), p


def test_the_leaf_set_is_exactly_the_extractor_output():
    """[B10] IncompleteCommitmentSet has a definition because the extractor is total."""
    assert set(S.TREE.paths) == set(extract(S.INTERNAL_RECORD))


# --------------------------------------------------------------------------
# [B8] envelope authenticity
# --------------------------------------------------------------------------


def test_ENVELOPE_IS_AUTHENTICATED():
    assert verify_record(REG, F.KEYRING, S.SIGNED_ENVELOPE, "SignedCommitmentEnvelope") is True


def test_self_consistent_but_unauthenticated_envelope_is_rejected():
    """An attacker can build a coherent tree; they cannot sign the envelope.

    Merkle verification alone proves internal consistency, which is why Phase 0.7
    dropping the envelope signature was a regression rather than a simplification.
    """
    forged_paths = {"case.tenant_id": encode(Atom("ALPHA")), "case.case_id": encode(Atom("PO-4471"))}
    forged_tree = build_tree(
        F.TENANT, F.CASE_ID, S.CASE_COMMITMENT, S.REVISION_COMMITMENT,
        S.MANIFEST_DIGEST, 1, F.SALT_CASE, forged_paths,
    )
    forged_envelope = Rec(
        "CommitmentEnvelope/v1",
        [
            Atom(F.TENANT), Atom(F.CASE_ID), S.CASE_COMMITMENT, S.REVISION_COMMITMENT,
            S.MANIFEST_DIGEST, S.DISCLOSURE_POLICY_DIGEST,
            type(S.COMMITMENT_ENVELOPE.fields[6])(1),
            type(S.COMMITMENT_ENVELOPE.fields[7])(len(forged_tree.leaves)),
            Bytes(forged_tree.root), Atom("key-muster-1"),
        ],
    )
    # Internally consistent ...
    i = forged_tree.index_of("case.case_id")
    assert verify_disclosure(
        forged_envelope, "case.case_id", forged_tree.values[i], forged_tree.salts[i],
        forged_tree.proof("case.case_id"),
    ) is True
    # ... but unsigned, and the attacker holds no MUSTER key.
    signed = Rec(
        "SignedCommitmentEnvelope/v1",
        [forged_envelope, Rec("Signature/v1", [Atom("HMAC-SHA256-SPEC-STANDIN"), Bytes(b"\x00" * 32)])],
    )
    assert verify_record(REG, F.KEYRING, signed, "SignedCommitmentEnvelope") is False


# --------------------------------------------------------------------------
# [B11] the salted revision commitment
# --------------------------------------------------------------------------


def test_REVISION_COMMITMENT_IS_NOT_AN_ORACLE():
    """A participant holding two candidate transcripts must not learn which is effective.

    With the raw semantic digest in the envelope they could rebuild both candidates
    and compare -- learning a private input the disclosure policy never released.
    The salted commitment removes the comparison without weakening any binding.
    """
    from muster_spec.digests import digest_node

    candidate_a = S.REVISION_SEMANTIC_DIGEST
    candidate_b = digest_node("CASE_REVISION", Atom("other-candidate"))

    # What the participant can compute unaided: nothing that matches the envelope.
    envelope_value = S.COMMITMENT_ENVELOPE.fields[3]
    assert envelope_value != candidate_a
    assert envelope_value != candidate_b
    assert encode(candidate_a) not in encode(S.SIGNED_ENVELOPE)

    # An auditor holding salt_case can still bind it exactly.
    assert commitment(F.SALT_CASE, "REVISION_COMMITMENT", candidate_a) == envelope_value
    assert commitment(F.SALT_CASE, "REVISION_COMMITMENT", candidate_b) != envelope_value


def test_case_commitment_is_also_salted():
    assert S.COMMITMENT_ENVELOPE.fields[2] == commitment(
        F.SALT_CASE, "CASE_COMMITMENT", S.CONSTRUCTION_DIGEST
    )
    assert encode(S.CONSTRUCTION_DIGEST) not in encode(S.SIGNED_ENVELOPE)


def test_salt_case_never_appears_in_any_outward_artifact():
    for artifact in (S.SIGNED_ENVELOPE, S.WAREHOUSE_VIEW, S.AUDITOR_VIEW):
        assert F.SALT_CASE not in encode(artifact)


# --------------------------------------------------------------------------
# dynamic commitment paths must be injective  (found by adversarial review)
# --------------------------------------------------------------------------


def _fact(value: int) -> Rec:
    from muster_spec.nodes import Int, Tagged

    return Rec(
        "EstablishedFact/v1",
        [
            F.Q_REF,
            Tagged("VInt", Int(value)),
            Tagged("AttestedBy", Rec("AttestedBy/v1", [S.RECEIPT_DIGEST])),
        ],
    )


def _non_effect(version: int, reason: str) -> Rec:
    from muster_spec.nodes import Int

    return Rec(
        "NonEffect/v1",
        [Atom("SelfServingClaimIsInert"), Int(version), Atom("SUP-12"), Atom(reason)],
    )


def _revision_with(index: int, members: list[Rec]) -> Rec:
    from muster_spec.nodes import Seq

    fields = list(S.CASE_REVISION.fields)
    fields[index] = Seq(members)
    return Rec("CaseRevision/v1", fields)


@pytest.mark.parametrize(
    "index,members,collection",
    [
        (10, [_fact(100), _fact(7)], "established"),
        (12, [_non_effect(1, "ADVERSE_INTEREST_ABSENT"), _non_effect(2, "NO_OPPOSED_BRACKET")],
         "non_effects"),
    ],
)
def test_COLLIDING_COMMITMENT_PATH_IS_UNREPRESENTABLE(index, members, collection):
    """Two members sharing a path would drop a leaf while leaf_count stayed consistent.

    The schema now makes the colliding revision unrepresentable, so the tree
    cannot commit to less than the whole authoritative record.
    """
    from muster_spec.schema import Ref, SchemaError, validate

    assert encode(members[0]) != encode(members[1])
    colliding = _revision_with(index, members)
    with pytest.raises(SchemaError, match="duplicate key"):
        validate(REG, colliding, Ref("CaseRevision"))


@pytest.mark.parametrize(
    "index,members",
    [
        (10, [_fact(100), _fact(7)]),
        (12, [_non_effect(1, "ADVERSE_INTEREST_ABSENT"), _non_effect(2, "NO_OPPOSED_BRACKET")]),
    ],
)
def test_EXTRACTOR_REFUSES_A_COLLISION_RATHER_THAN_DROPPING_A_LEAF(index, members):
    """Defence in depth: even handed a colliding revision, extract() must not overwrite."""
    from muster_spec.paths import DuplicateCommitmentPath, extract

    record = Rec(
        "InternalAnalysisRecord/v1",
        [
            S.ANALYSIS_CERTIFICATE,
            _revision_with(index, members),
            S.INTERNAL_RECORD.fields[2],
            S.INTERNAL_RECORD.fields[3],
        ],
    )
    with pytest.raises(DuplicateCommitmentPath, match="share a commitment path"):
        extract(record)


def test_every_dynamic_path_has_a_matching_uniqueness_rule():
    from muster_spec.paths import DYNAMIC_SOURCES

    for prefix, (owner, coll, keys, _domain) in DYNAMIC_SOURCES.items():
        declared = dict(REG[owner].unique_by).get(coll)
        assert declared is not None, prefix
        assert tuple(declared) == tuple(keys), prefix
