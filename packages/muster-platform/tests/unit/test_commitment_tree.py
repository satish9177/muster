"""The commitment tree, at the sizes and shapes where the rules differ.

Four of the frozen decisions only show up at particular sizes, so each is
exercised at the size that distinguishes it: the empty tree is a constant, one
leaf is *not* hashed again, three leaves promote rather than duplicate, and
four leaves pair evenly.  A conventional implementation passes the even sizes
and fails the odd one, which is exactly why the odd one is here.
"""

from __future__ import annotations

import pytest

from muster.core.results import InvariantViolation
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest, DigestKind, digest_octets
from muster.core.wire.nodes import NAtom
from muster.platform.commit.paths import CommittedRecord
from muster.platform.commit.salts import CaseSalt, field_salt
from muster.platform.commit.tree import (
    CommitmentTree,
    LeafBinding,
    ProofSide,
    ProofStep,
    RootBinding,
    build_tree,
    empty_hash,
    fold_proof,
    inclusion_proof,
    leaf_hash,
    node_hash,
    top_hash,
    verify_inclusion,
)

SALT = CaseSalt(bytes(range(32)))
TENANT = "ALPHA"
CASE = "CASE-1"
SCHEMA = 1

CASE_COMMITMENT = Digest(bytes(range(32)))
REVISION_COMMITMENT = Digest(bytes(range(32, 64)))
MANIFEST = Digest(bytes(range(64, 96)))

BINDING = LeafBinding(TENANT, CASE_COMMITMENT, REVISION_COMMITMENT, SCHEMA)
ROOT_BINDING = RootBinding(TENANT, CASE, REVISION_COMMITMENT, MANIFEST, SCHEMA)


def _leaves(count: int) -> tuple[bytes, ...]:
    return tuple(
        leaf_hash(
            BINDING,
            path="case.case_id",
            salt=field_salt(SALT, f"p{index}"),
            value_octets=bytes([index]),
        )
        for index in range(count)
    )


def _record(count: int) -> CommittedRecord:
    #  Paths are canonical-ordered by the record itself, so this builds them
    #  through the same constructor production uses.
    values = {
        "case.case_id" if index == 0 else f"revision.constraints.{index:064x}": bytes([index])
        for index in range(count)
    }
    ordered = sorted(values.items(), key=lambda item: encode(NAtom(item[0])))
    return CommittedRecord(tuple(ordered))


def test_the_empty_tree_is_a_fixed_constant_and_never_a_leaf() -> None:
    assert top_hash(()) == empty_hash()
    assert len(empty_hash()) == 32
    #  The separators are distinct, so no leaf hash can be read as the empty
    #  tree and no internal node can be read as a leaf.
    assert empty_hash() != node_hash(bytes(32), bytes(32))
    assert empty_hash() not in _leaves(4)


def test_one_leaf_is_not_hashed_again() -> None:
    leaves = _leaves(1)
    assert top_hash(leaves) == leaves[0]


def test_two_leaves_pair() -> None:
    leaves = _leaves(2)
    assert top_hash(leaves) == node_hash(leaves[0], leaves[1])


def test_three_leaves_promote_rather_than_duplicate() -> None:
    """The classic Merkle malleability defect, refused by construction.

    Duplicating the final leaf makes the tree over ``[A, B, C]`` and the tree
    over ``[A, B, C, C]`` produce one root, so a leaf multiset stops being
    determined by the root it hashes to. Promotion has no such collision.
    """
    leaves = _leaves(3)
    assert top_hash(leaves) == node_hash(node_hash(leaves[0], leaves[1]), leaves[2])
    duplicated = (*leaves, leaves[2])
    assert top_hash(leaves) != top_hash(duplicated)


def test_four_leaves_pair_evenly() -> None:
    leaves = _leaves(4)
    assert top_hash(leaves) == node_hash(
        node_hash(leaves[0], leaves[1]), node_hash(leaves[2], leaves[3])
    )


def test_five_six_and_seven_leaves_have_hand_written_tops() -> None:
    """Above four leaves the only oracle was the code that builds the proofs.

    ``top_hash`` and ``inclusion_proof`` both walk the same ``_levels``, so
    "every proof folds to the top" is self-consistency rather than
    correctness -- a defect at an odd *internal* level would satisfy it. Six is
    the smallest size with a promotion above the leaf level, so it is the one
    that matters; five and seven bracket it.
    """
    five = _leaves(5)
    #  5 -> [01][23][4] -> [0123][4] -> [01234]: the odd node rises twice.
    assert top_hash(five) == node_hash(
        node_hash(node_hash(five[0], five[1]), node_hash(five[2], five[3])), five[4]
    )

    six = _leaves(6)
    #  6 -> [01][23][45] -> [0123][45] -> promotion at an internal level.
    assert top_hash(six) == node_hash(
        node_hash(node_hash(six[0], six[1]), node_hash(six[2], six[3])),
        node_hash(six[4], six[5]),
    )

    seven = _leaves(7)
    #  7 -> [01][23][45][6] -> [0123][456] -> [0123456].
    assert top_hash(seven) == node_hash(
        node_hash(node_hash(seven[0], seven[1]), node_hash(seven[2], seven[3])),
        node_hash(node_hash(seven[4], seven[5]), seven[6]),
    )


def test_a_leaf_domain_is_not_an_internal_node_domain() -> None:
    """Without this, a 64-octet value is a second preimage for a node."""
    children = _leaves(2)
    as_node = node_hash(children[0], children[1])
    as_leaf = digest_octets(DigestKind.MERKLE_LEAF, children[0] + children[1]).octets
    assert as_node != as_leaf


@pytest.mark.parametrize("size", range(1, 9))
def test_every_leaf_proves_at_every_size(size: int) -> None:
    leaves = _leaves(size)
    top = top_hash(leaves)
    for index in range(size):
        assert fold_proof(leaves[index], inclusion_proof(leaves, index)) == top


@pytest.mark.parametrize("size", range(2, 9))
def test_a_proof_for_the_wrong_leaf_does_not_fold_to_the_top(size: int) -> None:
    leaves = _leaves(size)
    top = top_hash(leaves)
    for index in range(size):
        other = (index + 1) % size
        assert fold_proof(leaves[other], inclusion_proof(leaves, index)) != top


def test_a_promoted_node_contributes_no_step() -> None:
    """Three leaves: the last one rises a level untouched, so its proof is shorter."""
    leaves = _leaves(3)
    assert len(inclusion_proof(leaves, 0)) == 2
    assert len(inclusion_proof(leaves, 2)) == 1


def test_an_empty_tree_has_no_proof() -> None:
    with pytest.raises(InvariantViolation):
        inclusion_proof((), 0)


def test_children_are_thirty_two_octets() -> None:
    with pytest.raises(InvariantViolation):
        node_hash(b"short", bytes(32))
    with pytest.raises(InvariantViolation):
        node_hash(bytes(32), b"short")


def test_a_proof_step_sibling_is_thirty_two_octets() -> None:
    with pytest.raises(InvariantViolation):
        ProofStep(ProofSide.LEFT, b"short")


def _tree(count: int) -> CommitmentTree:
    return build_tree(binding=BINDING, root_binding=ROOT_BINDING, record=_record(count), salt=SALT)


def test_the_root_is_a_function_of_the_record_not_of_insertion_order() -> None:
    """The whole point of canonical ordering, stated as the property it buys."""
    record = _record(6)
    forward = build_tree(binding=BINDING, root_binding=ROOT_BINDING, record=record, salt=SALT)
    reversed_pairs = CommittedRecord(tuple(reversed(record.values)))
    #  A record built the other way round is *not* canonical, and the tree
    #  builder does not reorder it -- which is why the record constructor is
    #  the thing that establishes the order, and why a caller cannot move a
    #  root by discovering leaves differently.
    assert (
        forward.root
        != build_tree(
            binding=BINDING, root_binding=ROOT_BINDING, record=reversed_pairs, salt=SALT
        ).root
    )
    assert forward.paths == tuple(sorted(forward.paths, key=lambda path: encode(NAtom(path))))


def test_every_path_in_the_tree_verifies_against_its_own_root() -> None:
    tree = _tree(7)
    for path in tree.paths:
        opened = tree.disclosure_of(path)
        assert opened is not None
        value, salt, proof = opened
        assert verify_inclusion(
            binding=tree.binding,
            root_binding=tree.root_binding,
            leaf_count=tree.leaf_count,
            root=tree.root,
            path=path,
            value_octets=value,
            salt=salt,
            proof=proof,
        )


def test_a_path_the_record_does_not_hold_opens_to_nothing() -> None:
    tree = _tree(3)
    assert tree.disclosure_of("kernel.outcome.action") is None
    assert tree.index_of("kernel.outcome.action") is None


def test_the_leaf_count_is_committed_so_a_truncated_tree_is_a_different_root() -> None:
    tree = _tree(5)
    from muster.platform.commit.tree import root_hash

    lied = root_hash(tree.root_binding, leaf_count=tree.leaf_count - 1, top=top_hash(tree.leaves))
    assert lied != tree.root


def test_field_salts_are_path_specific_and_key_dependent() -> None:
    other = CaseSalt(bytes(range(1, 33)))
    assert field_salt(SALT, "case.case_id") != field_salt(SALT, "case.tenant_id")
    assert field_salt(SALT, "case.case_id") != field_salt(other, "case.case_id")
    assert field_salt(SALT, "case.case_id") == field_salt(SALT, "case.case_id")
