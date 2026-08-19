"""Sampled properties of the commitment tree and the leaf preimage.

The adversarial suite attacks specific, named mutations.  This samples instead,
because the properties below have to hold for leaf sets and mutations nobody
enumerated -- and because the cheapest way for a hash tree to be wrong is at a
size or a position that a hand-written case happened not to visit.

Nothing here needs a database, a bundle or a decided case: these are properties
of the hashing, and mixing a case fixture in would make a failure ambiguous
between the two.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from muster.core.wire.codec import encode
from muster.core.wire.nodes import NAtom
from muster.platform.commit.paths import CommittedRecord
from muster.platform.commit.salts import CaseSalt, field_salt
from muster.platform.commit.tree import (
    LeafBinding,
    ProofSide,
    RootBinding,
    build_tree,
    fold_proof,
    inclusion_proof,
    leaf_hash,
    top_hash,
    verify_inclusion,
)

from muster.core.wire.digests import Digest  # isort: skip

SALT = CaseSalt(bytes(range(32)))
BINDING = LeafBinding("ALPHA", Digest(bytes(32)), Digest(bytes(range(32, 64))), 1)
ROOT_BINDING = RootBinding("ALPHA", "CASE-1", Digest(bytes(range(32, 64))), Digest(bytes(32)), 1)

#: Two static paths and a family of dynamic ones, so a sampled set is always a
#: set of paths the inventory can actually produce.
_STATIC = ("case.case_id", "case.tenant_id")

_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:-"


def _paths(count: int) -> tuple[str, ...]:
    dynamic = tuple(f"revision.constraints.{index:064x}" for index in range(count))
    return (*_STATIC[: min(count, 2)], *dynamic[: max(count - 2, 0)])


def _record(count: int, values: list[bytes]) -> CommittedRecord:
    pairs = list(zip(_paths(count), values[:count], strict=True))
    return CommittedRecord(tuple(sorted(pairs, key=lambda item: encode(NAtom(item[0])))))


octets = st.binary(min_size=0, max_size=48)


@settings(max_examples=60, deadline=None)
@given(values=st.lists(octets, min_size=1, max_size=12))
def test_every_leaf_of_a_sampled_record_proves_against_its_own_root(
    values: list[bytes],
) -> None:
    tree = build_tree(
        binding=BINDING,
        root_binding=ROOT_BINDING,
        record=_record(len(values), values),
        salt=SALT,
    )
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


@settings(max_examples=60, deadline=None)
@given(values=st.lists(octets, min_size=2, max_size=12), index=st.integers(min_value=0))
def test_a_one_byte_value_mutation_never_still_proves(values: list[bytes], index: int) -> None:
    """The property the whole commitment rests on, sampled rather than assumed."""
    tree = build_tree(
        binding=BINDING,
        root_binding=ROOT_BINDING,
        record=_record(len(values), values),
        salt=SALT,
    )
    path = tree.paths[index % tree.leaf_count]
    opened = tree.disclosure_of(path)
    assert opened is not None
    value, salt, proof = opened
    mutated = bytes([value[0] ^ 1]) + value[1:] if value else b"\x01"
    assert not verify_inclusion(
        binding=tree.binding,
        root_binding=tree.root_binding,
        leaf_count=tree.leaf_count,
        root=tree.root,
        path=path,
        value_octets=mutated,
        salt=salt,
        proof=proof,
    )


@settings(max_examples=60, deadline=None)
@given(values=st.lists(octets, min_size=2, max_size=12), index=st.integers(min_value=0))
def test_a_value_moved_to_another_path_never_proves(values: list[bytes], index: int) -> None:
    """The leaf preimage binds the path, so a value cannot change field."""
    tree = build_tree(
        binding=BINDING,
        root_binding=ROOT_BINDING,
        record=_record(len(values), values),
        salt=SALT,
    )
    here = index % tree.leaf_count
    there = (here + 1) % tree.leaf_count
    opened = tree.disclosure_of(tree.paths[here])
    assert opened is not None
    value, salt, proof = opened
    assert not verify_inclusion(
        binding=tree.binding,
        root_binding=tree.root_binding,
        leaf_count=tree.leaf_count,
        root=tree.root,
        path=tree.paths[there],
        value_octets=value,
        salt=salt,
        proof=proof,
    )


@settings(max_examples=60, deadline=None)
@given(values=st.lists(octets, min_size=1, max_size=12))
def test_a_disclosure_from_another_case_never_proves_here(values: list[bytes]) -> None:
    """A second case: its own salt, its own commitments, its own leaves.

    Both halves matter and the test would be empty without the first. A salt is
    derived per tenant and case, so a second case's field salts differ; and the
    tenant, case commitment and revision commitment are inside every leaf, so
    even a value and salt that happened to coincide would recompute to a leaf
    that is not in this tree.
    """
    record = _record(len(values), values)
    here = build_tree(binding=BINDING, root_binding=ROOT_BINDING, record=record, salt=SALT)

    other_revision = Digest(bytes(range(64, 96)))
    elsewhere = build_tree(
        binding=LeafBinding("BETA", Digest(bytes(range(96, 128))), other_revision, 1),
        root_binding=RootBinding(
            "BETA", "CASE-2", other_revision, Digest(bytes(range(128, 160))), 1
        ),
        record=record,
        salt=CaseSalt(bytes(range(1, 33))),
    )
    assert here.root != elsewhere.root
    for path in here.paths:
        opened = elsewhere.disclosure_of(path)
        assert opened is not None
        value, salt, proof = opened
        assert not verify_inclusion(
            binding=here.binding,
            root_binding=here.root_binding,
            leaf_count=here.leaf_count,
            root=here.root,
            path=path,
            value_octets=value,
            salt=salt,
            proof=proof,
        )


@settings(max_examples=60, deadline=None)
@given(values=st.lists(octets, min_size=2, max_size=12), index=st.integers(min_value=0))
def test_flipping_a_proof_direction_never_still_folds(values: list[bytes], index: int) -> None:
    tree = build_tree(
        binding=BINDING,
        root_binding=ROOT_BINDING,
        record=_record(len(values), values),
        salt=SALT,
    )
    path = tree.paths[index % tree.leaf_count]
    opened = tree.disclosure_of(path)
    assert opened is not None
    value, salt, proof = opened
    if not proof:
        return
    from dataclasses import replace

    flipped = tuple(
        replace(step, side=ProofSide.LEFT if step.side is ProofSide.RIGHT else ProofSide.RIGHT)
        for step in proof
    )
    assert not verify_inclusion(
        binding=tree.binding,
        root_binding=tree.root_binding,
        leaf_count=tree.leaf_count,
        root=tree.root,
        path=path,
        value_octets=value,
        salt=salt,
        proof=flipped,
    )


@settings(max_examples=60, deadline=None)
@given(values=st.lists(octets, min_size=1, max_size=12))
def test_the_same_record_and_salt_reproduce_the_same_root(values: list[bytes]) -> None:
    """Determinism, which is what makes a commitment re-derivable after a restart."""
    record = _record(len(values), values)
    first = build_tree(binding=BINDING, root_binding=ROOT_BINDING, record=record, salt=SALT)
    second = build_tree(binding=BINDING, root_binding=ROOT_BINDING, record=record, salt=SALT)
    assert first.root == second.root
    assert first.leaves == second.leaves
    assert first.salts == second.salts


@settings(max_examples=60, deadline=None)
@given(values=st.lists(octets, min_size=1, max_size=12))
def test_a_different_case_salt_moves_every_leaf(values: list[bytes]) -> None:
    record = _record(len(values), values)
    here = build_tree(binding=BINDING, root_binding=ROOT_BINDING, record=record, salt=SALT)
    other = build_tree(
        binding=BINDING,
        root_binding=ROOT_BINDING,
        record=record,
        salt=CaseSalt(bytes(range(1, 33))),
    )
    assert here.root != other.root
    assert not set(here.salts) & set(other.salts)


#: The path grammar, as a strategy.  Sampling outside it would be sampling
#: inputs the extractor refuses, which says nothing about the salt derivation.
segment = st.text(
    alphabet=st.characters(whitelist_categories=(), whitelist_characters=_ALPHABET),
    min_size=1,
    max_size=24,
)
path_strategy = st.lists(segment, min_size=1, max_size=4).map(".".join)


@settings(max_examples=80, deadline=None)
@given(paths=st.lists(path_strategy, min_size=2, max_size=8, unique=True))
def test_distinct_paths_get_distinct_field_salts(paths: list[str]) -> None:
    salts = {field_salt(SALT, path) for path in paths}
    assert len(salts) == len(paths)


def test_a_path_outside_the_ascii_grammar_is_refused_rather_than_raising_a_codec_error() -> None:
    """A second line behind the extractor, and a typed one."""
    import pytest

    from muster.core.results import InvariantViolation

    with pytest.raises(InvariantViolation):
        field_salt(SALT, "case.café")


@settings(max_examples=60, deadline=None)
@given(count=st.integers(min_value=1, max_value=32))
def test_the_top_hash_is_a_function_of_the_leaf_sequence(count: int) -> None:
    """Two sequences differing anywhere produce two tops, at every size."""
    leaves = tuple(
        leaf_hash(
            BINDING,
            path="case.case_id",
            salt=field_salt(SALT, f"p{index}"),
            value_octets=bytes([index % 256]),
        )
        for index in range(count)
    )
    assert top_hash(leaves) == top_hash(leaves)
    if count > 1:
        swapped = (leaves[1], leaves[0], *leaves[2:])
        assert top_hash(swapped) != top_hash(leaves)
    for index in range(count):
        assert fold_proof(leaves[index], inclusion_proof(leaves, index)) == top_hash(leaves)
