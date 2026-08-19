"""The commitment tree: leaves, internal nodes, the root, and inclusion proofs.

    leaf(p)   = SHA-256("muster/v1/MERKLE_LEAF" ‖ 0x00 ‖ canonical(CommitmentLeaf))
    node(L,R) = SHA-256("muster/v1/MERKLE_NODE" ‖ 0x00 ‖ L ‖ R)
    empty     = SHA-256("muster/v1/MERKLE_EMPTY" ‖ 0x00)
    root      = SHA-256("muster/v1/MERKLE_ROOT" ‖ 0x00 ‖ canonical(CommitmentRoot))

Four decisions in that shape are load-bearing and none of them is the
conventional one, so each is stated rather than left to be inferred.

**Leaves and internal nodes have different domains.**  Without that, a 64-octet
"value" whose halves are two real leaf hashes gives a second preimage for an
internal node, and a tree can be re-read as a different tree with the same root.

**An odd level promotes its last node; it never duplicates it.**  Duplication is
the classic malleability defect: a tree over `[A, B, C]` and one over
`[A, B, C, C]` produce the same root, so a leaf multiset is not determined by
the root it hashes to.  Promotion has no such collision, and it is why a proof
step is absent at a level rather than being a step against oneself.

**Every leaf carries the tenant, the salted case commitment, the salted revision
commitment and the schema version.**  So a leaf lifted out of another case, or
another revision of the same case, fails when its hash is *recomputed* -- before
the proof is folded and long before the root is compared.  Transplantation is
refused at the leaf, which is the earliest and most specific place to refuse it.

**A proof's shape is a function of the leaf's position, and positions are
public.**  Leaves sit in canonical path order, so the sides of a disclosure's
proof steps, together with the committed ``leaf_count``, determine that leaf's
index -- and therefore how many *undisclosed* leaves sort before it.  A
recipient who knows the frozen inventory can turn that into per-region counts:
roughly how many facts a revision established, how many constraints it carried.
They learn a shape, never a value, and never which proposition any of it was
about, because a dynamic path segment is a digest.

This follows from the frozen construction -- index-ordered leaves, promotion,
``leaf_count`` in the root -- and removing it means a different tree (a
fixed-depth sparse one keyed by ``digest(path)``, where a proof's shape depends
only on the path).  That is a Phase-0.8 change, so it is recorded here rather
than worked around: the channel is counts and adjacency, and it is bounded by
the fact that everything it reveals is about *how much* the record holds.

**The root is a digest of a record, not of the top hash.**  ``CommitmentRoot``
carries the leaf count, so a verifier that folds a proof to the right top hash
still has to agree about how many leaves there were: a tree cannot be truncated
or extended and then presented under the same identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.results import InvariantViolation
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest, DigestKind, digest_octets
from muster.core.wire.nodes import DIGEST_OCTETS, NAtom, NBytes, NInt, Node, NRec
from muster.core.wire.shape import read_bytes, read_member, read_rec
from muster.platform.commit.domains import CommitmentDomain, unkeyed_digest
from muster.platform.commit.paths import CommittedRecord
from muster.platform.commit.salts import CaseSalt, field_salt

TAG_COMMITMENT_LEAF = "CommitmentLeaf/v1"
TAG_COMMITMENT_ROOT = "CommitmentRoot/v1"
TAG_PROOF_STEP = "ProofStep/v1"


class ProofSide(Enum):
    """Which side of the concatenation the *sibling* goes on."""

    LEFT = "L"
    RIGHT = "R"


PROOF_SIDES = frozenset(side.value for side in ProofSide)


@dataclass(frozen=True, slots=True)
class ProofStep:
    side: ProofSide
    sibling: bytes

    def __post_init__(self) -> None:
        if len(self.sibling) != DIGEST_OCTETS:
            raise InvariantViolation(f"a proof sibling is 32 octets, not {len(self.sibling)}")

    def to_node(self) -> NRec:
        return NRec(TAG_PROOF_STEP, (NAtom(self.side.value), NBytes(self.sibling)))


def read_proof_step(node: Node) -> ProofStep:
    side, sibling = read_rec(node, TAG_PROOF_STEP, 2)
    return ProofStep(
        ProofSide(read_member(side, PROOF_SIDES, "ProofStep.side")),
        read_bytes(sibling, DIGEST_OCTETS),
    )


@dataclass(frozen=True, slots=True)
class LeafBinding:
    """What every leaf in one tree shares, and what a transplanted leaf lacks.

    Passed as one value because these four fields are load-bearing together:
    a leaf hash computed with three of them and somebody else's fourth is not a
    leaf of any tree, and taking them one argument at a time invites a call site
    that supplies the envelope's tenant and the record's schema version.
    """

    tenant_id: str
    case_commitment: Digest
    revision_commitment: Digest
    certificate_schema_version: int


def leaf_node(binding: LeafBinding, *, path: str, salt: bytes, value_octets: bytes) -> NRec:
    return NRec(
        TAG_COMMITMENT_LEAF,
        (
            NAtom(binding.tenant_id),
            binding.case_commitment.to_node(),
            binding.revision_commitment.to_node(),
            NInt(binding.certificate_schema_version),
            NAtom(path),
            NBytes(salt),
            NBytes(value_octets),
        ),
    )


def leaf_hash(binding: LeafBinding, *, path: str, salt: bytes, value_octets: bytes) -> bytes:
    return digest_octets(
        DigestKind.MERKLE_LEAF,
        encode(leaf_node(binding, path=path, salt=salt, value_octets=value_octets)),
    ).octets


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != DIGEST_OCTETS or len(right) != DIGEST_OCTETS:
        raise InvariantViolation("an internal node's children are 32 octets each")
    return unkeyed_digest(CommitmentDomain.MERKLE_NODE, left + right)


def empty_hash() -> bytes:
    """The tree over no leaves.  A constant, and never a leaf hash."""
    return unkeyed_digest(CommitmentDomain.MERKLE_EMPTY, b"")


def _levels(leaves: tuple[bytes, ...]) -> tuple[tuple[bytes, ...], ...]:
    if not leaves:
        return ((empty_hash(),),)
    built: list[tuple[bytes, ...]] = [leaves]
    while len(built[-1]) > 1:
        current = built[-1]
        pairs = [node_hash(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)]
        if len(current) % 2 == 1:
            pairs.append(current[-1])  # promotion, never duplication
        built.append(tuple(pairs))
    return tuple(built)


def top_hash(leaves: tuple[bytes, ...]) -> bytes:
    """The top of the hash tree.  One leaf is *not* hashed again."""
    return _levels(leaves)[-1][0]


def inclusion_proof(leaves: tuple[bytes, ...], index: int) -> tuple[ProofStep, ...]:
    """Bottom-up steps.  A promoted node contributes no step at its level."""
    if not leaves:
        raise InvariantViolation("no proof exists in an empty tree")
    steps: list[ProofStep] = []
    position = index
    for level in _levels(leaves)[:-1]:
        if position == len(level) - 1 and len(level) % 2 == 1:
            position //= 2
            continue
        if position % 2 == 0:
            steps.append(ProofStep(ProofSide.RIGHT, level[position + 1]))
        else:
            steps.append(ProofStep(ProofSide.LEFT, level[position - 1]))
        position //= 2
    return tuple(steps)


def proof_bound(leaf_count: int) -> int:
    """The most steps an inclusion proof in a tree of this size can have.

    One step per level below the top, and promotion only ever removes one --
    so this is an upper bound rather than the exact length, which is what a
    verifier needs: it refuses the impossible without asserting the shape.
    """
    return max(leaf_count - 1, 0).bit_length()


def fold_proof(leaf: bytes, steps: tuple[ProofStep, ...]) -> bytes:
    folded = leaf
    for step in steps:
        if step.side is ProofSide.LEFT:
            folded = node_hash(step.sibling, folded)
        else:
            folded = node_hash(folded, step.sibling)
    return folded


@dataclass(frozen=True, slots=True)
class RootBinding:
    """The fields the root record binds beyond the hash tree itself."""

    tenant_id: str
    case_id: str
    revision_commitment: Digest
    bundle_manifest_digest: Digest
    certificate_schema_version: int


def root_node(binding: RootBinding, *, leaf_count: int, top: bytes) -> NRec:
    return NRec(
        TAG_COMMITMENT_ROOT,
        (
            NAtom(binding.tenant_id),
            NAtom(binding.case_id),
            binding.revision_commitment.to_node(),
            binding.bundle_manifest_digest.to_node(),
            NInt(binding.certificate_schema_version),
            NInt(leaf_count),
            NBytes(top),
        ),
    )


def root_hash(binding: RootBinding, *, leaf_count: int, top: bytes) -> bytes:
    return digest_octets(
        DigestKind.MERKLE_ROOT, encode(root_node(binding, leaf_count=leaf_count, top=top))
    ).octets


@dataclass(frozen=True, slots=True)
class CommitmentTree:
    """One committed record, salted and hashed.

    Holds the field salts, so it stays inside the boundary with the case salt
    that produced them.  What crosses is one salt per *disclosed* path, which
    tells a reader nothing about any other leaf.
    """

    binding: LeafBinding
    root_binding: RootBinding
    record: CommittedRecord
    salts: tuple[bytes, ...]
    leaves: tuple[bytes, ...]

    def __repr__(self) -> str:
        #  The field salts are derived secrets and the record is the case in
        #  cleartext. A default dataclass repr puts both in every traceback,
        #  every ``assert x, value`` and every log line that formatted this --
        #  and a reader who obtains one field salt can confirm a guess at the
        #  leaf it blinds, which is the oracle the salt exists to remove.
        return (
            f"CommitmentTree(case={self.root_binding.tenant_id}/{self.root_binding.case_id}, "
            f"leaves={len(self.leaves)}, root={self.root.hex()}, "
            f"record=<redacted>, salts=<redacted>)"
        )

    @property
    def paths(self) -> tuple[str, ...]:
        return self.record.paths

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)

    @property
    def root(self) -> bytes:
        return root_hash(self.root_binding, leaf_count=self.leaf_count, top=top_hash(self.leaves))

    def index_of(self, path: str) -> int | None:
        for index, candidate in enumerate(self.paths):
            if candidate == path:
                return index
        return None

    def disclosure_of(self, path: str) -> tuple[bytes, bytes, tuple[ProofStep, ...]] | None:
        """``(value octets, field salt, proof)`` for one path, or ``None``.

        ``None`` means the committed record has no leaf at this path for this
        outcome -- which is a normal state, not a failure: a policy naming
        ``kernel.outcome.action`` is silent, not wrong, on a divergent case.
        """
        index = self.index_of(path)
        if index is None:
            return None
        return (
            self.record.values[index][1],
            self.salts[index],
            inclusion_proof(self.leaves, index),
        )


def build_tree(
    *, binding: LeafBinding, root_binding: RootBinding, record: CommittedRecord, salt: CaseSalt
) -> CommitmentTree:
    """Salt every committed value and hash it into a tree.

    The leaf order is the record's canonical path order and nothing else, so
    the root is a function of the mapping.  Two processes that discovered the
    same leaves in different orders produce the same root; a process that
    discovered a different set does not, which is the only difference that
    should ever move it.
    """
    salts = tuple(field_salt(salt, path) for path in record.paths)
    leaves = tuple(
        leaf_hash(binding, path=path, salt=field, value_octets=octets)
        for (path, octets), field in zip(record.values, salts, strict=True)
    )
    return CommitmentTree(
        binding=binding,
        root_binding=root_binding,
        record=record,
        salts=salts,
        leaves=leaves,
    )


def verify_inclusion(
    *,
    binding: LeafBinding,
    root_binding: RootBinding,
    leaf_count: int,
    root: bytes,
    path: str,
    value_octets: bytes,
    salt: bytes,
    proof: tuple[ProofStep, ...],
) -> bool:
    """Recompute the leaf, fold the proof, rebuild the root record, compare.

    Everything this needs is either in the envelope the reader already holds or
    in the disclosure itself.  No undisclosed leaf is required, and no leaf the
    reader was not shown is revealed by running it.
    """
    if len(salt) != DIGEST_OCTETS or len(root) != DIGEST_OCTETS:
        return False
    if len(proof) > proof_bound(leaf_count):
        #  A proof longer than the tree can produce cannot fold to this root,
        #  and folding it anyway is work an adversary chose the size of. The
        #  bound is on the octets a sender supplied, so it is checked before
        #  any hashing rather than discovered by doing all of it.
        return False
    recomputed = leaf_hash(binding, path=path, salt=salt, value_octets=value_octets)
    folded = fold_proof(recomputed, proof)
    return root_hash(root_binding, leaf_count=leaf_count, top=folded) == root
