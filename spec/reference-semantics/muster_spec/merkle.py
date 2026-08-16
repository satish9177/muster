"""Canonical commitment tree.

NON-PRODUCTION SPECIFICATION MATERIAL.

    leaf(p)   = SHA-256("muster/v1/MERKLE_LEAF" || 0x00 || canonical(CommitmentLeaf))
    node(L,R) = SHA-256("muster/v1/MERKLE_NODE" || 0x00 || L || R)
    merkle(0) = SHA-256("muster/v1/MERKLE_EMPTY" || 0x00)
    root      = SHA-256("muster/v1/MERKLE_ROOT" || 0x00 || canonical(CommitmentRoot))

Odd levels PROMOTE the final node.  They do not duplicate it: duplication is the
construction behind the classic Merkle malleability defect in which a duplicated
final leaf collides with a different leaf multiset.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .digests import PREFIX, digest_bytes, field_salt
from .nodes import Atom, Bytes, Digest, Int, Node, Rec, Seq, encode


class CommitmentError(Exception):
    pass


def leaf_hash(
    tenant_id: str,
    case_commitment: Digest,
    revision_commitment: Digest,
    schema_version: int,
    path: str,
    salt: bytes,
    value_bytes: bytes,
) -> bytes:
    leaf = Rec(
        "CommitmentLeaf/v1",
        [
            Atom(tenant_id),
            case_commitment,
            revision_commitment,
            Int(schema_version),
            Atom(path),
            Bytes(salt),
            Bytes(value_bytes),
        ],
    )
    return digest_bytes("MERKLE_LEAF", encode(leaf))


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise CommitmentError("internal node children must be 32 octets")
    return digest_bytes("MERKLE_NODE", left + right)


def empty_hash() -> bytes:
    return hashlib.sha256(PREFIX + b"MERKLE_EMPTY\x00").digest()


def levels(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        return [[empty_hash()]]
    out = [list(leaves)]
    while len(out[-1]) > 1:
        cur = out[-1]
        nxt = [node_hash(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
        if len(cur) % 2 == 1:
            nxt.append(cur[-1])  # PROMOTION
        out.append(nxt)
    return out


def merkle(leaves: list[bytes]) -> bytes:
    return levels(leaves)[-1][0]


def inclusion_proof(leaves: list[bytes], index: int) -> list[tuple[str, bytes]]:
    """Bottom-up steps.  A promoted node contributes no step at its level."""
    if not leaves:
        raise CommitmentError("no proof exists in an empty tree")
    steps: list[tuple[str, bytes]] = []
    lv = levels(leaves)
    i = index
    for level in lv[:-1]:
        if i == len(level) - 1 and len(level) % 2 == 1:
            i //= 2
            continue  # promoted: no sibling, no step
        if i % 2 == 0:
            steps.append(("R", level[i + 1]))
        else:
            steps.append(("L", level[i - 1]))
        i //= 2
    return steps


def fold_proof(leaf: bytes, steps: list[tuple[str, bytes]]) -> bytes:
    h = leaf
    for side, sibling in steps:
        h = node_hash(sibling, h) if side == "L" else node_hash(h, sibling)
    return h


def commitment_root_node(
    tenant_id: str,
    case_id: str,
    revision_commitment: Digest,
    bundle_manifest_digest: Digest,
    schema_version: int,
    leaf_count: int,
    merkle_value: bytes,
) -> Rec:
    return Rec(
        "CommitmentRoot/v1",
        [
            Atom(tenant_id),
            Atom(case_id),
            revision_commitment,
            bundle_manifest_digest,
            Int(schema_version),
            Int(leaf_count),
            Bytes(merkle_value),
        ],
    )


def root_hash(root_node: Rec) -> bytes:
    return digest_bytes("MERKLE_ROOT", encode(root_node))


# --------------------------------------------------------------------------
# whole-tree construction
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Tree:
    tenant_id: str
    case_id: str
    case_commitment: Digest
    revision_commitment: Digest
    bundle_manifest_digest: Digest
    schema_version: int
    paths: tuple[str, ...]
    values: tuple[bytes, ...]
    salts: tuple[bytes, ...]
    leaves: tuple[bytes, ...]

    @property
    def merkle(self) -> bytes:
        return merkle(list(self.leaves))

    @property
    def root_node(self) -> Rec:
        return commitment_root_node(
            self.tenant_id,
            self.case_id,
            self.revision_commitment,
            self.bundle_manifest_digest,
            self.schema_version,
            len(self.leaves),
            self.merkle,
        )

    @property
    def root(self) -> bytes:
        return root_hash(self.root_node)

    def index_of(self, path: str) -> int:
        return self.paths.index(path)

    def proof(self, path: str) -> list[tuple[str, bytes]]:
        return inclusion_proof(list(self.leaves), self.index_of(path))


def build_tree(
    tenant_id: str,
    case_id: str,
    case_commitment: Digest,
    revision_commitment: Digest,
    bundle_manifest_digest: Digest,
    schema_version: int,
    salt_case: bytes,
    committed: dict[str, bytes],
) -> Tree:
    if len(set(committed)) != len(committed):  # pragma: no cover - dict is unique by build
        raise CommitmentError("DuplicateCommitmentPath")
    paths = sorted(committed, key=lambda p: encode(Atom(p)))
    salts = [field_salt(salt_case, p) for p in paths]
    leaves = [
        leaf_hash(
            tenant_id,
            case_commitment,
            revision_commitment,
            schema_version,
            p,
            s,
            committed[p],
        )
        for p, s in zip(paths, salts)
    ]
    return Tree(
        tenant_id=tenant_id,
        case_id=case_id,
        case_commitment=case_commitment,
        revision_commitment=revision_commitment,
        bundle_manifest_digest=bundle_manifest_digest,
        schema_version=schema_version,
        paths=tuple(paths),
        values=tuple(committed[p] for p in paths),
        salts=tuple(salts),
        leaves=tuple(leaves),
    )


def verify_disclosure(
    envelope: Rec,
    path: str,
    value_bytes: bytes,
    salt: bytes,
    proof: list[tuple[str, bytes]],
) -> bool:
    """Recompute the leaf, fold the proof, rebuild the root, compare.

    The verifier needs nothing it does not already hold: the envelope supplies
    tenant, case commitment, revision commitment, schema version, leaf count,
    bundle digest and root.  No undisclosed leaf is required.
    """
    (
        tenant_id,
        _case_id,
        case_commitment,
        revision_commitment,
        bundle_manifest_digest,
        _disclosure_policy_digest,
        schema_version,
        leaf_count,
        root,
        _signer,
    ) = envelope.fields
    assert isinstance(tenant_id, Atom) and isinstance(schema_version, Int)
    assert isinstance(case_commitment, Digest) and isinstance(revision_commitment, Digest)
    assert isinstance(root, Bytes) and isinstance(leaf_count, Int)

    computed_leaf = leaf_hash(
        tenant_id.value,
        case_commitment,
        revision_commitment,
        schema_version.value,
        path,
        salt,
        value_bytes,
    )
    folded = fold_proof(computed_leaf, proof)
    rebuilt = commitment_root_node(
        tenant_id.value,
        envelope.fields[1].value,  # type: ignore[union-attr]
        revision_commitment,
        bundle_manifest_digest,  # type: ignore[arg-type]
        schema_version.value,
        leaf_count.value,
        folded,
    )
    return root_hash(rebuilt) == root.value
