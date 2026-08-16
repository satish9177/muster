"""Domain-separated digests, salts and commitments.

NON-PRODUCTION SPECIFICATION MATERIAL.

    digest(KIND, bytes)   = SHA-256("muster/v1/" || KIND || 0x00 || bytes)
    salt(path)            = HMAC-SHA256(salt_case, "muster/v1/FIELD_SALT" || 0x00 || path)
    commit(KIND, d)       = HMAC-SHA256(salt_case, "muster/v1/" || KIND || 0x00 || d)

`digest` is public and deterministic.  `salt` and `commit` are keyed on the
per-case secret, which never leaves the trust boundary -- that keying is what
stops a participant from confirming a guessed value or a guessed revision by
recomputation.
"""

from __future__ import annotations

import hashlib
import hmac

from .nodes import Digest, Node, encode

PREFIX = b"muster/v1/"


class UndeclaredDigestDomain(Exception):
    """Raised when a digest is taken under a domain outside the closed namespace."""


def _require_declared(kind: str) -> None:
    from .domains import all_domains

    if kind not in all_domains():
        raise UndeclaredDigestDomain(
            f"{kind!r} is not a declared digest domain.  Domain separation is only "
            f"worth anything if the namespace is closed: give it to a type as its "
            f"digest_kind, or add it to AUXILIARY_DIGEST_DOMAINS with its preimage."
        )


def digest_bytes(kind: str, payload: bytes) -> bytes:
    _require_declared(kind)
    return hashlib.sha256(PREFIX + kind.encode("ascii") + b"\x00" + payload).digest()


def digest(kind: str, payload: bytes) -> Digest:
    return Digest(digest_bytes(kind, payload))


def digest_node(kind: str, node: Node) -> Digest:
    return digest(kind, encode(node))


def field_salt(salt_case: bytes, path: str) -> bytes:
    _require_salt(salt_case)
    _require_declared("FIELD_SALT")
    return hmac.new(
        salt_case, PREFIX + b"FIELD_SALT\x00" + path.encode("ascii"), hashlib.sha256
    ).digest()


def commitment(salt_case: bytes, kind: str, value: Digest) -> Digest:
    """[B11] A salted commitment to a public digest.

    `revision_semantic_digest` is a deterministic function of inputs a participant
    may be able to enumerate, so publishing it raw turns the envelope into an
    oracle: rebuild each candidate transcript, compare digests, learn the private
    input.  Keying on `salt_case` removes the oracle while preserving every
    binding property the verifier needs.
    """
    _require_salt(salt_case)
    _require_declared(kind)
    return Digest(
        hmac.new(
            salt_case, PREFIX + kind.encode("ascii") + b"\x00" + value.raw, hashlib.sha256
        ).digest()
    )


def _require_salt(salt_case: bytes) -> None:
    if len(salt_case) != 32:
        raise ValueError("salt_case must be exactly 32 octets")


# Merkle domain separators -- distinct tags so no leaf hash can be reinterpreted
# as an internal node.
MERKLE_LEAF = "MERKLE_LEAF"
MERKLE_NODE = "MERKLE_NODE"
MERKLE_EMPTY = "MERKLE_EMPTY"
MERKLE_ROOT = "MERKLE_ROOT"

CASE_COMMITMENT = "CASE_COMMITMENT"
REVISION_COMMITMENT = "REVISION_COMMITMENT"
