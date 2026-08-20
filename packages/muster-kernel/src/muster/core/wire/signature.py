"""A detached signature: an algorithm identifier and octets.

Deliberately carries **no key reference**.  A wrapper that restated the signer
would be a second, unsigned place for an identity to live, and re-attributing a
valid signature to another key would then be an edit rather than a forgery.
Every signed artifact in MUSTER puts its signer's own key reference *inside*
the body the signature covers, and a machine check says so.

It lives under ``wire`` rather than beside any one artifact because three
unrelated families need it -- transcript entries, authority publications and
commitment envelopes -- and the type they share must not make one of them
depend on another.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.wire.nodes import NAtom, NBytes, Node, NRec
from muster.core.wire.shape import read_atom, read_bytes, read_rec

TAG_SIGNATURE = "Signature/v1"


@dataclass(frozen=True, slots=True)
class Signature:
    algorithm: str
    octets: bytes

    def to_node(self) -> NRec:
        return NRec(TAG_SIGNATURE, (NAtom(self.algorithm), NBytes(self.octets)))


def read_signature(node: Node) -> Signature:
    algorithm, octets = read_rec(node, TAG_SIGNATURE, 2)
    return Signature(read_atom(algorithm), read_bytes(octets))
