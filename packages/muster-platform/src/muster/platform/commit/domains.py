"""The auxiliary half of the digest namespace, with its preimages written down.

``DigestKind`` in the kernel holds every domain whose preimage is one wire
type's canonical encoding.  These are the rest: a tree node has two children
and no type, the empty tree has no preimage at all, and a keyed salt label is
not an artifact anybody encodes.  They still need domains, and a domain whose
preimage is undocumented is exactly the thing that silently collides with a
type domain two milestones later -- so each member below carries its preimage
in words, and a test asserts the two namespaces are disjoint.

Both halves open their preimage with the same octets.  That construction lives
once, in :func:`muster.core.wire.digests.domain_separator`, and this module
calls it rather than restating it.

The union of the two halves is exactly the frozen namespace, and a test says
so rather than a docstring: every member here is declared in the frozen
auxiliary table with its preimage, every member of the type half names a frozen
type, and the two do not intersect.  A derivation label that is *not* a MUSTER
preimage domain -- an adapter's own key-derivation input, say -- does not
belong here at all, because putting it here would widen a namespace whose only
value is being closed.
"""

from __future__ import annotations

import hashlib
from enum import Enum

from muster.core.wire.digests import domain_separator


class CommitmentDomain(Enum):
    """Domains whose preimage is not a single wire type.

    The value of each member is the domain string exactly as it appears inside
    the preimage.  Nothing here is spelled at a call site: an operation takes a
    member, so an undeclared domain is unrepresentable rather than rejected.
    """

    #: The two 32-octet children of an internal node, concatenated left ‖ right.
    MERKLE_NODE = "MERKLE_NODE"
    #: The empty octet string.  The tree over no leaves is this fixed constant.
    MERKLE_EMPTY = "MERKLE_EMPTY"
    #: HMAC key = the case salt; message = the ASCII octets of a commitment path.
    FIELD_SALT = "FIELD_SALT"
    #: HMAC key = the case salt; message = the 32 octets of the construction digest.
    CASE_COMMITMENT = "CASE_COMMITMENT"
    #: HMAC key = the case salt; message = the 32 octets of the revision digest.
    REVISION_COMMITMENT = "REVISION_COMMITMENT"
    #: The canonical encoding of a ``Constraint``'s label, as a path segment.
    CONSTRAINT_LABEL = "CONSTRAINT_LABEL"
    #: The canonical encoding of SEQ[ATOM] of a ``NonEffect``'s (rule_id, subject).
    NON_EFFECT_KEY = "NON_EFFECT_KEY"


def unkeyed_digest(domain: CommitmentDomain, payload: bytes) -> bytes:
    """SHA-256 over ``domain`` and these octets.  Public and recomputable.

    Returns raw octets rather than a ``Digest``: both callers are tree hashing,
    where the result is an internal node rather than an artifact identity, and
    a ``Digest`` would claim it names something it does not.

    The keyed construction over the other five domains is *not* here.  It takes
    a case salt as its key, and the salt has exactly one home -- see
    ``commit.salts``, which is the only module allowed to hold one.
    """
    return hashlib.sha256(domain_separator(domain.value) + payload).digest()
