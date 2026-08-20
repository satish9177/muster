"""The closed digest-domain namespace.

NON-PRODUCTION SPECIFICATION MATERIAL.

Domain separation is only worth anything if the namespace is CLOSED.  Two kinds
of domain exist and they must be disjoint and jointly exhaustive:

  * TYPE domains  -- owned by a declared wire type, preimage = that type's
                     canonical encoding.  Derived from `registry.py`.
  * AUXILIARY     -- domains whose preimage is not a single wire type: tree
                     separators, keyed commitments, and digests of external
                     state.  Each is listed here WITH its preimage, because a
                     domain whose preimage is undocumented is exactly the kind
                     of thing that silently collides with a type domain later.

`digests.digest()` refuses any domain not in the union, so an undeclared domain
is unusable rather than merely undocumented.

**Two withdrawals landed with G1 (section 12.4), and neither is a
supplement.**  `KEY_REGISTRY_SNAPSHOT` committed to key *existence*, so the
only question it could answer was "does this key exist"; it is replaced by the
TYPE domain `AUTHORITY_REGISTRY_SNAPSHOT`, whose preimage is a snapshot
answering "may this key say this, here, now".  Two live authority preimages
would be a downgrade path, so the old one is gone rather than deprecated.
`REVOCATION_SNAPSHOT` followed it for a related reason: its auxiliary preimage
was an untenanted `SEQ[Digest]`, and Q-12(f) has to *resolve* the snapshot to
ask whether a key is in it -- something resolved by digest alone carries
neither a tenant nor a publisher signature, so an untenanted list is equally
valid under every tenant.  It is now a type with both.
"""

from __future__ import annotations

#: name -> exact preimage, in words.  No entry may duplicate a type digest kind.
AUXILIARY_DIGEST_DOMAINS: dict[str, str] = {
    "MERKLE_NODE": "the two 32-octet children, concatenated left || right",
    "MERKLE_EMPTY": "the empty octet string; merkle(0) is this fixed constant",
    "FIELD_SALT": "HMAC key = salt_case; message = ascii(path)",
    "CASE_COMMITMENT": "HMAC key = salt_case; message = the 32 octets of the case digest",
    "REVISION_COMMITMENT": "HMAC key = salt_case; message = the 32 octets of revision_semantic_digest",
    "CONSTRAINT_LABEL": "canonical(ATOM) of Constraint.label -- a commitment path segment",
    "NON_EFFECT_KEY": "canonical(SEQ[ATOM]) of (NonEffect.rule_id, NonEffect.subject)",
    "GOLDEN_VECTOR_CORPUS": "name || 0x00 || octets || 0x00 for each vector, in declared order",
}


def all_domains() -> frozenset[str]:
    from .registry import REG
    from .schema import digest_kinds

    return frozenset(digest_kinds(REG)) | frozenset(AUXILIARY_DIGEST_DOMAINS)
