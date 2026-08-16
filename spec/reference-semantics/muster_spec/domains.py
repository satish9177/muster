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
"""

from __future__ import annotations

#: name -> exact preimage, in words.  No entry may duplicate a type digest kind.
AUXILIARY_DIGEST_DOMAINS: dict[str, str] = {
    "MERKLE_NODE": "the two 32-octet children, concatenated left || right",
    "MERKLE_EMPTY": "the empty octet string; merkle(0) is this fixed constant",
    "FIELD_SALT": "HMAC key = salt_case; message = ascii(path)",
    "CASE_COMMITMENT": "HMAC key = salt_case; message = the 32 octets of the case digest",
    "REVISION_COMMITMENT": "HMAC key = salt_case; message = the 32 octets of revision_semantic_digest",
    "KEY_REGISTRY_SNAPSHOT": "key_ref || 0x00 || SHA-256(key material), ascending by key_ref",
    "REVOCATION_SNAPSHOT": "canonical(SEQ[Digest]) of the revoked signing-key references",
    "CONSTRAINT_LABEL": "canonical(ATOM) of Constraint.label -- a commitment path segment",
    "NON_EFFECT_KEY": "canonical(SEQ[ATOM]) of (NonEffect.rule_id, NonEffect.subject)",
    "GOLDEN_VECTOR_CORPUS": "name || 0x00 || octets || 0x00 for each vector, in declared order",
}


def all_domains() -> frozenset[str]:
    from .registry import REG
    from .schema import digest_kinds

    return frozenset(digest_kinds(REG)) | frozenset(AUXILIARY_DIGEST_DOMAINS)
