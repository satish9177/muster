"""What a source attestation and a case construction signature cover.

One function, and it lives here rather than in :mod:`muster.core.authority`
because of the direction the dependency has to run.  Authority is *beneath*
evidence -- check Q-12 runs during relation validation, so the check has to be
importable by the module that validates -- and a preimage construction over an
``AcquisitionPayload`` reaches the other way.  The preimage *type* stays with
the ports it is passed to; the construction stays with the artifact it covers.

The covered value is a domain-separated digest rather than the encoding itself,
so the octets handed to a signer are fixed-width whatever the payload contains.
That is what a key management service signs, and what a local implementation
must therefore sign too: replacing one with the other changes custody and
nothing about what was covered.
"""

from __future__ import annotations

from muster.core.authority.signing import AttestationPreimage, OfficerPreimage
from muster.core.evidence.transcript import AcquisitionPayload, CaseConstructionRecordBody
from muster.core.wire.codec import encode
from muster.core.wire.digests import DigestKind, digest_octets


def attestation_preimage(payload: AcquisitionPayload) -> AttestationPreimage:
    """The whole payload, under the attestation domain.

    Tenant, case, proposition, relation, schema pin, observation and issue
    instants, validity, nonce, source class, signer key reference, policy
    version and the request it answers.  There is no security-bearing field
    beside the signature, so a receipt cannot be re-tenanted, re-cased,
    re-classed or re-attributed by editing what the signature did not reach --
    and a receipt whose class was edited is a receipt whose signature no longer
    verifies, which is the first refusal on the admission path rather than the
    last.
    """
    return AttestationPreimage(
        digest_octets(DigestKind.ATTESTATION_PAYLOAD, encode(payload.to_node())).octets
    )


def case_construction_preimage(body: CaseConstructionRecordBody) -> OfficerPreimage:
    """The whole body, under the construction-body domain.

    Tenant, case, creation instant, subjects, contract, parties and their
    roles, declared instances, case scope coordinates and the officer's own key
    reference.  The coordinates are the field this exists for: Q-12(d) reads
    them and refuses a source that was not authorized over them, so a record
    whose coordinates were not covered by an officer signature would let a
    source name the site it is authorized for and be authorized for it.
    """
    return OfficerPreimage(
        digest_octets(DigestKind.CASE_CONSTRUCTION_BODY, encode(body.to_node())).octets
    )
