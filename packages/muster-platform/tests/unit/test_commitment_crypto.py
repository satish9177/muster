"""The two commitment ports and their local implementations, attacked directly.

Everything here was reachable only through the positive path of a higher-level
test until an adversarial review pointed out that a boundary exercised only by
success is a boundary whose failure modes nobody has seen.  A verifier that
raised instead of returning ``False``, or returned ``True`` for a key it holds
no material for, would have passed every other test in the suite.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.core.evidence.transcript import Signature
from muster.core.results import InvariantViolation
from muster.core.wire.digests import Digest
from muster.platform.adapters.crypto import (
    ECDSA_P256_SHA256,
    LocalEcdsaSigner,
    LocalMacSaltSource,
)
from muster.platform.commit.envelope import (
    CommitmentEnvelope,
    sign_envelope,
    signing_preimage,
    verify_envelope,
)
from support.commitment import MUSTER_KEY, OTHER_KEY, SALT_ROOT_KEY, signing_pair


def _envelope(**overrides: object) -> CommitmentEnvelope:
    base = CommitmentEnvelope(
        tenant_id="ALPHA",
        case_id="CASE-1",
        case_commitment=Digest(bytes(32)),
        revision_commitment=Digest(bytes(range(32, 64))),
        bundle_manifest_digest=Digest(bytes(range(64, 96))),
        disclosure_policy_digest=Digest(bytes(range(96, 128))),
        certificate_schema_version=1,
        leaf_count=24,
        root=bytes(range(32)),
        signer_key_ref=MUSTER_KEY,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


#  ---- the salt source -------------------------------------------------------


def test_the_salt_source_distinguishes_a_split_from_its_neighbour() -> None:
    """``("AB", "C")`` and ``("A", "BC")`` are two cases, not one.

    A delimiter-free concatenation gives them one salt, and one salt gives each
    of them every one of the other's leaves to forge with. The canonical
    encoding is what makes the pair unambiguous, and this is the test that says
    so rather than the comment.
    """
    source = LocalMacSaltSource(SALT_ROOT_KEY)
    assert source.salt_for(tenant_id="AB", case_id="C") != source.salt_for(
        tenant_id="A", case_id="BC"
    )


def test_the_salt_source_is_deterministic_and_key_dependent() -> None:
    """Deterministic, so a salt survives a restart without being written down."""
    here = LocalMacSaltSource(SALT_ROOT_KEY)
    elsewhere = LocalMacSaltSource(bytes(range(64, 96)))
    assert here.salt_for(tenant_id="A", case_id="C") == here.salt_for(tenant_id="A", case_id="C")
    assert here.salt_for(tenant_id="A", case_id="C") != elsewhere.salt_for(
        tenant_id="A", case_id="C"
    )


def test_a_short_root_key_is_refused() -> None:
    with pytest.raises(InvariantViolation):
        LocalMacSaltSource(bytes(16))


def test_the_salt_source_never_prints_its_root_key() -> None:
    assert SALT_ROOT_KEY.hex() not in repr(LocalMacSaltSource(SALT_ROOT_KEY))


#  ---- the signer and the verifier -------------------------------------------


def test_a_signature_verifies_and_the_signer_never_prints_its_key() -> None:
    signer, verifier = signing_pair()
    preimage = signing_preimage(_envelope())
    signature = signer.sign(preimage)
    assert signature.algorithm == ECDSA_P256_SHA256
    assert verifier.verify(key_ref=MUSTER_KEY, preimage=preimage, signature=signature)
    assert "redacted" in repr(signer)
    assert signer.private_key_pem.hex() not in repr(signer)


def test_the_verifier_refuses_a_signature_under_another_algorithm() -> None:
    """Algorithm confusion, refused rather than attempted."""
    signer, verifier = signing_pair()
    preimage = signing_preimage(_envelope())
    signature = signer.sign(preimage)
    swapped = replace(signature, algorithm="HMAC-SHA256-SPEC-STANDIN")
    assert not verifier.verify(key_ref=MUSTER_KEY, preimage=preimage, signature=swapped)


@pytest.mark.parametrize("octets", [b"", b"\x00", b"not der at all", bytes(70)])
def test_the_verifier_refuses_malformed_signature_octets_without_raising(
    octets: bytes,
) -> None:
    """Total by contract: these octets came from a participant.

    A bit-flip inside a well-formed DER signature exercises one path; empty,
    truncated and non-DER octets exercise the decode path, which is the one an
    exception escapes from.
    """
    _signer, verifier = signing_pair()
    preimage = signing_preimage(_envelope())
    assert not verifier.verify(
        key_ref=MUSTER_KEY, preimage=preimage, signature=Signature(ECDSA_P256_SHA256, octets)
    )


def test_the_verifier_refuses_a_key_reference_it_holds_no_material_for() -> None:
    """Distinct from the reader's trust list: this is an absent public key."""
    signer, _verifier = signing_pair()
    from muster.platform.adapters.crypto import LocalEcdsaVerifier

    empty = LocalEcdsaVerifier({})
    preimage = signing_preimage(_envelope())
    assert not empty.verify(key_ref=MUSTER_KEY, preimage=preimage, signature=signer.sign(preimage))


def test_a_key_that_is_not_an_ec_p256_key_is_refused() -> None:
    with pytest.raises(InvariantViolation):
        LocalEcdsaSigner(MUSTER_KEY, b"-----BEGIN PRIVATE KEY-----\nnope\n").sign(
            signing_preimage(_envelope())
        )


#  ---- the envelope ----------------------------------------------------------


def test_signing_refuses_an_envelope_that_names_another_key() -> None:
    """A signature under B over a body naming A verifies under neither reading."""
    signer, _verifier = signing_pair()
    with pytest.raises(InvariantViolation):
        sign_envelope(_envelope(signer_key_ref=OTHER_KEY), signer)


def test_verifying_refuses_a_signer_outside_the_trusted_set() -> None:
    """Authenticity and trust are two questions; answering only the first is the defect."""
    signer, verifier = signing_pair()
    signed = sign_envelope(_envelope(), signer)
    assert verify_envelope(signed, verifier, trusted_keys=frozenset({MUSTER_KEY}))
    assert not verify_envelope(signed, verifier, trusted_keys=frozenset())
    assert not verify_envelope(signed, verifier, trusted_keys=frozenset({OTHER_KEY}))


def test_verifying_refuses_a_tampered_signature() -> None:
    signer, verifier = signing_pair()
    signed = sign_envelope(_envelope(), signer)
    octets = signed.signature.octets
    tampered = replace(
        signed, signature=replace(signed.signature, octets=octets[:-1] + bytes([octets[-1] ^ 1]))
    )
    assert not verify_envelope(tampered, verifier, trusted_keys=frozenset({MUSTER_KEY}))


def test_every_envelope_field_is_covered_by_the_signature() -> None:
    """Field by field, because "no security-critical field beside a signature"
    is a claim about *which* fields, and a claim about which fields is only
    worth having if every one of them was tried."""
    signer, verifier = signing_pair()
    signed = sign_envelope(_envelope(), signer)
    mutations = (
        _envelope(tenant_id="BETA"),
        _envelope(case_id="CASE-2"),
        _envelope(case_commitment=Digest(bytes(range(1, 33)))),
        _envelope(revision_commitment=Digest(bytes(range(2, 34)))),
        _envelope(bundle_manifest_digest=Digest(bytes(range(3, 35)))),
        _envelope(disclosure_policy_digest=Digest(bytes(range(4, 36)))),
        _envelope(certificate_schema_version=2),
        _envelope(leaf_count=25),
        _envelope(root=bytes(range(1, 33))),
        _envelope(signer_key_ref=OTHER_KEY),
    )
    for mutated in mutations:
        assert not verifier.verify(
            key_ref=MUSTER_KEY,
            preimage=signing_preimage(mutated),
            signature=signed.signature,
        ), mutated


def test_an_envelope_refuses_a_root_that_is_not_a_digest() -> None:
    with pytest.raises(InvariantViolation):
        _envelope(root=b"short")


def test_an_envelope_refuses_a_negative_leaf_count() -> None:
    with pytest.raises(InvariantViolation):
        _envelope(leaf_count=-1)
