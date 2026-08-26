"""Process-stable demo keys are deterministic and population-separated."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from demo.stable_keys import _private_key, _public_key, _sign


def test_same_population_and_key_reference_resolve_one_key() -> None:
    assert _private_key("officer", "hero-key") is _private_key("officer", "hero-key")
    assert _public_key("officer", "hero-key") == _public_key("officer", "hero-key")


def test_populations_never_share_a_key() -> None:
    assert _public_key("officer", "same-ref") != _public_key("publisher", "same-ref")


def test_signing_the_same_preimage_twice_is_byte_identical() -> None:
    first = _sign("officer", "hero-key", b"authoritative preimage")
    second = _sign("officer", "hero-key", b"authoritative preimage")

    assert first == second
    assert first.octets == second.octets


def test_signature_verifies_only_under_its_own_population() -> None:
    preimage = b"authoritative preimage"
    signature = _sign("officer", "same-ref", preimage)
    officer = serialization.load_pem_public_key(_public_key("officer", "same-ref"))
    publisher = serialization.load_pem_public_key(_public_key("publisher", "same-ref"))
    assert isinstance(officer, ec.EllipticCurvePublicKey)
    assert isinstance(publisher, ec.EllipticCurvePublicKey)

    officer.verify(signature.octets, preimage, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignature):
        publisher.verify(signature.octets, preimage, ec.ECDSA(hashes.SHA256()))
