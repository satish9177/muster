"""The agent's own signing key, and the only place a crypto library appears here.

A source key lives with the source.  That is what makes a receipt evidence
*about the source* rather than about MUSTER, and it is why this module exists
at all rather than being imported from the control plane: the control plane's
crypto adapter also derives case salts, and a case salt is the one secret an
agent must never be one import away from.

So the primitive is implemented twice, in two distributions, and the
duplication is the boundary rather than a failure to factor.  What the two
copies must agree on is the *algorithm identifier and the covered octets*, and
they do -- the identifier is a constant both spell identically, and the covered
value is a domain-separated digest constructed by the kernel, which neither
copy computes for itself.  An architecture test asserts the identifier still
matches; if it ever stops, every receipt an agent signs stops verifying, loudly
and immediately, which is the failure mode to want.

Locally the key is a PEM an operator holds.  Deployed, the same interface is
satisfied by a managed key service, and the difference is custody rather than
semantics: the octets handed to a signer are a fixed-width digest whatever the
payload contains, which is exactly what a key service signs.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey

from muster.core.authority.signing import AttestationPreimage
from muster.core.results import InvariantViolation
from muster.core.wire.signature import Signature

#: The one algorithm a source attestation is signed under.  Spelled identically
#: in the control plane's own adapter; the two are checked against each other,
#: because a mismatch would make every agent-signed receipt unverifiable.
ECDSA_P256_SHA256 = "ECDSA-P256-SHA256"


@dataclass(frozen=True, slots=True)
class LocalSourceSigner:
    """Signs source attestations with a P-256 key this process holds.

    ``key_ref`` is a field rather than an argument, exactly as it is on every
    other signer in the system: the identity a signer signs under is a fact
    about the signer, so a payload cannot be built naming one key and signed
    with another.
    """

    key_ref: str
    private_key_pem: bytes

    def sign(self, preimage: AttestationPreimage) -> Signature:
        return Signature(
            ECDSA_P256_SHA256,
            _load(self.private_key_pem).sign(preimage.octets, ECDSA(hashes.SHA256())),
        )

    def __repr__(self) -> str:
        """Never the key material.

        A dataclass ``repr`` puts a private key into any log line, exception or
        test failure that interpolates the signer -- and an agent's signer is
        interpolated by exactly the diagnostics somebody writes at three in the
        morning.
        """
        return f"LocalSourceSigner(key_ref={self.key_ref!r}, private_key_pem=<redacted>)"


def _load(pem: bytes) -> EllipticCurvePrivateKey:
    """The signing key, or a typed refusal naming what was wrong with it.

    A signing key is supplied by an operator and never by a caller, so
    unloadable material is a deployment defect and raises.  It raises this
    codebase's invariant violation rather than whatever the library threw,
    because a bare ``ValueError`` escaping a signer says nothing about which
    key was wrong or whose process is about to stop attesting.
    """
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as failure:
        raise InvariantViolation("a source signing key does not load") from failure
    if not isinstance(key, EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise InvariantViolation("a source signing key is an EC P-256 private key")
    return key
