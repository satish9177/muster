"""Local implementations of the two commitment ports.

The architecture puts both of these in a key management service: case salts are
derived by a **MAC** the control plane cannot export, and envelopes are signed
with an **asymmetric EC P-256 key** the control plane cannot read.  Neither is
a cloud dependency yet, and this milestone deliberately builds no cloud, so
what is here is the same two primitives with the key held locally.

That is a custody difference and nothing else, which is precisely why the ports
exist.  The salt derivation is HMAC-SHA256 -- the primitive a KMS MAC key *is*.
The signature is ECDSA over P-256 with SHA-256 -- the primitive
``EC_SIGN_P256_SHA256`` *is*.  Substituting the managed version later replaces
these two classes and changes nothing else, because neither the covered octets
nor the algorithm identifier moves.

**This is not production key custody and does not pretend to be.**  A root key
in this process is readable by this process; a KMS key is not.  What the local
implementation does buy is the property that actually matters to milestone D --
verification is asymmetric, so a participant checking their own view holds
public material and could not forge a view for anybody, including themselves.

This is the only module in the control plane that imports a cryptography
library, the same way the SQL adapter is the only one that imports a driver.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from muster.core.evidence.transcript import Signature
from muster.core.results import InvariantViolation
from muster.core.wire.codec import encode
from muster.core.wire.nodes import NAtom, NSeq
from muster.platform.commit.envelope import SigningPreimage
from muster.platform.commit.salts import CASE_SALT_OCTETS, CaseSalt

#: The algorithm identifier that travels inside every ``Signature`` this signer
#: produces.  It names the primitive, not the custody, so a managed key
#: producing the same signatures produces the same identifier -- and a verifier
#: written against it does not have to learn where the key lived.
ECDSA_P256_SHA256 = "ECDSA-P256-SHA256"

#: The label this adapter's salt derivation opens with.  Deliberately *not* a
#: member of ``CommitmentDomain``: that enumeration is the frozen namespace of
#: domains MUSTER artifacts are digested under, and a local key-derivation
#: input is neither an artifact nor frozen.  It is prefixed and NUL-terminated
#: the same way, so it cannot collide with a declared domain, and it is a fact
#: about this adapter that a managed implementation replaces wholesale.
_SALT_LABEL = b"muster/v1/adapter/CASE_SALT\0"

_ROOT_KEY_MINIMUM_OCTETS = 32


def _salt_message(tenant_id: str, case_id: str) -> bytes:
    #  Canonically encoded rather than concatenated: ``("AB", "C")`` and
    #  ``("A", "BC")`` are different cases and a delimiter-free concatenation
    #  would give them one salt, which would give each of them the other's
    #  leaves to forge with.
    return encode(NSeq((NAtom(tenant_id), NAtom(case_id))))


@dataclass(frozen=True, slots=True)
class LocalMacSaltSource:
    """Case salts derived by MAC under a locally held root key.

    Deterministic, so a salt survives a restart without ever being written
    down: the same tenant and case produce the same salt for as long as the
    root key exists, and destroying the root key destroys every commitment's
    ability to be re-derived -- which is the crypto-shredding property the
    retention design wants, arrived at by not storing anything.
    """

    root_key: bytes

    def __post_init__(self) -> None:
        if len(self.root_key) < _ROOT_KEY_MINIMUM_OCTETS:
            raise InvariantViolation(
                f"a salt root key is at least {_ROOT_KEY_MINIMUM_OCTETS} octets"
            )

    def salt_for(self, *, tenant_id: str, case_id: str) -> CaseSalt:
        mac = hmac.new(
            self.root_key, _SALT_LABEL + _salt_message(tenant_id, case_id), hashlib.sha256
        )
        return CaseSalt(mac.digest()[:CASE_SALT_OCTETS])

    def __repr__(self) -> str:
        return "LocalMacSaltSource(root_key=<redacted>)"


def _load_private(pem: bytes) -> EllipticCurvePrivateKey:
    """The signing key, or a typed refusal.

    Unloadable material is a deployment defect rather than adversarial input --
    nobody but an operator supplies a signing key -- so it raises. It raises
    the *invariant* violation this codebase uses for a defect, though, rather
    than whatever the cryptography library happened to throw: a ``ValueError``
    escaping a signer says nothing about which of its two keys was wrong.
    """
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise InvariantViolation("a commitment signing key does not load") from exc
    if not isinstance(key, EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise InvariantViolation("a commitment signing key is an EC P-256 private key")
    return key


def _load_public(pem: bytes) -> EllipticCurvePublicKey:
    """The verification key.

    Raises for the same reason, and the verifier catches it: verification runs
    on a key reference a *participant* chose, so a keyring entry that will not
    load has to become ``False`` rather than an exception on the reader path.
    """
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise InvariantViolation("a commitment verification key is an EC P-256 public key")
    return key


@dataclass(frozen=True, slots=True)
class LocalEcdsaSigner:
    """Signs commitment envelopes with a locally held P-256 key.

    The key reference is a field, so it cannot disagree with the key: an
    envelope is built naming ``key_ref`` and this signer refuses to sign an
    envelope naming anything else.
    """

    key_ref: str
    private_key_pem: bytes

    def sign(self, preimage: SigningPreimage) -> Signature:
        signed = _load_private(self.private_key_pem).sign(preimage.octets, ECDSA(hashes.SHA256()))
        return Signature(ECDSA_P256_SHA256, signed)

    def __repr__(self) -> str:
        return f"LocalEcdsaSigner(key_ref={self.key_ref!r}, private_key_pem=<redacted>)"


@dataclass(frozen=True, slots=True)
class LocalEcdsaVerifier:
    """Checks commitment signatures against public keys the reader holds.

    Public material only.  A participant handed this can check every view they
    receive and forge none of them, which is the difference between "MUSTER
    says this is the record" and "somebody who could read a shared secret says
    so".
    """

    public_keys: Mapping[str, bytes]

    def verify(self, *, key_ref: str, preimage: SigningPreimage, signature: Signature) -> bool:
        if signature.algorithm != ECDSA_P256_SHA256:
            return False
        material = self.public_keys.get(key_ref)
        if material is None:
            return False
        try:
            _load_public(material).verify(signature.octets, preimage.octets, ECDSA(hashes.SHA256()))
        except (InvalidSignature, UnsupportedAlgorithm, InvariantViolation, ValueError):
            #  Total by contract.  These octets came from a participant, and a
            #  malformed key, a truncated DER signature and a wrong curve all
            #  mean the same thing to a reader: this view is not authentic.
            return False
        return True
