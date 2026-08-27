"""Process-stable synthetic keys shared by MUSTER's durable demos.

The keys derived here protect no real system. The cloud hero uses them for the
officer, authority-publisher, catalog-publisher, and fixture-source populations
on its synthetic hero tenant; it never derives a source key held by a deployed
agent. The local durable Ravi demo also uses the derived source population so
its entirely synthetic case can survive a process restart.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from hashlib import sha256

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from muster.core.authority.signing import (
    AttestationPreimage,
    OfficerPreimage,
    PublisherPreimage,
)
from muster.core.results import InvariantViolation
from muster.core.wire.signature import Signature
from muster.platform.adapters.crypto import ECDSA_P256_SHA256

_P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
_KEY_NAMESPACE = b"MUSTER local durable Ravi demo keys/v1\x00"


@dataclass(frozen=True, slots=True)
class _SourceSigner:
    key_ref: str

    def sign(self, preimage: AttestationPreimage) -> Signature:
        return _sign("source", self.key_ref, preimage.octets)


@dataclass(frozen=True, slots=True)
class _OfficerSigner:
    key_ref: str

    def sign(self, preimage: OfficerPreimage) -> Signature:
        return _sign("officer", self.key_ref, preimage.octets)


@dataclass(frozen=True, slots=True)
class _PublisherSigner:
    key_ref: str

    def sign(self, preimage: PublisherPreimage) -> Signature:
        return _sign("publisher", self.key_ref, preimage.octets)


@cache
def _private_key(population: str, key_ref: str) -> ec.EllipticCurvePrivateKey:
    label = _KEY_NAMESPACE + population.encode("ascii") + b"\x00" + key_ref.encode("utf-8")
    scalar = int.from_bytes(sha256(label).digest(), "big") % (_P256_ORDER - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


@cache
def _public_key(population: str, key_ref: str) -> bytes:
    return _private_key(population, key_ref).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _sign(population: str, key_ref: str, octets: bytes) -> Signature:
    try:
        signature = _private_key(population, key_ref).sign(
            octets,
            ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
        )
    except UnsupportedAlgorithm as error:
        raise InvariantViolation(
            "the local durable demo requires deterministic ECDSA support"
        ) from error
    return Signature(ECDSA_P256_SHA256, signature)
