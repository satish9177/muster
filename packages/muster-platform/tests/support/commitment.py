"""Composition for the commitment and disclosure suites.

Two signing implementations live here and they exist for different reasons.

``signing_pair`` builds a real EC P-256 keypair and hands back the production
adapter over it.  Every test about behaviour uses it, so every test runs the
primitive the architecture ratified, with the reader holding public material
and no ability to sign.

``spec_standin_pair`` is HMAC under the Phase-0.8 fixture secret, and it exists
for exactly one job: reproducing the frozen corpus.  What Phase 0.8 froze is
*which octets a commitment signature covers*, not the primitive, and the only
way to demonstrate that this build covers the same octets is to sign them the
way the corpus did and compare.  It is confined to this file and to the golden
suite, and nothing about the system's behaviour is tested through it.

Keys are generated per session rather than checked in, because a private key in
a repository is a private key regardless of what it is for.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from functools import cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from muster.core.evidence.transcript import Signature
from muster.core.results import Ok
from muster.core.values.times import Instant
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import Node
from muster.domains.workforce.bundle import workforce_bundle
from muster.platform.adapters.crypto import (
    LocalEcdsaSigner,
    LocalEcdsaVerifier,
    LocalMacSaltSource,
)
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.casework.advance import Casework
from muster.platform.casework.commands import append_transcript_entry, open_case
from muster.platform.casework.ports import CaseworkDatabase
from muster.platform.commit.envelope import SigningPreimage
from muster.platform.commit.publish import Commitment, CommittedCase, commit_case
from muster.platform.disclose.audience import (
    AudienceClass,
    DisclosureContext,
    Principal,
    PrincipalDirectory,
)
from muster.platform.disclose.queries import DisclosureService, get_my_view
from muster.platform.disclose.verify import ReaderContext
from muster.platform.disclose.views import View
from muster.policy.artifacts import DisclosurePolicy
from support.paths import REPOSITORY_ROOT
from support.ravi import RaviCase
from support.ravi import ravi as ravi_case

#: The control plane's salt root.  A fixed test constant, and the reason a
#: constant is safe here is the reason it is unsafe in production: every case
#: salt in the suite is derivable from it.
SALT_ROOT_KEY = bytes(range(32, 64))

MUSTER_KEY = "key-muster-1"
OTHER_KEY = "key-muster-2"

WORKER = Principal("muster-console", "RAVI")
EMPLOYER = Principal("muster-console", "EMPLOYER-1")
SITE = Principal("muster-console", "SITE-A")
OFFICER = Principal("muster-operators", "officer-1")
AUDITOR_PRINCIPAL = Principal("muster-operators", "auditor-1")
STRANGER = Principal("muster-console", "NOBODY")

NOTIFICATION = DisclosureContext("NOTIFICATION")
AUDIT = DisclosureContext("AUDIT")

#: The identity configuration the suite runs under.  Case parties are minted by
#: the console's issuer, *per tenant*; the one operator role is listed by whole
#: principal.  ``directory_for`` builds one for whichever tenants a test needs,
#: so a test can express a principal authoritative in one tenant and not in
#: another -- which is the escalation the per-tenant mapping exists to refuse.
PARTY_ISSUER = "muster-console"


def directory_for(*tenants: str) -> PrincipalDirectory:
    """A directory authoritative for exactly these tenants, and no others.

    Both halves are scoped, which is what lets a test express a principal --
    party or auditor -- who is authoritative in one tenant and nothing in
    another. A directory that scoped only its issuers would leave the auditor
    role global, and no test written against it could see that.
    """
    return PrincipalDirectory(
        party_issuers=dict.fromkeys(tenants, PARTY_ISSUER),
        auditors=dict.fromkeys(tenants, frozenset({AUDITOR_PRINCIPAL})),
    )


def salts() -> LocalMacSaltSource:
    return LocalMacSaltSource(SALT_ROOT_KEY)


@cache
def _keypair(key_ref: str) -> tuple[bytes, bytes]:
    #  ``key_ref`` is the cache key and nothing else: two references must get
    #  two different keys, or a test that swaps the signer would swap nothing.
    assert key_ref
    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def signing_pair(key_ref: str = MUSTER_KEY) -> tuple[LocalEcdsaSigner, LocalEcdsaVerifier]:
    """A signer and the verifier a reader would hold for it.

    The verifier knows both key references the suite uses, because a reader
    that only knew the honest one would reject a forged envelope for the wrong
    reason -- "unknown key" rather than "bad signature" -- and the two failures
    have to stay distinguishable.
    """
    private, public = _keypair(key_ref)
    other = _keypair(OTHER_KEY if key_ref == MUSTER_KEY else MUSTER_KEY)
    return (
        LocalEcdsaSigner(key_ref, private),
        LocalEcdsaVerifier(
            {key_ref: public, (OTHER_KEY if key_ref == MUSTER_KEY else MUSTER_KEY): other[1]}
        ),
    )


def commitment(
    database: CaseworkDatabase,
    *,
    key_ref: str = MUSTER_KEY,
    retired: frozenset[str] = frozenset(),
) -> Commitment:
    """The commitment composition over a database, with real keys.

    ``retired`` is how a test spells a key rotation: the control plane signs
    under ``key_ref`` and still accepts envelopes its predecessor signed.
    """
    signer, verifier = signing_pair(key_ref)
    return Commitment(
        casework=casework_over(database),
        salts=salts(),
        signer=signer,
        verifier=verifier,
        retired_key_refs=retired,
    )


def casework_over(database: CaseworkDatabase) -> Casework:
    from support import ravi as ravi_support

    return ravi_support.casework(database)


@dataclass(frozen=True, slots=True)
class Pins:
    """What a reader independently knows about *which* record it is asking about.

    One value rather than four arguments, because they are load-bearing
    together: a reader that pinned the case but not the bundle accepts a
    decision taken under a rulebook it never saw, and one that pinned the
    bundle but not the revision accepts a superseded view as current.
    """

    tenant_id: str
    case_id: str
    revision_commitment: Digest
    bundle_manifest_digest: Digest


def reader(
    *,
    policy: DisclosurePolicy,
    pins: Pins,
    audience: AudienceClass,
    context: DisclosureContext,
    key_ref: str = MUSTER_KEY,
    trusted: frozenset[str] | None = None,
) -> ReaderContext:
    """What a recipient independently holds when they check their own view.

    Every field is something the sender must not be allowed to answer for
    itself: the policy, the bundle, the revision, the trusted keys and who the
    reader believes itself to be.
    """
    _signer, verifier = signing_pair(key_ref)
    return ReaderContext(
        policy=policy,
        verifier=verifier,
        trusted_keys=frozenset({key_ref}) if trusted is None else trusted,
        tenant_id=pins.tenant_id,
        case_id=pins.case_id,
        audience_class=audience.value,
        disclosure_context=context.value,
        bundle_manifest_digest=pins.bundle_manifest_digest,
        revision_commitment=pins.revision_commitment,
    )


def workforce_policy() -> DisclosurePolicy:
    """The pinned policy a reader obtains out of band, from the bundle."""
    return workforce_bundle().disclosure_policy


#  ---- the frozen corpus, and the stand-in that reproduces it ---------------

_VECTORS = REPOSITORY_ROOT / "spec" / "reference-semantics" / "generated" / "golden_vectors.json"

#: The Phase-0.8 fixture secret for the envelope signer.  Published in the
#: reference material as a fixed test constant; it is not a secret and appears
#: nowhere outside the golden suite.
SPEC_SECRET = b"spec-secret-muster-envelope"
SPEC_ALGORITHM = "HMAC-SHA256-SPEC-STANDIN"


@cache
def vectors() -> dict[str, bytes]:
    document = json.loads(_VECTORS.read_text(encoding="utf-8"))
    return {entry["name"]: bytes.fromhex(entry["hex"]) for entry in document["vectors"]}


@cache
def vector_digests() -> dict[str, str | None]:
    document = json.loads(_VECTORS.read_text(encoding="utf-8"))
    return {entry["name"]: entry.get("digest") for entry in document["vectors"]}


def vector_node(name: str) -> Node:
    """One frozen vector, decoded by the production codec."""
    decoded = decode(vectors()[name])
    assert isinstance(decoded, Ok), decoded
    return decoded.value


@dataclass(frozen=True, slots=True)
class SpecStandinSigner:
    """HMAC under the frozen fixture secret.  Corpus reproduction only."""

    key_ref: str = MUSTER_KEY

    def sign(self, preimage: SigningPreimage) -> Signature:
        return Signature(
            SPEC_ALGORITHM, hmac.new(SPEC_SECRET, preimage.octets, hashlib.sha256).digest()
        )


@dataclass(frozen=True, slots=True)
class SpecStandinVerifier:
    """The reading half of the stand-in.  Symmetric, and confined accordingly."""

    def verify(self, *, key_ref: str, preimage: SigningPreimage, signature: Signature) -> bool:
        if signature.algorithm != SPEC_ALGORITHM or key_ref != MUSTER_KEY:
            return False
        expected = hmac.new(SPEC_SECRET, preimage.octets, hashlib.sha256).digest()
        return hmac.compare_digest(signature.octets, expected)


#  ---- a clock reading, fixed ------------------------------------------------

NOW: Instant = 1_760_000_000_000_000


#  ---- a committed case, in memory -------------------------------------------


@dataclass(frozen=True, slots=True)
class CommittedFixture:
    """A durable case, its published commitment, and the pieces a reader needs."""

    case: RaviCase
    service: DisclosureService
    committed: CommittedCase
    database: MemoryDatabase

    @property
    def tenant_id(self) -> str:
        return self.case.tenant_id

    @property
    def case_id(self) -> str:
        return self.case.case_id

    @property
    def policy(self) -> DisclosurePolicy:
        return self.committed.bundle.disclosure_policy

    @property
    def revision_commitment(self) -> Digest:
        return self.committed.commitment.envelope.revision_commitment

    @property
    def bundle_manifest_digest(self) -> Digest:
        return self.committed.bundle.digest()

    @property
    def pins(self) -> Pins:
        return Pins(
            tenant_id=self.tenant_id,
            case_id=self.case_id,
            revision_commitment=self.revision_commitment,
            bundle_manifest_digest=self.bundle_manifest_digest,
        )


def committed_case(
    *, tenant_id: str, case_id: str, attested: bool = False, key_ref: str = MUSTER_KEY
) -> CommittedFixture:
    """Open the Ravi case in memory, advance it, and commit the published head.

    Built through the real commands, because a fixture that assembled durable
    state directly would be committing a record the application never produced.
    """
    database = MemoryDatabase()
    case = ravi_case(tenant_id, case_id, attested=attested)
    work = commitment(database, key_ref=key_ref)
    opened = open_case(
        work.casework,
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=case.authorization_context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )
    assert isinstance(opened, Ok), opened
    for entry in case.entries:
        appended = append_transcript_entry(
            work.casework,
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            entry=entry,
            now=NOW,
        )
        assert isinstance(appended, Ok), appended

    published = commit_case(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(published, Ok), published
    return CommittedFixture(
        case=case,
        service=DisclosureService(commitment=work, directory=directory_for(tenant_id)),
        committed=published.value,
        database=database,
    )


def view_for(fixture: CommittedFixture, principal: Principal, context: DisclosureContext) -> View:
    """One participant's view, through the production query."""
    produced = get_my_view(
        fixture.service,
        tenant_id=fixture.tenant_id,
        principal=principal,
        case_id=fixture.case_id,
        context=context,
        acting_as=None,
    )
    assert isinstance(produced, Ok), produced
    return produced.value
