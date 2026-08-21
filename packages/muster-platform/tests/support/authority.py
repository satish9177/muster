"""Composition for the milestone-E authority and catalog suites.

Four key populations, held apart on purpose, because the separation is what
several of the adversarial regressions are *about*:

* **source keys** -- the site agent, the payroll system, the worker, a second
  site.  These sign attestations and nothing else;
* **the officer key** -- the one that signs a case construction record, and so
  fixes the parties, the declared instances and the coordinates Q-12(d) reads.
  It signs nothing else, and no source key is in its keyring;
* **publisher keys** -- the control plane's authority publisher and its catalog
  publisher.  These sign snapshots and nothing else;
* **the envelope key** -- milestone D's, in ``support.commitment``, untouched.

A test that wants to prove a source cannot mint its own grant signs with a
source key and offers the result to the publisher path; a test that wants to
prove a publisher cannot attest does the reverse.  Neither is expressible by
accident, because the preimage types differ and the keyrings are disjoint.

Keys are generated per session rather than checked in, for the reason milestone
D gave: a private key in a repository is a private key regardless of what it is
for.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from functools import cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from muster.core.authority.grants import AuthorityGrant, AuthorityRegistrySnapshot, canonical_grants
from muster.core.authority.revocation import RevocationSnapshot
from muster.core.authority.scope import ResourceScope
from muster.core.authority.signing import AttestationPreimage, OfficerPreimage, PublisherRole
from muster.core.case.revision import AuthorizationContext
from muster.core.catalog.profiles import (
    AgentCatalogSnapshot,
    AgentLifecycle,
    AgentProfile,
    canonical_profiles,
)
from muster.core.evidence.signing import attestation_preimage, case_construction_preimage
from muster.core.evidence.transcript import (
    Attestation,
    CaseConstructionRecord,
    TranscriptEntry,
    VerificationReceipt,
)
from muster.core.results import Ok
from muster.core.values.times import HalfOpenInterval, Instant
from muster.core.wire.signature import Signature
from muster.platform.adapters.crypto import (
    LocalEcdsaOfficerSigner,
    LocalEcdsaOfficerVerifier,
    LocalEcdsaPublisherSigner,
    LocalEcdsaPublisherVerifier,
    LocalEcdsaSourceSigner,
    LocalEcdsaSourceVerifier,
)
from muster.platform.authority.publish import (
    AuthorityPublisher,
    publish_authority_snapshot,
    publish_revocation_snapshot,
)
from muster.platform.casework.ports import CaseworkDatabase
from muster.platform.catalog.publish import CatalogPublisher, publish_catalog_snapshot

#  ---- identities ----------------------------------------------------------

SITE_A = "SITE-A"
SITE_B = "SITE-B"
EMPLOYER = "EMPLOYER-1"
WORKER = "RAVI"

SITE_A_KEY = "key-site-a-1"
SITE_B_KEY = "key-site-b-1"
PAYROLL_KEY = "key-hr-payroll-1"
WORKER_KEY = "key-worker-ravi-1"
#: The site agent's next key.  Used by the rotation regressions: a key that is
#: valid from a later instant, alongside a predecessor that stays historically
#: valid rather than being erased.
SITE_A_NEXT_KEY = "key-site-a-2"

#: The officer who opens cases.  A third key population: it signs the record
#: that says what a case is *about*, and Q-12(d) reads the case's coordinates
#: from what it covers.  A source holding this key could declare the site it
#: already had a grant over.
OFFICER_KEY = "key-officer-1"

AUTHORITY_PUBLISHER_KEY = "key-authority-publisher-1"
CATALOG_PUBLISHER_KEY = "key-catalog-publisher-1"
#: A publisher key nobody trusts.  Signing with it is how a test spells "the
#: wrong signer" without also spelling "a corrupt signature".
UNTRUSTED_PUBLISHER_KEY = "key-rogue-publisher-1"

SOURCE_KEYS: tuple[str, ...] = (
    SITE_A_KEY,
    SITE_B_KEY,
    PAYROLL_KEY,
    WORKER_KEY,
    SITE_A_NEXT_KEY,
)
PUBLISHER_KEYS: tuple[str, ...] = (
    AUTHORITY_PUBLISHER_KEY,
    CATALOG_PUBLISHER_KEY,
    UNTRUSTED_PUBLISHER_KEY,
)

SOURCE_SITE_ACCESS = "SITE_ACCESS_CONTROL"
SOURCE_PAYROLL = "HR_PAYROLL_SYSTEM"
#: A class from a *different* institutional domain, carried here so the generic
#: layer can be shown accepting one without a line of production code changing.
SOURCE_GOODS_RECEIPT = "GOODS_RECEIPT_SYSTEM"

REGISTRY_ID = "authority-registry-1"
REVOCATION_ID = "revocation-registry-1"
CATALOG_ID = "agent-catalog-1"

POLICY_VERSION = 1

#: The window every ordinary grant in the suite is live for.  Wide enough that
#: no test trips it by accident, and narrow enough that the boundary tests can
#: name both ends.
GRANT_START: Instant = 1_785_000_000_000_000
GRANT_END: Instant = 1_790_000_000_000_000
PUBLISHED_AT: Instant = 1_785_000_000_000_000


@cache
def _keypair(key_ref: str) -> tuple[bytes, bytes]:
    assert key_ref
    private = ec.generate_private_key(ec.SECP256R1())
    return (
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def officer_signer(key_ref: str = OFFICER_KEY) -> LocalEcdsaOfficerSigner:
    return LocalEcdsaOfficerSigner(key_ref, _keypair(key_ref)[0])


def officer_verifier() -> LocalEcdsaOfficerVerifier:
    """A reader holding the officer key, and no source or publisher key.

    Separate from :func:`source_verifier` rather than a superset of it, because
    "a source key cannot open a case" is a property the suite has to be able to
    exercise, and it is unexercisable against a keyring that holds both.
    """
    return LocalEcdsaOfficerVerifier({OFFICER_KEY: _keypair(OFFICER_KEY)[1]})


def sign_construction(
    record: CaseConstructionRecord, key_ref: str = OFFICER_KEY
) -> CaseConstructionRecord:
    """Re-sign a construction record honestly, under the key it names.

    The fixtures are authored as JSON and carry a placeholder signature, so
    every case the suite opens has to pass through here: from milestone E the
    admission path verifies the officer signature, and a record carrying the
    placeholder is refused before a head exists.  Naming the key on the record
    as well as signing with it keeps the two from disagreeing.
    """
    named = replace(record, signer_key_ref=key_ref)
    body = named.body()
    #  Through the same cache the attestation signatures use, and for the same
    #  reason: ECDSA is randomised, and a fixture that produced a different
    #  construction digest on every call would make the case identifier a
    #  function of the clock -- every determinism, idempotence and commitment
    #  test compares two independently built copies of one case.
    return replace(
        named,
        signature=_officer_signature(
            body.digest().octets, key_ref, case_construction_preimage(body).octets
        ),
    )


@cache
def _officer_signature(body_digest: bytes, key_ref: str, preimage: bytes) -> Signature:
    """One officer signature per (body, key), for the life of the session."""
    assert body_digest
    return officer_signer(key_ref).sign(OfficerPreimage(preimage))


def source_signer(key_ref: str) -> LocalEcdsaSourceSigner:
    return LocalEcdsaSourceSigner(key_ref, _keypair(key_ref)[0])


def source_public_key(key_ref: str) -> bytes:
    """The public half of a source key, as PEM.

    What a deployment publishes and a verifier holds.  Named for what it is,
    because it is the one piece of key material in this module that is safe to
    hand to anything -- and a test that stands in for a deployed agent needs
    exactly this and nothing else.
    """
    return _keypair(key_ref)[1]


def source_verifier() -> LocalEcdsaSourceVerifier:
    """A reader holding every source key the suite uses.

    Every one, deliberately.  A verifier that only knew the honest key would
    reject a worker-signed goods receipt as "unknown key", and the whole point
    of that regression is that the signature is **valid** and the authority is
    absent.  Holding all of them keeps the two failures distinguishable.
    """
    return source_keyring()


def source_keyring(**deployed: bytes) -> LocalEcdsaSourceVerifier:
    """The suite's source keys, plus the public half of any deployed key named.

    A deployed source signs under a key this process never generated: its
    private half was minted by an operator and lives in Secret Manager, and all
    that reaches here is the public PEM.  So the keyring is the suite's *plus*
    whatever the deployment registered, keyed by the reference the deployment
    configured.

    ``deployed`` is keyword-only and its keys are key references, which means a
    reference that collides with a fixture key **replaces** it rather than
    sitting beside it.  That is the honest behaviour and it is also why the
    deployment uses its own references: one reference resolves to one public
    key, so two keys under one name is a state the registry cannot represent
    and Q-12(b) would decide by whichever won the merge.
    """
    return LocalEcdsaSourceVerifier({key: _keypair(key)[1] for key in SOURCE_KEYS} | deployed)


def publisher_signer(key_ref: str = AUTHORITY_PUBLISHER_KEY) -> LocalEcdsaPublisherSigner:
    return LocalEcdsaPublisherSigner(key_ref, _keypair(key_ref)[0])


def publisher_verifier(
    *, trust_rogue: bool = False, one_key_for_everything: bool = False
) -> LocalEcdsaPublisherVerifier:
    """The publisher keyring a reader holds, scoped per role.

    The authority publisher is trusted for authority and revocation; the
    catalog publisher is trusted for the catalog; neither is trusted for the
    other's role.  That is the deployment the architecture describes, and the
    keyring is where a suite either models it or quietly does not.

    ``UNTRUSTED_PUBLISHER_KEY`` is outside every role unless a test asks for
    it, which is what makes "signed by the wrong publisher" a refusal rather
    than a different-looking success.

    ``one_key_for_everything`` builds the keyring as it was *before* roles
    existed -- one key trusted for all three publications.  It exists for one
    test: the one that shows a catalog key signing a fresh authority body is
    accepted under that keyring and refused under this one, which is the
    difference the role dimension buys.
    """
    if one_key_for_everything:
        every = {key: _keypair(key)[1] for key in (AUTHORITY_PUBLISHER_KEY, CATALOG_PUBLISHER_KEY)}
        return LocalEcdsaPublisherVerifier(dict.fromkeys(PublisherRole, every))

    authority_keys = {AUTHORITY_PUBLISHER_KEY: _keypair(AUTHORITY_PUBLISHER_KEY)[1]}
    catalog_keys = {CATALOG_PUBLISHER_KEY: _keypair(CATALOG_PUBLISHER_KEY)[1]}
    if trust_rogue:
        rogue = {UNTRUSTED_PUBLISHER_KEY: _keypair(UNTRUSTED_PUBLISHER_KEY)[1]}
        authority_keys |= rogue
        catalog_keys |= rogue
    return LocalEcdsaPublisherVerifier(
        {
            PublisherRole.AUTHORITY: authority_keys,
            PublisherRole.REVOCATION: authority_keys,
            PublisherRole.CATALOG: catalog_keys,
        }
    )


#  ---- grants --------------------------------------------------------------


def grant(
    *,
    key_ref: str,
    principal_id: str,
    tenant_id: str,
    source_class: str,
    predicates: tuple[str, ...],
    scope: tuple[ResourceScope, ...],
    validity: HalfOpenInterval | None = None,
    policy_version: int = POLICY_VERSION,
) -> AuthorityGrant:
    return AuthorityGrant(
        key_ref=key_ref,
        principal_id=principal_id,
        tenant_scope=tenant_id,
        source_class=source_class,
        permitted_predicates=predicates,
        resource_scope=scope,
        validity=validity if validity is not None else HalfOpenInterval(GRANT_START, GRANT_END),
        authorization_policy_version=policy_version,
    )


def site_grant(tenant_id: str, *, site: str = SITE_A, key_ref: str = SITE_A_KEY) -> AuthorityGrant:
    """The badge reader's grant: one site, two observation predicates."""
    return grant(
        key_ref=key_ref,
        principal_id=site,
        tenant_id=tenant_id,
        source_class=SOURCE_SITE_ACCESS,
        predicates=("on_site_duration", "present_on_site"),
        scope=(ResourceScope("SITE", site),),
    )


def payroll_grant(tenant_id: str, *, key_ref: str = PAYROLL_KEY) -> AuthorityGrant:
    """The payroll system's grant: one employer, two record predicates.

    ``key_ref`` is a parameter for the same reason it is one on
    :func:`site_grant`: a deployed agent signs under a key of its own, and the
    registry has to grant *that* reference the same standing -- same principal,
    same class, same predicates, same scope -- rather than a wider one.
    """
    return grant(
        key_ref=key_ref,
        principal_id=EMPLOYER,
        tenant_id=tenant_id,
        source_class=SOURCE_PAYROLL,
        predicates=("daily_rate", "scheduled"),
        scope=(ResourceScope("EMPLOYER", EMPLOYER),),
    )


def workforce_grants(tenant_id: str) -> tuple[AuthorityGrant, ...]:
    """The two grants the Ravi case needs, and nothing else.

    The worker's key holds no grant at all -- not a narrow one, none -- which
    is what makes ``VALID_SIGNATURE_WITHOUT_AUTHORITY_REJECTED`` a statement
    about the registry rather than about a scope comparison.
    """
    return (site_grant(tenant_id), payroll_grant(tenant_id))


def snapshot(
    tenant_id: str,
    grants: tuple[AuthorityGrant, ...],
    *,
    registry_id: str = REGISTRY_ID,
    policy_version: int = POLICY_VERSION,
    published_at: Instant = PUBLISHED_AT,
) -> AuthorityRegistrySnapshot:
    return AuthorityRegistrySnapshot(
        registry_id=registry_id,
        tenant_id=tenant_id,
        authorization_policy_version=policy_version,
        grants=canonical_grants(grants),
        published_at=published_at,
    )


def revocation(
    tenant_id: str,
    revoked: tuple[str, ...] = (),
    *,
    published_at: Instant = PUBLISHED_AT,
) -> RevocationSnapshot:
    return RevocationSnapshot(
        registry_id=REVOCATION_ID,
        tenant_id=tenant_id,
        revoked_key_refs=tuple(sorted(revoked)),
        published_at=published_at,
    )


def context(
    authority: AuthorityRegistrySnapshot,
    revoked: RevocationSnapshot,
    *,
    validity: HalfOpenInterval | None = None,
    policy_version: int = POLICY_VERSION,
) -> AuthorizationContext:
    """The pin a case carries. Both digests come from the snapshots themselves."""
    return AuthorizationContext(
        authorization_policy_version=policy_version,
        authority_registry_snapshot_digest=authority.digest(),
        revocation_snapshot_digest=revoked.digest(),
        context_validity=validity
        if validity is not None
        else HalfOpenInterval(GRANT_START, GRANT_END),
    )


#  ---- the fleet catalog ---------------------------------------------------


def site_profile(
    tenant_id: str,
    *,
    site: str = SITE_A,
    agent_id: str = "agent-site-a",
    version: int = 1,
    lifecycle: AgentLifecycle = AgentLifecycle.ACTIVE,
) -> AgentProfile:
    return AgentProfile(
        agent_id=agent_id,
        version=version,
        tenant_id=tenant_id,
        principal_id=site,
        source_class=SOURCE_SITE_ACCESS,
        acquirable_predicates=("on_site_duration", "present_on_site"),
        resource_scope=(ResourceScope("SITE", site),),
        endpoint_ref=f"local://{agent_id}",
        lifecycle=lifecycle,
    )


def payroll_profile(tenant_id: str) -> AgentProfile:
    return AgentProfile(
        agent_id="agent-hr-payroll",
        version=1,
        tenant_id=tenant_id,
        principal_id=EMPLOYER,
        source_class=SOURCE_PAYROLL,
        acquirable_predicates=("daily_rate", "scheduled"),
        resource_scope=(ResourceScope("EMPLOYER", EMPLOYER),),
        endpoint_ref="local://agent-hr-payroll",
        lifecycle=AgentLifecycle.ACTIVE,
    )


def catalog(
    tenant_id: str,
    profiles: tuple[AgentProfile, ...],
    authority_snapshot: AuthorityRegistrySnapshot,
    *,
    catalog_id: str = CATALOG_ID,
    published_at: Instant = PUBLISHED_AT,
) -> AgentCatalogSnapshot:
    return AgentCatalogSnapshot(
        catalog_id=catalog_id,
        tenant_id=tenant_id,
        profiles=canonical_profiles(profiles),
        published_at=published_at,
        authority_registry_snapshot_digest=authority_snapshot.digest(),
    )


#  ---- publication ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PublishedAuthority:
    """What a test published, so it can pin it and then attack it."""

    snapshot: AuthorityRegistrySnapshot
    revocation: RevocationSnapshot
    context: AuthorizationContext


@dataclass(frozen=True, slots=True)
class Publishing:
    """How a publication differs from the ordinary one, as one value.

    Every field has a default that is the honest case, so a test names only
    what it is varying -- and the signature of ``publish`` stays short enough
    to read.
    """

    grants: tuple[AuthorityGrant, ...] | None = None
    revoked: tuple[str, ...] = ()
    policy_version: int = POLICY_VERSION
    validity: HalfOpenInterval | None = None
    signer_key: str = AUTHORITY_PUBLISHER_KEY
    trust_rogue: bool = False
    published_at: Instant = PUBLISHED_AT


def publish(database: CaseworkDatabase, tenant_id: str, **changes: object) -> PublishedAuthority:
    """Publish an authority snapshot and a revocation snapshot, and pin both."""
    options = replace(Publishing(), **changes)  # type: ignore[arg-type]
    grants = options.grants
    revoked = options.revoked
    policy_version = options.policy_version
    validity = options.validity
    signer_key = options.signer_key
    trust_rogue = options.trust_rogue
    published_at = options.published_at
    registry = snapshot(
        tenant_id,
        workforce_grants(tenant_id) if grants is None else grants,
        policy_version=policy_version,
        published_at=published_at,
    )
    revoked_snapshot = revocation(tenant_id, revoked, published_at=published_at)
    publisher = AuthorityPublisher(
        database=database,
        signer=publisher_signer(signer_key),
        verifier=publisher_verifier(trust_rogue=trust_rogue),
    )
    first = publish_authority_snapshot(
        publisher, tenant_id=tenant_id, snapshot=registry, now=published_at
    )
    assert isinstance(first, Ok), first
    second = publish_revocation_snapshot(
        publisher, tenant_id=tenant_id, snapshot=revoked_snapshot, now=published_at
    )
    assert isinstance(second, Ok), second
    return PublishedAuthority(
        registry,
        revoked_snapshot,
        context(registry, revoked_snapshot, validity=validity, policy_version=policy_version),
    )


@dataclass(frozen=True, slots=True)
class Fleet:
    """How a fleet publication differs from the ordinary one."""

    profiles: tuple[AgentProfile, ...] | None = None
    signer_key: str = CATALOG_PUBLISHER_KEY
    trust_rogue: bool = False
    published_at: Instant = PUBLISHED_AT
    catalog_id: str = CATALOG_ID


def publish_fleet(
    database: CaseworkDatabase,
    tenant_id: str,
    authority_snapshot: AuthorityRegistrySnapshot,
    **changes: object,
) -> AgentCatalogSnapshot:
    """Publish a fleet catalog. Grants nothing, which is the whole point."""
    options = replace(Fleet(), **changes)  # type: ignore[arg-type]
    fleet = catalog(
        tenant_id,
        (site_profile(tenant_id), payroll_profile(tenant_id))
        if options.profiles is None
        else options.profiles,
        authority_snapshot,
        catalog_id=options.catalog_id,
        published_at=options.published_at,
    )
    published = publish_catalog_snapshot(
        CatalogPublisher(
            database=database,
            signer=publisher_signer(options.signer_key),
            verifier=publisher_verifier(trust_rogue=options.trust_rogue),
        ),
        tenant_id=tenant_id,
        snapshot=fleet,
    )
    assert isinstance(published, Ok), published
    return fleet


#  ---- signing attestations ------------------------------------------------


@cache
def _signature(payload_digest: bytes, key_ref: str, preimage: bytes) -> Signature:
    """One signature per (payload, key), for the life of the session.

    **ECDSA is randomised**, so signing the same payload twice produces two
    different octet strings and therefore two different ``TranscriptEntry``
    digests.  In production that is correct and harmless: a receipt is admitted
    once and its octets are the artifact from then on.  In a suite it is not,
    because half these tests build the same case twice -- once to open it and
    once to reach for "an entry it does not have yet" -- and rely on the same
    payload meaning the same entry.  Without this cache, a re-delivered receipt
    would look like a new one and idempotence would be untestable.

    Caching the *signature* rather than faking determinism inside the signer
    keeps the production primitive exactly as it is: this is a fixture holding
    on to a value, not a signer that stopped being randomised.
    """
    assert payload_digest
    return source_signer(key_ref).sign(AttestationPreimage(preimage))


def sign_receipt(receipt: VerificationReceipt, key_ref: str | None = None) -> VerificationReceipt:
    """The same payload, signed for real by the key it names.

    ``key_ref`` overrides the signer *without* touching the payload, which is
    how a test spells "the signature does not match the key the payload
    claims".  Leaving it ``None`` signs with the key the payload declares,
    which is the honest case and the one almost every test wants.
    """
    preimage = attestation_preimage(receipt.payload)
    return VerificationReceipt(
        receipt.payload,
        _signature(
            receipt.payload.digest().octets,
            key_ref or receipt.payload.signer_key_ref,
            preimage.octets,
        ),
    )


def sign_entry(entry: TranscriptEntry) -> TranscriptEntry:
    """Sign an attestation; leave a statement exactly as it is.

    Statements are inert by construction and are not signature-verified on the
    admission path, so re-signing one would be adding ceremony that proves
    nothing.  See ``ingest.admission`` for why that is safe rather than lazy.
    """
    match entry:
        case Attestation(receipt):
            return Attestation(sign_receipt(receipt))
        case _:
            return entry


def signed(entries: tuple[TranscriptEntry, ...]) -> tuple[TranscriptEntry, ...]:
    return tuple(sign_entry(entry) for entry in entries)
