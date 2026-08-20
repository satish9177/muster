"""Publishing authority and the fleet: the trusted operations, attacked.

Publication is the one place a grant can come into existence, so it is the one
place an attacker would like to reach.  Everything here checks that reaching it
requires a publisher key the *reader* trusts -- not a key the artifact names,
and not a source key, however valid.

The two families are tested together because the thing worth showing is that
they stay apart: a signature over a catalog is not a signature over a registry,
even under one key, because the two preimages are digested under two domains.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.core.authority.grants import (
    AuthorityRegistrySnapshotBody,
    SignedAuthorityRegistrySnapshot,
)
from muster.core.authority.scope import ResourceScope
from muster.core.authority.signing import (
    PublisherRole,
    authority_snapshot_preimage,
    revocation_snapshot_preimage,
)
from muster.core.catalog.discovery import DiscoveryQuery
from muster.core.catalog.profiles import AgentLifecycle
from muster.core.catalog.publishing import catalog_snapshot_preimage
from muster.core.results import Err, Ok
from muster.core.wire.codec import encode
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.authority.publish import (
    AuthorityPublisher,
    PublishAuthorityFailure,
    publish_authority_snapshot,
)
from muster.platform.authority.resolve import (
    AuthorityResolutionFailure,
    resolve_authority,
)
from muster.platform.casework.ports import Publication
from muster.platform.catalog.publish import (
    CatalogPublisher,
    PublishCatalogFailure,
    publish_catalog_snapshot,
)
from muster.platform.catalog.route import CatalogResolutionFailure, resolve_catalog, route
from support import authority as A

pytestmark = pytest.mark.postgres


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


def _publisher(
    database: SqlDatabase, *, key: str = A.AUTHORITY_PUBLISHER_KEY
) -> AuthorityPublisher:
    return AuthorityPublisher(
        database=database,
        signer=A.publisher_signer(key),
        verifier=A.publisher_verifier(),
    )


#  ---- publication -----------------------------------------------------------


def test_a_publication_signed_by_an_untrusted_publisher_is_refused(
    database: SqlDatabase, tenant_id: str
) -> None:
    """The publisher checks its own work against the keyring a *reader* holds.

    Which is why this fails at publication rather than at the first rebuild
    that needed the snapshot: a publisher configured with a key nobody trusts
    has produced an artifact nobody can use, and finding that out at
    publication is the difference between a deployment error and an outage.
    """
    rogue = AuthorityPublisher(
        database=database,
        signer=A.publisher_signer(A.UNTRUSTED_PUBLISHER_KEY),
        verifier=A.publisher_verifier(),
    )
    outcome = publish_authority_snapshot(
        rogue,
        tenant_id=tenant_id,
        snapshot=A.snapshot(tenant_id, A.workforce_grants(tenant_id)),
        now=A.PUBLISHED_AT,
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is PublishAuthorityFailure.SIGNATURE_INVALID


def test_a_snapshot_naming_another_tenant_cannot_be_published(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str
) -> None:
    """Publishing under one tenant an artifact that names another.

    Refused before it is signed, so no artifact exists that would resolve under
    the wrong tenant if a later check were relaxed.
    """
    outcome = publish_authority_snapshot(
        _publisher(database),
        tenant_id=tenant_id,
        snapshot=A.snapshot(other_tenant_id, A.workforce_grants(other_tenant_id)),
        now=A.PUBLISHED_AT,
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is PublishAuthorityFailure.TENANT_MISMATCH


def test_publishing_the_same_snapshot_twice_keeps_the_first(
    database: SqlDatabase, tenant_id: str
) -> None:
    """Immutable and insert-if-absent, like every other authored artifact.

    The octets differ only in a randomised signature, and two valid publisher
    signatures over identical content are equally true -- so keeping the first
    is the only choice under which an auditor who verified a snapshot
    yesterday is handed the same one today.
    """
    snapshot = A.snapshot(tenant_id, A.workforce_grants(tenant_id))
    first = publish_authority_snapshot(
        _publisher(database), tenant_id=tenant_id, snapshot=snapshot, now=A.PUBLISHED_AT
    )
    assert isinstance(first, Ok), first
    with database.writing(tenant_id) as scope:
        again = scope.authority.publish_authority(
            Publication(snapshot.digest(), encode(first.value.to_node()), A.PUBLISHED_AT)
        )
    assert isinstance(again, Ok)
    assert again.value is False


#  ---- resolution ------------------------------------------------------------


def test_a_tampered_snapshot_is_refused_at_resolution(
    database: SqlDatabase, tenant_id: str
) -> None:
    """Octets edited after publication, offered under the original digest.

    Reachable only by going around the repository, which is what an operator
    with SQL or a compromised row would do -- so the reader checks rather than
    trusting that nobody did.  Two things refuse it: the publisher signature
    does not cover the edited body, and the body does not hash to the key it
    is stored under.
    """
    published = A.publish(database, tenant_id)
    widened = replace(
        published.snapshot,
        grants=(
            *published.snapshot.grants[:1],
            replace(
                published.snapshot.grants[1],
                resource_scope=(
                    ResourceScope("SITE", A.SITE_A),
                    ResourceScope("SITE", A.SITE_B),
                ),
            ),
        ),
    )
    forged = SignedAuthorityRegistrySnapshot(
        AuthorityRegistrySnapshotBody(widened, A.AUTHORITY_PUBLISHER_KEY),
        #  The signature the publisher genuinely produced -- over the *original*
        #  body.  Reusing it is the attack: an edited artifact carrying real
        #  octets from a real key.
        A.publisher_signer().sign(
            authority_snapshot_preimage(
                AuthorityRegistrySnapshotBody(published.snapshot, A.AUTHORITY_PUBLISHER_KEY)
            )
        ),
    )
    with database.writing(tenant_id) as scope:
        #  Written under the pinned digest, past the publisher, the way a
        #  corrupted row would appear.
        scope.authority.publish_authority(
            Publication(widened.digest(), encode(forged.to_node()), A.PUBLISHED_AT)
        )

    context = replace(published.context, authority_registry_snapshot_digest=widened.digest())
    with database.reading(tenant_id) as scope:
        outcome = resolve_authority(scope, context, A.publisher_verifier())
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is AuthorityResolutionFailure.SNAPSHOT_SIGNATURE_INVALID


def test_a_snapshot_stored_under_a_digest_that_is_not_its_own_is_refused(
    database: SqlDatabase, tenant_id: str
) -> None:
    """The row's key and the row's content disagree.

    A store that returned the wrong preimage, or a row keyed under somebody
    else's digest, is caught before the snapshot decides anything -- rather
    than three layers later, where the symptom would be an authority answer
    nobody could explain.
    """
    mine = A.publish(database, tenant_id)
    theirs = A.snapshot(
        tenant_id,
        (A.site_grant(tenant_id, site=A.SITE_B, key_ref=A.SITE_B_KEY),),
        registry_id="authority-registry-2",
    )
    body = AuthorityRegistrySnapshotBody(theirs, A.AUTHORITY_PUBLISHER_KEY)
    signed = SignedAuthorityRegistrySnapshot(
        body, A.publisher_signer().sign(authority_snapshot_preimage(body))
    )
    misfiled = mine.snapshot.digest()
    with database.writing(tenant_id) as scope:
        #  A different snapshot, correctly signed, filed under the first one's
        #  digest.  Insert-if-absent means it only lands where nothing is, so
        #  a fresh key is used and the pin is redirected to it.
        scope.authority.publish_authority(
            Publication(theirs.digest(), encode(signed.to_node()), A.PUBLISHED_AT)
        )
    assert misfiled != theirs.digest()

    #  Now read it back under a *pin* that names something else, by writing the
    #  same octets under a second key.
    with database.writing(tenant_id) as scope:
        scope.authority.publish_authority(
            Publication(
                A.snapshot(tenant_id, A.workforce_grants(tenant_id), registry_id="r3").digest(),
                encode(signed.to_node()),
                A.PUBLISHED_AT,
            )
        )
    pin = A.snapshot(tenant_id, A.workforce_grants(tenant_id), registry_id="r3").digest()
    with database.reading(tenant_id) as scope:
        outcome = resolve_authority(
            scope,
            replace(mine.context, authority_registry_snapshot_digest=pin),
            A.publisher_verifier(),
        )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is AuthorityResolutionFailure.SNAPSHOT_DIGEST_MISMATCH


def test_a_revocation_signature_cannot_be_replayed_as_an_authority_signature(
    tenant_id: str,
) -> None:
    """Domain separation, as the property it exists to give.

    One publisher, one key, two artifacts -- and a signature over one is not a
    signature over the other, because the preimages are digested under
    different domains.  Without it, a publisher trusted to withdraw keys would
    be trusted to grant them.
    """
    from muster.core.authority.revocation import RevocationSnapshotBody

    snapshot = A.snapshot(tenant_id, A.workforce_grants(tenant_id))
    revocation = A.revocation(tenant_id)
    authority_body = AuthorityRegistrySnapshotBody(snapshot, A.AUTHORITY_PUBLISHER_KEY)
    revocation_body = RevocationSnapshotBody(revocation, A.AUTHORITY_PUBLISHER_KEY)

    assert authority_snapshot_preimage(authority_body).octets != (
        revocation_snapshot_preimage(revocation_body).octets
    )

    signer = A.publisher_signer()
    over_revocation = signer.sign(revocation_snapshot_preimage(revocation_body))
    assert not A.publisher_verifier().verify(
        role=PublisherRole.AUTHORITY,
        key_ref=A.AUTHORITY_PUBLISHER_KEY,
        preimage=authority_snapshot_preimage(authority_body),
        signature=over_revocation,
    )


def test_a_catalog_signature_is_not_an_authority_signature(tenant_id: str) -> None:
    """The same separation across the two families that must never merge."""
    from muster.core.catalog.profiles import AgentCatalogSnapshotBody

    snapshot = A.snapshot(tenant_id, A.workforce_grants(tenant_id))
    fleet = A.catalog(tenant_id, (A.site_profile(tenant_id),), snapshot)
    catalog_body = AgentCatalogSnapshotBody(fleet, A.CATALOG_PUBLISHER_KEY)
    authority_body = AuthorityRegistrySnapshotBody(snapshot, A.CATALOG_PUBLISHER_KEY)

    signer = A.publisher_signer(A.CATALOG_PUBLISHER_KEY)
    over_catalog = signer.sign(catalog_snapshot_preimage(catalog_body))
    assert not A.publisher_verifier().verify(
        role=PublisherRole.AUTHORITY,
        key_ref=A.CATALOG_PUBLISHER_KEY,
        preimage=authority_snapshot_preimage(authority_body),
        signature=over_catalog,
    )


#  ---- the fleet catalog, durably --------------------------------------------


def test_a_catalog_published_by_an_untrusted_key_is_refused(
    database: SqlDatabase, tenant_id: str
) -> None:
    outcome = publish_catalog_snapshot(
        CatalogPublisher(
            database=database,
            signer=A.publisher_signer(A.UNTRUSTED_PUBLISHER_KEY),
            verifier=A.publisher_verifier(),
        ),
        tenant_id=tenant_id,
        snapshot=A.catalog(
            tenant_id,
            (A.site_profile(tenant_id),),
            A.snapshot(tenant_id, A.workforce_grants(tenant_id)),
        ),
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is PublishCatalogFailure.SIGNATURE_INVALID


def test_the_route_resolves_the_most_recent_catalog(database: SqlDatabase, tenant_id: str) -> None:
    """Routing is a present-tense question, and this is the asymmetry that says so.

    A catalog *does* have a "latest"; the authority registry deliberately does
    not.  Asking which agent to send a request to now is correctly answered
    from the newest fleet; asking what a key was permitted to say when a case
    was decided is not.
    """
    published = A.publish(database, tenant_id)
    A.publish_fleet(
        database,
        tenant_id,
        published.snapshot,
        profiles=(A.site_profile(tenant_id),),
    )
    later = A.publish_fleet(
        database,
        tenant_id,
        published.snapshot,
        profiles=(A.site_profile(tenant_id, version=2), A.payroll_profile(tenant_id)),
        published_at=A.PUBLISHED_AT + 1,
    )

    with database.reading(tenant_id) as scope:
        resolved = resolve_catalog(scope, A.publisher_verifier())
    assert isinstance(resolved, Ok), resolved
    assert resolved.value.digest() == later.digest()

    with database.reading(tenant_id) as scope:
        routed = route(
            scope,
            A.publisher_verifier(),
            DiscoveryQuery(
                tenant_id=tenant_id,
                source_class=A.SOURCE_SITE_ACCESS,
                predicate_id="present_on_site",
                resource_scope=(ResourceScope("SITE", A.SITE_A),),
            ),
        )
    assert isinstance(routed, Ok), routed
    assert routed.value.version == 2


def test_CROSS_TENANT_CATALOG_DISCOVERY_REJECTED_DURABLY(
    database: SqlDatabase, tenant_id: str, other_tenant_id: str
) -> None:
    """A query for one tenant run under another's scope.

    The scope already makes a cross-tenant *read* unrepresentable.  This is the
    other direction -- a correctly scoped read asked a question about somebody
    else -- and answering it would leak the existence of another tenant's
    fleet.
    """
    published = A.publish(database, tenant_id)
    A.publish_fleet(database, tenant_id, published.snapshot)

    with database.reading(tenant_id) as scope:
        outcome = route(
            scope,
            A.publisher_verifier(),
            DiscoveryQuery(
                tenant_id=other_tenant_id,
                source_class=A.SOURCE_SITE_ACCESS,
                predicate_id="present_on_site",
                resource_scope=(ResourceScope("SITE", A.SITE_A),),
            ),
        )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is CatalogResolutionFailure.CATALOG_TENANT_MISMATCH

    #  And the other tenant has no catalog at all, so nothing leaks by absence
    #  either: the answer is "nothing published", not "nothing matched".
    with database.reading(other_tenant_id) as scope:
        absent = resolve_catalog(scope, A.publisher_verifier())
    assert isinstance(absent, Err)
    assert absent.error.failure is CatalogResolutionFailure.CATALOG_ABSENT


def test_STALE_AGENT_PROFILE_NOT_DISCOVERED_DURABLY(database: SqlDatabase, tenant_id: str) -> None:
    """A retired profile is published, readable, and never routed to."""
    published = A.publish(database, tenant_id)
    A.publish_fleet(
        database,
        tenant_id,
        published.snapshot,
        profiles=(A.site_profile(tenant_id, lifecycle=AgentLifecycle.RETIRED),),
    )
    with database.reading(tenant_id) as scope:
        outcome = route(
            scope,
            A.publisher_verifier(),
            DiscoveryQuery(
                tenant_id=tenant_id,
                source_class=A.SOURCE_SITE_ACCESS,
                predicate_id="present_on_site",
                resource_scope=(ResourceScope("SITE", A.SITE_A),),
            ),
        )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure.value == "NO_ACTIVE_PROFILE"


def test_publishing_a_fleet_grants_nothing(database: SqlDatabase, tenant_id: str) -> None:
    """The separation, end to end, through both durable paths.

    A profile is published claiming the site agent's whole capability under the
    *worker's* institution.  Discovery finds it.  The authority snapshot is
    untouched by the publication -- byte for byte the same digest it had -- and
    the worker's key still holds no grant.
    """
    published = A.publish(database, tenant_id)
    before = published.snapshot.digest()

    A.publish_fleet(
        database,
        tenant_id,
        published.snapshot,
        profiles=(
            A.site_profile(tenant_id, agent_id="agent-impostor"),
            A.payroll_profile(tenant_id),
        ),
        published_at=A.PUBLISHED_AT + 5,
    )

    with database.reading(tenant_id) as scope:
        resolved = resolve_authority(scope, published.context, A.publisher_verifier())
    assert isinstance(resolved, Ok), resolved
    assert resolved.value.snapshot.digest() == before
    assert resolved.value.snapshot.resolve(A.WORKER_KEY, A.SOURCE_SITE_ACCESS) == ()
