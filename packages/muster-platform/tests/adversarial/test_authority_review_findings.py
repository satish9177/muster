"""Durable regressions for the defects the milestone-E reviews found.

The headline is the first one.  A case pins its authority when it is opened and
nothing moves that pin -- ``_ADVANCE`` changes the prefix, the revision and the
certificate, and ``same_authored_case`` refuses a re-open under a different
context.  So a key revoked a month after a case opened went on establishing
facts in it forever: Q-12(f) reads the pin, and the pin predates the
revocation.  The exploit needed no forgery, no race and no operator error --
only patience.

The rest are gaps the test adversary found: refusals the platform suite
believed it was checking and was not, and clauses with no durable sibling.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.application.case_file import UNVERIFIED
from muster.core.authority.grants import AuthorityGrant
from muster.core.authority.revocation import (
    RevocationSnapshotBody,
    SignedRevocationSnapshot,
)
from muster.core.authority.scope import ResourceScope
from muster.core.authority.signing import (
    PublisherRole,
    authority_snapshot_preimage,
    revocation_snapshot_preimage,
)
from muster.core.evidence.transcript import (
    TAG_CASE_CONSTRUCTION,
    Attestation,
    entry_digest,
    read_case_construction,
)
from muster.core.results import Err, Ok
from muster.core.values.times import HalfOpenInterval
from muster.core.wire.digests import DigestKind
from muster.core.wire.nodes import NAtom, NRec
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import AppendFailure, append_transcript_entry
from support import authority as A
from support import ravi
from support.fixtures import open_ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

SATURDAY_PRESENCE = 18
SATURDAY_DURATION = 19


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


def _append(database: SqlDatabase, case: RaviCase, entry: object) -> object:
    return append_transcript_entry(
        ravi.casework(database),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=entry,  # type: ignore[arg-type]
        now=ravi.NOW,
    )


def _members(database: SqlDatabase, case: RaviCase) -> set[object]:
    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok), members
    return set(members.value)


#  ---- the CRITICAL --------------------------------------------------------


def test_A_REVOKED_KEY_CANNOT_ATTEST_INTO_AN_ALREADY_OPEN_CASE(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The bypass, in the shape it would actually be exploited.

    The case is opened and one authorized receipt is admitted, so the pin is
    real and the key genuinely held authority.  Then the key is compromised and
    the tenant does the correct thing: publishes a revocation snapshot naming
    it.  The attacker submits a second, perfectly signed receipt from the same
    key.

    Before the fix it was admitted, because Q-12(f) reads the *pinned*
    revocation snapshot and the pin predates the revocation -- and no operation
    anywhere in the control plane moves a case's pin.  The remedy would have
    been to abandon every open case.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, case)

    first = _append(database, case, case.entries[SATURDAY_PRESENCE])
    assert isinstance(first, Ok), first
    assert entry_digest(case.entries[SATURDAY_PRESENCE]) in _members(database, case)

    #  The key is withdrawn, by a publication the case knows nothing about.
    withdrawn = A.publish(
        database,
        tenant_id,
        revoked=(A.SITE_A_KEY,),
        published_at=A.PUBLISHED_AT + 1,
    )
    assert withdrawn.revocation.revokes(A.SITE_A_KEY)
    assert withdrawn.revocation.digest() != case.revocation_snapshot.digest()

    second = _append(database, case, case.entries[SATURDAY_DURATION])
    assert isinstance(second, Err), second
    assert second.error.failure is AppendFailure.ADMISSION_REFUSED
    assert "KEY_WITHDRAWN" in second.error.detail
    assert entry_digest(case.entries[SATURDAY_DURATION]) not in _members(database, case)


def test_the_withdrawal_gate_does_not_reach_backwards(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """What was admitted stays admitted, and replays to the same answer.

    The other half, and the one that would be wrong to get wrong in the
    opposite direction: a revocation that reached backwards would let a
    published case change its outcome with no new evidence and no new revision,
    which is the property the whole design exists to deny.  The gate is an
    admission control and touches no derivation.
    """
    from muster.platform.casework.commands import case_status
    from support.fixtures import append_all
    from tests.support.semantics import semantic_core

    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, case)
    advanced = append_all(work, case, now=ravi.NOW)
    assert advanced.published
    decided = semantic_core(advanced.analysis.revision, advanced.analysis)
    published = advanced.head.revision_digest

    A.publish(database, tenant_id, revoked=(A.SITE_A_KEY,), published_at=A.PUBLISHED_AT + 1)

    replayed = case_status(work, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(replayed, Ok), replayed
    assert replayed.value.analysis is not None
    assert replayed.value.analysis.revision.digest() == published
    assert semantic_core(replayed.value.analysis.revision, replayed.value.analysis) == decided


def test_a_later_publication_cannot_un_withdraw_a_key(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The union is why "the latest snapshot" was the wrong lookup.

    Publishing a newer revocation snapshot that omits a previously withdrawn
    key must not re-enable it.  A lookup that took only the most recent
    publication would, and would need a total order over publications with ties
    to arbitrate.  A union has neither problem and fails closed.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, case)

    A.publish(database, tenant_id, revoked=(A.SITE_A_KEY,), published_at=A.PUBLISHED_AT + 1)
    #  An "oops, un-revoke it" publication, newer than the withdrawal.
    A.publish(database, tenant_id, revoked=(), published_at=A.PUBLISHED_AT + 2)

    outcome = _append(database, case, case.entries[SATURDAY_PRESENCE])
    assert isinstance(outcome, Err), outcome
    assert "KEY_WITHDRAWN" in outcome.error.detail


#  ---- refusals the platform suite believed it was checking ----------------


def test_CROSS_TENANT_AUTHORITY_REJECTED_AT_ADMISSION(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """Q-12(c) on the durable path, reached rather than shadowed.

    Every platform "wrong tenant" test asserted ``TENANT_MISMATCH`` -- which is
    the *entry-binding* check in ``ingest.admission``, not Q-12(c) at all.  It
    fires first, on the entry's own tenant against the case's, so a grant
    mis-scoped to another tenant was invisible to it: both tenants in that
    comparison are the publishing one.

    Here the entry binds correctly and the *grant* names another tenant, so the
    binding check passes and cannot be what refuses.  What refuses on the
    durable path is the layer in front of Q-12(c): the snapshot is smuggled
    past its constructor into the store, and ``resolve_authority`` runs that
    constructor again on the way back out, so the mis-scoped grant never
    reaches the check at all.

    That is the stronger answer and it is the one asserted here.  Q-12(c)
    itself stays as the line behind it and is exercised directly in
    ``tests/adversarial/test_authority_review_findings`` in the kernel, where a
    snapshot can be handed to ``check_authority`` without passing a reader.
    Two lines, two tests, and neither is the one that was missing before: a
    mis-scoped grant used to be publishable, readable and refused only by a
    clause no test reached.
    """
    from muster.core.authority.grants import (
        AuthorityRegistrySnapshot,
        AuthorityRegistrySnapshotBody,
        SignedAuthorityRegistrySnapshot,
        canonical_grants,
    )
    from muster.core.wire.codec import encode
    from muster.platform.casework.ports import Publication

    case = ravi.ravi(tenant_id, case_id, attested=True)
    mis_scoped = tuple(
        replace(grant, tenant_scope="BETA") if grant.key_ref == A.SITE_A_KEY else grant
        for grant in case.authority_snapshot.grants
    )
    smuggled = object.__new__(AuthorityRegistrySnapshot)
    object.__setattr__(smuggled, "registry_id", case.authority_snapshot.registry_id)
    object.__setattr__(smuggled, "tenant_id", tenant_id)
    object.__setattr__(
        smuggled,
        "authorization_policy_version",
        case.authority_snapshot.authorization_policy_version,
    )
    object.__setattr__(smuggled, "grants", canonical_grants(mis_scoped))
    object.__setattr__(smuggled, "published_at", case.authority_snapshot.published_at)

    body = AuthorityRegistrySnapshotBody(smuggled, A.AUTHORITY_PUBLISHER_KEY)
    signed = SignedAuthorityRegistrySnapshot(
        body, A.publisher_signer().sign(authority_snapshot_preimage(body))
    )
    rebound = replace(
        case,
        authority_snapshot=smuggled,
        authorization_context=replace(
            case.authorization_context,
            authority_registry_snapshot_digest=smuggled.digest(),
        ),
    )

    work = ravi.casework(database)
    #  Published past the publisher's own constructor check, the way a forged
    #  row would appear, then pinned by a case opened directly.
    with database.writing(tenant_id) as scope:
        scope.authority.publish_authority(
            Publication(smuggled.digest(), encode(signed.to_node()), A.PUBLISHED_AT)
        )
        scope.authority.publish_revocation(
            Publication(
                rebound.revocation_snapshot.digest(),
                encode(_signed_revocation(rebound).to_node()),
                A.PUBLISHED_AT,
            )
        )
        #  Declared in force by the same forged hand that inserted it, so the
        #  open-case freshness gate has nothing to object to and the refusal
        #  below is the tenant binding rather than staleness.  This is the
        #  stronger construction: an attacker who can write the store can also
        #  write the row that says what is current, and the admission-time
        #  check has to hold anyway.
        scope.authority.set_in_force_authority(smuggled.digest())
        scope.authority.set_in_force_revocation(rebound.revocation_snapshot.digest())
    from muster.platform.casework.commands import open_case

    opened = open_case(
        work,
        tenant_id=rebound.tenant_id,
        construction=rebound.construction,
        authorization_context=rebound.authorization_context,
        policy_id=rebound.policy_id,
        as_of=rebound.as_of,
    )
    assert isinstance(opened, Ok), opened

    outcome = _append(database, rebound, rebound.entries[SATURDAY_PRESENCE])
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is AppendFailure.SNAPSHOT_REFUSED
    assert "SNAPSHOT_UNREADABLE" in outcome.error.detail
    assert "is scoped to 'BETA'" in outcome.error.detail
    assert entry_digest(rebound.entries[SATURDAY_PRESENCE]) not in _members(database, rebound)


def _signed_revocation(case: RaviCase) -> SignedRevocationSnapshot:
    body = RevocationSnapshotBody(case.revocation_snapshot, A.AUTHORITY_PUBLISHER_KEY)
    return SignedRevocationSnapshot(
        body, A.publisher_signer().sign(revocation_snapshot_preimage(body))
    )


def _published_with(
    database: SqlDatabase, case: RaviCase, grants: tuple[AuthorityGrant, ...]
) -> RaviCase:
    """Republish this case's authority with a different grant set, and repin it."""
    published = A.publish(
        database,
        case.tenant_id,
        grants=grants,
        published_at=A.PUBLISHED_AT,
    )
    return replace(
        case,
        authority_snapshot=published.snapshot,
        revocation_snapshot=published.revocation,
        authorization_context=published.context,
    )


def test_NOT_YET_VALID_GRANT_REJECTED_AT_ADMISSION(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """A grant whose window opens after the case's ``as_of``."""
    case = ravi.ravi(tenant_id, case_id, attested=True)
    future = A.grant(
        key_ref=A.SITE_A_KEY,
        principal_id=A.SITE_A,
        tenant_id=tenant_id,
        source_class=A.SOURCE_SITE_ACCESS,
        predicates=("on_site_duration", "present_on_site"),
        scope=(ResourceScope("SITE", A.SITE_A),),
        validity=HalfOpenInterval(case.as_of + 1, A.GRANT_END),
    )
    repinned = _published_with(database, case, (A.payroll_grant(tenant_id), future))
    open_ravi(ravi.casework(database), repinned)

    outcome = _append(database, repinned, repinned.entries[SATURDAY_PRESENCE])
    assert isinstance(outcome, Err), outcome
    assert "AuthorityNotYetValid" in outcome.error.detail


def test_PREDICATE_NOT_GRANTED_REJECTED_AT_ADMISSION(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """Right key, right class, right site, and a predicate the grant omits."""
    case = ravi.ravi(tenant_id, case_id, attested=True)
    narrow = A.grant(
        key_ref=A.SITE_A_KEY,
        principal_id=A.SITE_A,
        tenant_id=tenant_id,
        source_class=A.SOURCE_SITE_ACCESS,
        predicates=("on_site_duration",),
        scope=(ResourceScope("SITE", A.SITE_A),),
    )
    repinned = _published_with(database, case, (A.payroll_grant(tenant_id), narrow))
    open_ravi(ravi.casework(database), repinned)

    refused = _append(database, repinned, repinned.entries[SATURDAY_PRESENCE])
    assert isinstance(refused, Err), refused
    assert "PredicateNotAuthorizedForKey" in refused.error.detail

    #  And the predicate it does hold is admitted, so the grant is narrow
    #  rather than broken.
    admitted = _append(database, repinned, repinned.entries[SATURDAY_DURATION])
    assert isinstance(admitted, Ok), admitted


def test_RESOURCE_SCOPE_PREFIX_ATTACK_REJECTED_AT_ADMISSION(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """``SITE-A`` is a prefix of ``SITE-A1``, and reaches none of it.

    The kernel test proves the comparison; this proves the whole durable path
    uses it -- schema, construction record, resolver and check together.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    resited = replace(
        case,
        #  Signed by the officer, because this is the officer legitimately
        #  siting the case at SITE-A1 -- the attack is the *comparison*, not a
        #  forged coordinate, and an unsigned record would be refused earlier
        #  for a reason this test is not about.
        construction=A.sign_construction(
            replace(
                case.construction,
                case_scope_coordinates=(
                    ResourceScope("SITE", "SITE-A1"),
                    ResourceScope("EMPLOYER", A.EMPLOYER),
                ),
            )
        ),
    )
    open_ravi(ravi.casework(database), resited)

    outcome = _append(database, resited, resited.entries[SATURDAY_PRESENCE])
    assert isinstance(outcome, Err), outcome
    assert "ResourceScopeNotAuthorized" in outcome.error.detail


#  ---- publisher roles -----------------------------------------------------


def test_A_CATALOG_PUBLISHER_KEY_CANNOT_PUBLISH_AUTHORITY(
    database: SqlDatabase, tenant_id: str
) -> None:
    """Three roles needed three key sets, and had two.

    Domain separation stops a *signature* being replayed across families -- the
    preimages differ, so the octets do not verify.  It does nothing about the
    holder of the fleet key signing a fresh authority body, which is the attack
    that matters: the key an operator issues to fleet operations becomes a key
    that can grant.

    Both directions are checked, and the flat keyring is reconstructed to show
    the difference is the fix rather than an accident of which keys the fixture
    happens to hold.
    """
    from muster.platform.authority.publish import (
        AuthorityPublisher,
        PublishAuthorityFailure,
        publish_authority_snapshot,
    )
    from muster.platform.catalog.publish import (
        CatalogPublisher,
        PublishCatalogFailure,
        publish_catalog_snapshot,
    )

    snapshot = A.snapshot(tenant_id, A.workforce_grants(tenant_id))
    wrong_role = AuthorityPublisher(
        database=database,
        signer=A.publisher_signer(A.CATALOG_PUBLISHER_KEY),
        verifier=A.publisher_verifier(),
    )
    refused = publish_authority_snapshot(
        wrong_role, tenant_id=tenant_id, snapshot=snapshot, now=A.PUBLISHED_AT
    )
    assert isinstance(refused, Err), refused
    assert refused.error.failure is PublishAuthorityFailure.SIGNATURE_INVALID

    fleet = A.catalog(tenant_id, (A.site_profile(tenant_id),), snapshot)
    also_refused = publish_catalog_snapshot(
        CatalogPublisher(
            database=database,
            signer=A.publisher_signer(A.AUTHORITY_PUBLISHER_KEY),
            verifier=A.publisher_verifier(),
        ),
        tenant_id=tenant_id,
        snapshot=fleet,
    )
    assert isinstance(also_refused, Err), also_refused
    assert also_refused.error.failure is PublishCatalogFailure.SIGNATURE_INVALID

    #  Under the keyring as it was -- one key set for every role -- the same
    #  publication is accepted.  That is the defect, reproduced.
    body_preimage = authority_snapshot_preimage(
        __import__(
            "muster.core.authority.grants", fromlist=["AuthorityRegistrySnapshotBody"]
        ).AuthorityRegistrySnapshotBody(snapshot, A.CATALOG_PUBLISHER_KEY)
    )
    signature = A.publisher_signer(A.CATALOG_PUBLISHER_KEY).sign(body_preimage)
    assert A.publisher_verifier(one_key_for_everything=True).verify(
        role=PublisherRole.AUTHORITY,
        key_ref=A.CATALOG_PUBLISHER_KEY,
        preimage=body_preimage,
        signature=signature,
    )
    assert not A.publisher_verifier().verify(
        role=PublisherRole.AUTHORITY,
        key_ref=A.CATALOG_PUBLISHER_KEY,
        preimage=body_preimage,
        signature=signature,
    )


#  ---- catalog recency -----------------------------------------------------


def test_the_recency_column_is_the_signed_instant(database: SqlDatabase, tenant_id: str) -> None:
    """Recency comes from the signature, and no other value is in scope.

    The ordering column used to be the caller's clock reading, and nothing
    reconciled it with the signed ``published_at`` -- so a first publication
    could pin itself at the top of the order with a far-future ``now`` and no
    successor could ever retire an agent, while every signature and digest
    check still passed.

    The fix removed the parameter rather than validating it: ``publish_catalog_
    snapshot`` takes no ``now`` at all, so there is no second instant for a
    caller to disagree with.  Both halves are asserted -- the API has no such
    parameter, and the ordering follows the signed field.
    """
    import inspect

    from muster.core.catalog.profiles import AgentLifecycle
    from muster.platform.catalog.publish import publish_catalog_snapshot
    from muster.platform.catalog.route import resolve_catalog

    assert "now" not in inspect.signature(publish_catalog_snapshot).parameters

    published = A.publish(database, tenant_id)
    stale = A.publish_fleet(
        database,
        tenant_id,
        published.snapshot,
        profiles=(A.site_profile(tenant_id),),
        published_at=A.PUBLISHED_AT,
        catalog_id="agent-catalog-stale",
    )
    correction = A.publish_fleet(
        database,
        tenant_id,
        published.snapshot,
        profiles=(A.site_profile(tenant_id, lifecycle=AgentLifecycle.RETIRED),),
        published_at=A.PUBLISHED_AT + 1,
        catalog_id="agent-catalog-retire",
    )
    assert stale.digest() != correction.digest()

    with database.reading(tenant_id) as scope:
        resolved = resolve_catalog(scope, A.publisher_verifier())
    assert isinstance(resolved, Ok), resolved
    assert resolved.value.digest() == correction.digest()
    assert resolved.value.active() == ()


def test_two_catalogs_at_one_instant_are_refused_not_arbitrated(
    database: SqlDatabase, tenant_id: str
) -> None:
    """A tie is ambiguity, and this subsystem refuses ambiguity everywhere else.

    Broken by digest, the winner is chosen by content nobody controls or
    inspects and the loser vanishes with no signal -- and if the loser is the
    operator's correction, a retired agent stays routable.
    """
    from muster.core.catalog.profiles import AgentLifecycle
    from muster.platform.catalog.route import CatalogResolutionFailure, resolve_catalog

    published = A.publish(database, tenant_id)
    A.publish_fleet(
        database,
        tenant_id,
        published.snapshot,
        profiles=(A.site_profile(tenant_id, lifecycle=AgentLifecycle.RETIRED),),
        published_at=A.PUBLISHED_AT + 1,
        catalog_id="agent-catalog-retire",
    )
    A.publish_fleet(
        database,
        tenant_id,
        published.snapshot,
        profiles=(A.site_profile(tenant_id),),
        published_at=A.PUBLISHED_AT + 1,
        catalog_id="agent-catalog-rival",
    )

    with database.reading(tenant_id) as scope:
        outcome = resolve_catalog(scope, A.publisher_verifier())
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is CatalogResolutionFailure.CATALOG_ABSENT
    assert "PUBLICATION_AMBIGUOUS" in outcome.error.detail


#  ---- the request-target check, driven by the case rather than the receipt --


def test_A_NARROWED_REQUEST_CANNOT_BE_EVADED_BY_A_BOGUS_REQUEST_ID(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The per-request narrowing survives an attacker choosing its own identifier.

    ``request_id`` is inside the payload the signer writes.  The check used to
    resolve it and, when it resolved to nothing, perform no target check at all
    -- so a source facing a request that narrowed answerers to one class needed
    only to cite a digest nothing stores.  It was harmless solely because no
    producer narrows a target today, and "harmless because of a property
    somewhere else" is what a control is not.

    Here a narrowed request is written into the case's outstanding set by hand
    -- the planner does not narrow, which is the whole point -- and a receipt
    of an excluded class is offered with a **random, unresolvable**
    ``request_id``.  It must still be refused, because the check now reads what
    the case asked rather than what the receipt claims to answer.
    """
    import os

    from muster.core.evidence.requests import EvidenceRequest, EvidenceTarget, read_evidence_request
    from muster.core.values.classification import AcquisitionClass
    from muster.core.wire.codec import decode, encode
    from muster.core.wire.digests import Digest, DigestKind
    from muster.platform.casework.ports import RecordedRequest
    from support.fixtures import append_all

    #  Drive the case to the point where it genuinely dispatches a request, so
    #  the head names a revision and "outstanding" is a state this case is
    #  actually in rather than a row wedged past the join.
    case = ravi.ravi(tenant_id, case_id)
    work = ravi.casework(database)
    open_ravi(work, case)
    append_all(work, case, now=ravi.NOW)
    with database.reading(tenant_id) as scope:
        dispatched = scope.requests.outstanding(case_id)
    assert isinstance(dispatched, Ok), dispatched
    assert dispatched.value, "the case must have dispatched a request"
    revision_digest = dispatched.value[0].revision_digest

    attested = ravi.ravi(tenant_id, case_id, attested=True)
    presence = attested.entries[SATURDAY_PRESENCE]
    assert isinstance(presence, Attestation)
    proposition = presence.receipt.payload.proposition

    #  A second request, outstanding against the same revision, which narrows
    #  the answerers for this proposition to a class this source is not.
    narrowed = EvidenceRequest(
        tenant_id=tenant_id,
        case_id=case_id,
        revision_semantic_digest=revision_digest,
        targets=(
            EvidenceTarget(proposition, AcquisitionClass.ATTESTABLE, ("SOMEBODY_ELSE_ENTIRELY",)),
        ),
    )
    with database.writing(tenant_id) as scope:
        stored = scope.content.put(DigestKind.EVIDENCE_REQUEST, encode(narrowed.to_node()))
        assert isinstance(stored, Ok), stored
        recorded = scope.requests.record(
            RecordedRequest(
                case_id=case_id,
                request_id=narrowed.digest(),
                revision_digest=revision_digest,
                deadline=ravi.NOW + 1,
            )
        )
        assert isinstance(recorded, Ok), recorded

    #  Two requests now name this proposition and disagree, and the permissive
    #  one is the planner's.  Asserting that here is what makes the refusal
    #  below mean "every outstanding request is consulted" rather than "the
    #  narrower request's digest happened to sort first".
    with database.reading(tenant_id) as scope:
        both = scope.requests.outstanding(case_id)
    assert isinstance(both, Ok), both
    assert len(both.value) >= 2
    permissive = [
        recorded_request
        for recorded_request in both.value
        if recorded_request.request_id != narrowed.digest()
    ]
    assert permissive, "the planner's request must still be outstanding"
    with database.reading(tenant_id) as scope:
        for recorded_request in permissive:
            octets = scope.content.get(DigestKind.EVIDENCE_REQUEST, recorded_request.request_id)
            assert isinstance(octets, Ok), octets
            node = decode(octets.value)
            assert isinstance(node, Ok), node
            planned = read_evidence_request(node.value)
            permitted = {
                target.permitted_source_classes
                for target in planned.targets
                if target.proposition == proposition
            }
            assert permitted, "the planner's request must name this proposition"
            assert any(presence.receipt.payload.source_class in classes for classes in permitted), (
                "the planner's request must permit the class the narrowed one forbids"
            )

    #  The evasion: an identifier that resolves to nothing at all, signed for
    #  real so nothing earlier on the path can refuse it first.
    evading = Attestation(
        A.sign_receipt(
            replace(
                presence.receipt,
                payload=replace(presence.receipt.payload, request_id=Digest(os.urandom(32))),
            )
        )
    )
    outcome = _append(database, attested, evading)
    assert isinstance(outcome, Err), outcome
    assert "SourceClassNotPermittedForPredicate" in outcome.error.detail
    assert entry_digest(evading) not in _members(database, attested)

    #  And the honest receipt is refused identically -- the check does not
    #  depend on which identifier was cited, which is the property.
    honest = _append(database, attested, presence)
    assert isinstance(honest, Err), honest
    assert "SourceClassNotPermittedForPredicate" in honest.error.detail


#  ---- the CRITICAL from the final independent review ----------------------


def test_AN_UNSIGNED_CONSTRUCTION_RECORD_CANNOT_OPEN_A_CASE(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The record Q-12(d) reads the case's site from must be signed.

    It was not.  ``admit_case_construction`` checked the tenant binding and the
    parties' tenants and then stored the record; no verifier was called, and
    none was even a parameter.  The reference semantics have always declared
    ``CaseConstructionRecordBody`` under the ``CASE_CONSTRUCTION_BODY`` domain
    with ``signer_key_ref`` as the signing identity -- production had neither
    the body type nor the domain, so "signed at case construction by an
    officer" was a sentence in eight docstrings and in no code.

    The fixtures carry the placeholder ``Signature("UNSIGNED-LOCAL-DEVELOPMENT",
    b"")`` that milestones A to D used, so the case as authored is exactly the
    unsigned case, and opening it must fail closed.
    """
    from muster.platform.casework.commands import OpenFailure, open_case

    case = ravi.ravi(tenant_id, case_id)
    ravi.publish_authority(database, case)
    unsigned = replace(case.construction, signature=UNVERIFIED)

    refused = open_case(
        ravi.casework(database),
        tenant_id=tenant_id,
        construction=unsigned,
        authorization_context=case.authorization_context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )
    assert isinstance(refused, Err), refused
    assert refused.error.failure is OpenFailure.ADMISSION_REFUSED
    assert "SIGNATURE_INVALID" in refused.error.detail

    #  And nothing was stored under its digest: a record nobody trusted never
    #  becomes something a head can pin.
    with database.reading(tenant_id) as scope:
        stored = scope.content.get(DigestKind.CASE_CONSTRUCTION, unsigned.digest())
    assert isinstance(stored, Err), stored


def test_A_FORGED_SITE_COORDINATE_CANNOT_RESITE_A_CASE(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """SITE_A's key must not attest into a case that is really about SITE_B.

    The exploit needed no invalid signature anywhere.  ``case_scope_coordinates``
    travels in the construction record; Q-12(d) resolves the case's required
    coordinates from it and asks whether the signing key's grant covers them.
    With the record unauthenticated, anything reaching ``open_case`` could open
    a case that is about SITE-B while declaring the coordinates of SITE-A, and
    SITE-A's genuine, unrevoked, correctly scoped key would then attest into it
    with every clause of Q-12 passing.

    Two halves, so the test distinguishes the signature from the coordinate:
    editing the coordinates without re-signing is refused, and the honest
    record with its own coordinates still admits its own site's receipt.
    """
    from muster.core.authority.scope import ResourceScope
    from muster.platform.casework.commands import OpenFailure, open_case

    case = ravi.ravi(tenant_id, case_id, attested=True)
    resited = replace(case.construction, case_scope_coordinates=(ResourceScope("SITE", A.SITE_B),))
    assert resited.case_scope_coordinates != case.construction.case_scope_coordinates
    assert resited.signature == case.construction.signature

    ravi.publish_authority(database, case)
    refused = open_case(
        ravi.casework(database),
        tenant_id=tenant_id,
        construction=resited,
        authorization_context=case.authorization_context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )
    assert isinstance(refused, Err), refused
    assert refused.error.failure is OpenFailure.ADMISSION_REFUSED
    assert "SIGNATURE_INVALID" in refused.error.detail

    #  The control: the honest record opens, and its own site's receipt is
    #  admitted -- so the refusal above is the signature and not the fixture
    #  having become unopenable.
    work = ravi.casework(database)
    open_ravi(work, case)
    admitted = _append(database, case, case.entries[SATURDAY_PRESENCE])
    assert isinstance(admitted, Ok), admitted


def test_AN_OFFICER_RECORD_SIGNED_BY_A_SOURCE_KEY_IS_REFUSED(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The officer keyring holds no source key, and that is the whole control.

    A source that could sign a construction record could declare the site it
    already held a grant over and then attest to it.  Domain separation stops
    a signature being *replayed* across the two roles -- the preimages differ
    -- and does nothing about the holder of a source key signing a fresh
    construction body, which is this attack.  The keyrings are disjoint, so it
    fails at the verifier.
    """
    from muster.core.evidence.signing import case_construction_preimage
    from muster.platform.adapters.crypto import LocalEcdsaOfficerSigner
    from muster.platform.casework.commands import OpenFailure, open_case

    case = ravi.ravi(tenant_id, case_id)
    #  The same private key the site agent attests with, offered as an officer.
    impostor = LocalEcdsaOfficerSigner(A.SITE_A_KEY, A._keypair(A.SITE_A_KEY)[0])
    named = replace(case.construction, signer_key_ref=A.SITE_A_KEY)
    forged = replace(named, signature=impostor.sign(case_construction_preimage(named.body())))

    ravi.publish_authority(database, case)
    refused = open_case(
        ravi.casework(database),
        tenant_id=tenant_id,
        construction=forged,
        authorization_context=case.authorization_context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )
    assert isinstance(refused, Err), refused
    assert refused.error.failure is OpenFailure.ADMISSION_REFUSED
    assert "SIGNATURE_INVALID" in refused.error.detail


def test_a_key_cannot_be_listed_as_both_officer_and_source() -> None:
    """The officer/source separation gets a mechanical backstop, not a convention.

    The construction-record signature is only worth something because the
    officer population is not the source population: a source able to sign one
    would declare the site it already held a grant over and then attest into
    it, with every clause of Q-12 passing on genuine material.  Domain
    separation does not touch that attack -- it is a fresh signature, not a
    replayed one -- so the only control is the keyrings being disjoint, and a
    control nothing enforces is what this milestone exists to stop shipping.
    """
    from muster.core.authority.signing import PublisherRole
    from muster.core.results import InvariantViolation
    from muster.platform.adapters.crypto import LocalKeyrings

    source = {key: A._keypair(key)[1] for key in A.SOURCE_KEYS}
    officer = {A.OFFICER_KEY: A._keypair(A.OFFICER_KEY)[1]}
    publisher = {
        PublisherRole.AUTHORITY: {
            A.AUTHORITY_PUBLISHER_KEY: A._keypair(A.AUTHORITY_PUBLISHER_KEY)[1]
        }
    }

    #  The honest composition stands.
    honest = LocalKeyrings(source=source, officer=officer, publisher=publisher)
    assert honest.officer_verifier().public_keys.keys() == {A.OFFICER_KEY}
    assert A.SITE_A_KEY not in honest.officer_verifier().public_keys

    #  The site agent's key, also listed as an officer.
    with pytest.raises(InvariantViolation) as escalation:
        LocalKeyrings(
            source=source,
            officer={**officer, A.SITE_A_KEY: A._keypair(A.SITE_A_KEY)[1]},
            publisher=publisher,
        )
    assert A.SITE_A_KEY in str(escalation.value)

    #  And the same rule across every publisher role, which is the case
    #  ``PublisherRole`` already made and this extends rather than replaces.
    with pytest.raises(InvariantViolation):
        LocalKeyrings(
            source=source,
            officer=officer,
            publisher={
                **publisher,
                PublisherRole.CATALOG: {
                    A.AUTHORITY_PUBLISHER_KEY: A._keypair(A.AUTHORITY_PUBLISHER_KEY)[1]
                },
            },
        )


def test_a_construction_record_with_no_officer_is_unrepresentable() -> None:
    """An empty ``signer_key_ref`` is refused at construction, not at use.

    It used to be constructible and decodable on the record and fatal one call
    later inside ``body()`` -- and ``body()`` is reached on the read path after
    the decoder's guard has already returned, so a row an operator wrote with
    an empty atom raised out of functions that promise a typed refusal.  The
    head pins that digest and nothing replaces it, so the case would have been
    permanently unreadable, unadvanceable and undisclosable, reporting a stack
    trace rather than ``CONTENT_UNREADABLE``.

    The record now carries the same invariant its body does, so the value does
    not exist to be read back.
    """
    from muster.core.results import InvariantViolation

    honest = ravi.unbound().construction
    assert honest.signer_key_ref

    with pytest.raises(InvariantViolation):
        replace(honest, signer_key_ref="")

    #  And the decoder refuses the same octets, so a row written past every
    #  constructor is a refusal rather than a crash.
    with pytest.raises(InvariantViolation):
        read_case_construction(
            NRec(
                TAG_CASE_CONSTRUCTION,
                (*honest.to_node().fields[:8], NAtom(""), honest.signature.to_node()),
            )
        )
