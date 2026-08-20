"""Ravi, with source authority: the walkthrough's authority beat, mechanized.

Nine steps, through the production commands, against a real database.

    1  the case is open and the Saturday observations are what it lacks;
    2  the fleet catalog is asked which agent could acquire them, and names one
       -- an address, and nothing more;
    3  that agent's key signs the observation, for real;
    4  Q-12 confirms the exact key, the exact source class, the exact tenant,
       the exact site, the exact predicates, a live grant and the pinned
       authorization-policy version;
    5  the receipt becomes transcript membership and the case advances;
    6  the analysis moves -- from divergent to invariant -- **because the
       now-authorized evidence was admitted**, which is checked by admitting it
       and observing the change rather than by asserting a digest;
    7  the same signed observation, offered under a worker key, is refused;
    8  offered for a case sited at SITE_B, refused -- on scope alone;
    9  offered under another tenant, refused;

and then, because a milestone that broke the previous one would be no
milestone at all, the D commitment and disclosure paths are run over the
authorized case and produce the views they produced before.

**The attestation payload is deterministic test data.**  No model interprets
anything here; the observation is a value this file writes down.  What is real
is everything after it: the signature, the registry, the check, the transaction
and the analysis.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.core.analysis.outcomes import Divergent, Invariant, outcome_class
from muster.core.authority.check import (
    AuthorityView,
    SourceClaim,
    check_authority,
    required_coordinates,
)
from muster.core.authority.scope import ResourceScope
from muster.core.catalog.discovery import DiscoveryQuery
from muster.core.evidence.transcript import Attestation, entry_digest
from muster.core.results import Err, Ok
from muster.domains.workforce.bundle import workforce_bundle
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import AppendFailure, append_transcript_entry, case_status
from muster.platform.catalog.route import route
from muster.platform.commit.publish import commit_case
from muster.platform.disclose.audience import DisclosureContext, Principal
from muster.platform.disclose.queries import DisclosureService, get_my_view
from muster.platform.orchestration.status import CaseStatus
from support import authority as A
from support import ravi
from support.authority import sign_receipt
from support.commitment import commitment, directory_for
from support.fixtures import append_all, open_ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

#  The two Saturday observations the hinge identifies as what the case needs.
SATURDAY_PRESENCE = 18
SATURDAY_DURATION = 19

PRESENT = "present_on_site(RAVI, SAT)"
DURATION = "on_site_duration(RAVI, SAT)"


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


def _open_case(database: SqlDatabase, case: RaviCase) -> object:
    """The case with everything except the two Saturday observations."""
    work = ravi.casework(database)
    open_ravi(work, case)
    return work


def _without_saturday(case: RaviCase) -> RaviCase:
    keep = tuple(
        entry
        for index, entry in enumerate(case.entries)
        if index not in (SATURDAY_PRESENCE, SATURDAY_DURATION)
    )
    return replace(case, entries=keep)


def test_the_ravi_authority_beat(database: SqlDatabase, tenant_id: str, case_id: str) -> None:
    """Steps 1 to 9, in order, with each one's evidence taken from the system."""
    attested = ravi.ravi(tenant_id, case_id, attested=True)
    case = _without_saturday(attested)

    #  ---- 1. the case is open, and what it lacks is the two observations ----
    work = _open_case(database, case)
    advanced = append_all(work, case, now=ravi.NOW)  # type: ignore[arg-type]
    assert advanced.published
    assert outcome_class(advanced.analysis.kernel.outcome) == "DIVERGENT"
    assert isinstance(advanced.analysis.kernel.outcome, Divergent)

    report = case_status(work, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)  # type: ignore[arg-type]
    assert isinstance(report, Ok), report
    assert report.value.status is CaseStatus.AWAITING_EVIDENCE
    unresolved = {str(ref) for ref in report.value.analysis.projected.unresolved()}  # type: ignore[union-attr]
    assert {PRESENT, DURATION} <= unresolved

    #  ---- 2. the catalog names a candidate, and that is all it does ---------
    A.publish_fleet(database, tenant_id, case.authority_snapshot)
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
    assert routed.value.principal_id == A.SITE_A
    assert routed.value.endpoint_ref == "local://agent-site-a"

    #  ---- 3 and 4. the agent signs; Q-12 confirms every clause --------------
    presence = attested.entries[SATURDAY_PRESENCE]
    assert isinstance(presence, Attestation)
    payload = presence.receipt.payload
    assert payload.signer_key_ref == A.SITE_A_KEY
    assert payload.source_class == A.SOURCE_SITE_ACCESS

    bundle = workforce_bundle()
    spec = bundle.predicate_schema.spec_for(payload.proposition)
    assert spec is not None
    authorized = check_authority(
        SourceClaim(
            tenant_id=payload.tenant_id,
            signer_key_ref=payload.signer_key_ref,
            source_class=payload.source_class,
            proposition=payload.proposition,
            authorization_policy_version=payload.authorization_policy_version,
        ),
        frozenset(spec.permitted_source_classes),
        required_coordinates(
            payload.proposition,
            spec.arg_kinds,
            spec.resource_scope_kinds,
            case.construction.case_scope_coordinates,
        ),
        AuthorityView(
            snapshot=case.authority_snapshot,
            revocation=case.revocation_snapshot,
            tenant_id=tenant_id,
            authorization_policy_version=(case.authorization_context.authorization_policy_version),
            case_scope_coordinates=case.construction.case_scope_coordinates,
            as_of=case.as_of,
        ),
    )
    assert isinstance(authorized, Ok), authorized
    grant = authorized.value
    assert grant.key_ref == A.SITE_A_KEY
    assert grant.principal_id == A.SITE_A
    assert grant.tenant_scope == tenant_id
    assert grant.source_class == A.SOURCE_SITE_ACCESS
    assert set(grant.permitted_predicates) == {"present_on_site", "on_site_duration"}
    assert grant.resource_scope == (ResourceScope("SITE", A.SITE_A),)
    assert grant.validity.contains(case.as_of)
    assert grant.authorization_policy_version == (
        case.authorization_context.authorization_policy_version
    )
    assert not case.revocation_snapshot.revokes(A.SITE_A_KEY)

    #  ---- 5 and 6. admission, and the analysis moves because of it ----------
    before = report.value.analysis.revision.digest()  # type: ignore[union-attr]
    for index in (SATURDAY_PRESENCE, SATURDAY_DURATION):
        appended = append_transcript_entry(
            work,  # type: ignore[arg-type]
            tenant_id=tenant_id,
            case_id=case_id,
            entry=attested.entries[index],
            now=ravi.NOW,
        )
        assert isinstance(appended, Ok), appended
        assert appended.value.created

    settled = case_status(work, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)  # type: ignore[arg-type]
    assert isinstance(settled, Ok), settled
    analysis = settled.value.analysis
    assert analysis is not None
    assert analysis.revision.digest() != before
    assert isinstance(analysis.kernel.outcome, Invariant)
    assert outcome_class(analysis.kernel.outcome) == "INVARIANT"
    assert analysis.kernel.outcome.action.kind == "PAY"
    assert settled.value.status is CaseStatus.PROPOSED

    #  The two propositions land differently, and the difference is the
    #  architecture's rather than an accident: presence is an exact value and
    #  becomes an established fact; the duration arrives as a *bound* and
    #  becomes a constraint, so ``shift_payable``'s premise is not closed and
    #  the definition group materialises as a constraint too.  The case is
    #  invariant while the duration is still unresolved, which is the product
    #  claim in one line.
    established = {str(fact.ref) for fact in analysis.revision.established}
    assert PRESENT in established
    assert DURATION not in established
    assert DURATION in {str(ref) for ref in analysis.projected.unresolved()}
    assert any(DURATION in item.label for item in analysis.revision.constraints)

    #  ---- 7, 8, 9. the same observation, three ways, all refused ------------
    _refused_under_a_worker_key(work, database, tenant_id, case_id, attested)
    _refused_for_another_site(database, tenant_id, case_id)
    _refused_under_another_tenant(database, tenant_id, case_id)

    #  ---- and milestone D still works over the authorized case --------------
    _the_commitment_and_views_still_work(database, tenant_id, case_id)


def _refused_under_a_worker_key(
    work: object, database: SqlDatabase, tenant_id: str, case_id: str, case: RaviCase
) -> None:
    """Step 7. Wrong class for the key -- Q-12(b).

    The worker really did sign this: the signature verifies against the
    worker's public material.  What the worker does not have is a
    ``SITE_ACCESS_CONTROL`` grant, and declaring the class does not create one.
    """
    entry = case.entries[SATURDAY_PRESENCE]
    assert isinstance(entry, Attestation)
    forged = Attestation(
        sign_receipt(
            replace(
                entry.receipt,
                payload=replace(entry.receipt.payload, signer_key_ref=A.WORKER_KEY),
            )
        )
    )
    outcome = append_transcript_entry(
        work,  # type: ignore[arg-type]
        tenant_id=tenant_id,
        case_id=case_id,
        entry=forged,
        now=ravi.NOW,
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is AppendFailure.ADMISSION_REFUSED
    assert "UnauthorizedSourceClassForKey" in outcome.error.detail

    with database.reading(tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok)
    assert entry_digest(forged) not in set(members.value)


def _refused_for_another_site(database: SqlDatabase, tenant_id: str, case_id: str) -> None:
    """Step 8. SITE_A's key, SITE_B's case -- Q-12(d), and only (d).

    Every other clause passes: same key, same class, same tenant, same
    predicate, same live grant, same policy version.  A shared source class is
    not a shared authority, and this is the beat that makes "sources may
    attest" a mechanism rather than a convention.
    """
    elsewhere = ravi.ravi(tenant_id, f"{case_id}-site-b", attested=True)
    elsewhere = replace(
        elsewhere,
        construction=A.sign_construction(
            replace(
                elsewhere.construction,
                case_scope_coordinates=(
                    ResourceScope("SITE", A.SITE_B),
                    ResourceScope("EMPLOYER", A.EMPLOYER),
                ),
            )
        ),
    )
    work = ravi.casework(database)
    open_ravi(work, elsewhere)
    outcome = append_transcript_entry(
        work,
        tenant_id=tenant_id,
        case_id=elsewhere.case_id,
        entry=elsewhere.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(outcome, Err), outcome
    assert "ResourceScopeNotAuthorized" in outcome.error.detail
    #  And *only* that: the same receipt into the correctly-sited case is
    #  admitted, which is what makes this a statement about the site.
    assert "UnauthorizedSourceClassForKey" not in outcome.error.detail
    assert "PredicateNotAuthorizedForKey" not in outcome.error.detail


def _refused_under_another_tenant(database: SqlDatabase, tenant_id: str, case_id: str) -> None:
    """Step 9. The same principal identifiers under a second tenant.

    Same case identifier, same site name, same key reference, same predicate --
    a different tenant, and therefore a different authority.  Tenant
    qualification is structural: the store is keyed by tenant, the grant names
    one, the snapshot names one, and Q-12 requires all four to agree.
    """
    other = f"{tenant_id}-beta"
    theirs = ravi.ravi(other, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, theirs)

    #  A receipt from the first tenant, offered into the second tenant's case.
    mine = ravi.ravi(tenant_id, case_id, attested=True)
    outcome = append_transcript_entry(
        work,
        tenant_id=other,
        case_id=case_id,
        entry=mine.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is AppendFailure.ADMISSION_REFUSED
    assert "TENANT_MISMATCH" in outcome.error.detail


def _the_commitment_and_views_still_work(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """Milestone D over the authorized case: commit, then disclose.

    The case now closes as invariant on an action, which is the outcome class
    the disclosure policy has a different row for -- so this exercises the row
    milestone D added *and* proves the authorized evidence did not break it.
    """
    work = commitment(database)
    committed = commit_case(work, tenant_id=tenant_id, case_id=case_id)
    assert isinstance(committed, Ok), committed
    assert committed.value.published

    service = DisclosureService(commitment=work, directory=directory_for(tenant_id))
    for principal, context, expected in (
        (Principal("muster-console", "RAVI"), "NOTIFICATION", "WORKER"),
        (Principal("muster-console", "EMPLOYER-1"), "NOTIFICATION", "EMPLOYER"),
        (Principal("muster-console", "SITE-A"), "NOTIFICATION", "SITE"),
        (Principal("muster-operators", "auditor-1"), "AUDIT", "AUDITOR"),
    ):
        view = get_my_view(
            service,
            tenant_id=tenant_id,
            principal=principal,
            case_id=case_id,
            context=DisclosureContext(context),
            acting_as=None,
        )
        assert isinstance(view, Ok), (expected, view)
        assert view.value.audience_class == expected

    #  The site contributed the observation that closed the case and still
    #  learns neither the outcome nor the amount.  Milestone E admitted its
    #  evidence; it did not widen what it is told.
    site_view = get_my_view(
        service,
        tenant_id=tenant_id,
        principal=Principal("muster-console", "SITE-A"),
        case_id=case_id,
        context=DisclosureContext("NOTIFICATION"),
        acting_as=None,
    )
    assert isinstance(site_view, Ok), site_view
    disclosed = {disclosure.path for disclosure in site_view.value.disclosures}
    assert "kernel.outcome.tag" not in disclosed
    assert "kernel.outcome.action" not in disclosed
