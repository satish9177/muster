"""The fleet catalog under attack: a route is an address, never a permission.

The catalog's whole risk is that it *looks* like authority.  A profile names an
institution, a source class, a set of predicates and a resource scope -- the
same four things a grant names -- and the difference between them is not in
what they say but in what reads them.  A grant is read by Q-12.  A profile is
read by nobody who decides anything.

So the tests here come in two halves.  The first is about discovery being
exact, total and unambiguous, because a routing layer that guessed would send
requests to agents that will fail Q-12 and waste signatures.  The second is
about the separation, and it is the half that matters: publishing a profile
claiming a capability must buy the publisher nothing at all, and the way to
show that is to publish one and watch the authority answer not move.
"""

from __future__ import annotations

import pytest

from muster.core.authority.check import check_authority, required_coordinates
from muster.core.authority.scope import ResourceScope
from muster.core.catalog.discovery import (
    DiscoveryError,
    DiscoveryFailure,
    DiscoveryQuery,
    discover,
)
from muster.core.catalog.profiles import (
    AgentCatalogSnapshot,
    AgentLifecycle,
    AgentProfile,
    canonical_profiles,
)
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.symbols import SymbolRef
from muster.core.wire.digests import Digest
from tests.support import authority as A

PRESENT = SymbolRef("present_on_site", ("RAVI", "SAT"))
SITE_SCOPE = (ResourceScope("SITE", A.SITE_A),)
SITE_PREDICATES = ("on_site_duration", "present_on_site")

#  A digest standing for "the authority snapshot this fleet was published
#  against".  A constant, because nothing reads it to decide anything -- which
#  is the property several tests below establish.
AUTHORITY_PIN = Digest(bytes(range(32)))


def profile(**changes: object) -> AgentProfile:
    base: dict[str, object] = {
        "agent_id": "agent-site-a",
        "version": 1,
        "tenant_id": A.TENANT,
        "principal_id": A.SITE_A,
        "source_class": A.SOURCE_SITE_ACCESS,
        "acquirable_predicates": SITE_PREDICATES,
        "resource_scope": SITE_SCOPE,
        "endpoint_ref": "local://agent-site-a",
        "lifecycle": AgentLifecycle.ACTIVE,
    }
    base.update(changes)
    return AgentProfile(**base)  # type: ignore[arg-type]


def catalog(*profiles: AgentProfile, tenant_id: str = A.TENANT) -> AgentCatalogSnapshot:
    return AgentCatalogSnapshot(
        catalog_id=A.REGISTRY_ID,
        tenant_id=tenant_id,
        profiles=canonical_profiles(profiles),
        published_at=A.FOREVER.start,
        authority_registry_snapshot_digest=AUTHORITY_PIN,
    )


def query(**changes: object) -> DiscoveryQuery:
    base: dict[str, object] = {
        "tenant_id": A.TENANT,
        "source_class": A.SOURCE_SITE_ACCESS,
        "predicate_id": "present_on_site",
        "resource_scope": SITE_SCOPE,
    }
    base.update(changes)
    return DiscoveryQuery(**base)  # type: ignore[arg-type]


def _refused(outcome: Result[AgentProfile, DiscoveryError]) -> DiscoveryFailure:
    assert isinstance(outcome, Err), outcome
    return outcome.error.failure


#  ---- discovery is exact ----------------------------------------------------


def test_the_matching_agent_is_discovered() -> None:
    found = discover(catalog(profile()), query())
    assert isinstance(found, Ok), found
    assert found.value.agent_id == "agent-site-a"
    assert found.value.endpoint_ref == "local://agent-site-a"


def test_CROSS_TENANT_CATALOG_DISCOVERY_REJECTED() -> None:
    """Answering would disclose that another tenant's fleet covers this.

    The *existence* of a matching agent is information, so the refusal comes
    before any matching runs -- not "no candidate" but "this catalog is not
    yours to ask".
    """
    assert _refused(discover(catalog(profile()), query(tenant_id="BETA"))) is (
        DiscoveryFailure.WRONG_TENANT
    )
    #  And a profile smuggled into another tenant's catalog is unrepresentable
    #  rather than merely unmatched.
    with pytest.raises(InvariantViolation, match="in a catalog for"):
        catalog(profile(tenant_id="BETA"))


def test_STALE_AGENT_PROFILE_NOT_DISCOVERED() -> None:
    """A retired profile stays in the snapshot and is never routed to.

    Kept rather than deleted, because a catalog is published whole and a reader
    comparing two snapshots should see that an agent went away rather than
    infer it from an absence.  The refusal is named separately from "no
    candidate" because it is the state a half-finished rollout leaves.
    """
    retired = catalog(profile(lifecycle=AgentLifecycle.RETIRED))
    assert _refused(discover(retired, query())) is DiscoveryFailure.NO_ACTIVE_PROFILE
    assert retired.profiles  # still there, still readable
    assert retired.active() == ()


def test_an_ambiguous_route_is_refused_and_not_arbitrated() -> None:
    """Two active versions of one agent is an operator mid-rollout.

    Routing to whichever sorted first would make the choice invisible and
    unrepeatable, so the snapshot refuses to hold two -- the same rule the
    authority registry applies to two grants on one key, for the same reason.
    """
    with pytest.raises(InvariantViolation, match="two active versions"):
        catalog(profile(version=1), profile(version=2))

    #  A retired predecessor beside an active successor is the legitimate
    #  shape, and it routes to the successor without ceremony.
    rolling = catalog(profile(version=1, lifecycle=AgentLifecycle.RETIRED), profile(version=2))
    found = discover(rolling, query())
    assert isinstance(found, Ok), found
    assert found.value.version == 2


def test_two_distinct_agents_matching_one_query_are_refused() -> None:
    """Ambiguity across agents, not only across versions of one."""
    twins = catalog(profile(), profile(agent_id="agent-site-a-standby"))
    assert _refused(discover(twins, query())) is DiscoveryFailure.AMBIGUOUS_CANDIDATE


def test_a_duplicate_agent_identity_is_unrepresentable() -> None:
    with pytest.raises(InvariantViolation, match="version 1"):
        catalog(profile(), profile(endpoint_ref="local://elsewhere"))


def test_each_narrowing_stage_reports_its_own_absence() -> None:
    """The first constraint that emptied the set is the one reported.

    Reporting "resource not covered" when no agent of that class is cataloged
    at all would send an operator to the wrong problem, so the narrowing order
    is the reporting order.
    """
    fleet = catalog(profile())
    assert _refused(discover(fleet, query(source_class="GOODS_RECEIPT_SYSTEM"))) is (
        DiscoveryFailure.NO_SUCH_SOURCE_CLASS
    )
    assert _refused(discover(fleet, query(predicate_id="daily_rate"))) is (
        DiscoveryFailure.CAPABILITY_NOT_DECLARED
    )
    assert (
        _refused(discover(fleet, query(resource_scope=(ResourceScope("SITE", A.SITE_B),))))
        is DiscoveryFailure.RESOURCE_NOT_COVERED
    )


def test_discovery_matching_is_exact_and_has_no_prefix_rule() -> None:
    """The same trap the authority scope has, in the layer that chooses a route."""
    fleet = catalog(profile(resource_scope=(ResourceScope("SITE", "site-1"),)))
    assert isinstance(discover(fleet, query(resource_scope=(ResourceScope("SITE", "site-1"),))), Ok)
    assert (
        _refused(discover(fleet, query(resource_scope=(ResourceScope("SITE", "site-10"),))))
        is DiscoveryFailure.RESOURCE_NOT_COVERED
    )


def test_a_query_over_no_resource_is_unrepresentable() -> None:
    """Discovery over "any resource" would return an agent that covers something.

    Which is exactly the answer that later fails Q-12(d) and wastes a
    signature, so it is refused at the query rather than at the receipt.
    """
    with pytest.raises(InvariantViolation, match="at least one resource coordinate"):
        query(resource_scope=())


def test_a_profile_declaring_nothing_is_unrepresentable() -> None:
    """The same empty-set hazard the authority registry refuses, refused here."""
    with pytest.raises(InvariantViolation, match="no acquirable predicate"):
        profile(acquirable_predicates=())
    with pytest.raises(InvariantViolation, match="no resource scope"):
        profile(resource_scope=())


#  ---- the separation, which is the point ------------------------------------


def test_CATALOG_DISCOVERY_DOES_NOT_GRANT_AUTHORITY() -> None:
    """Discovery succeeds and Q-12 refuses, from the same facts.

    The strongest form of the claim available without a database: one profile
    advertising exactly the acquisition the query asks for, discovered
    successfully -- and an authority snapshot that grants the key nothing,
    refusing the receipt that comes back.  If discovery conferred anything,
    these two lines could not both hold.
    """
    fleet = catalog(profile())
    routed = discover(fleet, query())
    assert isinstance(routed, Ok), routed

    #  The registry is empty of any grant for the key that would sign.
    empty = A.snapshot(
        A.grant(
            key_ref=A.PAYROLL_KEY,
            principal_id=A.EMPLOYER,
            source_class=A.SOURCE_PAYROLL,
            predicates=("daily_rate",),
            scope=(ResourceScope("EMPLOYER", A.EMPLOYER),),
        )
    )
    outcome = check_authority(
        A.claim(PRESENT),
        frozenset({A.SOURCE_SITE_ACCESS}),
        required_coordinates(PRESENT, ("WORKER", "DAY"), ("SITE",), A.CASE_COORDINATES),
        A.view(empty),
    )
    assert isinstance(outcome, Err), outcome


def test_SELF_DECLARED_CAPABILITY_DOES_NOT_GRANT_AUTHORITY() -> None:
    """ "I am SITE_B and I can attest attendance", published, and worth nothing.

    The attack in the form an agent would actually mount it: a profile
    declaring the widest capability the type allows -- another site, both
    predicates, an endpoint of its own -- accepted by the catalog, discovered
    happily, and conferring no authority whatever, because the snapshot Q-12
    reads has never heard of the key that would sign for it.

    Note what is *not* being tested here: nothing about whether the catalog
    would accept such a publication.  It would -- it is a routing record, and a
    control plane may legitimately catalog an agent it has issued no grant to
    yet.  The property is that accepting it changes no admission decision.
    """
    impostor = profile(
        agent_id="agent-site-b",
        principal_id=A.SITE_B,
        resource_scope=(ResourceScope("SITE", A.SITE_B),),
        endpoint_ref="local://agent-site-b",
    )
    fleet = catalog(impostor)
    routed = discover(fleet, query(resource_scope=(ResourceScope("SITE", A.SITE_B),)))
    assert isinstance(routed, Ok), routed
    assert routed.value.principal_id == A.SITE_B

    #  And the registry, which is the only thing that decides, grants the SITE_A
    #  key nothing over SITE_B -- profile or no profile.
    snapshot = A.snapshot(
        A.grant(
            key_ref=A.SITE_A_KEY,
            principal_id=A.SITE_A,
            source_class=A.SOURCE_SITE_ACCESS,
            predicates=SITE_PREDICATES,
            scope=SITE_SCOPE,
        )
    )
    outcome = check_authority(
        A.claim(PRESENT),
        frozenset({A.SOURCE_SITE_ACCESS}),
        required_coordinates(
            PRESENT, ("WORKER", "DAY"), ("SITE",), (ResourceScope("SITE", A.SITE_B),)
        ),
        A.view(snapshot, coordinates=(ResourceScope("SITE", A.SITE_B),)),
    )
    assert isinstance(outcome, Err), outcome


def test_check_authority_has_no_parameter_a_catalog_could_reach() -> None:
    """The separation as a fact about the signature, not about discipline.

    A reviewer asking "could a profile influence Q-12" should be able to answer
    it by reading four parameter names.  None of them is a catalog, a profile,
    or anything a catalog produces -- so there is no call site at which the
    confusion could be introduced, only a refactor that would have to change
    this signature and fail here.
    """
    import inspect

    parameters = list(inspect.signature(check_authority).parameters)
    assert parameters == ["claim", "permitted_source_classes", "required", "authority"]

    annotations = inspect.get_annotations(check_authority, eval_str=False)
    for name, annotation in annotations.items():
        assert "Catalog" not in str(annotation), name
        assert "Profile" not in str(annotation), name


def test_the_catalogs_authority_reference_is_provenance_and_nothing_else() -> None:
    """A catalog names the snapshot it was published against, and no reader cares.

    Established by changing it and observing that nothing about routing moves:
    the same profiles, discovered the same way, under a reference to a
    completely different authority snapshot.
    """
    one = catalog(profile())
    other = AgentCatalogSnapshot(
        catalog_id=one.catalog_id,
        tenant_id=one.tenant_id,
        profiles=one.profiles,
        published_at=one.published_at,
        authority_registry_snapshot_digest=Digest(bytes(reversed(range(32)))),
    )
    assert one.digest() != other.digest()

    first = discover(one, query())
    second = discover(other, query())
    assert isinstance(first, Ok) and isinstance(second, Ok)
    assert first.value == second.value


def test_a_profile_names_no_key() -> None:
    """The field that would make a catalog an authority registry is absent.

    A catalog able to say "and this key speaks for it" would be a second
    registry with weaker rules -- unsigned per entry, mutable per publication,
    and read by a routing layer.  Asserted as an absence over the type's own
    fields, so adding one fails here rather than being noticed later.
    """
    fields = set(AgentProfile.__dataclass_fields__)
    assert not {name for name in fields if "key" in name.lower()}
    assert "validity" not in fields
    assert "permitted_predicates" not in fields


def test_a_retired_profile_does_not_mask_an_active_ones_failure() -> None:
    """Every stage narrows the *routable* set; the lifecycle is not the last filter.

    Filtering lifecycle last meant retired profiles survived every stage and
    emptied the set only at the end -- so a retired agent that declared a
    capability could mask an active one that did not, and the reported stage
    was computed over a set nobody could route to.

    Each stage now runs over the active profiles, and the full set is consulted
    for one purpose only: telling two absences apart.  Which produces the
    answer below, and it is worth being explicit about why it is not
    ``RESOURCE_NOT_COVERED``.  Both facts are true -- no active agent covers
    this site, and a retired one does -- and the second is the one an operator
    can act on: bring the retired agent back, or extend the live one's scope.
    ``NO_ACTIVE_PROFILE`` says both; ``RESOURCE_NOT_COVERED`` says only the
    first and hides the fix.
    """
    fleet = catalog(
        #  Active, right class, right capability, wrong site.
        profile(agent_id="agent-live", resource_scope=(ResourceScope("SITE", A.SITE_B),)),
        #  Retired, and the only one that covers the site being asked about.
        profile(agent_id="agent-gone", lifecycle=AgentLifecycle.RETIRED),
    )
    assert _refused(discover(fleet, query())) is DiscoveryFailure.NO_ACTIVE_PROFILE


def test_a_retired_profile_does_not_supply_a_capability_no_live_agent_has() -> None:
    """The masking this actually fixes, in the stage where it did damage.

    A retired agent declaring ``present_on_site`` used to keep the capability
    stage populated, so a fleet whose *only* live agent acquires something else
    reported a resource failure -- or none at all -- instead of saying the
    capability is not live.  The stages now see only what can be routed to.
    """
    fleet = catalog(
        profile(agent_id="agent-live", acquirable_predicates=("on_site_duration",)),
        profile(agent_id="agent-gone", lifecycle=AgentLifecycle.RETIRED),
    )
    assert _refused(discover(fleet, query())) is DiscoveryFailure.NO_ACTIVE_PROFILE

    #  And with no retired profile to fall back on, the stage names itself.
    live_only = catalog(profile(agent_id="agent-live", acquirable_predicates=("on_site_duration",)))
    assert _refused(discover(live_only, query())) is DiscoveryFailure.CAPABILITY_NOT_DECLARED
