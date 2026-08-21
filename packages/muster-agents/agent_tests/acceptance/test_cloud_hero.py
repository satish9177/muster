"""The cloud composition root, driven against real agents holding deployed keys.

``demo/cloud_hero.py`` is what runs in the Cloud Run job.  This suite runs the
same function, with the same case, the same grants, the same catalog and the
same admission path -- and with the network replaced by the in-process
transport, which is the one substitution a test can make here and the one the
architecture already treats as a port.

**What it is really checking is the key story.**  A deployed agent signs under a
key this process never generated, so the run adds two grants naming the
*deployed* key references and hands the control plane the matching public
halves.  Everything downstream is unchanged production code, so if either half
of that were wrong the receipts would be authentic and refused, the case would
stay divergent, and no other test in this repository would notice.

The last two assertions are the product claim, and they are the same two the
local worked run makes:

    the case reaches **Invariant**
    while ``on_site_duration`` is still **unresolved**
"""

from __future__ import annotations

from demo.cloud_hero import CloudHeroRun, RawAccess, cloud_case, run_cloud_hero

from agent_tests.support import cloud, fleet
from muster.core.analysis.outcomes import Invariant
from muster.core.values.scalars import VScaled
from muster.core.values.symbols import SymbolRef
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.dispatch.acquire import AgentExchange, Answered
from muster.platform.orchestration.status import CaseStatus
from support import ravi
from support.authority import PAYROLL_KEY, SITE_A_KEY

#: Six days at 850.00: what the case is worth if the Saturday counts.
FULL_WEEK = VScaled("INR", 2, 510_000)


#  ---- what the run replayed and what it asked for -------------------------


def test_the_claim_is_replayed_and_still_moves_nothing(cloud_run: CloudHeroRun) -> None:
    """No worker agent runs here, and the claim is exactly as inert as before.

    The plan still asks the site for presence, which it would not do if a claim
    established anything -- and the claim is *correct*, which is the sharpest
    form of the point.
    """
    assert len(cloud_run.claims) == 1
    claim = cloud_run.claims[0]
    assert claim.proposition == SymbolRef("present_on_site", ("RAVI", "SAT"))
    assert claim.claimant == "RAVI"
    assert claim.role_in_case == "WORKER"
    asked = {target.proposition.predicate_id for target in cloud_run.solicited.targets}
    assert "present_on_site" in asked


def test_the_plan_names_exactly_what_nobody_has_attested(cloud_run: CloudHeroRun) -> None:
    asked = {
        (target.proposition.predicate_id, target.proposition.args)
        for target in cloud_run.solicited.targets
    }
    assert asked == {
        ("scheduled", ("RAVI", "SAT")),
        ("present_on_site", ("RAVI", "SAT")),
        ("on_site_duration", ("RAVI", "SAT")),
    }


def test_the_normative_conclusion_is_never_requested(cloud_run: CloudHeroRun) -> None:
    """It is DERIVED, so no target can exist for it and no source can carry it."""
    requested = {target.proposition.predicate_id for target in cloud_run.solicited.targets}
    assert "shift_payable_under_policy" not in requested


def test_one_request_routes_to_two_agents_by_source_class(cloud_run: CloudHeroRun) -> None:
    addressed = {exchange.assignment.agent_id for exchange in _exchanges(cloud_run)}
    assert addressed == {fleet.SITE_AGENT_ID, fleet.EMPLOYER_AGENT_ID}
    for exchange in _exchanges(cloud_run):
        assert isinstance(exchange.result, Answered), exchange.result


def test_nothing_was_left_unroutable(cloud_run: CloudHeroRun) -> None:
    for report in cloud_run.reports:
        assert report.unroutable == (), report.unroutable


#  ---- the deployed keys, which is the part that is new --------------------


def test_every_receipt_is_signed_under_a_deployed_key_reference(
    cloud_run: CloudHeroRun,
) -> None:
    """Not the seeded one.  The whole cloud story rests on this being true."""
    signed = {
        exchange.assignment.agent_id: {
            admitted.proposition.predicate_id for admitted in _answered(exchange).admitted
        }
        for exchange in _exchanges(cloud_run)
    }
    assert signed[fleet.SITE_AGENT_ID] == {"present_on_site", "on_site_duration"}
    assert signed[fleet.EMPLOYER_AGENT_ID] == {"scheduled"}


def test_the_seeded_record_and_the_acquired_one_verify_under_one_keyring(
    cloud_run: CloudHeroRun,
) -> None:
    """Two key populations in one case, and both admitted.

    The undisputed week was signed by the fixture's keys and the Saturday by
    the deployment's, under different references.  Both are in the transcript
    and the case rebuilt over all of it -- which is what "a rotation is a new
    reference" buys, stated over an artifact rather than over a policy.
    """
    assert cloud_run.report is not None
    assert cloud_run.report.status is CaseStatus.PROPOSED
    for exchange in _exchanges(cloud_run):
        assert _answered(exchange).refused == (), _answered(exchange).refused


def test_a_case_whose_registry_lacks_the_deployed_grant_admits_nothing(
    tenant_id: str, case_id: str
) -> None:
    """The negative control: the same run with the deployed grants withheld.

    Every receipt is authentic and every one is refused, which is Q-12(b)
    working -- and it is the failure this composition would otherwise produce
    silently if the two grants were dropped from ``cloud_case``.
    """
    run = run_cloud_hero(
        ravi.casework(MemoryDatabase(), sources=cloud.keyring()),
        cloud.transport(tenant_id),
        case=ravi.without_attestations(ravi.ravi(tenant_id, case_id), *ravi.ACQUIRED_BY_THE_FLEET),
        site_endpoint=cloud.SITE_ENDPOINT,
        employer_endpoint=cloud.EMPLOYER_ENDPOINT,
    )
    refused = [
        rejected.error.failure.value
        for exchange in _exchanges(run)
        for rejected in _answered(exchange).refused
    ]
    assert refused, "the deployed keys were admitted without a grant naming them"
    assert set(refused) == {"ADMISSION_REFUSED"}
    assert not run.reached_invariant()


#  ---- what the network identity is not ------------------------------------


def test_the_control_plane_identity_holds_no_grant_in_the_case_it_judges(
    tenant_id: str, case_id: str
) -> None:
    """Being able to call an agent is not being able to say anything.

    The control plane mints an identity token per audience, holds
    ``roles/run.invoker`` on each service, publishes the catalog and publishes
    the authority snapshot -- and appears in none of the grants inside it.  The
    registry names sources; the invoker binding names a caller; and no code path
    turns the second into the first, which is the claim, stated over the
    artifact the case is actually judged against.
    """
    case = cloud_case(cloud.configuration(tenant_id, case_id))
    granted = {grant.key_ref for grant in case.authority_snapshot.grants}
    assert granted == {
        SITE_A_KEY,
        PAYROLL_KEY,
        cloud.SITE_KEY_REF,
        cloud.EMPLOYER_KEY_REF,
    }, sorted(granted)

    principals = {grant.principal_id for grant in case.authority_snapshot.grants}
    assert principals == {"SITE-A", "EMPLOYER-1"}, sorted(principals)
    for name in granted | principals:
        assert "control-plane" not in name and "control_plane" not in name, name


def test_the_deployed_grants_widen_nothing(tenant_id: str, case_id: str) -> None:
    """A deployed key gets what the seeded key has, and not a predicate more.

    The two grants the composition root adds are the same institution holding a
    newer key.  A grant that widened the predicates, the scope or the validity
    would be the deployment quietly buying standing it was never given -- and it
    would be invisible, because every receipt would still be admitted.
    """
    case = cloud_case(cloud.configuration(tenant_id, case_id))
    by_ref = {grant.key_ref: grant for grant in case.authority_snapshot.grants}
    for seeded, deployed in (
        (SITE_A_KEY, cloud.SITE_KEY_REF),
        (PAYROLL_KEY, cloud.EMPLOYER_KEY_REF),
    ):
        before, after = by_ref[seeded], by_ref[deployed]
        assert after.principal_id == before.principal_id
        assert after.source_class == before.source_class
        assert after.permitted_predicates == before.permitted_predicates
        assert after.resource_scope == before.resource_scope
        assert after.validity == before.validity
        assert after.authorization_policy_version == before.authorization_policy_version


def test_the_case_pins_the_snapshot_that_carries_the_deployed_grants(
    tenant_id: str, case_id: str
) -> None:
    """Adding a grant makes a new snapshot, and a case pins one by digest.

    A composition that added the grants and kept the original pin would resolve
    to a snapshot that does not contain them -- Q-12(c) working, and a confusing
    way to discover that the repin was forgotten.
    """
    case = cloud_case(cloud.configuration(tenant_id, case_id))
    assert (
        case.authorization_context.authority_registry_snapshot_digest
        == case.authority_snapshot.digest()
    )


def test_the_fleet_the_catalog_names_is_the_two_acquisition_agents(
    cloud_run: CloudHeroRun,
) -> None:
    """Two here, three in the architecture, and the third is not missing.

    The worker agent takes a claim and can attest nothing, so it holds no
    profile, no key reference and no endpoint -- there is nothing for a catalog
    to say about it.  A cloud run that addressed a third acquisition agent would
    be a fleet somebody had grown.
    """
    addressed = {exchange.assignment.agent_id for exchange in _exchanges(cloud_run)}
    assert addressed == {fleet.SITE_AGENT_ID, fleet.EMPLOYER_AGENT_ID}
    assert len(addressed) == 2


#  ---- the boundary and the answer ----------------------------------------


def test_no_raw_object_is_reached_and_none_is_configured(cloud_run: CloudHeroRun) -> None:
    """Off a deployment there is nothing to probe, and it says so rather than passing."""
    assert cloud_run.raw_access.outcome is RawAccess.SKIPPED
    assert cloud_run.raw_access.reference == ""


def test_the_case_reaches_the_invariant_answer(cloud_run: CloudHeroRun) -> None:
    assert cloud_run.reached_invariant()
    assert cloud_run.report is not None
    analysis = cloud_run.report.analysis
    assert analysis is not None
    outcome = analysis.kernel.outcome
    assert isinstance(outcome, Invariant)
    amounts = {
        field.value for field in outcome.action.consequential_fields if field.name == "amount"
    }
    assert amounts == {FULL_WEEK}, amounts


def test_the_duration_is_never_established(cloud_run: CloudHeroRun) -> None:
    """The product claim: an invariant answer over an unresolved quantity."""
    assert cloud_run.report is not None
    analysis = cloud_run.report.analysis
    assert analysis is not None
    unresolved = {reference.predicate_id for reference in analysis.projected.unresolved()}
    assert "on_site_duration" in unresolved


#  ---- composition ---------------------------------------------------------


def _exchanges(run: CloudHeroRun) -> tuple[AgentExchange, ...]:
    return tuple(exchange for report in run.reports for exchange in report.exchanges)


def _answered(exchange: AgentExchange) -> Answered:
    assert isinstance(exchange.result, Answered), exchange.result
    return exchange.result
