"""The cloud composition root, stood up without a cloud.

``demo/cloud_hero.py`` is what a Cloud Run job executes.  What a deployment
gives it is a configuration record, two Cloud Run URLs and two public keys; what
a suite can give it is the same record, two in-process endpoints and the public
halves of two keys generated here.  Everything between those two ends -- the
case, the grants, the catalog, the routing, the envelope checks, admission,
Q-12 and the rebuild -- is the same code on both.

**The keys are the point of this fixture.**  A deployed agent signs under a key
the control plane never generated, and the composition root's whole job is to
grant *that* reference and hold *that* public half.  So the agents built here
are given the deployment's key references rather than the fixture's, and the
keyring the control plane holds is the fixture's plus those two.  If either
half were wrong the receipts would be authentic, refused, and the case would
quietly stay divergent.
"""

from __future__ import annotations

from dataclasses import replace

from demo.cloud_hero import CloudFleet, CloudHeroRun, cloud_case, run_cloud_hero

from agent_tests.support import fleet
from muster.agents.runtime.agent import AcquisitionAgent
from muster.agents.transport.inprocess import InProcessAcquisitionTransport
from muster.platform.adapters.crypto import LocalEcdsaSourceVerifier
from muster.platform.adapters.memory import MemoryDatabase
from support import ravi
from support.authority import source_keyring, source_public_key

#: The references a deployment configures, and deliberately not the fixture's.
#: A deployed key is a different key, so it carries a different name -- see
#: ``infra/scripts/env.sh``, where the same two strings are the defaults.
SITE_KEY_REF = "key-site-a-cloud-1"
EMPLOYER_KEY_REF = "key-hr-payroll-cloud-1"

#: Endpoints in the shape a catalog carries them.  In-process here, because the
#: transport is the one thing this fixture substitutes; a deployment's are
#: Cloud Run URLs, and the composition root refuses anything but HTTPS when it
#: reads its own configuration.
SITE_ENDPOINT = "local://agent-site-a"
EMPLOYER_ENDPOINT = "local://agent-hr-payroll"


def configuration(tenant_id: str, case_id: str) -> CloudFleet:
    """The record a deployment supplies, assembled without one.

    Built rather than read from the environment: what these suites are about is
    what the composition root *does* with a configuration, and reading one would
    make every test depend on the parser as well.
    """
    return CloudFleet(
        tenant_id=tenant_id,
        case_id=case_id,
        site_endpoint=SITE_ENDPOINT,
        employer_endpoint=EMPLOYER_ENDPOINT,
        site_key_ref=SITE_KEY_REF,
        employer_key_ref=EMPLOYER_KEY_REF,
        site_public_key=source_public_key(SITE_KEY_REF),
        employer_public_key=source_public_key(EMPLOYER_KEY_REF),
        timeout_seconds=None,
        raw_object=None,
        postgres=None,
    )


def keyring() -> LocalEcdsaSourceVerifier:
    """The suite's source keys, plus the public halves of the two deployed ones."""
    return source_keyring(
        **{
            SITE_KEY_REF: source_public_key(SITE_KEY_REF),
            EMPLOYER_KEY_REF: source_public_key(EMPLOYER_KEY_REF),
        }
    )


def site(tenant_id: str) -> AcquisitionAgent:
    return fleet.site(tenant_id, identity=fleet.site_identity(tenant_id, key_ref=SITE_KEY_REF))


def employer(tenant_id: str) -> AcquisitionAgent:
    """The payroll agent, holding the key its deployment mounts.

    Rebound rather than rebuilt: the profile factory checks the source class and
    the identity against each other, and what changes in a deployment is the
    key, not the institution.
    """
    agent = fleet.employer(tenant_id)
    return replace(
        agent,
        identity=replace(agent.identity, key_ref=EMPLOYER_KEY_REF),
        signer=fleet.signer(EMPLOYER_KEY_REF),
    )


def transport(tenant_id: str) -> InProcessAcquisitionTransport:
    return InProcessAcquisitionTransport(
        {SITE_ENDPOINT: site(tenant_id), EMPLOYER_ENDPOINT: employer(tenant_id)}
    )


def worked_run(tenant_id: str, case_id: str) -> CloudHeroRun:
    """The whole run: seeded case, deployed keys, real agents, Q-12, rebuild."""
    return run_cloud_hero(
        ravi.casework(MemoryDatabase(), sources=keyring()),
        transport(tenant_id),
        case=cloud_case(configuration(tenant_id, case_id)),
        site_endpoint=SITE_ENDPOINT,
        employer_endpoint=EMPLOYER_ENDPOINT,
    )
