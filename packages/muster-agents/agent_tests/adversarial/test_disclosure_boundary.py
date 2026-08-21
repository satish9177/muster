"""What a participant is shown, after a fleet acquired the evidence.

Milestone D proved that a view is a subset of a committed record.  What this
adds is the question the fleet raises: the site's material was read by a model,
and a model's input is the least controlled thing in the system -- so does any
of it end up in a view?

It does not, and the reason is structural rather than editorial.  A view is
derived from a commitment, a commitment from the revision, and the revision
from signed receipts that carry one relation each.  The raw material was never
in any of them, so there is nothing for the disclosure policy to have to
redact.  This file checks that the chain really does hold end to end.
"""

from __future__ import annotations

import pytest
from demo.hero import run_hero

from agent_tests.adversarial.test_acquisition_boundary import RAW_NEEDLES
from agent_tests.support import fleet
from muster.core.results import Ok
from muster.core.wire.codec import encode
from muster.core.wire.nodes import Node
from muster.platform.commit.publish import commit_case
from muster.platform.disclose.audience import DisclosureContext, Principal
from muster.platform.disclose.queries import DisclosureService, get_my_view
from muster.platform.disclose.views import AuditorView, ParticipantView, View
from support import ravi
from support.commitment import (
    AUDIT,
    AUDITOR_PRINCIPAL,
    EMPLOYER,
    NOTIFICATION,
    SITE,
    WORKER,
    commitment,
    directory_for,
)

AUDIENCES: tuple[tuple[Principal, str, DisclosureContext], ...] = (
    (WORKER, "WORKER", NOTIFICATION),
    (EMPLOYER, "EMPLOYER", NOTIFICATION),
    (SITE, "SITE", NOTIFICATION),
    (AUDITOR_PRINCIPAL, "AUDITOR", AUDIT),
)


@pytest.fixture
def views(tenant_id: str, case_id: str) -> dict[str, View]:
    """Run the fleet, commit what it produced, and issue every ratified view."""
    from muster.platform.adapters.memory import MemoryDatabase

    database = MemoryDatabase()
    work = commitment(database)
    run_hero(
        ravi.casework(database),
        fleet.whole_fleet(tenant_id),
        tenant_id=tenant_id,
        case_id=case_id,
    )
    published = commit_case(work, tenant_id=tenant_id, case_id=case_id)
    assert isinstance(published, Ok), published

    service = DisclosureService(commitment=work, directory=directory_for(tenant_id))
    produced: dict[str, View] = {}
    for principal, audience, context in AUDIENCES:
        issued = get_my_view(
            service,
            tenant_id=tenant_id,
            principal=principal,
            case_id=case_id,
            context=context,
            acting_as=None,
        )
        assert isinstance(issued, Ok), (audience, issued)
        produced[audience] = issued.value
    return produced


#  ---- RAW_SITE_EVIDENCE_NEVER_ENTERS_DISCLOSURE_VIEW ----------------------


def test_no_view_carries_any_of_the_site_material(views: dict[str, View]) -> None:
    """Every audience, over the octets each view actually is."""
    assert set(views) == {"WORKER", "EMPLOYER", "SITE", "AUDITOR"}
    for audience, view in views.items():
        octets = encode(_node_of(view))
        for needle in RAW_NEEDLES:
            assert needle not in octets, f"{needle!r} reached the {audience} view"


def test_the_site_is_not_shown_the_outcome_it_produced(views: dict[str, View]) -> None:
    """The disclosure property that survives the fleet, unchanged.

    The site attested the two observations that settled the case and is still
    not told what they settled.  Acquiring evidence is not a reason to be shown
    a decision, and nothing about routing a request to an agent changed that.
    """
    site = encode(_node_of(views["SITE"]))
    worker = encode(_node_of(views["WORKER"]))
    assert b"INVARIANT" in worker or b"PAY" in worker
    assert b"INVARIANT" not in site
    assert b"PAY" not in site


def _node_of(view: View) -> Node:
    """Whichever of the two view types this is, as its canonical node."""
    assert isinstance(view, ParticipantView | AuditorView), view
    return view.to_node()
