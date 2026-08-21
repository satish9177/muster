"""What an operator may see of a round, and what a log line therefore cannot say.

The events an acquisition round produces are the visibility this milestone
adds, and the property that matters about them is negative: a line rendered
from one carries no material a source read, no prompt, no model response, no
confidence and no detail string a model could have written into.
"""

from __future__ import annotations

import pytest
from demo.hero import HeroRun, run_hero

from agent_tests.adversarial.test_acquisition_boundary import RAW_NEEDLES
from agent_tests.support import fleet
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.dispatch.observe import (
    AcquisitionEvent,
    AcquisitionEventKind,
    acquisition_events,
)
from support import ravi


@pytest.fixture
def events(tenant_id: str, case_id: str) -> tuple[AcquisitionEvent, ...]:
    run: HeroRun = run_hero(
        ravi.casework(MemoryDatabase()),
        fleet.whole_fleet(tenant_id),
        tenant_id=tenant_id,
        case_id=case_id,
    )
    produced: list[AcquisitionEvent] = []
    for report in run.reports:
        produced.extend(acquisition_events(report))
    return tuple(produced)


def test_the_round_is_visible_end_to_end(events: tuple[AcquisitionEvent, ...]) -> None:
    """Enough to prove the workflow ran, and in the order it ran.

    Two agents addressed, three receipts admitted, and the head moving each
    time -- which together are what somebody watching a demo needs to believe
    that anything happened at all.
    """
    kinds = [event.kind for event in events]
    assert kinds.count(AcquisitionEventKind.AGENT_ADDRESSED) == 2
    assert kinds.count(AcquisitionEventKind.RECEIPT_ADMITTED) == 3
    assert AcquisitionEventKind.REVISION_PUBLISHED in kinds
    assert AcquisitionEventKind.RECEIPT_REFUSED not in kinds
    assert AcquisitionEventKind.TARGET_UNROUTABLE not in kinds


def test_no_event_carries_any_of_the_source_material(
    events: tuple[AcquisitionEvent, ...],
) -> None:
    for event in events:
        rendered = event.render().encode("utf-8")
        for needle in RAW_NEEDLES:
            assert needle not in rendered, f"{needle!r} is in {event.render()}"


def test_an_event_carries_no_free_text_a_model_could_have_written(
    events: tuple[AcquisitionEvent, ...],
) -> None:
    """Every reason is a typed enum value, never a detail string.

    A detail carries whatever produced it -- an exception message, a model's
    own words, a file name -- and a log that quoted one would be a log that
    can quote anything the source read.
    """
    permitted = {member.value for member in AcquisitionEventKind}
    for event in events:
        if event.reason is None:
            continue
        assert event.reason.isupper(), event.reason
        assert " " not in event.reason, event.reason
    assert {event.kind.value for event in events} <= permitted


def test_every_event_carries_the_coordinates_a_reader_joins_on(
    events: tuple[AcquisitionEvent, ...],
    tenant_id: str,
    case_id: str,
) -> None:
    for event in events:
        if event.kind is AcquisitionEventKind.TARGET_UNROUTABLE:
            continue
        assert event.tenant_id == tenant_id
        assert event.case_id == case_id
        assert event.request
        assert event.agent_id
