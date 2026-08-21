"""Running the eight cases through a real agent, and scoring the answers.

Each case is materialised into a directory of its own, handed to a genuine site
agent, and asked the two questions the worked case asks.  What is asserted is
the whole answer: the exact relations for the cases that have one, and the
exact abstention reason for the cases that do not.

**A test that only checked "it produced something" would pass on every one of
these.**  Half of them are supposed to produce nothing, and the other half are
supposed to produce a specific bound rather than a plausible one -- so the
scoring is exact on both sides.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agent_tests.eval.cases import CASES, Case
from agent_tests.eval.interpreter import GateLogInterpreter
from agent_tests.support import assignments, fleet
from muster.agents.runtime.agent import AcquisitionAgent
from muster.core.evidence.acquisition import (
    AcquiredEvidence,
    AcquisitionAbstention,
    AcquisitionResponse,
)
from muster.core.evidence.relations import (
    ClosedLowerBound,
    ClosedUpperBound,
    ExactValue,
)
from muster.core.values.scalars import VBool, VInt

TENANT = "ALPHA"
CASE_ID = "CASE-EVAL"


def _answer(case: Case, material: Path) -> AcquisitionResponse:
    agent = fleet.site(
        TENANT,
        model=GateLogInterpreter(model="gate-log-reader"),
        material=case.materialise(material),
    )
    return asyncio.run(
        agent.acquire(
            assignments.site_assignment(
                tenant_id=TENANT, case_id=CASE_ID, agent_id=fleet.SITE_AGENT_ID
            )
        )
    )


def _relations(response: AcquisitionResponse) -> dict[str, tuple[str, str]]:
    assert isinstance(response.outcome, AcquiredEvidence), response.outcome
    found: dict[str, tuple[str, str]] = {}
    for receipt in response.outcome.receipts:
        found[receipt.payload.proposition.predicate_id] = _named(receipt.payload.relation)
    return found


def _named(relation: object) -> tuple[str, str]:
    """One relation, as the pair a case writes down."""
    match relation:
        case ExactValue(VBool(value)):
            return ("exact", "true" if value else "false")
        case ExactValue(VInt(value)):
            return ("exact", str(value))
        case ClosedLowerBound(VInt(value)):
            return ("at_least", str(value))
        case ClosedUpperBound(VInt(value)):
            return ("at_most", str(value))
        case _:
            raise AssertionError(f"a case does not describe {relation!r}")


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_the_interpreter_answers_or_declines_as_the_case_requires(
    case: Case, tmp_path: Path
) -> None:
    response = _answer(case, tmp_path)
    if case.expected.abstention is not None:
        assert isinstance(response.outcome, AcquisitionAbstention), (case.why, response.outcome)
        assert response.outcome.reason is case.expected.abstention, case.why
        return
    assert case.expected.observations is not None
    assert _relations(response) == case.expected.observations, case.why


def test_no_case_produces_a_receipt_for_something_nobody_asked_about(
    tmp_path: Path,
) -> None:
    """Across every case, including the ones that answer.

    The whitelist is checked per candidate, so this is belt to those braces --
    and it is the assertion that would fail first if a future interpreter
    started volunteering.
    """
    asked = {"present_on_site", "on_site_duration"}
    for case in CASES:
        response = _answer(case, tmp_path)
        if isinstance(response.outcome, AcquiredEvidence):
            for receipt in response.outcome.receipts:
                assert receipt.payload.proposition.predicate_id in asked, case.name


def test_every_receipt_any_case_produces_is_bound_to_the_assignment(
    tmp_path: Path,
) -> None:
    for case in CASES:
        response = _answer(case, tmp_path)
        if not isinstance(response.outcome, AcquiredEvidence):
            continue
        for receipt in response.outcome.receipts:
            assert receipt.payload.tenant_id == TENANT
            assert receipt.payload.case_id == CASE_ID
            assert receipt.payload.source_class == "SITE_ACCESS_CONTROL"
            assert receipt.payload.signer_key_ref == fleet.SITE_KEY_REF


def test_half_the_cases_are_meant_to_produce_nothing() -> None:
    """A guard on the set itself, not on the agent.

    An evaluation whose cases all have answers measures whether an interpreter
    can answer, which is the easy half.  If somebody later removes the
    abstention cases, this fails and says so.
    """
    declining = [case for case in CASES if case.expected.abstention is not None]
    assert len(declining) == 4, [case.name for case in declining]


def test_the_agent_used_is_the_deployed_one() -> None:
    """The evaluation runs the real runtime, not a harness of its own."""
    agent = fleet.site(TENANT, model=GateLogInterpreter(model="gate-log-reader"))
    assert isinstance(agent, AcquisitionAgent)
