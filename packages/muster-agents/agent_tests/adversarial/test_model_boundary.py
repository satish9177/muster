"""What a model produces, and what a model can therefore never cause.

Each test names a thing a language model does -- answers a question nobody
asked, returns a value outside the declared range, cites a source it never saw,
says nothing at all, raises, or loops -- and asserts the same outcome every
time: **no evidence**.

The model here is real in every respect that matters.  It is a ``BaseLlm``, it
runs through the ADK ``Runner``, its tool calls are dispatched by ADK against
generated declarations, and the agent it drives is the one a deployment runs.
What is replaced is the network, which is the only part that could not be made
to misbehave on demand.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agent_tests.support import assignments, fleet
from agent_tests.support.models import (
    Call,
    FailingModel,
    LoopingModel,
    Say,
    declining,
    scripted,
)
from muster.agents.common.identity import SourceIdentity
from muster.agents.profiles import site_agent
from muster.agents.runtime.agent import AcquisitionAgent
from muster.core.authority.scope import ResourceScope
from muster.core.evidence.acquisition import (
    AbstentionReason,
    AcquiredEvidence,
    AcquisitionAbstention,
    AcquisitionAssignment,
    AcquisitionResponse,
)
from muster.core.results import InvariantViolation

TENANT = "ALPHA"
CASE = "CASE-RAVI-SAT-001"


def site_assignment(**changes: object) -> AcquisitionAssignment:
    return assignments.site_assignment(
        tenant_id=str(changes.get("tenant_id", TENANT)),
        case_id=str(changes.get("case_id", CASE)),
        agent_id=str(changes.get("agent_id", fleet.SITE_AGENT_ID)),
    )


def ask(agent: AcquisitionAgent, assignment: AcquisitionAssignment) -> AcquisitionResponse:
    return asyncio.run(agent.acquire(assignment))


def abstention(response: AcquisitionResponse) -> AcquisitionAbstention:
    assert isinstance(response.outcome, AcquisitionAbstention), response.outcome
    return response.outcome


#  ---- SITE_AGENT_CANNOT_EXPORT_UNREQUESTED_PREDICATE ----------------------


def test_site_agent_cannot_export_an_unrequested_predicate() -> None:
    """A model answering a target nobody offered produces nothing at all.

    The interesting half is *why*: a model cannot name a proposition. It names
    a label from the brief, and the only way to answer something else is to
    name a label that does not resolve -- so the attack is not blocked by a
    check on the predicate, it is unspellable.
    """
    model = scripted(
        [
            Call("list_local_evidence", {}),
            Call("read_text_evidence", {"ref": "gate-log-sat"}),
            Call(
                "record_observation",
                {
                    "target": "T7",
                    "relation": "exact",
                    "value": "true",
                    "observed_at": fleet.OBSERVED_AT,
                    "basis": "gate-log-sat",
                },
            ),
            Say("done"),
        ]
    )
    outcome = abstention(ask(fleet.site(TENANT, model=model), site_assignment()))
    assert outcome.reason is AbstentionReason.INTERPRETATION_REJECTED
    assert outcome.detail == "UNKNOWN_TARGET"


def test_a_model_answering_two_targets_of_which_one_is_unknown_yields_nothing() -> None:
    """All or nothing, deliberately.

    One model turn is one reading of one source's material.  Signing the half
    that parsed would present a partial reading as a complete answer, and the
    case has no way to tell the difference.
    """
    model = scripted(
        [
            Call("list_local_evidence", {}),
            Call("read_text_evidence", {"ref": "gate-log-sat"}),
            Call(
                "record_observation",
                {
                    "target": "T1",
                    "relation": "exact",
                    "value": "true",
                    "observed_at": fleet.OBSERVED_AT,
                    "basis": "gate-log-sat",
                },
            ),
            Call(
                "record_observation",
                {
                    "target": "T4",
                    "relation": "exact",
                    "value": "true",
                    "observed_at": fleet.OBSERVED_AT,
                    "basis": "gate-log-sat",
                },
            ),
            Say("done"),
        ]
    )
    outcome = abstention(ask(fleet.site(TENANT, model=model), site_assignment()))
    assert outcome.reason is AbstentionReason.INTERPRETATION_REJECTED


#  ---- MALFORMED_GEMINI_OUTPUT_CREATES_NO_EVIDENCE -------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("value", "probably"),
        ("value", ""),
        ("relation", "roughly"),
        ("observed_at", "last Saturday"),
        ("observed_at", "2026-08-01T09:12:00"),
        ("basis", "cctv-camera-9"),
    ],
)
def test_malformed_model_output_creates_no_evidence(field: str, value: str) -> None:
    arguments: dict[str, object] = {
        "target": "T1",
        "relation": "exact",
        "value": "true",
        "observed_at": fleet.OBSERVED_AT,
        "basis": "gate-log-sat",
    }
    arguments[field] = value
    model = scripted(
        [
            Call("list_local_evidence", {}),
            Call("read_text_evidence", {"ref": "gate-log-sat"}),
            Call("record_observation", arguments),
            Say("done"),
        ]
    )
    outcome = abstention(ask(fleet.site(TENANT, model=model), site_assignment()))
    assert outcome.reason is AbstentionReason.INTERPRETATION_REJECTED


def test_a_duration_outside_the_declared_domain_creates_no_evidence() -> None:
    """The pinned domain is [0, 1440] minutes.  A day has no more."""
    model = scripted(
        [
            Call("list_local_evidence", {}),
            Call("read_text_evidence", {"ref": "gate-log-sat"}),
            Call(
                "record_observation",
                {
                    "target": "T2",
                    "relation": "at_least",
                    "value": "99999",
                    "observed_at": fleet.OBSERVED_AT,
                    "basis": "gate-log-sat",
                },
            ),
            Say("done"),
        ]
    )
    outcome = abstention(ask(fleet.site(TENANT, model=model), site_assignment()))
    assert outcome.reason is AbstentionReason.INTERPRETATION_REJECTED
    assert outcome.detail == "VALUE_OUT_OF_DOMAIN"


#  ---- GEMINI_ABSTENTION_CREATES_NO_EVIDENCE -------------------------------


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        ("no_evidence", AbstentionReason.EVIDENCE_NOT_FOUND),
        ("subject_not_identified", AbstentionReason.SUBJECT_NOT_IDENTIFIED),
        ("ambiguous", AbstentionReason.EVIDENCE_AMBIGUOUS),
        ("contradictory", AbstentionReason.EVIDENCE_CONTRADICTORY),
        ("unreadable", AbstentionReason.EVIDENCE_UNREADABLE),
    ],
)
def test_a_declining_model_creates_no_evidence(declared: str, expected: AbstentionReason) -> None:
    """Abstention is a success of the protocol and a non-event for the case."""
    model = scripted(declining(declared, "the material does not show it"))
    outcome = abstention(ask(fleet.site(TENANT, model=model), site_assignment()))
    assert outcome.reason is expected


def test_a_model_that_only_talks_creates_no_evidence() -> None:
    """Prose is not an answer anywhere in MUSTER, and is not treated as one."""
    model = scripted([Say("I had a look and it seems like he was probably there.")])
    outcome = abstention(ask(fleet.site(TENANT, model=model), site_assignment()))
    assert outcome.reason is AbstentionReason.INTERPRETATION_REJECTED


def test_a_model_declaring_a_reason_outside_its_vocabulary_creates_no_evidence() -> None:
    model = scripted(declining("i_would_rather_not", "no comment"))
    outcome = abstention(ask(fleet.site(TENANT, model=model), site_assignment()))
    assert outcome.reason is AbstentionReason.INTERPRETATION_REJECTED


#  ---- the model failing, rather than misbehaving --------------------------


def test_a_model_that_raises_creates_no_evidence() -> None:
    """Quota, authentication, transport: one fact to a case, and it is not evidence."""
    outcome = abstention(
        ask(fleet.site(TENANT, model=FailingModel(model="failing")), site_assignment())
    )
    assert outcome.reason is AbstentionReason.INTERPRETER_UNAVAILABLE
    assert "MODEL_ERROR" in outcome.detail


def test_a_model_that_never_stops_is_bounded_and_creates_no_evidence() -> None:
    """The call budget, not the deadline, is what ends a runaway interpretation.

    A source that answered nothing until its request expired would be a source
    that is indistinguishable from an unreachable one, hours later.  The budget
    turns that into an abstention in seconds, naming the reason.
    """
    outcome = abstention(
        ask(fleet.site(TENANT, model=LoopingModel(model="looping")), site_assignment())
    )
    assert outcome.reason is AbstentionReason.INTERPRETER_UNAVAILABLE
    #  The failure and the exception type, and never its message: a model
    #  client's exception can quote the request body it failed on.
    assert outcome.detail == "MODEL_ERROR: LlmCallsLimitExceededError"


#  ---- WRONG_SITE_RESPONSE_REJECTED ----------------------------------------
#
#  Refused at the source, before a model runs.  The control-plane half of the
#  same property -- a reply that arrives claiming to be from another agent --
#  is in test_acquisition_boundary.py under WRONG_AGENT_RESPONSE_REJECTED.


def test_wrong_site_assignment_is_refused_before_a_model_is_invoked() -> None:
    """An agent that serves SITE-A declines an assignment about SITE-B.

    Refused *here* rather than after signing, and Q-12(d) would refuse the
    receipt anyway.  What the early refusal buys is that the fault is reported
    as the routing fault it is, instead of as an authority failure that reads
    like a compromised key.
    """
    elsewhere = assignments.assignment(
        assignments.target(assignments.PRESENT, scope=(ResourceScope("SITE", "SITE-B"),)),
        tenant_id=TENANT,
        case_id=CASE,
        agent_id=fleet.SITE_AGENT_ID,
    )
    model = FailingModel(model="never-reached")
    outcome = abstention(ask(fleet.site(TENANT, model=model), elsewhere))
    assert outcome.reason is AbstentionReason.NOT_SERVED_BY_THIS_SOURCE
    assert "SITE-B" in outcome.detail


def test_a_predicate_this_agent_does_not_acquire_is_refused() -> None:
    payroll = assignments.assignment(
        assignments.target(
            assignments.SCHEDULED,
            source_class=assignments.SITE_ACCESS_CONTROL,
            scope=(ResourceScope("SITE", fleet.SITE),),
        ),
        tenant_id=TENANT,
        case_id=CASE,
        agent_id=fleet.SITE_AGENT_ID,
    )
    outcome = abstention(ask(fleet.site(TENANT, model=FailingModel(model="x")), payroll))
    assert outcome.reason is AbstentionReason.NOT_SERVED_BY_THIS_SOURCE


def test_an_assignment_for_another_tenant_is_refused() -> None:
    other = assignments.site_assignment(
        tenant_id="BETA", case_id=CASE, agent_id=fleet.SITE_AGENT_ID
    )
    outcome = abstention(ask(fleet.site(TENANT, model=FailingModel(model="x")), other))
    assert outcome.reason is AbstentionReason.ASSIGNMENT_REFUSED


def test_an_assignment_addressed_to_another_agent_is_refused() -> None:
    misaddressed = assignments.site_assignment(
        tenant_id=TENANT, case_id=CASE, agent_id="agent-site-b"
    )
    outcome = abstention(ask(fleet.site(TENANT, model=FailingModel(model="x")), misaddressed))
    assert outcome.reason is AbstentionReason.ASSIGNMENT_REFUSED


def test_an_assignment_decided_at_an_instant_the_source_cannot_cover_is_refused() -> None:
    """A window that does not contain the case's instant would admit and do nothing.

    Refused before the signature, and named, because a receipt that verifies,
    admits and has no effect is the most confusing failure this system has.
    """
    ancient = assignments.site_assignment(
        tenant_id=TENANT, case_id=CASE, agent_id=fleet.SITE_AGENT_ID, as_of=1
    )
    outcome = abstention(ask(fleet.site(TENANT), ancient))
    assert outcome.reason is AbstentionReason.ASSIGNMENT_REFUSED
    assert outcome.detail == "OUTSIDE_CASE_INSTANT"


#  ---- EMPLOYER_AGENT_CANNOT_SELF_UPGRADE_SOURCE_CLASS ---------------------


def test_the_employer_agent_cannot_present_itself_as_a_site() -> None:
    """The source class is configuration, and there is no argument for it.

    A model cannot set it, a tool cannot carry it, and an assignment addressed
    to a class this agent does not speak as is refused rather than answered.
    Q-12(b) is the authoritative refusal; this one costs no signature.
    """
    site_work = assignments.site_assignment(
        tenant_id=TENANT, case_id=CASE, agent_id=fleet.EMPLOYER_AGENT_ID
    )
    outcome = abstention(ask(fleet.employer(TENANT), site_work))
    assert outcome.reason is AbstentionReason.NOT_SERVED_BY_THIS_SOURCE


def test_an_employer_identity_cannot_be_built_as_a_site_agent() -> None:
    """The composition refuses it, so the process does not start.

    A deployment that pointed the site profile at the payroll agent's identity
    would otherwise come up and produce receipts nobody can use.
    """
    with pytest.raises(InvariantViolation) as refusal:
        fleet.site(TENANT, identity=fleet.employer_identity(TENANT))
    assert "HR_PAYROLL_SYSTEM" in str(refusal.value)


def test_an_agent_cannot_hold_a_signer_for_a_key_it_does_not_name() -> None:
    borrowed = SourceIdentity(
        agent_id=fleet.SITE_AGENT_ID,
        principal_id=fleet.SITE,
        tenant_id=TENANT,
        source_class="SITE_ACCESS_CONTROL",
        key_ref="key-site-b-1",
        acquirable_predicates=("present_on_site",),
        resource_scope=(ResourceScope("SITE", fleet.SITE),),
    )
    #  The identity names SITE-B's key and the fixture hands it SITE-A's signer.
    honest = fleet.site(TENANT)
    with pytest.raises(InvariantViolation):
        site_agent(
            identity=borrowed,
            store=honest.store,
            model=FailingModel(model="x"),
            signer=fleet.signer(fleet.SITE_KEY_REF),
            clock=honest.clock,
            nonces=honest.nonces,
            limits=fleet.LIMITS,
            policy=fleet.POLICY,
        )


#  ---- what a source-local failure looks like ------------------------------


def test_a_source_that_cannot_read_its_own_material_abstains(tmp_path: Path) -> None:
    """Holding nothing and being unable to read what you hold are different.

    Two operational facts with two different fixes -- a fleet-coverage gap and
    a deployment fault -- so they are two abstention reasons rather than one
    silence.
    """
    empty = fleet.site(TENANT, material=tmp_path)
    outcome = abstention(ask(empty, site_assignment()))
    assert outcome.reason is AbstentionReason.INTERPRETER_UNAVAILABLE
    assert outcome.detail == "STORE_UNAVAILABLE"


def test_the_worked_material_still_produces_two_signed_receipts() -> None:
    """The positive case, here as well, so the refusals above mean something."""
    response = ask(fleet.site(TENANT), site_assignment())
    assert isinstance(response.outcome, AcquiredEvidence), response.outcome
    assert len(response.outcome.receipts) == 2
    for receipt in response.outcome.receipts:
        assert receipt.payload.source_class == "SITE_ACCESS_CONTROL"
        assert receipt.payload.signer_key_ref == fleet.SITE_KEY_REF
