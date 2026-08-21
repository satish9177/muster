"""Named regressions for the defects the milestone-F review found.

Four of them, each reproduced against the real runtime before it was fixed, and
each one a way a model or a source-side failure reached further than the
architecture says it can:

* a storage failure became a signed attestation, because a citation was checked
  against what the source *offered* rather than what the interpreter *received*;
* a model's own words crossed the source boundary through an abstention's
  detail -- a channel the receipt path deliberately does not have;
* a model-authored timestamp had no lower bound, so it could widen the receipt's
  validity window and make it admissible at an instant the source was never
  near;
* the dispatcher compared every field of a receipt against the assignment
  except the subject, which is signed provenance nothing downstream reads.

Kept together and named after the finding rather than filed by subject, because
what a regression suite is for is the second time.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace

import pytest

from agent_tests.support import assignments, fleet
from agent_tests.support.models import Call, Say, Turn, scripted
from muster.agents.profiles import site_agent
from muster.agents.runtime.agent import _DECLINED as DECLINED
from muster.agents.runtime.agent import AcquisitionAgent
from muster.agents.runtime.observations import ObservationFailure
from muster.agents.sources.ports import (
    EvidenceHandle,
    EvidenceItem,
    EvidenceStoreError,
    EvidenceStoreFailure,
    SourceEvidenceStore,
)
from muster.core.authority.scope import ResourceScope
from muster.core.evidence.acquisition import (
    AbstentionReason,
    AcquiredEvidence,
    AcquisitionAbstention,
    AcquisitionAssignment,
    AcquisitionResponse,
)
from muster.core.results import Err, Ok, Result
from muster.core.wire.codec import DecodeFailure, decode, encode
from muster.core.wire.nodes import TAG_TAGGED, TAG_UNIT, NAtom
from muster.platform.dispatch.acquire import (
    SubmissionFailure,
    _check_receipt,
    _read_response,
)

TENANT = "ALPHA"
CASE = "CASE-REVIEW"

#: A line of the site's own gate log, naming a worker who is not the subject.
#: Used as the payload for every "does this leak" test, because if it appears
#: anywhere outside the source then a third party's records have too.
LEAKED = "B-2210,PRIYA,IN,08:55,NORTH-TURNSTILE-1 not for redistribution"


def _assignment(*, as_of: int = assignments.AS_OF) -> AcquisitionAssignment:
    return assignments.site_assignment(
        tenant_id=TENANT, case_id=CASE, agent_id=fleet.SITE_AGENT_ID, as_of=as_of
    )


def _ask(agent: AcquisitionAgent, assignment: AcquisitionAssignment) -> AcquisitionResponse:
    return asyncio.run(agent.acquire(assignment))


def _abstention(response: AcquisitionResponse) -> AcquisitionAbstention:
    assert isinstance(response.outcome, AcquisitionAbstention), response.outcome
    return response.outcome


#  ---- a storage failure must not become an attestation --------------------


@dataclass(frozen=True)
class _ListsButCannotRead(SourceEvidenceStore):
    """A source whose manifest is readable and whose objects are not.

    The realistic shape of a rotated binding, a deleted object or a transient
    denial: the site still knows what it holds, and cannot open any of it.
    """

    def handles(
        self,
        *,
        subject: str,  # noqa: ARG002 - the port's shape; this source holds one set
        coordinates: tuple[ResourceScope, ...],  # noqa: ARG002
    ) -> Result[tuple[EvidenceHandle, ...], EvidenceStoreError]:
        return Ok(
            (
                EvidenceHandle("gate-log-sat", "text/plain", "north gate export"),
                EvidenceHandle("attendance-board-sat", "image/png", "attendance board"),
            )
        )

    def read(self, ref: str) -> Result[EvidenceItem, EvidenceStoreError]:
        return Err(EvidenceStoreError(EvidenceStoreFailure.ACCESS_DENIED, f"403 reading {ref}"))


def _denied_agent() -> AcquisitionAgent:
    honest = fleet.site(TENANT)
    return site_agent(
        identity=fleet.site_identity(TENANT),
        store=_ListsButCannotRead(),
        model=fleet.site_reader(),
        signer=fleet.signer(fleet.SITE_KEY_REF),
        clock=honest.clock,
        nonces=honest.nonces,
        limits=fleet.LIMITS,
        policy=fleet.POLICY,
    )


def test_a_source_never_attests_over_material_it_could_not_read() -> None:
    """The reported defect: every read denied, two receipts signed anyway.

    A candidate's citation was checked against the handles the source *offered*
    rather than the references whose octets actually reached the interpreter --
    so a site whose bucket binding had rotated went on signing observations
    about evidence nobody had seen. Nothing about it required a hostile model:
    the shipped interpreter produced it.
    """
    outcome = _abstention(_ask(_denied_agent(), _assignment()))
    assert outcome.reason is AbstentionReason.INTERPRETATION_REJECTED


def test_a_partial_read_failure_refuses_only_what_it_should() -> None:
    """The precision the fix buys, and the reason it is not a blanket refusal.

    A site whose photograph is missing can still have its gate log read, and an
    observation resting on the log is honest. What must fail is an observation
    that cites the item which never loaded.
    """
    honest = fleet.site(TENANT)

    @dataclass(frozen=True)
    class _MediaDenied(SourceEvidenceStore):
        def handles(
            self, *, subject: str, coordinates: tuple[ResourceScope, ...]
        ) -> Result[tuple[EvidenceHandle, ...], EvidenceStoreError]:
            return honest.store.handles(subject=subject, coordinates=coordinates)

        def read(self, ref: str) -> Result[EvidenceItem, EvidenceStoreError]:
            if ref.startswith("attendance-board"):
                return Err(EvidenceStoreError(EvidenceStoreFailure.NOT_FOUND, ref))
            return honest.store.read(ref)

    agent = site_agent(
        identity=fleet.site_identity(TENANT),
        store=_MediaDenied(),
        model=fleet.site_reader(),
        signer=fleet.signer(fleet.SITE_KEY_REF),
        clock=honest.clock,
        nonces=honest.nonces,
        limits=fleet.LIMITS,
        policy=fleet.POLICY,
    )
    #  The shipped interpreter cites the photograph for presence, so this run
    #  refuses -- by name, on the citation, and not on a guess about which
    #  observations a missing file might have affected.
    outcome = _abstention(_ask(agent, _assignment()))
    assert outcome.reason is AbstentionReason.INTERPRETATION_REJECTED


def test_the_worked_source_still_attests() -> None:
    """The positive control: the fix refuses failures, not the ordinary case."""
    response = _ask(fleet.site(TENANT), _assignment())
    assert isinstance(response.outcome, AcquiredEvidence), response.outcome
    assert len(response.outcome.receipts) == 2


#  ---- a model's words must not cross the source boundary ------------------


@pytest.mark.parametrize(
    "turns",
    [
        pytest.param(
            [Call("decline", {"reason": "unreadable", "detail": LEAKED}), Say("done")],
            id="through-a-decline",
        ),
        pytest.param(
            [
                Call("list_local_evidence", {}),
                Call("read_text_evidence", {"ref": "gate-log-sat"}),
                Call(
                    "record_observation",
                    {
                        "target": "T1",
                        "relation": "exact",
                        "value": LEAKED,
                        "observed_at": fleet.OBSERVED_AT,
                        "basis": "gate-log-sat",
                    },
                ),
                Say("done"),
            ],
            id="through-a-rejected-value",
        ),
        pytest.param(
            [
                Call("list_local_evidence", {}),
                Call("read_text_evidence", {"ref": "gate-log-sat"}),
                Call(
                    "record_observation",
                    {
                        "target": LEAKED,
                        "relation": "exact",
                        "value": "true",
                        "observed_at": fleet.OBSERVED_AT,
                        "basis": "gate-log-sat",
                    },
                ),
                Say("done"),
            ],
            id="through-a-rejected-label",
        ),
        pytest.param(
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
                        "basis": LEAKED,
                    },
                ),
                Say("done"),
            ],
            id="through-a-rejected-citation",
        ),
    ],
)
def test_nothing_a_model_writes_reaches_the_response(turns: list[Turn]) -> None:
    """The reported defect: a refusal quoted what it refused.

    Every string a model authors -- the decline note, the value, the label, the
    citation -- was being echoed into the abstention's detail, and the detail is
    encoded into the response that crosses the source boundary. A model with a
    private gate log in its context has somewhere to put it.

    What travels now is the clause name, which is what an operator is deciding
    between; the rest stays where the material is.
    """
    response = _ask(fleet.site(TENANT, model=scripted(turns)), _assignment())
    outcome = _abstention(response)
    assert outcome.reason in {
        AbstentionReason.INTERPRETATION_REJECTED,
        AbstentionReason.EVIDENCE_UNREADABLE,
    }
    octets = encode(response.to_node())
    for needle in (b"PRIYA", b"NORTH-TURNSTILE-1", b"not for redistribution", b"B-2210"):
        assert needle not in octets, f"{needle!r} crossed the source boundary"


def test_an_abstention_detail_is_drawn_from_a_closed_vocabulary() -> None:
    """Stated as a property rather than only as an absence of one string.

    Whatever the model said, the detail is either a clause name this package
    declares or a fixed phrase it wrote -- never something a model chose.
    """
    permitted = {member.value for member in ObservationFailure} | {DECLINED}
    outcome = _abstention(
        _ask(
            fleet.site(
                TENANT,
                model=scripted(
                    [Call("decline", {"reason": "ambiguous", "detail": LEAKED}), Say("done")]
                ),
            ),
            _assignment(),
        )
    )
    assert outcome.detail in permitted


#  ---- an observation instant must be bounded at both ends -----------------


def test_a_back_dated_observation_cannot_widen_the_validity_window() -> None:
    """The reported defect: the model chose where the window started.

    The instant is the one field a model authors freely, and it decides the
    start of the interval the receipt is admissible over. Unbounded below, a
    model could date an observation to the epoch and make its receipt valid at
    any case instant at all -- defeating the agent's own refusal *and* the
    rebuild's expiry check, with a signature already spent.
    """
    back_dated = scripted(
        [
            Call("list_local_evidence", {}),
            Call("read_text_evidence", {"ref": "gate-log-sat"}),
            Call(
                "record_observation",
                {
                    "target": "T1",
                    "relation": "exact",
                    "value": "true",
                    "observed_at": "1970-01-01T00:00:00+00:00",
                    "basis": "gate-log-sat",
                },
            ),
            Say("done"),
        ]
    )
    #  The assignment an honest source refuses: its instant is long before
    #  anything this source observed.
    outcome = _abstention(_ask(fleet.site(TENANT, model=back_dated), _assignment(as_of=1)))
    assert outcome.reason is AbstentionReason.INTERPRETATION_REJECTED
    assert outcome.detail == "OBSERVED_AT_OUT_OF_RANGE"


def test_an_observation_from_the_future_is_still_refused() -> None:
    """The other end of the same bound, kept."""
    ahead = scripted(
        [
            Call("list_local_evidence", {}),
            Call("read_text_evidence", {"ref": "gate-log-sat"}),
            Call(
                "record_observation",
                {
                    "target": "T1",
                    "relation": "exact",
                    "value": "true",
                    "observed_at": "2027-01-01T00:00:00+00:00",
                    "basis": "gate-log-sat",
                },
            ),
            Say("done"),
        ]
    )
    outcome = _abstention(_ask(fleet.site(TENANT, model=ahead), _assignment()))
    assert outcome.detail == "OBSERVED_AT_OUT_OF_RANGE"


def test_the_window_a_source_signs_is_bounded_by_its_own_policy() -> None:
    """What the horizon buys, stated over the artifact rather than the check."""
    response = _ask(fleet.site(TENANT), _assignment())
    assert isinstance(response.outcome, AcquiredEvidence), response.outcome
    for receipt in response.outcome.receipts:
        validity = receipt.payload.validity
        assert validity.end is not None
        span = validity.end - validity.start
        #  At most the horizon it will read back over, plus the window it
        #  stands behind an answer for.  Both are configured lengths; neither
        #  is a number a model chose.
        assert span <= fleet.OBSERVATION_HORIZON.microseconds + fleet.VALIDITY_TTL.microseconds


#  ---- a receipt must answer the subject it was asked about ----------------


def test_a_receipt_naming_another_subject_is_not_submitted() -> None:
    """``subject`` is signed provenance that no later check reads.

    Not the rebuild, not Q-12, not a view. It is correct today because an
    honest agent copies it from the target it was handed -- so the dispatcher,
    which is the last place holding both the answer and the question, is where
    a mismatch can still be seen.
    """
    assignment = _assignment()
    response = _ask(fleet.site(TENANT), assignment)
    assert isinstance(response.outcome, AcquiredEvidence), response.outcome
    honest = response.outcome.receipts[0]

    reattributed = replace(honest, payload=replace(honest.payload, subject="SOMEBODY-ELSE"))
    refused = _check_receipt(reattributed, assignment)
    assert isinstance(refused, Err), refused
    assert refused.error.failure is SubmissionFailure.UNREQUESTED_SUBJECT

    assert isinstance(_check_receipt(honest, assignment), Ok)


#  ---- a source cannot raise out of the function that reads its answer -----


def test_a_deeply_nested_response_is_refused_rather_than_raised() -> None:
    """The responder is untrusted, and the decoder was recursive.

    ``_read_response`` promises a ``Result`` and ``acquire_outstanding``
    promises one on top of it, so every way a reply can be wrong has to be a
    value. It was not: twelve kilobytes of nested variants -- well inside the
    transport's megabyte cap, and inside the agent's own quarter-megabyte
    inbound cap -- exhausted the interpreter stack instead, and the
    ``RecursionError`` came out of the control plane's dispatcher.

    The bound is in the kernel decoder rather than here, because both edges
    read octets somebody else wrote and guarding one of them would leave the
    other. What this test pins is the consequence at the edge that matters:
    the control plane treats it as an unreadable reply and the case is exactly
    as it was.
    """
    hostile = bytearray()
    for _ in range(3_000):
        hostile.append(TAG_TAGGED)
        hostile += encode(NAtom("x"))
    hostile.append(TAG_UNIT)

    refused = _read_response(bytes(hostile))
    assert isinstance(refused, Err), refused
    assert refused.error.failure is SubmissionFailure.RESPONSE_UNREADABLE
    assert DecodeFailure.NESTING_TOO_DEEP.value in refused.error.detail


def test_the_agent_refuses_the_same_shape_on_the_way_in() -> None:
    """The assignment side of the same edge, so neither is guarded alone."""
    hostile = bytearray()
    for _ in range(3_000):
        hostile.append(TAG_TAGGED)
        hostile += encode(NAtom("x"))
    hostile.append(TAG_UNIT)

    outcome = decode(bytes(hostile))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.NESTING_TOO_DEEP
