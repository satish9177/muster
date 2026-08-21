"""What a source can send back, and what the control plane will do with it.

Every test here starts from a *working* fleet and breaks exactly one thing:
the agent that answers, the request the receipt cites, the case it names, the
number of times it arrives.  The subject is the control plane's side of the
boundary -- the envelope checks, the admission path, and check Q-12 behind them.

Two claims run through all of it and are asserted separately at the end:

    a catalog entry grants no authority
    a network identity grants no authority, and authority grants no network access
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import replace

import pytest
from demo.hero import HeroRun, run_hero

from agent_tests.support import assignments, fleet
from muster.agents.transport import identity as network
from muster.agents.transport.inprocess import InProcessAcquisitionTransport
from muster.core.authority.check import AuthorityFailure, check_authority
from muster.core.authority.grants import AuthorityGrant
from muster.core.authority.scope import ResourceScope
from muster.core.catalog.discovery import DiscoveryQuery
from muster.core.evidence.acquisition import (
    AcquiredEvidence,
    AcquisitionResponse,
    read_acquisition_response,
)
from muster.core.evidence.delivery import (
    AcquisitionTransport,
    TransportError,
    TransportFailure,
)
from muster.core.evidence.transcript import Attestation, Statement
from muster.core.results import Err, Ok, Result
from muster.core.wire.codec import decode, encode
from muster.core.wire.digests import Digest
from muster.platform.adapters.memory import MemoryDatabase, MemoryRecords
from muster.platform.casework.advance import Casework
from muster.platform.casework.commands import append_transcript_entry
from muster.platform.catalog.route import route
from muster.platform.dispatch.acquire import (
    AgentExchange,
    Answered,
    EnvelopeRefused,
    SubmissionFailure,
    Unreachable,
    acquire_outstanding,
)
from muster.platform.orchestration.status import CaseStatus
from support import ravi
from support.authority import publish_fleet, publisher_verifier, site_profile
from support.fixtures import open_ravi

#  The distinctive strings of the site's own material.  If any of these ever
#  appears in the control plane's durable state, the raw evidence left the
#  source -- which is the one thing this milestone exists to prevent.
RAW_NEEDLES: tuple[bytes, ...] = (
    b"NORTH-TURNSTILE-2",
    b"B-4471",
    b"PRIYA",
    b"gate-ctl",
    b"not for redistribution",
    b"\x89PNG",
)


@pytest.fixture
def worked(tenant_id: str, case_id: str) -> tuple[HeroRun, MemoryRecords]:
    """One completed run, with the durable state it produced."""
    database = MemoryDatabase()
    run = run_hero(
        ravi.casework(database),
        fleet.whole_fleet(tenant_id),
        tenant_id=tenant_id,
        case_id=case_id,
    )
    return run, database.records


#  ---- RAW_SITE_EVIDENCE_NEVER_ENTERS_CONTROL_PLANE ------------------------


def test_raw_site_evidence_never_enters_the_control_plane(
    worked: tuple[HeroRun, MemoryRecords],
) -> None:
    """Scanned over every octet the control plane durably holds.

    Not over a summary of them, and not over the fields somebody remembered to
    check: the store *is* the control plane's memory, so a needle absent from
    all of it is absent from everything derived from it -- including every
    revision, every certificate and every view.
    """
    _run, records = worked
    assert records.content, "the run stored nothing, so this proves nothing"
    for (_tenant, digest), (kind, octets) in records.content.items():
        for needle in RAW_NEEDLES:
            assert needle not in octets, f"{needle!r} is in a stored {kind} {digest.hex[:12]}"


def test_the_receipts_carry_a_proposition_and_not_a_picture(
    worked: tuple[HeroRun, MemoryRecords],
) -> None:
    """One relation over one declared proposition, plus provenance.

    The attendance board is two kilobytes of PNG and the gate log names two
    workers.  What left the site is a boolean and a lower bound.
    """
    run, _records = worked
    for exchange in _exchanges(run):
        assert isinstance(exchange.result, Answered), exchange.result
        for admitted in exchange.result.admitted:
            assert admitted.proposition.predicate_id in {
                "scheduled",
                "present_on_site",
                "on_site_duration",
            }


def test_the_material_is_not_in_the_octets_that_cross_the_wire() -> None:
    """The encoded response is what a transport carries.  Search it directly."""
    octets = encode(_site_response().to_node())
    for needle in RAW_NEEDLES:
        assert needle not in octets, f"{needle!r} crossed the source boundary"


def test_the_basis_reference_does_not_travel_either() -> None:
    """A receipt carries a proposition, not a pointer into a private store.

    Naming the file would tell a reader that ``gate-log-sat`` exists at
    ``SITE-A`` -- a smaller disclosure than the log itself, and still one the
    site never agreed to.
    """
    octets = encode(_site_response().to_node())
    assert b"gate-log-sat" not in octets
    assert b"attendance-board-sat" not in octets


#  ---- WRONG_AGENT_RESPONSE_REJECTED ---------------------------------------


def test_a_response_from_another_agent_is_rejected(tenant_id: str, case_id: str) -> None:
    """The agent that answers must be the agent that was addressed."""
    refused = _attack(tenant_id, case_id, agent_id="agent-site-b")
    assert refused is SubmissionFailure.RESPONSE_FROM_ANOTHER_AGENT


def test_a_response_about_another_case_is_rejected(tenant_id: str, case_id: str) -> None:
    refused = _attack(tenant_id, case_id, case_id_claimed="SOMEBODY-ELSES-CASE")
    assert refused is SubmissionFailure.RESPONSE_NOT_FOR_THIS_REQUEST


def test_a_response_about_another_tenant_is_rejected(tenant_id: str, case_id: str) -> None:
    refused = _attack(tenant_id, case_id, tenant_id_claimed="BETA")
    assert refused is SubmissionFailure.RESPONSE_NOT_FOR_THIS_REQUEST


#  ---- STALE_REQUEST_RESPONSE_REJECTED -------------------------------------


def test_a_reply_bound_to_another_request_is_not_submitted(tenant_id: str, case_id: str) -> None:
    """A dispatcher does not submit an answer to a question it did not just ask.

    Admission would treat a stale citation from this case as *volunteered*
    evidence, which is the ratified behaviour and is right at that layer: what
    is admissible is a property of the case, not of the round.  The dispatcher
    is a different question -- did this exchange answer this assignment -- and
    a round that reported a stale answer as its own reply would be reporting a
    round that did not happen.
    """
    refused = _attack(tenant_id, case_id, request_id=assignments.request_id("an-older-round"))
    assert refused is SubmissionFailure.RESPONSE_NOT_FOR_THIS_REQUEST


#  ---- DUPLICATE_AGENT_RESPONSE_IS_IDEMPOTENT ------------------------------


def test_a_duplicate_receipt_is_admitted_once(tenant_id: str, case_id: str) -> None:
    """At-least-once delivery costs nothing, because a receipt is its own digest.

    The same octets submitted twice are the same transcript member, so the
    second submission reports ``created=False``, the membership set does not
    grow, and the head does not move.  No deduplication table, no idempotency
    key, no bookkeeping -- the property is structural.
    """
    database = MemoryDatabase()
    casework = ravi.casework(database)
    transport = _Replaying(fleet.whole_fleet(tenant_id))
    run = run_hero(casework, transport, tenant_id=tenant_id, case_id=case_id)
    assert run.report.status is CaseStatus.PROPOSED
    settled = run.report.head.revision_digest

    with database.reading(tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members
    before = members.value

    #  Every receipt the fleet produced, delivered a second time.  This is what
    #  a retried transport call does after a response was lost on the way back.
    resubmitted = 0
    for exchange in _exchanges(run):
        assert isinstance(exchange.result, Answered), exchange.result
        answered = transport.deliver(
            endpoint_ref=exchange.endpoint_ref,
            assignment=encode(exchange.assignment.to_node()),
        )
        assert isinstance(answered, Ok), answered
        node = decode(answered.value)
        assert isinstance(node, Ok), node
        response = read_acquisition_response(node.value)
        assert isinstance(response.outcome, AcquiredEvidence), response.outcome
        for receipt in response.outcome.receipts:
            appended = append_transcript_entry(
                casework,
                tenant_id=tenant_id,
                case_id=case_id,
                entry=Attestation(receipt),
                now=ravi.NOW,
            )
            assert isinstance(appended, Ok), appended
            assert not appended.value.created, "a re-delivered receipt was treated as new"
            resubmitted += 1
    assert resubmitted == 3, resubmitted

    with database.reading(tenant_id) as scope:
        after = scope.transcript.members(case_id)
        head = scope.heads.read(case_id)
    assert isinstance(after, Ok) and isinstance(head, Ok)
    assert after.value == before
    assert head.value.revision_digest == settled


def test_a_second_round_on_a_settled_case_asks_nobody(tenant_id: str, case_id: str) -> None:
    """Nothing is outstanding, so nothing is dispatched.

    Re-driving acquisition is safe because it is driven by what the case has
    outstanding, and a case whose head has moved past a request has none.
    """
    casework = ravi.casework(MemoryDatabase())
    transport = fleet.whole_fleet(tenant_id)
    run_hero(casework, transport, tenant_id=tenant_id, case_id=case_id)

    again = acquire_outstanding(
        casework, transport, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW
    )
    assert isinstance(again, Ok), again
    assert again.value == ()


#  ---- the transport failing -----------------------------------------------


def test_an_unknown_endpoint_is_a_transport_failure_and_not_evidence(
    tenant_id: str, case_id: str
) -> None:
    """A request that is not delivered leaves the case exactly as it was."""
    casework = ravi.casework(MemoryDatabase())
    _prepare(casework, tenant_id, case_id)

    acquired = acquire_outstanding(
        casework,
        InProcessAcquisitionTransport({}),
        tenant_id=tenant_id,
        case_id=case_id,
        now=ravi.NOW,
    )
    assert isinstance(acquired, Ok), acquired
    exchanges = [exchange for report in acquired.value for exchange in report.exchanges]
    assert exchanges, "nothing was even attempted"
    for exchange in exchanges:
        assert isinstance(exchange.result, Unreachable), exchange.result
        assert exchange.result.error.failure is TransportFailure.ENDPOINT_UNKNOWN


#  ---- CATALOG_SELECTION_DOES_NOT_GRANT_AUTHORITY --------------------------


def test_catalog_selection_does_not_grant_authority(tenant_id: str, case_id: str) -> None:
    """A cataloged agent for a site whose key holds no grant over it.

    The catalog routes to it, because routing is an address.  The authority
    snapshot the case pinned grants that key nothing here, and Q-12 reads the
    snapshot and takes no catalog argument at all -- so publishing a profile
    that claims a capability changes which agent is asked and changes no
    admission decision.
    """
    database = MemoryDatabase()
    case = _worked_case(tenant_id, case_id)
    open_ravi(ravi.casework(database), case)

    impostor = site_profile(tenant_id, site="SITE-B", agent_id="agent-site-b")
    publish_fleet(database, tenant_id, case.authority_snapshot, profiles=(impostor,))

    with database.reading(tenant_id) as scope:
        found = route(
            scope,
            publisher_verifier(),
            DiscoveryQuery(
                tenant_id=tenant_id,
                source_class="SITE_ACCESS_CONTROL",
                predicate_id="present_on_site",
                resource_scope=(ResourceScope("SITE", "SITE-B"),),
            ),
        )
    assert isinstance(found, Ok), found
    assert found.value.agent_id == "agent-site-b"

    granted = {
        (grant.key_ref, grant.source_class, tuple(str(scope) for scope in grant.resource_scope))
        for grant in case.authority_snapshot.grants
    }
    assert ("key-site-b-1", "SITE_ACCESS_CONTROL", ("(SITE, SITE-B)",)) not in granted


#  ---- NETWORK_IDENTITY_DOES_NOT_GRANT_Q12_AUTHORITY -----------------------
#  ---- Q12_AUTHORITY_DOES_NOT_GRANT_NETWORK_ACCESS -------------------------


def test_network_identity_and_source_authority_are_different_questions() -> None:
    """Two layers, two vocabularies, and no argument between them.

    The transport's failure vocabulary has no member meaning "unauthorized to
    attest", the caller-identity vocabulary has none either, and check Q-12 has
    no parameter through which a caller identity could arrive.  Neither can be
    spelled in terms of the other, which is the strongest form the separation
    takes.
    """
    transport_reasons = {member.value for member in TransportFailure}
    identity_reasons = {member.value for member in network.IdentityFailure}
    authority_reasons = {member.value for member in AuthorityFailure}
    assert transport_reasons.isdisjoint(authority_reasons)
    assert identity_reasons.isdisjoint(authority_reasons)

    parameters = check_authority.__code__.co_varnames[: check_authority.__code__.co_argcount]
    assert not any("caller" in name or "token" in name or "identity" in name for name in parameters)


def test_source_authority_does_not_grant_network_access() -> None:
    """A grant is not an invoker binding, and the code says so by absence.

    An authority grant has no field naming an endpoint, and the delivery port
    has no argument naming a key: a key authorized to attest ``present_on_site``
    at ``SITE-A`` cannot thereby call anything.
    """
    fields = set(AuthorityGrant.__dataclass_fields__)
    assert not any("endpoint" in name or "url" in name or "invoke" in name for name in fields)

    parameters = set(inspect.signature(AcquisitionTransport.deliver).parameters)
    assert "endpoint_ref" in parameters
    assert not any("key" in name or "grant" in name for name in parameters)


#  ---- helpers -------------------------------------------------------------


class _Rewriting:
    """A transport that corrupts one envelope field of every response.

    A misbehaving agent, expressed as a transport, because the envelope is what
    the control plane checks and this is the smallest way to make one wrong.
    """

    def __init__(
        self,
        inner: AcquisitionTransport,
        *,
        agent_id: str | None = None,
        tenant_id_claimed: str | None = None,
        case_id_claimed: str | None = None,
        request_id: Digest | None = None,
    ) -> None:
        self._inner = inner
        self._agent_id = agent_id
        self._tenant_id = tenant_id_claimed
        self._case_id = case_id_claimed
        self._request_id = request_id

    def deliver(self, *, endpoint_ref: str, assignment: bytes) -> Result[bytes, TransportError]:
        answered = self._inner.deliver(endpoint_ref=endpoint_ref, assignment=assignment)
        if isinstance(answered, Err):
            return answered
        node = decode(answered.value)
        assert isinstance(node, Ok), node
        response = read_acquisition_response(node.value)
        if self._agent_id is not None:
            response = replace(response, agent_id=self._agent_id)
        if self._tenant_id is not None:
            response = replace(response, tenant_id=self._tenant_id)
        if self._case_id is not None:
            response = replace(response, case_id=self._case_id)
        if self._request_id is not None:
            response = replace(response, request_id=self._request_id)
        return Ok(encode(response.to_node()))


class _Replaying:
    """A transport that remembers what it answered and answers it again.

    Not a corruption: at-least-once delivery is what every network has, and the
    property under test is that the second delivery costs nothing.
    """

    def __init__(self, inner: AcquisitionTransport) -> None:
        self._inner = inner
        self._answers: dict[str, bytes] = {}

    def deliver(self, *, endpoint_ref: str, assignment: bytes) -> Result[bytes, TransportError]:
        remembered = self._answers.get(endpoint_ref)
        if remembered is not None:
            return Ok(remembered)
        answered = self._inner.deliver(endpoint_ref=endpoint_ref, assignment=assignment)
        if isinstance(answered, Ok):
            self._answers[endpoint_ref] = answered.value
        return answered


def _site_response() -> AcquisitionResponse:
    """One site agent answer to the worked assignment, unsubmitted."""
    return asyncio.run(
        fleet.site("ALPHA").acquire(
            assignments.site_assignment(
                tenant_id="ALPHA", case_id="CASE-1", agent_id=fleet.SITE_AGENT_ID
            )
        )
    )


def _worked_case(tenant_id: str, case_id: str) -> ravi.RaviCase:
    return fleet.without(
        ravi.ravi(tenant_id, case_id),
        *fleet.ACQUIRED_BY_THE_FLEET,
        ("present_on_site", (fleet.WORKER, fleet.SATURDAY)),
    )


def _prepare(casework: Casework, tenant_id: str, case_id: str) -> None:
    """Open the worked case and append everything up to the evidence request."""
    case = _worked_case(tenant_id, case_id)
    open_ravi(casework, case)
    publish_fleet(casework.database, tenant_id, case.authority_snapshot)
    for entry in case.entries:
        appended = append_transcript_entry(
            casework, tenant_id=tenant_id, case_id=case_id, entry=entry, now=ravi.NOW
        )
        assert isinstance(appended, Ok), appended
    claimed = asyncio.run(
        fleet.worker().interpret(fleet.worker_brief(tenant_id, case_id), fleet.WORKER_ACCOUNT)
    )
    assert isinstance(claimed, tuple), claimed
    for statement in claimed:
        appended = append_transcript_entry(
            casework,
            tenant_id=tenant_id,
            case_id=case_id,
            entry=Statement(statement),
            now=ravi.NOW,
        )
        assert isinstance(appended, Ok), appended


def _attack(tenant_id: str, case_id: str, **corruption: object) -> SubmissionFailure:
    """Run the worked case over a corrupted transport; report the one refusal."""
    casework = ravi.casework(MemoryDatabase())
    _prepare(casework, tenant_id, case_id)
    transport = _Rewriting(
        fleet.whole_fleet(tenant_id),
        agent_id=_text(corruption.get("agent_id")),
        tenant_id_claimed=_text(corruption.get("tenant_id_claimed")),
        case_id_claimed=_text(corruption.get("case_id_claimed")),
        request_id=_digest(corruption.get("request_id")),
    )
    acquired = acquire_outstanding(
        casework, transport, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW
    )
    assert isinstance(acquired, Ok), acquired
    refusals = {
        exchange.result.error.failure
        for report in acquired.value
        for exchange in report.exchanges
        if isinstance(exchange.result, EnvelopeRefused)
    }
    assert len(refusals) == 1, refusals
    return next(iter(refusals))


def _text(value: object) -> str | None:
    """One corruption argument, typed at the boundary the test hands it over."""
    if value is None:
        return None
    assert isinstance(value, str), value
    return value


def _digest(value: object) -> Digest | None:
    if value is None:
        return None
    assert isinstance(value, Digest), value
    return value


def _exchanges(run: HeroRun) -> tuple[AgentExchange, ...]:
    return tuple(exchange for report in run.reports for exchange in report.exchanges)
