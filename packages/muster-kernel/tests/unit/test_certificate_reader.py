"""Reading a stored certificate back: exact where it can be, refusing where it cannot.

A certificate is an immutable derived artifact, and something has to be able to
turn its stored octets back into the value that was assembled -- otherwise the
only way to read one is to re-run the solver that produced it, and a solver that
has since been reconfigured is entitled to answer differently.

Two properties, and the second is the interesting one.

**Exact.**  Reading and re-encoding reproduces the octets, so every leaf a
commitment publishes from a read certificate is the leaf publication would have
produced.  Checked here on both Ravi certificates -- the divergent case and the
attested one that closes as invariant -- because between them they exercise
every variant the reader has: an evidence request with targets, a proven support
with deletion witnesses, an exact reachable set, two witness worlds, an
invariant action.

**Refusing.**  The encoding is not injective in one place: ``NoActionRequired``
carries a ``reason`` the frozen shape does not encode.  Re-encoding is therefore
blind to it -- a wrong reason round-trips perfectly and no digest check
anywhere can see it -- and that field decides a case status and a dispatch.  So
the reader recovers it from the outcome that produced it, and refuses the
pairings no planner produces rather than inventing one.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.core.analysis.certificate import (
    TAG_ANALYSIS_CERTIFICATE,
    AnalysisCertificate,
    no_action_reason,
    read_analysis_certificate,
)
from muster.core.analysis.outcomes import (
    Divergent,
    Indeterminate,
    IndeterminateReason,
    Infeasible,
    Invariant,
    outcome_node,
)
from muster.core.analysis.planning import (
    NoActionReason,
    NoActionRequired,
    PlanningRecord,
    read_planning_outcome,
)
from muster.core.analysis.worlds import read_world
from muster.core.results import Ok
from muster.core.wire.codec import decode, encode
from muster.core.wire.nodes import NRec, NSeq, NTagged, NUnit
from muster.core.wire.shape import WireDecodeError, WireFailure
from tests.support import ravi


def _round_trip(certificate: AnalysisCertificate) -> None:
    octets = encode(certificate.to_node())
    node = decode(octets)
    assert isinstance(node, Ok), node
    read = read_analysis_certificate(node.value)
    assert encode(read.to_node()) == octets
    assert read.digest() == certificate.digest()


def test_the_divergent_ravi_certificate_round_trips_exactly() -> None:
    _round_trip(ravi.analysis().certificate)


def test_the_attested_ravi_certificate_round_trips_exactly() -> None:
    """The invariant half, which carries an action, a witness and a silent plan."""
    from muster.application.pipeline import analyse_revision
    from muster.application.rebuild import rebuild, transcript_prefix

    case = ravi.attested_case_file()
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    built = rebuild(
        case.rebuild_inputs(ravi.bundle().digest(), prefix.digest()),
        case.construction,
        case.entries,
        ravi.bundle(),
        case.authorization_context,
        case.authority_snapshot,
        case.revocation_snapshot,
        case.solicitations,
    )
    assert isinstance(built, Ok), built
    produced = analyse_revision(built.value, ravi.bundle(), ravi.backend(), ravi.limits())
    assert isinstance(produced, Ok), produced
    assert isinstance(produced.value.certificate.kernel.outcome, Invariant)
    _round_trip(produced.value.certificate)


def test_the_reason_a_planner_asked_for_nothing_is_recovered_never_invented() -> None:
    """Two outcomes explain a silence; the other two do not, and say so."""
    divergent = ravi.analysis().certificate.kernel.outcome
    assert no_action_reason(Infeasible(("C-1",))) is NoActionReason.INFEASIBLE
    assert no_action_reason(Indeterminate(IndeterminateReason.BUDGET_EXHAUSTED)) is None
    #  Ravi's own outcome is divergent, and a divergent case is asked about
    #  rather than left alone -- so it explains no silence either.
    assert no_action_reason(divergent) is None


def test_a_plan_requesting_nothing_under_an_outcome_that_requests_something_is_refused() -> None:
    """The refusal the round trip cannot make for itself.

    A row pairing a divergent outcome with a payload-less ``NoActionRequired``
    is not a certificate any planner produced.  Reading it would mean choosing
    a reason from nowhere, re-encoding would reproduce the octets regardless,
    and the fabricated value would be indistinguishable downstream from one the
    planner wrote.  So it fails closed.
    """
    node = NTagged("NoActionRequired", NUnit())
    assert read_planning_outcome(node, no_action_reason=NoActionReason.INFEASIBLE) == (
        NoActionRequired(NoActionReason.INFEASIBLE)
    )
    with pytest.raises(WireDecodeError) as refused:
        read_planning_outcome(node, no_action_reason=None)
    assert refused.value.error.failure is WireFailure.OUT_OF_RANGE


def test_a_certificate_pairing_a_divergent_outcome_with_a_silent_plan_is_refused() -> None:
    """The same refusal, reached the way a corrupt row would reach it."""
    certificate = ravi.analysis().certificate
    silent = replace(
        certificate,
        planning=PlanningRecord(NoActionRequired(NoActionReason.ACTION_INVARIANT), None),
    )
    node = decode(encode(silent.to_node()))
    assert isinstance(node, Ok), node
    with pytest.raises(WireDecodeError):
        read_analysis_certificate(node.value)


def test_an_unknown_outcome_tag_is_refused_rather_than_guessed() -> None:
    certificate = ravi.analysis().certificate
    fields = certificate.to_node().fields
    kernel = fields[5]
    assert isinstance(kernel, NRec)
    tampered = NRec(
        TAG_ANALYSIS_CERTIFICATE,
        (
            *fields[:5],
            NRec(
                kernel.tag,
                (
                    kernel.fields[0],
                    NTagged("Authorized", outcome_node(certificate.kernel.outcome)),
                    *kernel.fields[2:],
                ),
            ),
            *fields[6:],
        ),
    )
    with pytest.raises(WireDecodeError) as refused:
        read_analysis_certificate(tampered)
    assert refused.value.error.failure is WireFailure.UNKNOWN_VARIANT


def test_a_world_whose_bindings_are_out_of_order_is_refused_as_a_wire_failure() -> None:
    """Not as an exception. A stored artifact's invariant violation is a finding.

    ``World`` refuses an unordered or repeating binding set by raising, which is
    right for a value the system is building and wrong for octets that arrived
    from a store: there, the violation is a fact about the row and has to reach
    the caller as one.
    """
    outcome = ravi.analysis().certificate.kernel.outcome
    assert isinstance(outcome, Divergent)
    witness = outcome.left
    bindings = witness.to_node().fields[0]
    assert isinstance(bindings, NSeq)
    assert len(bindings.items) > 1

    reversed_world = NRec(witness.to_node().tag, (NSeq(tuple(reversed(bindings.items))),))
    with pytest.raises(WireDecodeError) as refused:
        read_world(reversed_world)
    assert refused.value.error.failure is WireFailure.NOT_CANONICAL

    repeated = NRec(witness.to_node().tag, (NSeq((bindings.items[0], bindings.items[0])),))
    with pytest.raises(WireDecodeError) as repeat:
        read_world(repeated)
    assert repeat.value.error.failure is WireFailure.NOT_CANONICAL

    #  And the honest one still reads, so the refusals are about the tampering.
    assert read_world(witness.to_node()) == witness
