"""The gate between what a model said and what a source may sign.

Every case here is a thing a language model does, expressed as a candidate:
a label nobody offered, a value in the wrong shape, a number outside the
declared range, a timestamp in the future, a citation to material that was
never there.  All of them produce a typed refusal and nothing else.
"""

from __future__ import annotations

import pytest

from agent_tests.support import assignments
from agent_tests.support.fleet import OBSERVED_AT
from muster.agents.runtime.observations import (
    CandidateObservation,
    ObservationError,
    ObservationFailure,
    ValidatedObservation,
    parse_value,
    validate_all,
    validate_candidate,
)
from muster.core.evidence.acquisition import AcquisitionTargetSpec
from muster.core.evidence.relations import ClosedLowerBound, ClosedUpperBound, ExactValue
from muster.core.results import Err, Ok, Result
from muster.core.values.scalars import VBool, VInt, VScaled
from muster.core.values.sorts import BoolSort, IntSort, ScaledSort

ISSUED_AT = 1_785_996_400_000_000
#  Thirty days back.  The floor under the one field a model authors freely:
#  the instant decides where a receipt's validity window starts, so a
#  candidate dated before this is refused rather than signed.
HORIZON = ISSUED_AT - 30 * 24 * 3_600 * 1_000_000
OFFERED = frozenset({"gate-log-sat", "attendance-board-sat"})


def targets() -> dict[str, AcquisitionTargetSpec]:
    site = assignments.site_assignment(tenant_id="ALPHA", case_id="CASE-1", agent_id="agent-site-a")
    return {"T1": site.targets[0], "T2": site.targets[1]}


def candidate(**changes: str) -> CandidateObservation:
    fields = {
        "label": "T1",
        "relation": "exact",
        "value": "true",
        "observed_at": OBSERVED_AT,
        "basis": "gate-log-sat",
    }
    fields.update(changes)
    return CandidateObservation(
        label=fields["label"],
        relation=fields["relation"],
        value=fields["value"],
        observed_at=fields["observed_at"],
        basis=fields["basis"],
    )


def validated(**changes: str) -> Result[ValidatedObservation, ObservationError]:
    return validate_candidate(
        candidate(**changes),
        targets=targets(),
        offered=OFFERED,
        issued_at=ISSUED_AT,
        horizon=HORIZON,
    )


def refusal(**changes: str) -> ObservationFailure:
    outcome = validated(**changes)
    assert isinstance(outcome, Err), outcome
    return outcome.error.failure


def test_the_worked_presence_observation_survives() -> None:
    outcome = validated()
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.relation == ExactValue(VBool(True))
    assert outcome.value.proposition == assignments.PRESENT


def test_a_lower_bound_on_the_duration_survives() -> None:
    outcome = validated(label="T2", relation="at_least", value="240")
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.relation == ClosedLowerBound(VInt(240))


def test_a_model_cannot_answer_a_target_nobody_offered() -> None:
    """The narrowest refusal in the package, and the one that matters most.

    A label is the only way to name a proposition, so a model that answers
    something it was not asked about has to name a label that does not exist.
    """
    assert refusal(label="T9") is ObservationFailure.UNKNOWN_TARGET


def test_a_model_cannot_answer_one_target_twice() -> None:
    outcome = validate_all(
        (candidate(), candidate(value="false")),
        targets=targets(),
        offered=OFFERED,
        issued_at=ISSUED_AT,
        horizon=HORIZON,
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is ObservationFailure.DUPLICATE_TARGET


def test_a_value_outside_the_declared_domain_is_refused() -> None:
    assert refusal(label="T2", relation="exact", value="4000") is (
        ObservationFailure.VALUE_OUT_OF_DOMAIN
    )


@pytest.mark.parametrize("spelling", ["yes", "1", "TRUE-ish", "", "  "])
def test_a_boolean_has_two_spellings_and_no_others(spelling: str) -> None:
    assert refusal(value=spelling) is ObservationFailure.VALUE_UNPARSABLE


@pytest.mark.parametrize("spelling", ["1_000", "١٢٣", "240.5", "+240", " 240 x"])
def test_an_integer_is_plain_digits_and_nothing_else(spelling: str) -> None:
    """``int()`` would accept most of these, which is exactly the problem.

    Underscores, a leading plus and non-Latin digit forms are all things a
    model reaches for, and a source that was believed about ``1_000`` minutes
    would be believed about a quantity nobody wrote.
    """
    assert refusal(label="T2", relation="exact", value=spelling) is (
        ObservationFailure.VALUE_UNPARSABLE
    )


def test_an_ordering_relation_needs_an_ordered_sort() -> None:
    assert refusal(relation="at_least") is ObservationFailure.RELATION_NOT_AVAILABLE_FOR_SORT


def test_a_relation_kind_outside_the_four_is_refused() -> None:
    assert refusal(relation="probably") is ObservationFailure.UNKNOWN_RELATION


def test_a_citation_to_material_that_was_never_offered_is_refused() -> None:
    """A model that names a source it never saw has not read anything."""
    assert refusal(basis="cctv-feed-3") is ObservationFailure.BASIS_NOT_OFFERED


@pytest.mark.parametrize(
    "instant",
    ["2026-08-01T09:12:00", "yesterday", "", "2026-08-01"],
)
def test_an_instant_without_an_offset_is_refused(instant: str) -> None:
    """A local reading is ambiguous by up to twelve hours, and a source-local
    observation that could be either is not one a case can use."""
    assert refusal(observed_at=instant) is ObservationFailure.OBSERVED_AT_UNPARSABLE


def test_a_source_cannot_have_observed_something_after_it_signed_for_it() -> None:
    assert refusal(observed_at="2027-01-01T00:00:00+00:00") is (
        ObservationFailure.OBSERVED_AT_OUT_OF_RANGE
    )


def test_a_source_cannot_have_observed_something_before_it_will_attest() -> None:
    """The floor, and the reason there is one.

    The instant decides where the receipt's validity window *starts*.  Left
    unbounded below, a model could date an observation to the epoch and make
    its receipt admissible at any case instant at all -- with the signature
    already spent, and both the agent's own window check and the rebuild's
    expiry check satisfied.
    """
    assert refusal(observed_at="1970-01-01T00:00:00+00:00") is (
        ObservationFailure.OBSERVED_AT_OUT_OF_RANGE
    )


def test_an_upper_bound_is_expressible_and_typed() -> None:
    outcome = validated(label="T2", relation="at_most", value="1440")
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.relation == ClosedUpperBound(VInt(1440))


@pytest.mark.parametrize(
    ("text", "expected"),
    [("850.00", 85_000), ("850", 85_000), ("0.01", 1), ("0", 0)],
)
def test_a_scaled_amount_is_read_at_the_declared_scale(text: str, expected: int) -> None:
    outcome = parse_value(text, ScaledSort("INR", 2))
    assert isinstance(outcome, Ok), outcome
    assert outcome.value == VScaled("INR", 2, expected)


@pytest.mark.parametrize("text", ["850.000", "8,50", "850.0.0", "eight fifty"])
def test_a_scaled_amount_finer_than_the_scale_is_refused(text: str) -> None:
    """More decimals than the unit has is a claim the unit cannot carry."""
    assert isinstance(parse_value(text, ScaledSort("INR", 2)), Err)


def test_the_parser_agrees_with_the_sorts_it_is_given() -> None:
    assert isinstance(parse_value("true", BoolSort()), Ok)
    assert isinstance(parse_value("true", IntSort()), Err)
    assert isinstance(parse_value("-5", IntSort()), Ok)
