"""The acquisition relation algebra: validation, and the ordered lowering table.

The row order is the correction the module exists for.  Listing "the subset is
the whole domain" and "the subset has one member" as independent rows means a
single-member domain matches both, and one signed payload rebuilds into two
different octet sequences.  The tests below are bounded-exhaustive over one-,
two- and three-member domains, so the overlap cannot come back unnoticed.
"""

from __future__ import annotations

from itertools import combinations

import pytest

from muster.core.evidence.relations import (
    ClosedLowerBound,
    ClosedUpperBound,
    EnumSubset,
    ExactValue,
    LoweredConstraint,
    LoweredFact,
    LoweredNonEffect,
    PredicateInfo,
    RelationFailure,
    lower_relation,
    validate_relation,
)
from muster.core.expr.ir import Binary, BinaryOp, Leaf, LitEnum, LitInt, NAry, NAryOp
from muster.core.expr.terms import term_node
from muster.core.results import Err, InvariantViolation, Ok
from muster.core.values.classification import EvidenceLayer
from muster.core.values.scalars import VBool, VEnum, VInt
from muster.core.values.sorts import (
    BoolDomain,
    BoolSort,
    EnumDomain,
    EnumSort,
    IntRange,
    IntSort,
)
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import encode
from tests.support import authority

SOURCE = "SITE_ACCESS_CONTROL"
COLOUR = SymbolRef("colour", ("W-1",))
DURATION = SymbolRef("on_site_duration", ("W-1", "SAT"))


def _enum_info(members: tuple[str, ...]) -> PredicateInfo:
    return authority.info(EnumSort("colour"), EnumDomain(members), EvidenceLayer.OBSERVATION)


def _int_info() -> PredicateInfo:
    return authority.info(IntSort(), IntRange(0, 1440), EvidenceLayer.OBSERVATION)


def _bool_info() -> PredicateInfo:
    return authority.info(BoolSort(), BoolDomain(), EvidenceLayer.OBSERVATION)


def _validated(
    relation: object, info: PredicateInfo, *, proposition: SymbolRef = DURATION
) -> object:
    """Validate under a view that grants exactly this claim.

    Every test below is about Q-4 to Q-11, so the authority input is arranged
    to be satisfied rather than removed -- there is no switch that skips Q-12,
    here or anywhere.  What that costs is one helper; what it buys is that no
    test in this file can pass because a check was not run.
    """
    claim = authority.claim(proposition)
    return validate_relation(
        relation,  # type: ignore[arg-type]
        info.value_sort,
        info,
        claim,
        authority.granting(info, claim),
    )


#  ---- the ordered lowering table ----------------------------------------


@pytest.mark.parametrize("members", [("RED",), ("RED", "BLUE"), ("RED", "BLUE", "GREEN")])
def test_a_subset_covering_the_whole_domain_constrains_nothing(members: tuple[str, ...]) -> None:
    """Row 1, and it must win over row 2 on a single-member domain."""
    domain = EnumDomain(members)
    allowed = tuple(VEnum("colour", member) for member in members)
    lowered = lower_relation(EnumSubset(allowed), COLOUR, domain)
    assert isinstance(lowered, LoweredNonEffect)
    assert lowered.reason == "VACUOUS_SUBSET"


@pytest.mark.parametrize("members", [("RED", "BLUE"), ("RED", "BLUE", "GREEN")])
def test_a_single_member_subset_is_an_equality_never_a_unary_disjunction(
    members: tuple[str, ...],
) -> None:
    """Row 2."""
    domain = EnumDomain(members)
    lowered = lower_relation(EnumSubset((VEnum("colour", "RED"),)), COLOUR, domain)
    assert isinstance(lowered, LoweredConstraint)
    assert lowered.formula == Binary(BinaryOp.EQ, Leaf(COLOUR), LitEnum(VEnum("colour", "RED")))


def test_a_proper_subset_disjoins_in_declared_domain_order() -> None:
    """Row 3, and the order is the domain's, not the submitter's."""
    domain = EnumDomain(("RED", "BLUE", "GREEN"))
    forwards = EnumSubset((VEnum("colour", "RED"), VEnum("colour", "GREEN")))
    backwards = EnumSubset((VEnum("colour", "GREEN"), VEnum("colour", "RED")))

    first = lower_relation(forwards, COLOUR, domain)
    second = lower_relation(backwards, COLOUR, domain)
    assert isinstance(first, LoweredConstraint)
    assert isinstance(second, LoweredConstraint)
    assert encode(term_node(first.formula)) == encode(term_node(second.formula))
    assert first.formula == NAry(
        NAryOp.OR,
        (
            Binary(BinaryOp.EQ, Leaf(COLOUR), LitEnum(VEnum("colour", "RED"))),
            Binary(BinaryOp.EQ, Leaf(COLOUR), LitEnum(VEnum("colour", "GREEN"))),
        ),
    )


@pytest.mark.parametrize("size", [1, 2, 3])
def test_every_non_empty_subset_of_every_small_domain_lowers_exactly_once(size: int) -> None:
    """Bounded exhaustive: the rows are mutually exclusive over all of them."""
    members = ("RED", "BLUE", "GREEN")[:size]
    domain = EnumDomain(members)
    for count in range(1, size + 1):
        for chosen in combinations(members, count):
            allowed = tuple(VEnum("colour", member) for member in chosen)
            lowered = lower_relation(EnumSubset(allowed), COLOUR, domain)
            if count == size:
                assert isinstance(lowered, LoweredNonEffect), chosen
            elif count == 1:
                assert isinstance(lowered, LoweredConstraint)
                assert isinstance(lowered.formula, Binary), chosen
            else:
                assert isinstance(lowered, LoweredConstraint)
                assert isinstance(lowered.formula, NAry), chosen
                assert len(lowered.formula.operands) == count


def test_an_exact_value_is_the_only_relation_that_establishes_a_fact() -> None:
    """Row 4."""
    lowered = lower_relation(ExactValue(VInt(480)), DURATION, IntRange(0, 1440))
    assert isinstance(lowered, LoweredFact)
    assert lowered.value == VInt(480)


def test_a_closed_lower_bound_lowers_to_greater_or_equal() -> None:
    """Row 5. Compared as octets, so a flipped operator cannot read as equal."""
    lowered = lower_relation(ClosedLowerBound(VInt(240)), DURATION, IntRange(0, 1440))
    assert isinstance(lowered, LoweredConstraint)
    assert encode(term_node(lowered.formula)) == encode(
        term_node(Binary(BinaryOp.GE, Leaf(DURATION), LitInt(240)))
    )


def test_a_closed_upper_bound_lowers_to_less_or_equal() -> None:
    """Row 6 -- the sibling the fixtures never exercise."""
    lowered = lower_relation(ClosedUpperBound(VInt(600)), DURATION, IntRange(0, 1440))
    assert isinstance(lowered, LoweredConstraint)
    assert encode(term_node(lowered.formula)) == encode(
        term_node(Binary(BinaryOp.LE, Leaf(DURATION), LitInt(600)))
    )


def test_an_empty_subset_is_unrepresentable_rather_than_rejected() -> None:
    with pytest.raises(InvariantViolation):
        EnumSubset(())


#  ---- validation, on the relation kinds the fixtures never reach ---------


def test_an_ordering_relation_needs_an_ordered_sort() -> None:
    """Q-5. Without it a bound against a boolean rebuilds into an ill-typed term."""
    for info in (_bool_info(), _enum_info(("RED", "BLUE"))):
        outcome = _validated(ClosedUpperBound(VBool(True)), info)
        assert isinstance(outcome, Err)
        assert outcome.error.failure is RelationFailure.NON_NUMERIC_RELATION


def test_an_enum_subset_needs_an_enum_sort() -> None:
    """Q-6."""
    info = _int_info()
    outcome = _validated(EnumSubset((VEnum("colour", "RED"),)), info)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is RelationFailure.INVALID_ENUM_SUBSET


def test_every_member_of_a_subset_is_checked_not_only_the_first() -> None:
    """A loop that inspected only the first member would pass a bad second."""
    info = _enum_info(("RED", "BLUE"))
    outcome = _validated(EnumSubset((VEnum("colour", "RED"), VEnum("colour", "MAUVE"))), info)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is RelationFailure.VALUE_OUT_OF_DOMAIN


def test_a_valid_upper_bound_is_admitted() -> None:
    info = _int_info()
    outcome = _validated(ClosedUpperBound(VInt(600)), info)
    assert isinstance(outcome, Ok)


def test_a_valid_enum_subset_is_admitted() -> None:
    info = _enum_info(("RED", "BLUE", "GREEN"))
    outcome = _validated(EnumSubset((VEnum("colour", "RED"), VEnum("colour", "BLUE"))), info)
    assert isinstance(outcome, Ok)
