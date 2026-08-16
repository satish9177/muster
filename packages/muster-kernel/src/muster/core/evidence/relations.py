"""Acquisition relations: what a source is permitted to say about a proposition.

A source does not send a fact.  It sends one of four relations over one declared
proposition, and what that relation becomes -- a fact, a constraint, or nothing
-- is decided here, by an ordered table, not by the source.

The order of the table matters.  A superseded draft listed "the subset is the
whole domain" and "the subset has one member" as independent rows, so a
single-member domain matched both and one signed payload rebuilt into two
different octet sequences.  Full domain wins, and it wins first.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.expr.ir import Binary, BinaryOp, Leaf, NAry, NAryOp
from muster.core.expr.terms import Term, literal
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.classification import EvidenceLayer
from muster.core.values.scalars import Value, VEnum, sort_of, value_in_domain
from muster.core.values.sorts import Domain, EnumDomain, EnumSort, IntSort, ScaledSort, Sort
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import canonical_set
from muster.core.wire.nodes import Node, NRec, NTagged

TAG_EXACT_VALUE = "ExactValue/v1"
TAG_CLOSED_LOWER = "ClosedLowerBound/v1"
TAG_CLOSED_UPPER = "ClosedUpperBound/v1"
TAG_ENUM_SUBSET = "EnumSubset/v1"


@dataclass(frozen=True, slots=True)
class ExactValue:
    value: Value

    def to_node(self) -> NRec:
        return NRec(TAG_EXACT_VALUE, (self.value.to_node(),))


@dataclass(frozen=True, slots=True)
class ClosedLowerBound:
    """``ref >= bound``. Closed: strict bounds are not representable."""

    bound: Value

    def to_node(self) -> NRec:
        return NRec(TAG_CLOSED_LOWER, (self.bound.to_node(),))


@dataclass(frozen=True, slots=True)
class ClosedUpperBound:
    bound: Value

    def to_node(self) -> NRec:
        return NRec(TAG_CLOSED_UPPER, (self.bound.to_node(),))


@dataclass(frozen=True, slots=True)
class EnumSubset:
    allowed: tuple[Value, ...]

    def __post_init__(self) -> None:
        if not self.allowed:
            raise InvariantViolation("an enum subset has at least one member")

    def to_node(self) -> NRec:
        return NRec(
            TAG_ENUM_SUBSET,
            (canonical_set(value.to_node() for value in self.allowed),),
        )


type AcquisitionRelation = ExactValue | ClosedLowerBound | ClosedUpperBound | EnumSubset


def relation_node(relation: AcquisitionRelation) -> Node:
    match relation:
        case ExactValue():
            return NTagged("ExactValue", relation.to_node())
        case ClosedLowerBound():
            return NTagged("ClosedLowerBound", relation.to_node())
        case ClosedUpperBound():
            return NTagged("ClosedUpperBound", relation.to_node())
        case EnumSubset():
            return NTagged("EnumSubset", relation.to_node())


class RelationFailure(Enum):
    """Every rejection is typed.  There is no "accept with reduced weight"."""

    UNIT_MISMATCH = "UnitMismatch"
    NON_NUMERIC_RELATION = "NonNumericRelation"
    INVALID_ENUM_SUBSET = "InvalidEnumSubset"
    VALUE_OUT_OF_DOMAIN = "ValueOutOfDomain"
    LAYER_FLOW_VIOLATION = "LayerFlowViolation"
    RELATION_VALUE_SORT_MISMATCH = "RelationValueSortMismatch"
    SOURCE_CLASS_NOT_PERMITTED_FOR_PREDICATE = "SourceClassNotPermittedForPredicate"


@dataclass(frozen=True, slots=True)
class RelationError:
    failure: RelationFailure
    detail: str


@dataclass(frozen=True, slots=True)
class PredicateInfo:
    """What relation validation is allowed to know about a predicate.

    ``permitted_source_classes`` is carried here deliberately.  A declared
    authority field that no function receives cannot be a control, and that is
    precisely how source authorization came to be self-declared: the field
    existed in the schema and nothing read it.
    """

    value_sort: Sort
    domain: Domain
    layer: EvidenceLayer
    permitted_source_classes: frozenset[str]


@dataclass(frozen=True, slots=True)
class LoweredFact:
    """The relation pinned the value exactly, so it becomes an established fact."""

    value: Value


@dataclass(frozen=True, slots=True)
class LoweredConstraint:
    """The relation narrowed the value, so it becomes a constraint on it."""

    formula: Term


@dataclass(frozen=True, slots=True)
class LoweredNonEffect:
    """The relation added nothing, and says so rather than leaving silence."""

    reason: str


type Lowering = LoweredFact | LoweredConstraint | LoweredNonEffect


def validate_relation(
    relation: AcquisitionRelation,
    declared_value_sort: Sort,
    info: PredicateInfo,
    source_class: str,
) -> Result[AcquisitionRelation, RelationError]:
    """Q-4 to Q-11, plus Q-12(a).

    Milestone A implements the bundle half of source authorization: the pinned
    predicate schema must permit this source class for this predicate.  The
    registry half -- that *this key* holds that class, for this tenant, this
    resource scope and this validity window -- is check Q-12(b) to (f), which
    needs the ratified ``AuthorityRegistrySnapshot`` and lands before milestone
    E.  Until then ``source_class`` selects which grant would have to exist; it
    does not prove one does.
    """
    #  Q-4: the payload's declared sort must be the schema's declared sort.
    if declared_value_sort != info.value_sort:
        return Err(
            RelationError(
                RelationFailure.UNIT_MISMATCH, f"{declared_value_sort} vs {info.value_sort}"
            )
        )

    #  Q-8: no relation may reach a normative variable, at any layer, from any
    #  source.  This is the barrier, checked before anything else about content.
    if info.layer is EvidenceLayer.NORMATIVE:
        return Err(RelationError(RelationFailure.LAYER_FLOW_VIOLATION, str(info.layer.value)))

    #  Q-12(a): the bundle must permit this class for this predicate.
    if source_class not in info.permitted_source_classes:
        return Err(
            RelationError(
                RelationFailure.SOURCE_CLASS_NOT_PERMITTED_FOR_PREDICATE,
                f"{source_class} not in {sorted(info.permitted_source_classes)}",
            )
        )

    match relation:
        case ExactValue(value):
            return _check_value(value, info, relation)
        case ClosedLowerBound(bound) | ClosedUpperBound(bound):
            #  Q-5: an ordering relation needs an ordered sort.
            if not isinstance(info.value_sort, IntSort | ScaledSort):
                return Err(
                    RelationError(RelationFailure.NON_NUMERIC_RELATION, str(info.value_sort))
                )
            return _check_value(bound, info, relation)
        case EnumSubset(allowed):
            #  Q-6: an enum subset needs an enum sort and declared members.
            if not isinstance(info.value_sort, EnumSort):
                return Err(RelationError(RelationFailure.INVALID_ENUM_SUBSET, str(info.value_sort)))
            for member in allowed:
                outcome = _check_value(member, info, relation)
                if isinstance(outcome, Err):
                    return outcome
            return Ok(relation)


def _check_value(
    value: Value, info: PredicateInfo, relation: AcquisitionRelation
) -> Result[AcquisitionRelation, RelationError]:
    #  Q-11: the relation *value's own* sort, not merely the declared one.  A
    #  lower bound carrying a scaled amount against an integer predicate passes
    #  Q-4 and rebuilds into an ill-typed comparison without this check.
    if sort_of(value) != info.value_sort:
        return Err(
            RelationError(
                RelationFailure.RELATION_VALUE_SORT_MISMATCH,
                f"{sort_of(value)} vs {info.value_sort}",
            )
        )
    #  Q-7: in the declared domain.
    if not value_in_domain(value, info.domain):
        return Err(RelationError(RelationFailure.VALUE_OUT_OF_DOMAIN, str(value)))
    return Ok(relation)


def lower_relation(relation: AcquisitionRelation, ref: SymbolRef, domain: Domain) -> Lowering:
    """The ordered lowering table.

    Rows are evaluated in order and are mutually exclusive; the ordering is the
    correction, not a detail.
    """
    match relation:
        #  Row 1: a subset covering the whole domain constrains nothing.  It
        #  must be checked before the single-member row, or a single-member
        #  domain matches two rows and lowers two different ways.
        case EnumSubset(allowed) if _covers_domain(allowed, domain):
            return LoweredNonEffect("VACUOUS_SUBSET")
        #  Row 2: exactly one member is an equality, never a unary disjunction.
        case EnumSubset(allowed) if len(allowed) == 1:
            return LoweredConstraint(Binary(BinaryOp.EQ, Leaf(ref), literal(allowed[0])))
        #  Row 3: two or more members, in declared order.
        case EnumSubset(allowed):
            return LoweredConstraint(
                NAry(
                    NAryOp.OR,
                    tuple(
                        Binary(BinaryOp.EQ, Leaf(ref), literal(member))
                        for member in _in_domain_order(allowed, domain)
                    ),
                )
            )
        #  Row 4: an exact value is the only relation that establishes a fact.
        case ExactValue(value):
            return LoweredFact(value)
        #  Row 5 and 6: closed bounds.
        case ClosedLowerBound(bound):
            return LoweredConstraint(Binary(BinaryOp.GE, Leaf(ref), literal(bound)))
        case ClosedUpperBound(bound):
            return LoweredConstraint(Binary(BinaryOp.LE, Leaf(ref), literal(bound)))


def _covers_domain(allowed: tuple[Value, ...], domain: Domain) -> bool:
    if not isinstance(domain, EnumDomain):
        return False
    members = {member.member for member in allowed if isinstance(member, VEnum)}
    return members == set(domain.members)


def _in_domain_order(allowed: tuple[Value, ...], domain: Domain) -> tuple[Value, ...]:
    if not isinstance(domain, EnumDomain):
        return allowed
    position = {member: index for index, member in enumerate(domain.members)}
    return tuple(sorted(allowed, key=lambda value: position.get(_member_of(value), len(position))))


def _member_of(value: Value) -> str:
    return value.member if isinstance(value, VEnum) else ""
