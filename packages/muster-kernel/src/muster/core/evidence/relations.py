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

from muster.core.authority.check import (
    AuthorityError,
    AuthorityView,
    SourceClaim,
    check_authority,
    required_coordinates,
)
from muster.core.expr.ir import Binary, BinaryOp, Leaf, NAry, NAryOp
from muster.core.expr.terms import Term, literal
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.classification import EvidenceLayer
from muster.core.values.scalars import Value, VEnum, read_value, sort_of, value_in_domain
from muster.core.values.sorts import Domain, EnumDomain, EnumSort, IntSort, ScaledSort, Sort
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import canonical_set
from muster.core.wire.nodes import Node, NRec, NTagged
from muster.core.wire.shape import (
    WireError,
    WireFailure,
    decoded,
    fail,
    read_rec,
    read_set,
    read_tagged,
)

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


def read_relation(node: Node) -> AcquisitionRelation:
    """The inverse of :func:`relation_node`, over one canonical node."""
    tag, payload = read_tagged(node, "AcquisitionRelation")
    match tag:
        case "ExactValue":
            (value,) = read_rec(payload, TAG_EXACT_VALUE, 1)
            return ExactValue(read_value(value))
        case "ClosedLowerBound":
            (bound,) = read_rec(payload, TAG_CLOSED_LOWER, 1)
            return ClosedLowerBound(read_value(bound))
        case "ClosedUpperBound":
            (bound,) = read_rec(payload, TAG_CLOSED_UPPER, 1)
            return ClosedUpperBound(read_value(bound))
        case "EnumSubset":
            (allowed,) = read_rec(payload, TAG_ENUM_SUBSET, 1)
            return EnumSubset(read_set(allowed, read_value, minimum=1))
        case _:
            raise fail(WireFailure.UNKNOWN_VARIANT, "AcquisitionRelation", tag)


def decode_relation(node: Node) -> Result[AcquisitionRelation, WireError]:
    return decoded(lambda: read_relation(node))


class RelationFailure(Enum):
    """Every rejection is typed.  There is no "accept with reduced weight"."""

    UNIT_MISMATCH = "UnitMismatch"
    NON_NUMERIC_RELATION = "NonNumericRelation"
    INVALID_ENUM_SUBSET = "InvalidEnumSubset"
    VALUE_OUT_OF_DOMAIN = "ValueOutOfDomain"
    LAYER_FLOW_VIOLATION = "LayerFlowViolation"
    RELATION_VALUE_SORT_MISMATCH = "RelationValueSortMismatch"


@dataclass(frozen=True, slots=True)
class RelationError:
    failure: RelationFailure
    detail: str


#  Q-12's rejections are *not* restated here.  Source authorization owns its
#  own failure vocabulary in :mod:`muster.core.authority.check`, and validation
#  returns whichever of the two refused -- so there is exactly one definition
#  of "the predicate is not granted to this key", and no chance of a second
#  copy drifting from it.
type ValidationError = RelationError | AuthorityError


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
    #  Q-12(d) resolves the resource coordinates a proposition ranges over from
    #  these two, both of which come from inside the signed bundle: the kinds
    #  authority over this predicate is scoped by, and the argument kinds that
    #  may supply their values.  A coordinate derived from anything the source
    #  supplied would let the source choose which grant it needed.
    arg_kinds: tuple[str, ...]
    resource_scope_kinds: tuple[str, ...]


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
    claim: SourceClaim,
    authority: AuthorityView,
) -> Result[AcquisitionRelation, ValidationError]:
    """Q-12(a) to (f), then Q-4 to Q-8, then Q-11 -- in that ratified order.

    The order is the specification, not an implementation detail: the first
    failure is the reported one, so two conforming implementations return the
    same rejection rather than merely *a* rejection.

    **Authority precedes content.**  An unauthorized source's payload should
    never have its content evaluated at all -- not because evaluating it would
    be unsafe, but because a rejection that named a unit mismatch would tell a
    key with no grant that its units were the problem, and a system that
    negotiates with an unauthorized source is one that has already started
    trusting it.  The consequence is deliberate and worth stating: an
    attestation that is *both* unauthorized and aimed at a normative variable
    is refused on authority, not on the layer barrier.  The barrier is not
    weakened -- an authorized source aimed at a normative variable still fails
    Q-8 below, and nothing reaches a normative variable by either path -- but
    the reason recorded is the first one that applied.

    ``claim`` and ``authority`` are separate arguments on purpose.  The claim
    is per receipt and every field in it is signer-supplied; the view is per
    rebuild and no field in it is.  Folding one into the other would rebuild
    the pinned authority state once per receipt and would blur the line the
    whole check exists to draw.
    """
    #  Q-12(a) to (f).  The pinned bundle must permit this class for this
    #  predicate, and the pinned snapshot must grant *this key* that class, for
    #  this tenant, over this resource, for this predicate, in force at the
    #  revision's ``as_of``, unrevoked, under the pinned policy version.
    authorized = check_authority(
        claim,
        info.permitted_source_classes,
        required_coordinates(
            claim.proposition,
            info.arg_kinds,
            info.resource_scope_kinds,
            authority.case_scope_coordinates,
        ),
        authority,
    )
    if isinstance(authorized, Err):
        return Err(authorized.error)

    #  Q-4: the payload's declared sort must be the schema's declared sort.
    if declared_value_sort != info.value_sort:
        return Err(
            RelationError(
                RelationFailure.UNIT_MISMATCH, f"{declared_value_sort} vs {info.value_sort}"
            )
        )

    #  Q-8: no relation may reach a normative variable, at any layer, from any
    #  source -- including one holding a grant for it, which is why this is
    #  checked after authority rather than instead of it.
    if info.layer is EvidenceLayer.NORMATIVE:
        return Err(RelationError(RelationFailure.LAYER_FLOW_VIOLATION, str(info.layer.value)))

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
) -> Result[AcquisitionRelation, ValidationError]:
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
