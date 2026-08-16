"""[A4] The Phase-1 acquisition relation algebra: validation and lowering.

NON-PRODUCTION SPECIFICATION MATERIAL.

Four relations, closed bounds only.  `|A| = 0` is unrepresentable (min_count 1),
not merely rejected.  The lowering table below is ORDERED and its rows are
mutually exclusive -- Phase 0.7's table had overlapping rows, so an EnumSubset
over a single-member domain matched both `|A| = 1` and `A = domain` and produced
two different byte sequences from one signed payload.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hinge import T, node_to_val
from .nodes import Atom, Node, Rec, Seq, SetV, Tagged, encode


class RelationError(Exception):
    pass


class UnitMismatch(RelationError):
    pass


class NonNumericRelation(RelationError):
    pass


class InvalidEnumSubset(RelationError):
    pass


class ValueOutOfDomain(RelationError):
    pass


class LayerFlowViolation(RelationError):
    pass


class RelationValueSortMismatch(RelationError):
    pass


def sort_of_value(value: Node) -> Node:
    """The sort a Value denotes.  Total over the Value union."""
    assert isinstance(value, Tagged)
    if value.variant == "VBool":
        return Tagged("Bool", __import__("muster_spec.nodes", fromlist=["Unit"]).Unit())
    if value.variant == "VInt":
        return Tagged("Int", __import__("muster_spec.nodes", fromlist=["Unit"]).Unit())
    if value.variant == "VScaled":
        assert isinstance(value.value, Rec)
        unit, scale, _minor = value.value.fields
        return Tagged("Scaled", Rec("ScaledSort/v1", [unit, scale]))
    if value.variant == "VEnum":
        assert isinstance(value.value, Rec)
        enum_id, _member = value.value.fields
        return Tagged("Enum", Rec("EnumSort/v1", [enum_id]))
    raise RelationError(f"unknown Value variant {value.variant!r}")


def domain_members(domain: Node) -> list[str]:
    assert isinstance(domain, Tagged) and domain.variant == "EnumDomain"
    assert isinstance(domain.value, Rec)
    members = domain.value.fields[0]
    assert isinstance(members, Seq)
    return [m.value for m in members.items]  # type: ignore[union-attr]


def in_domain(value: Node, domain: Node) -> bool:
    assert isinstance(value, Tagged) and isinstance(domain, Tagged)
    if domain.variant == "BoolDomain":
        return value.variant == "VBool"
    if domain.variant == "IntRange":
        assert isinstance(domain.value, Rec)
        lo, hi = domain.value.fields
        return value.variant == "VInt" and lo.value <= value.value.value <= hi.value  # type: ignore[union-attr]
    if domain.variant == "ScaledRange":
        assert isinstance(domain.value, Rec) and isinstance(value.value, Rec)
        lo, hi = domain.value.fields
        return value.variant == "VScaled" and lo.value <= value.value.fields[2].value <= hi.value  # type: ignore[union-attr]
    if domain.variant == "EnumDomain":
        if value.variant != "VEnum":
            return False
        assert isinstance(value.value, Rec)
        return value.value.fields[1].value in domain_members(domain)  # type: ignore[union-attr]
    raise RelationError(f"unknown Domain variant {domain.variant!r}")


@dataclass(frozen=True, slots=True)
class PredicateInfo:
    value_sort: Node
    domain: Node
    layer: str


def validate_relation(relation: Node, declared_value_sort: Node, info: PredicateInfo) -> None:
    """Q-4 .. Q-11.  Q-11 is the check Phase 0.7 omitted."""
    assert isinstance(relation, Tagged)

    # Q-8: an attested relation may never touch a NORMATIVE instance.
    if info.layer == "NORMATIVE":
        raise LayerFlowViolation("attested relation on a NORMATIVE predicate")

    # Q-4: the signer's declared sort must equal the schema's.
    if encode(declared_value_sort) != encode(info.value_sort):
        raise UnitMismatch(
            f"payload value_sort {declared_value_sort} != schema {info.value_sort}"
        )

    body = relation.value
    assert isinstance(body, Rec)

    if relation.variant in ("ClosedLowerBound", "ClosedUpperBound"):
        # Q-5: bounds are numeric only.
        if info.value_sort.variant not in ("Int", "Scaled"):  # type: ignore[union-attr]
            raise NonNumericRelation(f"{relation.variant} on a {info.value_sort.variant} sort")  # type: ignore[union-attr]
        bound = body.fields[0]
        # Q-11: THE BOUND VALUE'S OWN SORT.  Without this,
        # ClosedLowerBound(VScaled("INR",2,99)) passes Q-4 against `Int q` and
        # rebuilds into the ill-typed term Ge(Var(q: Int), Lit(Scaled)).
        if encode(sort_of_value(bound)) != encode(info.value_sort):
            raise RelationValueSortMismatch(
                f"bound sort {sort_of_value(bound)} != predicate sort {info.value_sort}"
            )
        if not in_domain(bound, info.domain):
            raise ValueOutOfDomain(f"bound outside the declared domain")
        return

    if relation.variant == "ExactValue":
        value = body.fields[0]
        if encode(sort_of_value(value)) != encode(info.value_sort):
            raise RelationValueSortMismatch("ExactValue sort does not match the predicate")
        if not in_domain(value, info.domain):  # Q-7
            raise ValueOutOfDomain("ExactValue outside the declared domain")
        return

    if relation.variant == "EnumSubset":
        if info.value_sort.variant != "Enum":  # type: ignore[union-attr]
            raise InvalidEnumSubset("EnumSubset on a non-enum predicate")
        allowed = body.fields[0]
        assert isinstance(allowed, SetV)
        if not allowed.items:  # unreachable: min_count 1
            raise InvalidEnumSubset("empty subset")
        members = domain_members(info.domain)
        for v in allowed.items:
            if encode(sort_of_value(v)) != encode(info.value_sort):
                raise RelationValueSortMismatch("EnumSubset member sort mismatch")
            assert isinstance(v, Tagged) and isinstance(v.value, Rec)
            if v.value.fields[1].value not in members:  # type: ignore[union-attr]
                raise InvalidEnumSubset(f"member outside the declared domain")
        return

    raise RelationError(f"unknown relation {relation.variant!r}")


def lower_relation(relation: Node, ref: Node, info: PredicateInfo) -> tuple[str, object]:
    """Deterministic reconstruction.  The caller chooses nothing.

    Row order is significant and the rows are mutually exclusive:

        1. EnumSubset with A = domain      -> no constraint, NonEffect(VACUOUS_SUBSET)
        2. EnumSubset with |A| = 1         -> Eq            (never a unary Or)
        3. EnumSubset otherwise            -> Or, arity >= 2, in declaration order
        4. ExactValue                      -> EstablishedFact
        5. ClosedLowerBound                -> Ge
        6. ClosedUpperBound                -> Le

    Row 1 precedes row 2 deliberately.  Over a single-member domain both rows are
    logically equivalent -- the domain assertion already pins the value -- so only
    determinism is at stake, and "full domain wins" is the rule that has no
    overlap with anything.
    """
    assert isinstance(relation, Tagged)
    body = relation.value
    assert isinstance(body, Rec)

    if relation.variant == "EnumSubset":
        allowed = body.fields[0]
        assert isinstance(allowed, SetV)
        members = domain_members(info.domain)
        chosen = [v.value.fields[1].value for v in allowed.items]  # type: ignore[union-attr]

        if set(chosen) == set(members):  # row 1
            return "noneffect", "VACUOUS_SUBSET"
        if len(chosen) == 1:  # row 2
            return "constraint", T.eq(T.var(ref), T.lit(node_to_val(allowed.items[0])))
        ordered = [m for m in members if m in set(chosen)]  # row 3, declaration order
        enum_id = info.value_sort.value.fields[0].value  # type: ignore[union-attr]
        return "constraint", T.or_(
            *[T.eq(T.var(ref), T.lit(("enum", enum_id, m))) for m in ordered]
        )

    if relation.variant == "ExactValue":  # row 4
        return "fact", node_to_val(body.fields[0])
    if relation.variant == "ClosedLowerBound":  # row 5
        return "constraint", T.ge(T.var(ref), T.lit(node_to_val(body.fields[0])))
    if relation.variant == "ClosedUpperBound":  # row 6
        return "constraint", T.le(T.var(ref), T.lit(node_to_val(body.fields[0])))
    raise RelationError(f"unknown relation {relation.variant!r}")
