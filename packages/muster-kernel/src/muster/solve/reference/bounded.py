"""A bounded reference backend: enumeration over the decoded query.

This backend reads the query and nothing else.  It does not know that ``(L, q)``
and ``(R, q)`` are related, it has never heard of a case, and it has no access
to the policy that produced the assertions.  That ignorance is the point: a
query representation that collapsed the two worlds, or failed to tie them
together, shows up here as disagreement with the case-level reference semantics
rather than as a plausible wrong answer.

It is a **reference oracle**, not evidence that a general port is substitutable.
It requires finite domains and a budget, and it says so in its capabilities.

Three preprocessing steps make the enumeration affordable without weakening it:

* **Unit pinning.**  A top-level ``v = literal`` conjunct fixes ``v``.  Exact.
* **Equality merging.**  A top-level ``a = b`` conjunct makes ``a`` and ``b`` one
  enumerated slot.  Exact, and it is what removes the cross-world equalities
  that would otherwise force full enumeration of both sides.
* **Threshold classes.**  A variable that occurs *only* inside comparisons
  against literals is enumerated over one representative per equivalence class
  those literals induce, plus the domain endpoints.  Every atom mentioning the
  variable has the same truth value throughout a class, so a satisfying
  assignment exists in the abstraction exactly when one exists in the domain.
  A variable occurring anywhere else is enumerated over its whole domain.

Soundness needs no argument in the ``Sat`` direction: candidate assignments are
real in-domain values and every assertion is *evaluated* against them, so a
model returned here satisfies the query as written.  The three steps exist to
preserve completeness, which is the direction that would otherwise be dangerous
-- a missed model would be reported as invariance.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from itertools import product

from muster.core.expr.evaluate import evaluate_bool
from muster.core.expr.ir import (
    Binary,
    BinaryOp,
    EnumTable,
    Ite,
    Leaf,
    LitBool,
    LitEnum,
    LitInt,
    LitScaled,
    MulConst,
    NAry,
    NAryOp,
    Neg,
    Not,
    Rescale,
    Scale,
)
from muster.core.results import Err
from muster.core.values.fingerprint import SolverFingerprint
from muster.core.values.scalars import (
    Value,
    VBool,
    VEnum,
    VInt,
    VScaled,
    enumerate_domain,
    value_in_domain,
)
from muster.core.values.sorts import (
    BoolDomain,
    Domain,
    EnumDomain,
    IntRange,
    ScaledRange,
    ScaledSort,
    Sort,
    domain_cardinality,
    domain_is_finite,
)
from muster.core.wire.codec import encode
from muster.solve.query import LabeledAssertion, QTerm, QueryVar, SolverQuery
from muster.solve.verdict import (
    FragmentCapabilities,
    Sat,
    SolverModel,
    SolverVerdict,
    Unknown,
    UnknownReason,
    Unsat,
    UnsupportedFragment,
)

BACKEND_NAME = "reference-bounded"
BACKEND_VERSION = "1"
BACKEND_LOGIC = "QF_FINITE_ENUMERATION"

_COMPARISONS = frozenset(
    {BinaryOp.EQ, BinaryOp.NE, BinaryOp.LT, BinaryOp.LE, BinaryOp.GT, BinaryOp.GE}
)

#  Labels a certificate may repeat.  Internal encoding labels are query-scoped
#  and never leave the backend.
_SOURCE_LABEL_PREFIX = "C:"


@dataclass(frozen=True, slots=True)
class _Occurrences:
    """Where a variable appears, which decides how it must be enumerated."""

    thresholds: dict[QueryVar, set[Value]]
    opaque: set[QueryVar]


class BoundedEnumerationBackend:
    """Enumerates finite domains under a declared budget."""

    def __init__(self, max_enumerated_assignments: int) -> None:
        if max_enumerated_assignments < 1:
            raise ValueError("the enumeration budget must be at least one assignment")
        self._budget = max_enumerated_assignments

    def capabilities(self) -> FragmentCapabilities:
        return FragmentCapabilities(
            backend=BACKEND_NAME,
            version=BACKEND_VERSION,
            requires_finite_domains=True,
            max_enumerated_assignments=self._budget,
        )

    def fingerprint(self) -> SolverFingerprint:
        return SolverFingerprint(
            backend=BACKEND_NAME,
            version=BACKEND_VERSION,
            seed=0,
            logic=BACKEND_LOGIC,
            budget=self._budget,
        )

    def check(self, query: SolverQuery) -> SolverVerdict:
        declared = {decl.var(): decl for decl in query.declarations}
        for decl in query.declarations:
            if not domain_is_finite(decl.domain):
                return UnsupportedFragment(f"{decl.ref} has an unbounded domain")

        conjuncts = tuple(_flatten(assertion.formula) for assertion in query.assertions)
        flat: list[QTerm] = [term for group in conjuncts for term in group]

        classes = _merge_equalities(flat, set(declared))
        pins = _unit_pins(flat, classes)
        if pins is None:
            return Unsat(_source_labels(query.assertions))
        for var, value in pins.items():
            decl = declared[var]
            if not value_in_domain(value, decl.domain):
                return Unsat(_source_labels(query.assertions))

        residual = [
            term
            for term in flat
            if not _is_unit_pin(term, set(declared))
            and not _is_variable_equality(term, set(declared))
        ]
        occurrences = _analyse(residual)

        slots: list[tuple[tuple[QueryVar, ...], tuple[Value, ...]]] = []
        assignments = 1
        for members in _class_members(classes, pins):
            representative = members[0]
            decl = declared[representative]
            candidates = _candidates(decl.sort, decl.domain, members, occurrences, self._budget)
            if candidates is None:
                return Unknown(UnknownReason.BUDGET_EXHAUSTED, str(representative))
            slots.append((members, candidates))
            assignments *= len(candidates)
            if assignments > self._budget:
                return Unknown(UnknownReason.BUDGET_EXHAUSTED, f"{assignments} assignments")

        for combination in _enumerate(slots):
            model: SolverModel = dict(pins)
            for members, value in combination:
                for member in members:
                    model[member] = value
            satisfied = _satisfies(query.assertions, model)
            if satisfied is None:
                return Unknown(UnknownReason.BACKEND_FAILURE, "assertion did not evaluate")
            if satisfied:
                return Sat(model)

        return Unsat(_source_labels(query.assertions))


def _satisfies(assertions: Iterable[LabeledAssertion], model: SolverModel) -> bool | None:
    for assertion in assertions:
        outcome = evaluate_bool(assertion.formula, model)
        if isinstance(outcome, Err):
            return None
        if not outcome.value:
            return False
    return True


def _source_labels(assertions: Iterable[LabeledAssertion]) -> tuple[str, ...]:
    """Every source constraint present in the query.

    Deliberately not called a core: this backend does not compute one, and a
    non-minimal contributing set that says so is better than a minimal-looking
    one that is not.
    """
    return tuple(
        sorted(
            assertion.label
            for assertion in assertions
            if assertion.label.startswith(_SOURCE_LABEL_PREFIX)
        )
    )


def _flatten(term: QTerm) -> tuple[QTerm, ...]:
    if isinstance(term, NAry) and term.op is NAryOp.AND:
        return tuple(part for operand in term.operands for part in _flatten(operand))
    return (term,)


def _literal_value(term: QTerm) -> Value | None:
    match term:
        case LitBool(flag):
            return VBool(flag)
        case LitInt(number):
            return VInt(number)
        case LitScaled(value):
            return value
        case LitEnum(value):
            return value
        case _:
            return None


def _is_unit_pin(term: QTerm, declared: set[QueryVar]) -> bool:
    return _unit_pin(term, declared) is not None


def _unit_pin(term: QTerm, declared: set[QueryVar]) -> tuple[QueryVar, Value] | None:
    if not isinstance(term, Binary) or term.op is not BinaryOp.EQ:
        return None
    for side, other in ((term.left, term.right), (term.right, term.left)):
        if isinstance(side, Leaf) and side.ref in declared:
            value = _literal_value(other)
            if value is not None:
                return side.ref, value
    return None


def _is_variable_equality(term: QTerm, declared: set[QueryVar]) -> bool:
    return _variable_equality(term, declared) is not None


def _variable_equality(term: QTerm, declared: set[QueryVar]) -> tuple[QueryVar, QueryVar] | None:
    if not isinstance(term, Binary) or term.op is not BinaryOp.EQ:
        return None
    if (
        isinstance(term.left, Leaf)
        and isinstance(term.right, Leaf)
        and term.left.ref in declared
        and term.right.ref in declared
    ):
        return term.left.ref, term.right.ref
    return None


def _merge_equalities(flat: list[QTerm], declared: set[QueryVar]) -> dict[QueryVar, QueryVar]:
    """Union-find over variables an equality identifies.

    Exact rather than approximate: equality on a domain is a bijection, so two
    identified variables are one enumerated slot with no loss.
    """
    parent: dict[QueryVar, QueryVar] = {var: var for var in declared}

    def find(var: QueryVar) -> QueryVar:
        while parent[var] != var:
            parent[var] = parent[parent[var]]
            var = parent[var]
        return var

    for term in flat:
        pair = _variable_equality(term, declared)
        if pair is None:
            continue
        left, right = find(pair[0]), find(pair[1])
        if left != right:
            #  Canonical representative, so the merge order cannot change the
            #  enumeration order and therefore cannot change which model is
            #  returned first.
            low, high = sorted((left, right), key=lambda var: encode(var.to_node()))
            parent[high] = low

    return {var: find(var) for var in declared}


def _unit_pins(
    flat: list[QTerm], classes: dict[QueryVar, QueryVar]
) -> dict[QueryVar, Value] | None:
    """Fixed values, propagated across merged classes. ``None`` means conflict."""
    declared = set(classes)
    by_class: dict[QueryVar, Value] = {}
    for term in flat:
        pin = _unit_pin(term, declared)
        if pin is None:
            continue
        var, value = pin
        root = classes[var]
        existing = by_class.get(root)
        if existing is not None and existing != value:
            return None
        by_class[root] = value
    return {var: by_class[root] for var, root in classes.items() if root in by_class}


def _class_members(
    classes: dict[QueryVar, QueryVar], pins: dict[QueryVar, Value]
) -> list[tuple[QueryVar, ...]]:
    grouped: dict[QueryVar, list[QueryVar]] = {}
    for var, root in classes.items():
        if var in pins:
            continue
        grouped.setdefault(root, []).append(var)
    ordered = sorted(grouped.items(), key=lambda item: encode(item[0].to_node()))
    return [tuple(sorted(members, key=lambda var: encode(var.to_node()))) for _, members in ordered]


def _analyse(residual: list[QTerm]) -> _Occurrences:
    occurrences = _Occurrences(thresholds={}, opaque=set())
    for term in residual:
        _walk(term, occurrences)
    return occurrences


def _walk(term: QTerm, occurrences: _Occurrences) -> None:
    match term:
        case Binary(op, left, right) if op in _COMPARISONS:
            if _record_threshold(left, right, occurrences) or _record_threshold(
                right, left, occurrences
            ):
                return
            _walk(left, occurrences)
            _walk(right, occurrences)
        case Leaf(ref):
            #  A bare occurrence outside a literal comparison: the abstraction
            #  cannot see what the value is used for, so the whole domain is
            #  enumerated.
            occurrences.opaque.add(ref)
        case LitBool() | LitInt() | LitScaled() | LitEnum():
            return
        case Not(operand) | Neg(operand) | MulConst(_, operand) | Rescale(operand, _):
            _walk(operand, occurrences)
        case Scale(operand, _, _):
            _walk(operand, occurrences)
        case NAry(_, operands):
            for operand in operands:
                _walk(operand, occurrences)
        case Binary(_, left, right):
            _walk(left, occurrences)
            _walk(right, occurrences)
        case Ite(cond, if_true, if_false):
            _walk(cond, occurrences)
            _walk(if_true, occurrences)
            _walk(if_false, occurrences)
        case EnumTable(scrutinee, arms):
            _walk(scrutinee, occurrences)
            for arm in arms:
                _walk(arm.term, occurrences)


def _record_threshold(candidate: QTerm, other: QTerm, occurrences: _Occurrences) -> bool:
    if not isinstance(candidate, Leaf):
        return False
    value = _literal_value(other)
    if value is None:
        return False
    occurrences.thresholds.setdefault(candidate.ref, set()).add(value)
    return True


def _candidates(
    sort: Sort,
    domain: Domain,
    members: tuple[QueryVar, ...],
    occurrences: _Occurrences,
    budget: int,
) -> tuple[Value, ...] | None:
    """Values to try for one enumerated slot, in ascending canonical order."""
    match domain:
        case BoolDomain() | EnumDomain():
            return enumerate_domain(sort, domain)
        case IntRange(lo, hi) | ScaledRange(lo, hi):
            opaque = any(member in occurrences.opaque for member in members)
            thresholds: set[Value] = set()
            for member in members:
                thresholds |= occurrences.thresholds.get(member, set())
            if not opaque:
                return _threshold_representatives(sort, lo, hi, thresholds)
            #  The variable is used somewhere the abstraction cannot see, so the
            #  whole domain is enumerated -- or refused, never approximated.
            if domain_cardinality(domain) > budget:
                return None
            return enumerate_domain(sort, domain)


def _threshold_representatives(
    sort: Sort, lo: int, hi: int, thresholds: set[Value]
) -> tuple[Value, ...]:
    """One value per equivalence class the thresholds induce, plus endpoints.

    Every atom mentioning the variable is a comparison against one of these
    thresholds, so its truth value is constant within a class; taking the
    endpoints as well covers the classes below the smallest and above the
    largest threshold.
    """
    points: set[int] = {lo, hi}
    for value in thresholds:
        magnitude = _magnitude(value)
        if magnitude is None:
            continue
        points.update({magnitude - 1, magnitude, magnitude + 1})
    inside = sorted(point for point in points if lo <= point <= hi)
    unit_tag, scale = (sort.unit_tag, sort.scale) if isinstance(sort, ScaledSort) else ("", 0)
    if isinstance(sort, ScaledSort):
        return tuple(VScaled(unit_tag, scale, point) for point in inside)
    return tuple(VInt(point) for point in inside)


def _magnitude(value: Value) -> int | None:
    match value:
        case VInt(number):
            return number
        case VScaled(_, _, minor):
            return minor
        case VBool() | VEnum():
            return None


def _enumerate(
    slots: list[tuple[tuple[QueryVar, ...], tuple[Value, ...]]],
) -> Iterator[tuple[tuple[tuple[QueryVar, ...], Value], ...]]:
    """Cartesian product in a fixed order, so the first model found is stable."""
    if not slots:
        yield ()
        return
    members = [slot[0] for slot in slots]
    for combination in product(*(slot[1] for slot in slots)):
        yield tuple(zip(members, combination, strict=True))
