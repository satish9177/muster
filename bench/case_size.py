"""The |U| benchmark that fixes the G5 case-size admission cap.

The architecture makes the cap mandatory and configurable in milestone A and
says the *number* comes from here: "a number invented now would be either
theatre or an outage".  So this measures, and the cap is read off what it
measured.

What is being measured, and why it is the right thing to measure
----------------------------------------------------------------

The decision path issues a query per question, and the count is a function of
``|U|``:

    1 feasibility
  + 1 invariance
  + (reachable enumeration, bounded by ``reachable_action_cap`` + 1)
  + |U| necessity            -- Sufficient(U \\ {v}) for each v
  + 1 sufficiency over the acquirable candidates
  + |U| deletion             -- greedy minimisation of that candidate set

so roughly ``2|U| + c`` queries, each of which is *itself* superlinear in the
case size.  Wall time is therefore the honest measure and query count is the
honest explanation, and both are recorded.

Every case is deterministic and every case is built the same way at every size,
so the only thing that varies across a row is ``|U|``.  Six families, because
one shape would fix a cap for one shape:

``independent``   |U| booleans, each contributing to a sum. The easy direction.
``correlated``    the action needs a conjunction, so no single variable is
                  necessary and the whole deletion pass runs to the end.
``threshold``     wide integer domains compared only against literals -- the
                  bounded backend's threshold abstraction applies.
``opaque``        wide integer domains used inside arithmetic, so the
                  abstraction cannot apply and the backend must enumerate or
                  refuse. This is the family that finds the refusal point.
``enum``          enum-sorted variables and a table per variable.
``ravi``          the workforce shape: a definitional constraint per day, a
                  guarded sum, and the same all-subsets planning the real case
                  runs.

Run it::

    python bench/case_size.py --out bench/results

It writes ``case-size.json`` (every sample) and ``case-size.md`` (the table
that goes in the architecture document).  Nothing here is imported by
production code or by the test suite: it is a measuring instrument, and it
lives outside ``packages/`` so that it cannot become one by accident.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "packages" / "muster-kernel" / "src"))

import z3  # noqa: E402  -- reported in the environment block, nowhere else

from muster.core.actions import (  # noqa: E402
    ActionKindSpec,
    ActionSchema,
    Consequentiality,
    FieldSpec,
)
from muster.core.analysis.logical_case import LogicalCase  # noqa: E402
from muster.core.analysis.outcomes import (  # noqa: E402
    Divergent,
    Indeterminate,
    Infeasible,
    Invariant,
)
from muster.core.case.constraints import Constraint, StructuralDeriv  # noqa: E402
from muster.core.case.facts import AttestedBy, EstablishedFact  # noqa: E402
from muster.core.evidence.requests import EvidenceTarget  # noqa: E402
from muster.core.expr.ir import (  # noqa: E402
    Arm,
    Binary,
    BinaryOp,
    EnumTable,
    Ite,
    Leaf,
    LitEnum,
    LitInt,
    LitScaled,
    NAry,
    NAryOp,
)
from muster.core.expr.terms import Term  # noqa: E402
from muster.core.values.classification import AcquisitionClass  # noqa: E402
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled  # noqa: E402
from muster.core.values.sorts import (  # noqa: E402
    BoolDomain,
    BoolSort,
    Domain,
    EnumDomain,
    EnumSort,
    IntRange,
    IntSort,
    ScaledRange,
    ScaledSort,
    Sort,
)
from muster.core.values.symbols import SymbolRef  # noqa: E402
from muster.core.wire.codec import canonical_order  # noqa: E402
from muster.core.wire.digests import Digest  # noqa: E402
from muster.evidence.planning import plan_evidence  # noqa: E402
from muster.hinge.analyze import analyze  # noqa: E402
from muster.hinge.oracle import Oracle  # noqa: E402
from muster.hinge.prepare import EngineLimits  # noqa: E402
from muster.hinge.project import ProjectedCase, SymbolDeclaration  # noqa: E402
from muster.policy.program import ActionTerm, DecisionProgram, FieldTerm, ProgramRule  # noqa: E402
from muster.solve.query import SolverQuery  # noqa: E402
from muster.solve.reference.bounded import BoundedEnumerationBackend  # noqa: E402
from muster.solve.verdict import (  # noqa: E402
    FragmentCapabilities,
    SolverVerdict,
    Unknown,
    UnknownReason,
    UnsupportedFragment,
)
from muster.solve.z3.backend import Z3Backend  # noqa: E402

PLACEHOLDER = Digest(bytes(32))

CURRENCY = "INR"
CURRENCY_SCALE = 2
MONEY = ScaledSort(CURRENCY, CURRENCY_SCALE)

ACTION_PAY = "PAY"
ACTION_HOLD = "HOLD"
FIELD_AMOUNT = "amount"
FIELD_REASON = "reason"
ENUM_HOLD = "hold_reason"
HOLD_REASONS: tuple[str, ...] = ("REVIEW", "BLOCKED")
ENUM_COLOUR = "colour"
COLOURS: tuple[str, ...] = ("RED", "GREEN", "BLUE")

#  The engine limits the benchmark runs under.  ``max_unresolved`` is set out of
#  the way on purpose: this run is measuring where the cap should be, so it must
#  not be gated by whatever the cap is today.
BENCH_LIMITS = EngineLimits(max_unresolved=4096, reachable_action_cap=64)
ENUMERATION_BUDGET = 200_000

#  A single decision above this is already far past anything an interactive
#  answer can spend, so it is *abandoned* rather than measured and the family
#  stops growing.  Abandoning is not a timeout bolted on from outside: the
#  budget is spent by the wrapped backend, which starts returning the engine's
#  own ``BUDGET_EXHAUSTED`` once it is gone.  The run therefore unwinds through
#  the same fail-closed path a real resource limit would take -- ``Indeterminate``
#  or ``NotComputed``, never a partial answer -- and the row that records it is
#  a lower bound rather than a number.
RUN_BUDGET_SECONDS = 20.0

#  Every size through 8, then widening.  The cap turns out to sit in the low
#  single digits on the reference backend, and a grid that stepped in twos
#  there would have read it off a resolution coarser than the answer.
SIZES: tuple[int, ...] = (1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32)


def money(minor: int) -> VScaled:
    return VScaled(CURRENCY, CURRENCY_SCALE, minor)


def schema() -> ActionSchema:
    return ActionSchema(
        schema_id="bench-actions",
        schema_version=1,
        kinds=(
            ActionKindSpec(
                kind=ACTION_PAY,
                fields=(
                    FieldSpec(
                        name=FIELD_AMOUNT,
                        sort=MONEY,
                        bounds=ScaledRange(0, 100_000_000),
                        consequentiality=Consequentiality.CONSEQUENTIAL,
                        required=True,
                    ),
                ),
            ),
            ActionKindSpec(
                kind=ACTION_HOLD,
                fields=(
                    FieldSpec(
                        name=FIELD_REASON,
                        sort=EnumSort(ENUM_HOLD),
                        bounds=EnumDomain(HOLD_REASONS),
                        consequentiality=Consequentiality.CONSEQUENTIAL,
                        required=True,
                    ),
                ),
            ),
        ),
    )


SCHEMA = schema()


def pay(amount: Term) -> ActionTerm:
    return ActionTerm(ACTION_PAY, (FieldTerm(FIELD_AMOUNT, amount),))


def hold(reason: str) -> ActionTerm:
    return ActionTerm(ACTION_HOLD, (FieldTerm(FIELD_REASON, LitEnum(VEnum(ENUM_HOLD, reason))),))


def closed(rules: tuple[ProgramRule, ...], otherwise: ActionTerm) -> DecisionProgram:
    draft = DecisionProgram(inputs=(), rules=rules, otherwise=otherwise)
    return DecisionProgram(
        inputs=canonical_order(draft.free_symbols(), lambda ref: ref.to_node()),
        rules=rules,
        otherwise=otherwise,
    )


def build_case(
    *,
    declarations: dict[SymbolRef, tuple[Sort, Domain]],
    constraints: tuple[tuple[str, Term], ...],
    program: DecisionProgram,
    known: dict[SymbolRef, Value] | None = None,
) -> ProjectedCase:
    declared = canonical_order(
        (SymbolDeclaration(ref, sort, domain) for ref, (sort, domain) in declarations.items()),
        lambda declaration: declaration.ref.to_node(),
    )
    formulas = canonical_order(
        (
            Constraint(label, formula, StructuralDeriv(PLACEHOLDER))
            for label, formula in constraints
        ),
        lambda constraint: constraint.to_node(),
    )
    facts = canonical_order(
        (
            EstablishedFact(ref, value, AttestedBy(PLACEHOLDER))
            for ref, value in (known or {}).items()
        ),
        lambda fact: fact.to_node(),
    )
    logical = LogicalCase(
        universe=canonical_order(declarations, lambda ref: ref.to_node()),
        known=facts,
        constraints=formulas,
        decision_program_digest=program.digest(),
        action_schema_digest=SCHEMA.digest(),
        predicate_schema_digest=PLACEHOLDER,
    )
    return ProjectedCase(logical, declared, program, SCHEMA)


#  ---- the six families ----------------------------------------------------


def flag(index: int) -> SymbolRef:
    return SymbolRef("flag", (f"{index:03d}",))


def count(index: int) -> SymbolRef:
    return SymbolRef("count", (f"{index:03d}",))


def tint(index: int) -> SymbolRef:
    return SymbolRef("tint", (f"{index:03d}",))


def independent(size: int) -> ProjectedCase:
    """|U| booleans, each contributing to the amount. Every one is necessary.

    The contributions are small and distinct rather than powers of two.  Powers
    of two make every subset a distinct amount, which is a nicer property and a
    useless one here: past ``|U| = 27`` the sum leaves the ``PAY`` amount's
    declared bound, the program stops being total, and the run reports
    ``Indeterminate`` for a reason that has nothing to do with case size.  The
    engine is right to refuse it -- a value outside its declared domain is a
    rejection, not a clamp -- but a benchmark that measured that would be
    measuring its own fixture.
    """
    refs = [flag(index) for index in range(size)]
    contributions = tuple(
        Ite(Leaf(ref), LitScaled(money(index + 1)), LitScaled(money(0)))
        for index, ref in enumerate(refs)
    )
    amount: Term = contributions[0] if len(contributions) == 1 else NAry(NAryOp.ADD, contributions)
    return build_case(
        declarations={ref: (BoolSort(), BoolDomain()) for ref in refs},
        constraints=(),
        program=closed((), pay(amount)),
    )


def correlated(size: int) -> ProjectedCase:
    """The action needs every flag at once, so no single flag is necessary.

    This is the shape the whole planning design exists for, and it is the one
    that runs the deletion pass all the way to the end rather than short
    circuiting -- so it is the honest upper bound on planning cost.
    """
    refs = [flag(index) for index in range(size)]
    guard: Term = (
        Leaf(refs[0]) if len(refs) == 1 else NAry(NAryOp.AND, tuple(Leaf(ref) for ref in refs))
    )
    return build_case(
        declarations={ref: (BoolSort(), BoolDomain()) for ref in refs},
        constraints=(),
        program=closed(
            (ProgramRule(guard=guard, action=pay(LitScaled(money(5)))),), hold("REVIEW")
        ),
    )


def threshold(size: int) -> ProjectedCase:
    """Wide integer domains, compared only against literals.

    The bounded backend's threshold abstraction applies here, so this measures
    the case it was built for rather than the case it refuses.
    """
    refs = [count(index) for index in range(size)]
    contributions = tuple(
        Ite(
            Binary(BinaryOp.GE, Leaf(ref), LitInt(720)),
            LitScaled(money(100 + index)),
            LitScaled(money(0)),
        )
        for index, ref in enumerate(refs)
    )
    amount: Term = contributions[0] if len(contributions) == 1 else NAry(NAryOp.ADD, contributions)
    constraints = tuple(
        (f"K{index}", Binary(BinaryOp.LE, Leaf(ref), LitInt(1_440)))
        for index, ref in enumerate(refs)
    )
    return build_case(
        declarations={ref: (IntSort(), IntRange(0, 1_440)) for ref in refs},
        constraints=constraints,
        program=closed((), pay(amount)),
    )


def opaque(size: int) -> ProjectedCase:
    """Wide integer domains inside arithmetic: the abstraction cannot apply.

    A bare occurrence outside a literal comparison makes the bounded backend
    enumerate the whole domain, so this is the family that finds its refusal
    point -- and it refuses rather than approximating, which is the property
    being measured.
    """
    refs = [count(index) for index in range(size)]
    total: Term = (
        Leaf(refs[0]) if len(refs) == 1 else NAry(NAryOp.ADD, tuple(Leaf(ref) for ref in refs))
    )
    return build_case(
        declarations={ref: (IntSort(), IntRange(0, 1_440)) for ref in refs},
        constraints=(),
        program=closed(
            (
                ProgramRule(
                    guard=Binary(BinaryOp.GE, total, LitInt(90 * size)),
                    action=pay(LitScaled(money(7))),
                ),
            ),
            hold("BLOCKED"),
        ),
    )


def enums(size: int) -> ProjectedCase:
    """Enum-sorted variables and a table over each one."""
    refs = [tint(index) for index in range(size)]
    contributions = tuple(
        EnumTable(
            Leaf(ref),
            tuple(
                Arm(member, LitScaled(money(position * (index + 1))))
                for position, member in enumerate(COLOURS)
            ),
        )
        for index, ref in enumerate(refs)
    )
    amount: Term = contributions[0] if len(contributions) == 1 else NAry(NAryOp.ADD, contributions)
    return build_case(
        declarations={ref: (EnumSort(ENUM_COLOUR), EnumDomain(COLOURS)) for ref in refs},
        constraints=(),
        program=closed((), pay(amount)),
    )


def scheduled(day: int) -> SymbolRef:
    return SymbolRef("scheduled", ("W", f"D{day:03d}"))


def present(day: int) -> SymbolRef:
    return SymbolRef("present_on_site", ("W", f"D{day:03d}"))


def duration(day: int) -> SymbolRef:
    return SymbolRef("on_site_duration", ("W", f"D{day:03d}"))


def payable(day: int) -> SymbolRef:
    return SymbolRef("shift_payable_under_policy", ("W", f"D{day:03d}"))


RATE = SymbolRef("daily_rate", ("W",))


def ravi_like(size: int) -> ProjectedCase:
    """The workforce shape, scaled by the number of days left open.

    Faithful to the real case rather than merely inspired by it: the daily rate
    and the roster are established, each *open* day contributes the three
    unresolved variables the site could still attest, and a definitional
    constraint determines the normative one from the other two.  That is the
    structure in which no single variable is necessary while evidence is
    unmistakably required -- the shape the whole planning design exists for --
    and it is why this family, not ``independent``, is the one the cap is read
    off.

    A whole day carries three unresolved variables, which would leave ``|U|``
    stepping in threes and the cap being read off a grid coarser than the
    decision it is used to make.  So the last day is *partly* settled -- the
    site has already attested some of it, exactly as it might have in practice
    -- and ``|U|`` lands on the requested number rather than near it.
    """
    days = max(1, -(-size // 3))
    settled_on_the_last_day = 3 * days - size
    declarations: dict[SymbolRef, tuple[Sort, Domain]] = {RATE: (MONEY, ScaledRange(0, 1_000_000))}
    #  Established, exactly as in the real case: the payroll record is on file
    #  and the roster is known; what is open is what happened on the site.
    known: dict[SymbolRef, Value] = {RATE: money(250_000)}
    constraints: list[tuple[str, Term]] = []
    contributions: list[Term] = []
    for day in range(days):
        declarations[scheduled(day)] = (BoolSort(), BoolDomain())
        declarations[present(day)] = (BoolSort(), BoolDomain())
        declarations[duration(day)] = (IntSort(), IntRange(0, 1_440))
        declarations[payable(day)] = (BoolSort(), BoolDomain())
        known[scheduled(day)] = VBool(True)
        if day == days - 1:
            #  ``payable`` is never settled here: it is the normative one, the
            #  constraint determines it, and establishing it directly would
            #  remove the dependence this family exists to measure.
            partial = ((present(day), VBool(True)), (duration(day), VInt(480)))
            known.update(dict(partial[:settled_on_the_last_day]))
        constraints.append(
            (
                f"C-ENT-{day:03d}",
                Binary(
                    BinaryOp.IFF,
                    Leaf(payable(day)),
                    NAry(
                        NAryOp.AND,
                        (
                            Leaf(scheduled(day)),
                            Leaf(present(day)),
                            Binary(BinaryOp.GE, Leaf(duration(day)), LitInt(240)),
                        ),
                    ),
                ),
            )
        )
        contributions.append(Ite(Leaf(payable(day)), Leaf(RATE), LitScaled(money(0))))
    amount: Term = (
        contributions[0] if len(contributions) == 1 else NAry(NAryOp.ADD, tuple(contributions))
    )
    return build_case(
        declarations=declarations,
        constraints=tuple(constraints),
        program=closed((), pay(amount)),
        known=known,
    )


FAMILIES: tuple[tuple[str, Callable[[int], ProjectedCase]], ...] = (
    ("independent", independent),
    ("correlated", correlated),
    ("threshold", threshold),
    ("opaque", opaque),
    ("enum", enums),
    ("ravi", ravi_like),
)


#  ---- measurement ---------------------------------------------------------


class Counting:
    """A backend that answers as its delegate does, counts, and spends a budget.

    It is a pass-through until the wall budget for one decision is gone, so
    nothing about the measured path changes: the same queries are built,
    lowered and decided.  What it adds is the explanation -- how many queries a
    size costs, and how many came back inconclusive -- and a stopping rule.

    The stopping rule matters more than it looks.  A decision that has already
    spent longer than anybody would wait is not interesting to measure
    precisely, and grinding one out costs hours; but killing it from outside
    would leave no row at all.  So the budget is spent *here*, and once it is
    gone every further query answers ``BUDGET_EXHAUSTED`` -- the engine's own
    resource-limit verdict.  The decision then unwinds the way it would under a
    real limit, ``Indeterminate`` or ``NotComputed`` rather than a partial
    answer, and the row says the size was abandoned rather than pretending to
    have timed it.
    """

    def __init__(
        self, delegate: BoundedEnumerationBackend | Z3Backend, budget_seconds: float
    ) -> None:
        self._delegate = delegate
        self._deadline = time.perf_counter() + budget_seconds
        self.queries = 0
        self.inconclusive = 0
        self.abandoned = False
        self.detail: list[str] = []

    def capabilities(self) -> FragmentCapabilities:
        return self._delegate.capabilities()

    def fingerprint(self) -> object:
        return self._delegate.fingerprint()

    def check(self, query: SolverQuery) -> SolverVerdict:
        self.queries += 1
        if time.perf_counter() > self._deadline:
            self.abandoned = True
            self.inconclusive += 1
            return Unknown(UnknownReason.BUDGET_EXHAUSTED, "the benchmark wall budget was spent")
        verdict = self._delegate.check(query)
        if isinstance(verdict, Unknown | UnsupportedFragment):
            self.inconclusive += 1
            if len(self.detail) < 3:
                self.detail.append(f"{query.kind.value}: {verdict}")
        return verdict


@dataclass
class Sample:
    analyze_seconds: float
    planning_seconds: float
    analyze_queries: int
    planning_queries: int
    inconclusive: int
    outcome: str
    abandoned: bool = False
    detail: list[str] = field(default_factory=list)

    def total_seconds(self) -> float:
        return self.analyze_seconds + self.planning_seconds


def one_run(case: ProjectedCase, backend: BoundedEnumerationBackend | Z3Backend) -> Sample:
    """One full decision: analyze, then plan. Timed separately, because the two
    scale differently -- analyze is ``O(1)`` queries plus enumeration, planning
    is ``O(|U|)`` self-composed ones."""
    counting = Counting(backend, RUN_BUDGET_SECONDS)
    oracle = Oracle(counting, case)  # type: ignore[arg-type]

    started = time.perf_counter()
    kernel = analyze(case, oracle, BENCH_LIMITS)
    analyze_seconds = time.perf_counter() - started
    analyze_queries = counting.queries

    unresolved = case.unresolved()
    candidates = tuple(
        EvidenceTarget(ref, AcquisitionClass.ATTESTABLE, ("BENCH_SOURCE",)) for ref in unresolved
    )
    started = time.perf_counter()
    plan_evidence(
        oracle=oracle,
        outcome=kernel.outcome,
        unresolved=unresolved,
        candidates=candidates,
        tenant_id="BENCH",
        case_id="BENCH-1",
        revision_digest=PLACEHOLDER,
    )
    planning_seconds = time.perf_counter() - started

    return Sample(
        analyze_seconds=analyze_seconds,
        planning_seconds=planning_seconds,
        analyze_queries=analyze_queries,
        planning_queries=counting.queries - analyze_queries,
        inconclusive=counting.inconclusive,
        outcome=_outcome_name(kernel.outcome),
        abandoned=counting.abandoned,
        detail=counting.detail,
    )


def _outcome_name(outcome: object) -> str:
    match outcome:
        case Invariant():
            return "INVARIANT"
        case Divergent():
            return "DIVERGENT"
        case Infeasible():
            return "INFEASIBLE"
        case Indeterminate(reason):
            return f"INDETERMINATE:{reason.value}"
        case _:  # pragma: no cover - the outcome type is closed
            return "UNKNOWN"


@dataclass
class Row:
    family: str
    backend: str
    unresolved: int
    repetitions: int
    outcome: str
    queries: int
    median_seconds: float
    p95_seconds: float
    worst_seconds: float
    analyze_median: float
    planning_median: float
    inconclusive: int
    abandoned: bool
    detail: list[str]


def percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank, which is the honest reading of a handful of samples.

    Interpolating between two of five samples invents a number that was never
    observed; nearest-rank returns one that was.
    """
    ordered = sorted(values)
    rank = -(-int(fraction * 100) * len(ordered) // 100)
    index = max(0, min(len(ordered) - 1, rank - 1))
    return ordered[index]


def measure(
    family: str,
    build: Callable[[int], ProjectedCase],
    size: int,
    backend_name: str,
    backend: BoundedEnumerationBackend | Z3Backend,
    repetitions: int,
) -> Row | None:
    case = build(size)
    actual = len(case.unresolved())
    if actual == 0:  # pragma: no cover - every family declares at least one
        return None

    #  One untimed run first: the first call through any code path pays for
    #  imports, interning and Z3's own warm-up, and reporting that as the
    #  median would describe the interpreter rather than the query.
    warm = one_run(case, backend)
    samples = [one_run(case, backend) for _ in range(repetitions)]

    totals = [sample.total_seconds() for sample in samples]
    return Row(
        family=family,
        backend=backend_name,
        unresolved=actual,
        repetitions=repetitions,
        outcome=warm.outcome,
        queries=warm.analyze_queries + warm.planning_queries,
        median_seconds=statistics.median(totals),
        p95_seconds=percentile(totals, 0.95),
        worst_seconds=max(totals),
        analyze_median=statistics.median([sample.analyze_seconds for sample in samples]),
        planning_median=statistics.median([sample.planning_seconds for sample in samples]),
        inconclusive=warm.inconclusive,
        abandoned=warm.abandoned or any(sample.abandoned for sample in samples),
        detail=warm.detail,
    )


def repetitions_for(seconds: float) -> int:
    """More samples where they are cheap, enough samples where they are not.

    Three is the floor: a median and a worst over fewer than three samples is
    not a distribution, it is two numbers.
    """
    if seconds < 0.05:
        return 15
    if seconds < 0.5:
        return 9
    if seconds < 3.0:
        return 5
    return 3


def run(sizes: tuple[int, ...]) -> Iterator[Row]:
    backends: tuple[tuple[str, Callable[[], BoundedEnumerationBackend | Z3Backend]], ...] = (
        ("bounded", lambda: BoundedEnumerationBackend(ENUMERATION_BUDGET)),
        ("z3", Z3Backend),
    )
    for family, build in FAMILIES:
        for backend_name, make in backends:
            #  A family whose size parameter rounds -- ``ravi`` counts days --
            #  can produce one |U| from several targets. Measuring it twice
            #  would put the same case in the table under two rows.
            seen: set[int] = set()
            for size in sizes:
                case = build(size)
                actual = len(case.unresolved())
                if actual in seen:
                    continue
                seen.add(actual)

                backend = make()
                probe = one_run(case, backend)
                elapsed = probe.total_seconds()
                row = measure(family, build, size, backend_name, backend, repetitions_for(elapsed))
                if row is None:  # pragma: no cover
                    continue
                mark = " ABANDONED" if row.abandoned else ""
                print(
                    f"  {family:<12} {backend_name:<8} |U|={row.unresolved:>4}  "
                    f"{row.outcome:<30} q={row.queries:<5} "
                    f"med={row.median_seconds:8.4f}s p95={row.p95_seconds:8.4f}s{mark}",
                    flush=True,
                )
                yield row
                if row.abandoned or elapsed > RUN_BUDGET_SECONDS:
                    print(
                        f"  {family:<12} {backend_name:<8} stopped above |U|={row.unresolved}: "
                        f"one decision cost {elapsed:.1f}s against a "
                        f"{RUN_BUDGET_SECONDS:.0f}s budget",
                        flush=True,
                    )
                    break


def environment() -> dict[str, str]:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unreported",
        "python": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "z3": z3.get_version_string(),
        "enumeration_budget": str(ENUMERATION_BUDGET),
        "reachable_action_cap": str(BENCH_LIMITS.reachable_action_cap),
    }


def markdown(rows: list[Row], env: dict[str, str]) -> str:
    lines = [
        "# G5 case-size benchmark",
        "",
        "Generated by `bench/case_size.py`. Every row is one deterministic case",
        "family at one `|U|`, decided end to end -- `analyze` and then",
        "`plan_evidence` -- against one backend.",
        "",
        "## Environment",
        "",
        "| Key | Value |",
        "|---|---|",
    ]
    lines.extend(f"| {key} | {value} |" for key, value in env.items())
    lines.extend(
        [
            "",
            "## Measurements",
            "",
            "`queries` is the number of solver queries one decision issued.",
            "`analyze` and `planning` are medians of their two phases.",
            "",
            f"A decision that ran past the {RUN_BUDGET_SECONDS:.0f}s wall budget is marked",
            "`abandoned`: its times are a lower bound, and its outcome is whatever the engine",
            "produced once the budget started answering `BUDGET_EXHAUSTED`. The family stops",
            "growing at the first abandoned size.",
            "",
            "| family | backend | \\|U\\| | outcome | queries | median s | p95 s | worst s "
            "| analyze s | planning s | inconclusive | abandoned |",
            "|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    for row in rows:
        lines.append(
            f"| {row.family} | {row.backend} | {row.unresolved} | {row.outcome} "
            f"| {row.queries} | {row.median_seconds:.4f} | {row.p95_seconds:.4f} "
            f"| {row.worst_seconds:.4f} | {row.analyze_median:.4f} "
            f"| {row.planning_median:.4f} | {row.inconclusive} "
            f"| {'yes' if row.abandoned else 'no'} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=REPOSITORY_ROOT / "bench" / "results")
    parser.add_argument("--max-size", type=int, default=max(SIZES))
    arguments = parser.parse_args()

    sizes = tuple(size for size in SIZES if size <= arguments.max_size)
    env = environment()
    print("environment:", flush=True)
    for key, value in env.items():
        print(f"  {key}: {value}", flush=True)
    print("measurements:", flush=True)

    rows = list(run(sizes))

    arguments.out.mkdir(parents=True, exist_ok=True)
    (arguments.out / "case-size.json").write_text(
        json.dumps(
            {"environment": env, "rows": [asdict(row) for row in rows]},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (arguments.out / "case-size.md").write_text(markdown(rows, env), encoding="utf-8")
    print(f"\nwrote {arguments.out / 'case-size.json'} and {arguments.out / 'case-size.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
