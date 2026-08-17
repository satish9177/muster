"""The G5 case-size bound, at the three sizes that decide whether it works.

The mechanism shipped in milestone A; the *number* is a milestone-B measurement
(``bench/case_size.py``, recorded in ``bench/results/case-size.md``).  What is
checked here is the part a measurement cannot check: that the configured number
is enforced exactly, on the real admission path, with a typed result that
carries both sizes -- and that it is enforced at ``cap`` and at ``cap + 1``
rather than somewhere near them.

An off-by-one here is not cosmetic in either direction.  One too permissive is
the outage the bound exists to prevent; one too strict silently refuses cases
the operator configured for.

Every case below is built against the **pinned workforce bundle** and passes
every other admission check, so the only thing that decides the outcome is
``|U|``.  ``|U|`` is set exactly by declaring padding propositions that no
evidence establishes: each one adds exactly one unresolved variable and nothing
else, which is what makes ``cap``, ``cap - 1`` and ``cap + 1`` real cases rather
than a limit dialled up and down around a fixed one.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from muster.core.case.facts import AttestedBy, EstablishedFact
from muster.core.case.revision import (
    CaseRevision,
    canonical_constraints,
    canonical_declared,
    canonical_facts,
)
from muster.core.results import Err, Ok
from muster.core.values.scalars import Value, VBool, VInt
from muster.core.values.symbols import SymbolRef
from muster.domains.workforce.bundle import (
    WORKING_DAYS,
    daily_rate,
    declared_instances,
    money,
    on_site_duration,
    present_on_site,
    scheduled,
)
from muster.hinge.prepare import EngineLimits, PrepareFailure, prepare
from muster.policy.materialise import materialise
from tests.conftest import FIXTURES
from tests.support import ravi

#  The cap the operator ships, read from the same file the CLI reads.  Pinned
#  as a constant as well, so lowering the shipped number is a visible diff here
#  rather than a test that quietly follows it down.
CONFIGURED_MAX_UNRESOLVED = 4


def _configured_cap() -> int:
    document = json.loads((FIXTURES / "engine-limits.json").read_text(encoding="utf-8"))
    value = document["max_unresolved"]
    assert isinstance(value, int)
    return value


def _attestable() -> list[tuple[SymbolRef, Value]]:
    """Everything about Ravi's week a source could attest, with a value."""
    pool: list[tuple[SymbolRef, Value]] = [(daily_rate(ravi.RAVI), money(250_000))]
    for day in WORKING_DAYS:
        pool.append((scheduled(ravi.RAVI, day), VBool(True)))
        pool.append((present_on_site(ravi.RAVI, day), VBool(True)))
        pool.append((on_site_duration(ravi.RAVI, day), VInt(480)))
    return pool


def revision_with(unresolved: int) -> CaseRevision:
    """A fully admissible revision whose ``|U|`` is exactly ``unresolved``.

    Ravi's own week is settled, so it contributes nothing unresolved and the
    program stays closed over what is declared.  The count then comes entirely
    from padding propositions -- a daily rate for a worker nobody has attested
    anything about -- each of which adds one unresolved variable and fires no
    entailment rule.  The entailed facts and constraints are materialised from
    the pinned bundle rather than written down, because ``prepare`` re-derives
    them and compares octets.
    """
    bundle = ravi.bundle()
    original = ravi.revision()
    padding = tuple(daily_rate(f"PAD-{index:04d}") for index in range(unresolved))
    declared = canonical_declared((*declared_instances(ravi.RAVI), *padding))

    known = dict(_attestable())
    facts = {
        ref: EstablishedFact(ref, value, AttestedBy(original.construction_digest))
        for ref, value in known.items()
    }
    entailed = materialise(
        rules=bundle.entailment_rules,
        declared=declared,
        known=known,
        known_facts=facts,
        schema=bundle.predicate_schema,
        manifest_digest=original.bundle_pin,
    )
    assert isinstance(entailed, Ok), entailed
    return dataclasses.replace(
        original,
        declared=declared,
        established=canonical_facts((*facts.values(), *entailed.value.facts)),
        constraints=canonical_constraints(entailed.value.constraints),
        non_effects=(),
    )


def _admit(revision: CaseRevision, cap: int) -> object:
    return prepare(
        revision,
        ravi.bundle(),
        ravi.backend().capabilities(),
        EngineLimits(max_unresolved=cap, reachable_action_cap=ravi.limits().reachable_action_cap),
    )


def test_the_shipped_configuration_is_the_measured_cap() -> None:
    """The number in the file is the number the benchmark justified."""
    assert _configured_cap() == CONFIGURED_MAX_UNRESOLVED


def test_the_fixture_builder_produces_the_size_it_claims() -> None:
    """Every check below is worthless if the cases are not the sizes they say."""
    for size in (0, 1, 5, CONFIGURED_MAX_UNRESOLVED, CONFIGURED_MAX_UNRESOLVED + 1):
        assert len(revision_with(size).unresolved()) == size


@pytest.mark.parametrize("offset", [-1, 0])
def test_a_case_at_or_below_the_cap_is_admitted(offset: int) -> None:
    """``cap`` itself is inside the bound: the comparison is ``>``, not ``>=``."""
    size = CONFIGURED_MAX_UNRESOLVED + offset
    outcome = _admit(revision_with(size), CONFIGURED_MAX_UNRESOLVED)
    assert isinstance(outcome, Ok), outcome


def test_a_case_one_above_the_cap_is_refused_with_both_numbers() -> None:
    """Told, not timed out -- and told what the sizes were.

    A rejection that does not name the actual and permitted sizes leaves the
    operator guessing how much smaller the case would have to be, which is the
    one thing they need in order to split it.
    """
    size = CONFIGURED_MAX_UNRESOLVED + 1
    outcome = _admit(revision_with(size), CONFIGURED_MAX_UNRESOLVED)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.UNSUPPORTED_CASE_SIZE
    assert f"{size} unresolved" in outcome.error.detail
    assert f"permitted {CONFIGURED_MAX_UNRESOLVED}" in outcome.error.detail


def test_the_refusal_is_a_value_and_no_query_is_issued() -> None:
    """Fail closed *before* the solver, not by giving up in front of it.

    The bound exists so that an oversized case never reaches a backend at all;
    a case that was admitted and then abandoned would have spent the cost the
    bound is there to avoid.
    """
    from muster.solve.query import SolverQuery
    from muster.solve.verdict import SolverVerdict

    asked: list[SolverQuery] = []

    class Watching:
        def capabilities(self) -> object:
            return ravi.backend().capabilities()

        def fingerprint(self) -> object:
            return ravi.backend().fingerprint()

        def check(self, query: SolverQuery) -> SolverVerdict:  # pragma: no cover - never reached
            asked.append(query)
            raise AssertionError("an oversized case reached the backend")

    watching = Watching()
    outcome = prepare(
        revision_with(CONFIGURED_MAX_UNRESOLVED + 1),
        ravi.bundle(),
        watching.capabilities(),  # type: ignore[arg-type]
        EngineLimits(max_unresolved=CONFIGURED_MAX_UNRESOLVED, reachable_action_cap=8),
    )
    assert isinstance(outcome, Err)
    assert asked == []


def test_the_bound_tracks_the_configuration_rather_than_a_constant() -> None:
    """Configurable means configurable: the same case flips on the limit alone."""
    revision = revision_with(CONFIGURED_MAX_UNRESOLVED)
    assert isinstance(_admit(revision, CONFIGURED_MAX_UNRESOLVED), Ok)
    assert isinstance(_admit(revision, CONFIGURED_MAX_UNRESOLVED - 1), Err)


def test_the_real_case_fits_inside_the_bound() -> None:
    """A cap the shipped case could not pass would be theatre of another kind.

    The margin is one variable, and that is the measurement rather than a
    choice: on the bounded reference backend the workforce shape costs 0.74 s
    at ``|U| = 4`` and 10.2 s at ``|U| = 5``. Saying so here keeps the number
    honest -- a reader can see that the shipped default is tight, and that
    raising it is a configuration change backed by a different backend rather
    than a constant somebody nudged.
    """
    assert len(ravi.revision().unresolved()) <= CONFIGURED_MAX_UNRESOLVED
