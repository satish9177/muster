"""The second revision: the case closes while the duration stays unresolved.

The site attests presence exactly and the duration only as a **lower bound**.
The bound does not put the duration in ``K``, so the definition group is not
evaluable and materialises as a *constraint* rather than a fact -- and every
admissible world still satisfies it, so the normative conclusion holds in all of
them.

The result is ``Invariant`` over an unresolved variable: the exact number of
minutes is never established, never disclosed, and never needed.  An exact
attestation would settle the case too; the weaker relation is the more private
one, and the policy is indifferent between them.
"""

from __future__ import annotations

from functools import cache

from muster.application.case_file import load_case_file
from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.analysis.outcomes import Invariant
from muster.core.analysis.planning import NoActionReason, NoActionRequired
from muster.core.results import Ok
from muster.core.values.scalars import VScaled
from muster.domains.workforce.bundle import on_site_duration, present_on_site, shift_payable
from tests.conftest import FIXTURES
from tests.support import ravi

ATTESTED_CASE = FIXTURES / "ravi-saturday-attested.json"
FULL_WEEK_TOTAL = VScaled("INR", 2, 510_000)


@cache
def attested_analysis() -> CaseAnalysis:
    loaded = load_case_file(ATTESTED_CASE)
    assert isinstance(loaded, Ok), loaded
    case = loaded.value
    bundle = ravi.bundle()
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    built = rebuild(
        case.rebuild_inputs(bundle.digest(), prefix.digest()),
        case.construction,
        case.entries,
        bundle,
        case.authorization_context,
        case.authority_snapshot,
        case.revocation_snapshot,
        case.solicitations,
    )
    assert isinstance(built, Ok), built
    produced = analyse_revision(built.value, bundle, ravi.backend(), ravi.limits())
    assert isinstance(produced, Ok), produced
    return produced.value


def test_the_action_is_invariant() -> None:
    outcome = attested_analysis().kernel.outcome
    assert isinstance(outcome, Invariant)
    assert outcome.action.kind == "PAY"
    amounts = {
        field.value for field in outcome.action.consequential_fields if field.name == "amount"
    }
    assert amounts == {FULL_WEEK_TOTAL}


def test_the_invariant_outcome_carries_a_feasibility_witness() -> None:
    """Vacuous unsatisfiability on an empty world set must never read as invariance."""
    outcome = attested_analysis().kernel.outcome
    assert isinstance(outcome, Invariant)
    assert outcome.witness.bindings
    assert outcome.invariance_query_digest in attested_analysis().kernel.query_digests


def test_the_duration_is_never_established() -> None:
    """The product claim, in one assertion."""
    duration = on_site_duration(ravi.RAVI, ravi.SATURDAY)
    assert duration in set(attested_analysis().projected.unresolved())
    assert duration not in {fact.ref for fact in attested_analysis().revision.established}


def test_presence_is_established_and_the_conclusion_is_not() -> None:
    established = {fact.ref for fact in attested_analysis().revision.established}
    assert present_on_site(ravi.RAVI, ravi.SATURDAY) in established
    assert shift_payable(ravi.RAVI, ravi.SATURDAY) not in established


def test_nothing_further_is_requested_and_the_record_says_why() -> None:
    outcome = attested_analysis().planning.record.planning_outcome
    assert isinstance(outcome, NoActionRequired)
    assert outcome.reason is NoActionReason.ACTION_INVARIANT


def test_necessity_is_not_computed_rather_than_reported_as_empty() -> None:
    assert attested_analysis().planning.necessary is None


def test_the_duration_remains_acquirable_even_though_it_is_not_requested() -> None:
    """The report must not call an attestable variable un-attestable."""
    acquirable = {target.proposition for target in attested_analysis().acquirable}
    assert on_site_duration(ravi.RAVI, ravi.SATURDAY) in acquirable
    assert shift_payable(ravi.RAVI, ravi.SATURDAY) not in acquirable


def test_a_lower_bound_becomes_a_constraint_not_a_fact() -> None:
    from muster.core.case.constraints import AttestedRelationDeriv
    from muster.core.expr.ir import freevars

    duration = on_site_duration(ravi.RAVI, ravi.SATURDAY)
    attested = [
        constraint
        for constraint in attested_analysis().revision.constraints
        if duration in freevars(constraint.formula)
        and isinstance(constraint.derivation, AttestedRelationDeriv)
    ]
    assert len(attested) == 1
