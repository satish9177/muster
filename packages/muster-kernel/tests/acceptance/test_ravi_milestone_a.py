"""The Milestone A exit criteria, asserted directly.

The Ravi case must yield **Divergent**, with a plan naming **both**
``present_on_site(RAVI, SAT)`` and ``on_site_duration(RAVI, SAT)`` -- a
two-member irredundant set in which **no member is individually necessary** --
from a file, with no network.
"""

from __future__ import annotations

from muster.application.cli import EXIT_OK, main, render
from muster.core.analysis.outcomes import Divergent, ExactReachable
from muster.core.analysis.planning import EvidenceRequested, ProvenIrredundantSupport
from muster.core.case.facts import AttestedBy, DerivationMode, EntailedBy, Modality
from muster.core.values.scalars import VBool, VScaled
from muster.domains.workforce.bundle import (
    PREDICATE_PAYABLE,
    SOURCE_SITE_ACCESS,
    on_site_duration,
    present_on_site,
    shift_payable,
)
from tests.support import ravi

WEEKDAY_TOTAL = VScaled("INR", 2, 425_000)
FULL_WEEK_TOTAL = VScaled("INR", 2, 510_000)


def test_the_case_is_divergent() -> None:
    outcome = ravi.analysis().kernel.outcome
    assert isinstance(outcome, Divergent)


def test_exactly_two_reachable_actions_at_the_expected_amounts() -> None:
    outcome = ravi.analysis().kernel.outcome
    assert isinstance(outcome, Divergent)
    assert isinstance(outcome.reachable, ExactReachable)
    amounts = {
        field.value
        for action in outcome.reachable.actions
        for field in action.consequential_fields
        if field.name == "amount"
    }
    assert amounts == {WEEKDAY_TOTAL, FULL_WEEK_TOTAL}


def test_three_variables_are_unresolved() -> None:
    unresolved = set(ravi.analysis().projected.unresolved())
    assert unresolved == {
        present_on_site(ravi.RAVI, ravi.SATURDAY),
        on_site_duration(ravi.RAVI, ravi.SATURDAY),
        shift_payable(ravi.RAVI, ravi.SATURDAY),
    }


def test_no_unresolved_variable_is_individually_necessary() -> None:
    """The sharpest statement of why the primary output is a set.

    Drop any one variable and the rest still determine the action; fix nothing
    and they do not.  A per-variable relevance flag reports "nothing matters"
    here and authorizes the smaller payment.
    """
    assert ravi.analysis().planning.necessary == ()


def test_the_plan_is_exactly_the_two_acquirable_observations() -> None:
    outcome = ravi.analysis().planning.record.planning_outcome
    assert isinstance(outcome, EvidenceRequested)
    assert {target.proposition for target in outcome.request.targets} == {
        present_on_site(ravi.RAVI, ravi.SATURDAY),
        on_site_duration(ravi.RAVI, ravi.SATURDAY),
    }
    for target in outcome.request.targets:
        assert target.permitted_source_classes == (SOURCE_SITE_ACCESS,)


def test_the_support_is_irredundant_with_a_witness_for_every_member() -> None:
    support = ravi.analysis().planning.record.support
    assert isinstance(support, ProvenIrredundantSupport)
    assert len(support.members) == 2
    assert {witness.member for witness in support.deletion_witnesses} == set(support.members)


def test_the_normative_predicate_is_never_requested() -> None:
    """It is DERIVED, so no target can name it -- structurally, not by rule."""
    outcome = ravi.analysis().planning.record.planning_outcome
    assert isinstance(outcome, EvidenceRequested)
    for target in outcome.request.targets:
        assert target.proposition.predicate_id != PREDICATE_PAYABLE


def test_the_worker_claim_moves_nothing_and_says_so() -> None:
    """Ravi claims the very proposition the site would attest, and it is inert.

    Being correct is not the same as being evidence: the claim agrees with what
    an authorized source would say, and it still contributes nothing.  What it
    leaves behind is a recorded non-effect naming the rule and the claimant.
    """
    from muster.core.case.constraints import AttestedRelationDeriv
    from muster.core.expr.ir import freevars

    revision = ravi.revision()
    claimed = present_on_site(ravi.RAVI, ravi.SATURDAY)

    #  It is not a fact: no justification variant accepts a claim.
    assert claimed not in {fact.ref for fact in revision.established}

    #  And it is not an attested constraint either: nothing attested it, so no
    #  constraint mentioning it may carry an attestation derivation.
    mentioning = [
        constraint for constraint in revision.constraints if claimed in freevars(constraint.formula)
    ]
    assert mentioning, "the variable is declared, so its domain is stated"
    assert not any(
        isinstance(constraint.derivation, AttestedRelationDeriv) for constraint in mentioning
    )

    #  The claim still leaves a trace, because silence and "the rule never ran"
    #  are indistinguishable.
    assert any(
        effect.rule_id == "SelfServingClaimIsInert" and effect.subject == ravi.RAVI
        for effect in revision.non_effects
    )


def test_weekday_payability_is_derived_by_full_evaluation() -> None:
    """Every premise is closed on those days, so the conclusion is a fact."""
    derived = {
        fact.ref: fact.justification
        for fact in ravi.revision().established
        if isinstance(fact.justification, EntailedBy)
    }
    for day in ("MON", "TUE", "WED", "THU", "FRI"):
        justification = derived[shift_payable(ravi.RAVI, day)]
        assert isinstance(justification, EntailedBy)
        assert justification.modality is Modality.DEFINITION
        assert justification.derivation_mode is DerivationMode.FULL_EVALUATION
        assert justification.premise_digests


def test_saturday_payability_stays_open_as_a_constraint() -> None:
    """Its premise is not closed, so it materialises as a constraint, not a fact."""
    revision = ravi.revision()
    saturday = shift_payable(ravi.RAVI, ravi.SATURDAY)
    assert saturday not in {fact.ref for fact in revision.established}

    from muster.core.case.constraints import PolicyEntailmentDeriv
    from muster.core.expr.ir import freevars

    mentioning = [
        constraint
        for constraint in revision.constraints
        if saturday in freevars(constraint.formula)
    ]
    assert len(mentioning) == 1
    derivation = mentioning[0].derivation
    assert isinstance(derivation, PolicyEntailmentDeriv)
    assert derivation.ratification_ref is not None


def test_attested_facts_carry_a_receipt_and_nothing_else() -> None:
    for fact in ravi.revision().established:
        assert isinstance(fact.justification, AttestedBy | EntailedBy)


def test_scheduled_saturday_is_established_by_attestation() -> None:
    from muster.domains.workforce.bundle import scheduled

    facts = {fact.ref: fact for fact in ravi.revision().established}
    saturday = facts[scheduled(ravi.RAVI, ravi.SATURDAY)]
    assert saturday.value == VBool(True)
    assert isinstance(saturday.justification, AttestedBy)


def test_analysis_is_byte_identical_when_repeated() -> None:
    """Same inputs, same octets -- for the revision, the record and the certificate."""
    from muster.application.pipeline import analyse_revision
    from muster.core.results import Ok
    from muster.core.wire.codec import encode

    first = ravi.analysis()
    again = analyse_revision(ravi.revision(), ravi.bundle(), ravi.backend(), ravi.limits())
    assert isinstance(again, Ok)
    assert encode(first.revision.to_node()) == encode(again.value.revision.to_node())
    assert encode(first.kernel.to_node()) == encode(again.value.kernel.to_node())
    assert encode(first.certificate.to_node()) == encode(again.value.certificate.to_node())


def test_the_report_is_stable() -> None:
    assert render(ravi.analysis(), ravi.bundle()) == render(ravi.analysis(), ravi.bundle())


def test_the_cli_runs_the_case_from_files() -> None:
    code = main(["analyse", "--case", str(ravi.CASE_FILE), "--config", str(ravi.LIMITS_FILE)])
    assert code == EXIT_OK


def test_the_certificate_binds_the_revision_and_the_bundle() -> None:
    analysis = ravi.analysis()
    assert analysis.certificate.revision_semantic_digest == analysis.revision.digest()
    assert analysis.certificate.bundle_manifest_digest == ravi.bundle().digest()
    assert analysis.certificate.kernel.logical_case_digest == analysis.projected.logical.digest()


def test_no_action_is_proposed_on_a_divergent_case() -> None:
    from muster.application.pipeline import proposed_action

    assert proposed_action(ravi.analysis()) is None
