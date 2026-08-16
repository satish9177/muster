"""Entailment materialisation, over a synthetic rule set.

The workforce bundle declares exactly one ``DefinitionRule`` per conclusion, so
three of the five branches of the pass are unreachable from any fixture:
``RULE_FIRED``, ``WITNESS_DISJUNCT``, the deferred-implication constraint, and
the conflict detections.  A small rule set built here reaches all of them.

The two claims worth pinning are the ones the prose makes loudest.
``WITNESS_DISJUNCT`` must cite the **complete** set of evaluable-true rules --
"no pick-one ambiguity" is only true if the citation is the whole set -- and it
must make **no** claim about the rules it does not cite, which is what lets it
avoid evaluating an open term.
"""

from __future__ import annotations

import pytest

from muster.core.case.facts import DerivationMode, EntailedBy, EstablishedFact, Modality
from muster.core.expr.ir import Binary, BinaryOp, Leaf, LitBool, LitInt
from muster.core.expr.terms import Term, term_digest
from muster.core.results import Err, Ok
from muster.core.values.classification import AcquisitionClass, EvidenceLayer
from muster.core.values.scalars import Value, VBool, VInt
from muster.core.values.sorts import BoolDomain, BoolSort, IntRange, IntSort
from muster.core.values.symbols import SymbolRef, SymbolRefTemplate
from muster.core.wire.digests import Digest
from muster.policy.entailment import (
    DefinitionRule,
    EntailmentRule,
    EntailmentRules,
    ImplicationRule,
)
from muster.policy.materialise import MaterialisationFailure, materialise
from muster.policy.predicates import PredicateSchema, PredicateSpec

MANIFEST = Digest(bytes(32))
WORKER = "W-1"
BINDER = "W"

PAYABLE = SymbolRef("payable", (WORKER,))
PRESENT = SymbolRef("present", (WORKER,))
SCHEDULED = SymbolRef("scheduled", (WORKER,))
MINUTES = SymbolRef("minutes", (WORKER,))

DECLARED = (PAYABLE, PRESENT, SCHEDULED, MINUTES)


def _schema() -> PredicateSchema:
    def observation(name: str, sort: object, domain: object) -> PredicateSpec:
        return PredicateSpec(
            predicate_id=name,
            arg_kinds=("WORKER",),
            value_sort=sort,  # type: ignore[arg-type]
            domain=domain,  # type: ignore[arg-type]
            layer=EvidenceLayer.OBSERVATION,
            acquisition=AcquisitionClass.ATTESTABLE,
            permitted_source_classes=("SITE",),
        )

    return PredicateSchema(
        schema_version=1,
        predicates=(
            PredicateSpec(
                predicate_id="payable",
                arg_kinds=("WORKER",),
                value_sort=BoolSort(),
                domain=BoolDomain(),
                layer=EvidenceLayer.NORMATIVE,
                acquisition=AcquisitionClass.DERIVED,
                permitted_source_classes=(),
            ),
            observation("present", BoolSort(), BoolDomain()),
            observation("scheduled", BoolSort(), BoolDomain()),
            observation("minutes", IntSort(), IntRange(0, 1440)),
        ),
    )


def _template() -> SymbolRefTemplate:
    return SymbolRefTemplate("payable", (BINDER,))


def _leaf(predicate: str) -> Term:
    return Leaf(SymbolRef(predicate, (BINDER,)))


def _definition(rule_id: str, premise: Term) -> DefinitionRule:
    return DefinitionRule(
        rule_id=rule_id,
        binder_args=(BINDER,),
        conclusion=_template(),
        premise=premise,
        exhaustiveness_ratification_ref=term_digest(premise),
    )


def _implication(rule_id: str, premise: Term, value: Term) -> ImplicationRule:
    return ImplicationRule(
        rule_id=rule_id,
        binder_args=(BINDER,),
        conclusion=_template(),
        premise=premise,
        conclusion_value=value,
    )


def _run(rules: tuple[EntailmentRule, ...], known: dict[SymbolRef, Value]) -> object:
    facts = {
        ref: EstablishedFact(
            ref,
            value,
            EntailedBy(MANIFEST, Modality.DEFINITION, DerivationMode.FULL_EVALUATION, ("x",), ()),
        )
        for ref, value in known.items()
    }
    return materialise(
        rules=EntailmentRules(1, rules),
        declared=DECLARED,
        known=known,
        known_facts=facts,
        schema=_schema(),
        manifest_digest=MANIFEST,
    )


#  ---- implication ---------------------------------------------------------


def test_a_fired_implication_establishes_the_recomputed_value() -> None:
    outcome = _run((_implication("R1", _leaf("present"), LitBool(True)),), {PRESENT: VBool(True)})
    assert isinstance(outcome, Ok)
    (fact,) = outcome.value.facts
    assert fact.ref == PAYABLE
    assert fact.value == VBool(True)
    justification = fact.justification
    assert isinstance(justification, EntailedBy)
    assert justification.modality is Modality.IMPLICATION
    assert justification.derivation_mode is DerivationMode.RULE_FIRED
    assert justification.rule_ids == ("R1",)


def test_two_agreeing_implications_cite_both_rules() -> None:
    """``rule_ids`` is the complete fired set, not the first match."""
    rules = (
        _implication("R1", _leaf("present"), LitBool(True)),
        _implication("R2", _leaf("scheduled"), LitBool(True)),
    )
    outcome = _run(rules, {PRESENT: VBool(True), SCHEDULED: VBool(True)})
    assert isinstance(outcome, Ok)
    (fact,) = outcome.value.facts
    justification = fact.justification
    assert isinstance(justification, EntailedBy)
    assert justification.rule_ids == ("R1", "R2")


def test_two_disagreeing_implications_are_a_conflict_not_a_choice() -> None:
    """Picking either would hide a policy defect behind a plausible answer."""
    rules = (
        _implication("R1", _leaf("present"), LitBool(True)),
        _implication("R2", _leaf("scheduled"), LitBool(False)),
    )
    outcome = _run(rules, {PRESENT: VBool(True), SCHEDULED: VBool(True)})
    assert isinstance(outcome, Err)
    assert outcome.error.failure is MaterialisationFailure.NORMATIVE_DERIVATION_CONFLICT


def test_an_unevaluable_implication_defers_to_a_constraint() -> None:
    outcome = _run((_implication("R1", _leaf("present"), LitBool(True)),), {})
    assert isinstance(outcome, Ok)
    assert not outcome.value.facts
    (constraint,) = outcome.value.constraints
    assert constraint.formula == Binary(
        BinaryOp.IMPLIES, _leaf_of(PRESENT), Binary(BinaryOp.EQ, Leaf(PAYABLE), LitBool(True))
    )


def test_two_deferred_implications_do_not_collide_on_a_label() -> None:
    """The revision requires unique labels; two rules on one conclusion must differ."""
    rules = (
        _implication("R1", _leaf("present"), LitBool(True)),
        _implication("R2", _leaf("scheduled"), LitBool(True)),
    )
    outcome = _run(rules, {})
    assert isinstance(outcome, Ok)
    labels = [constraint.label for constraint in outcome.value.constraints]
    assert len(labels) == 2
    assert len(set(labels)) == 2


def test_a_group_mixing_modalities_is_refused() -> None:
    rules = (
        _implication("R1", _leaf("present"), LitBool(True)),
        _definition("R2", _leaf("scheduled")),
    )
    outcome = _run(rules, {PRESENT: VBool(True), SCHEDULED: VBool(True)})
    assert isinstance(outcome, Err)
    assert outcome.error.failure is MaterialisationFailure.MODALITY_CONFLICT


#  ---- definition ----------------------------------------------------------


def test_a_fully_evaluable_definition_may_establish_false() -> None:
    """``FULL_EVALUATION`` is the only mode that can conclude the negative."""
    outcome = _run((_definition("R1", _leaf("present")),), {PRESENT: VBool(False)})
    assert isinstance(outcome, Ok)
    (fact,) = outcome.value.facts
    assert fact.value == VBool(False)
    justification = fact.justification
    assert isinstance(justification, EntailedBy)
    assert justification.derivation_mode is DerivationMode.FULL_EVALUATION


def test_a_witness_disjunct_cites_every_true_rule_and_only_those() -> None:
    """One rule is closed and true, one is open, one is closed and false.

    The conclusion is true on the witness alone, and the citation must be the
    complete set of evaluable-true rules -- no more, so no claim is made about
    the open rule, and no fewer, so there is no pick-one ambiguity.
    """
    rules = (
        _definition("R-TRUE", _leaf("present")),
        _definition("R-OPEN", Binary(BinaryOp.GE, _leaf("minutes"), LitInt(240))),
        _definition("R-FALSE", _leaf("scheduled")),
    )
    outcome = _run(rules, {PRESENT: VBool(True), SCHEDULED: VBool(False)})
    assert isinstance(outcome, Ok)
    (fact,) = outcome.value.facts
    assert fact.value == VBool(True)
    justification = fact.justification
    assert isinstance(justification, EntailedBy)
    assert justification.derivation_mode is DerivationMode.WITNESS_DISJUNCT
    assert justification.rule_ids == ("R-TRUE",)
    assert not outcome.value.constraints


def test_an_open_definition_group_becomes_one_biconditional_constraint() -> None:
    rules = (
        _definition("R1", _leaf("present")),
        _definition("R2", _leaf("scheduled")),
    )
    outcome = _run(rules, {})
    assert isinstance(outcome, Ok)
    assert not outcome.value.facts
    (constraint,) = outcome.value.constraints
    assert isinstance(constraint.formula, Binary)
    assert constraint.formula.op is BinaryOp.IFF
    from muster.core.case.constraints import PolicyEntailmentDeriv

    assert isinstance(constraint.derivation, PolicyEntailmentDeriv)
    assert constraint.derivation.rule_ids == ("R1", "R2")
    assert constraint.derivation.ratification_ref is not None


def test_a_single_open_definition_disjoins_to_the_bare_premise() -> None:
    """One premise is the premise, never a one-armed disjunction."""
    from muster.core.expr.ir import NAry

    outcome = _run((_definition("R1", _leaf("present")),), {})
    assert isinstance(outcome, Ok)
    (constraint,) = outcome.value.constraints
    assert isinstance(constraint.formula, Binary)
    assert not isinstance(constraint.formula.right, NAry)


#  ---- layer flow ----------------------------------------------------------


def test_a_normative_premise_is_refused() -> None:
    """A normative premise would make entailment chain, and one pass incomplete."""
    rule = DefinitionRule(
        rule_id="R1",
        binder_args=(BINDER,),
        conclusion=SymbolRefTemplate("present", (BINDER,)),
        premise=Leaf(SymbolRef("payable", (BINDER,))),
        exhaustiveness_ratification_ref=MANIFEST,
    )
    outcome = _run((rule,), {})
    assert isinstance(outcome, Err)
    assert outcome.error.failure in {
        MaterialisationFailure.CONCLUSION_NOT_NORMATIVE,
        MaterialisationFailure.PREMISE_IS_NORMATIVE,
    }


def _leaf_of(ref: SymbolRef) -> Term:
    return Leaf(ref)


@pytest.mark.parametrize("value", [VInt(0), VInt(1440)])
def test_premise_digests_are_ordered_by_digest_not_by_discovery(value: Value) -> None:
    """The cited set is constructed exactly, so two implementations agree."""
    rules = (
        _implication(
            "R1",
            Binary(BinaryOp.GE, _leaf("minutes"), LitInt(0)),
            LitBool(True),
        ),
    )
    outcome = _run(rules, {MINUTES: value, PRESENT: VBool(True)})
    assert isinstance(outcome, Ok)
    (fact,) = outcome.value.facts
    justification = fact.justification
    assert isinstance(justification, EntailedBy)
    octets = [digest.octets for digest in justification.premise_digests]
    assert octets == sorted(octets)
