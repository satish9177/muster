"""Attacks on the OBSERVATION -> NORMATIVE barrier.

The barrier is only worth something if it survives the constraint channel.
Restricting which justifications may carry a normative fact leaves the obvious
bypass open: submit ``shift_payable_under_policy(SAT) = true`` as a well-typed
*constraint*, keep the established set clean, and force the payment in every
admissible world.  Each test here is that attack in a different costume.
"""

from __future__ import annotations

import dataclasses

import pytest

from muster.core.case.constraints import (
    AttestedRelationDeriv,
    Constraint,
    PolicyEntailmentDeriv,
    StructuralDeriv,
)
from muster.core.case.facts import (
    AttestedBy,
    DerivationMode,
    EntailedBy,
    EstablishedFact,
    Modality,
)
from muster.core.case.revision import CaseRevision, canonical_constraints, canonical_facts
from muster.core.evidence.relations import (
    ClosedLowerBound,
    ExactValue,
    PredicateInfo,
    RelationFailure,
    validate_relation,
)
from muster.core.expr.ir import Binary, BinaryOp, Leaf, LitBool
from muster.core.results import Err, Ok
from muster.core.values.classification import EvidenceLayer
from muster.core.values.scalars import VBool, VInt, VScaled
from muster.core.values.sorts import BoolDomain, BoolSort, IntRange, IntSort
from muster.domains.workforce.bundle import (
    SOURCE_PAYROLL,
    SOURCE_SITE_ACCESS,
    on_site_duration,
    present_on_site,
    shift_payable,
)
from muster.hinge.prepare import PrepareFailure, prepare
from tests.support import ravi

SATURDAY_PAYABLE = shift_payable(ravi.RAVI, ravi.SATURDAY)


def _prepared(revision: CaseRevision) -> object:
    return prepare(revision, ravi.bundle(), ravi.backend().capabilities(), ravi.limits())


def _with(revision: CaseRevision, **changes: object) -> CaseRevision:
    return dataclasses.replace(revision, **changes)  # type: ignore[arg-type]


def test_the_unmodified_case_prepares() -> None:
    """The control: every attack below starts from a case that is accepted."""
    assert isinstance(_prepared(ravi.revision()), Ok)


def test_a_forged_constraint_pinning_the_normative_variable_is_refused() -> None:
    """The constraint-channel bypass, in its most direct form."""
    forged = Constraint(
        label="C-ATT:forged",
        formula=Binary(BinaryOp.EQ, Leaf(SATURDAY_PAYABLE), LitBool(True)),
        derivation=AttestedRelationDeriv(1, ravi.revision().construction_digest),
    )
    attacked = _with(
        ravi.revision(),
        constraints=canonical_constraints((*ravi.revision().constraints, forged)),
    )
    outcome = _prepared(attacked)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.LAYER_FLOW_VIOLATION


def test_a_structural_derivation_cannot_launder_a_normative_constraint() -> None:
    """Relabelling the same forgery as structural does not make it admissible."""
    forged = Constraint(
        label="C-DOM:forged",
        formula=Binary(BinaryOp.EQ, Leaf(SATURDAY_PAYABLE), LitBool(True)),
        derivation=StructuralDeriv(ravi.bundle().predicate_schema.digest()),
    )
    attacked = _with(
        ravi.revision(),
        constraints=canonical_constraints((*ravi.revision().constraints, forged)),
    )
    outcome = _prepared(attacked)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.LAYER_FLOW_VIOLATION


def test_a_policy_entailment_label_does_not_survive_re_derivation() -> None:
    """The forgery wears the only permitted derivation, and still fails.

    Layer flow alone would accept this: it carries ``PolicyEntailment``.  What
    rejects it is recomputation -- the pinned bundle's rules do not produce this
    constraint from these attested facts, so its octets do not reproduce.
    """
    forged = Constraint(
        label="C-ENT:forged",
        formula=Binary(BinaryOp.EQ, Leaf(SATURDAY_PAYABLE), LitBool(True)),
        derivation=PolicyEntailmentDeriv(
            ravi.bundle().digest(), Modality.DEFINITION, ("R-SHIFT-PAYABLE-1",), None
        ),
    )
    attacked = _with(
        ravi.revision(),
        constraints=canonical_constraints((*ravi.revision().constraints, forged)),
    )
    outcome = _prepared(attacked)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.ENTAILMENT_VALIDATION_FAILED


def test_a_forged_entailed_fact_does_not_survive_re_derivation() -> None:
    """It names a rule that resolves and premises that exist. It is still refused."""
    forged = EstablishedFact(
        SATURDAY_PAYABLE,
        VBool(True),
        EntailedBy(
            ravi.bundle().digest(),
            Modality.DEFINITION,
            DerivationMode.WITNESS_DISJUNCT,
            ("R-SHIFT-PAYABLE-1",),
            (),
        ),
    )
    attacked = _with(
        ravi.revision(), established=canonical_facts((*ravi.revision().established, forged))
    )
    outcome = _prepared(attacked)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.ENTAILMENT_VALIDATION_FAILED


def test_an_attested_normative_fact_is_refused() -> None:
    """A source cannot attest a policy conclusion, at any layer, under any key."""
    forged = EstablishedFact(
        SATURDAY_PAYABLE, VBool(True), AttestedBy(ravi.revision().construction_digest)
    )
    attacked = _with(
        ravi.revision(), established=canonical_facts((*ravi.revision().established, forged))
    )
    outcome = _prepared(attacked)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.LAYER_FLOW_VIOLATION
    assert "cannot be attested" in outcome.error.detail


def test_a_relation_over_a_normative_predicate_is_refused_at_validation() -> None:
    """The engine cannot even accept the shape of such an attestation."""
    info = PredicateInfo(
        value_sort=BoolSort(),
        domain=BoolDomain(),
        layer=EvidenceLayer.NORMATIVE,
        permitted_source_classes=frozenset({SOURCE_SITE_ACCESS}),
    )
    outcome = validate_relation(ExactValue(VBool(True)), BoolSort(), info, SOURCE_SITE_ACCESS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is RelationFailure.LAYER_FLOW_VIOLATION


def test_a_source_class_the_bundle_does_not_permit_is_refused() -> None:
    """Q-12(a): the pinned schema decides which class may speak for a predicate.

    This is the bundle half of source authorization.  The registry half -- that
    *this key* holds that class, for this tenant and this resource -- is Q-12(b)
    to (f) and is not implemented in this milestone.
    """
    info = PredicateInfo(
        value_sort=BoolSort(),
        domain=BoolDomain(),
        layer=EvidenceLayer.OBSERVATION,
        permitted_source_classes=frozenset({SOURCE_SITE_ACCESS}),
    )
    outcome = validate_relation(ExactValue(VBool(True)), BoolSort(), info, SOURCE_PAYROLL)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is RelationFailure.SOURCE_CLASS_NOT_PERMITTED_FOR_PREDICATE


def test_a_bound_of_the_wrong_sort_is_refused() -> None:
    """Q-11: the relation value's own sort, not merely the declared one.

    A scaled bound against an integer predicate passes the declared-sort check
    and would rebuild into an ill-typed comparison.
    """
    info = PredicateInfo(
        value_sort=IntSort(),
        domain=IntRange(0, 1440),
        layer=EvidenceLayer.OBSERVATION,
        permitted_source_classes=frozenset({SOURCE_SITE_ACCESS}),
    )
    outcome = validate_relation(
        ClosedLowerBound(VScaled("INR", 2, 99)), IntSort(), info, SOURCE_SITE_ACCESS
    )
    assert isinstance(outcome, Err)
    assert outcome.error.failure is RelationFailure.RELATION_VALUE_SORT_MISMATCH


def test_a_bound_outside_the_declared_domain_is_refused() -> None:
    info = PredicateInfo(
        value_sort=IntSort(),
        domain=IntRange(0, 1440),
        layer=EvidenceLayer.OBSERVATION,
        permitted_source_classes=frozenset({SOURCE_SITE_ACCESS}),
    )
    outcome = validate_relation(ClosedLowerBound(VInt(9999)), IntSort(), info, SOURCE_SITE_ACCESS)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is RelationFailure.VALUE_OUT_OF_DOMAIN


def test_a_declaration_the_pinned_schema_does_not_describe_is_refused() -> None:
    from muster.core.case.revision import canonical_declared
    from muster.core.values.symbols import SymbolRef

    attacked = _with(
        ravi.revision(),
        declared=canonical_declared((*ravi.revision().declared, SymbolRef("invented", ("X",)))),
    )
    outcome = _prepared(attacked)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.PREDICATE_SCHEMA_MISMATCH


def test_a_revision_pinning_another_bundle_is_refused() -> None:
    from muster.core.wire.digests import Digest

    attacked = _with(ravi.revision(), bundle_pin=Digest(bytes(32)))
    outcome = _prepared(attacked)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.POLICY_PIN_MISMATCH


def test_an_established_value_outside_its_declared_domain_is_refused() -> None:
    from muster.core.case.facts import AttestedBy as Attested

    over_long = EstablishedFact(
        on_site_duration(ravi.RAVI, "MON"),
        VInt(99_999),
        Attested(ravi.revision().construction_digest),
    )
    kept = tuple(fact for fact in ravi.revision().established if fact.ref != over_long.ref)
    attacked = _with(ravi.revision(), established=canonical_facts((*kept, over_long)))
    outcome = _prepared(attacked)
    assert isinstance(outcome, Err)
    assert outcome.error.failure in {
        PrepareFailure.VALUE_OUT_OF_DOMAIN,
        PrepareFailure.ENTAILMENT_VALIDATION_FAILED,
    }


def test_a_case_above_the_configured_size_is_refused_with_its_numbers() -> None:
    """G5: the mechanism ships now; the constant is the operator's, not ours."""
    import dataclasses as _dataclasses

    tight = _dataclasses.replace(ravi.limits(), max_unresolved=1)
    outcome = prepare(ravi.revision(), ravi.bundle(), ravi.backend().capabilities(), tight)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is PrepareFailure.UNSUPPORTED_CASE_SIZE
    assert "3 unresolved" in outcome.error.detail
    assert "permitted 1" in outcome.error.detail


def test_no_evidence_target_can_name_a_derived_predicate() -> None:
    """Unrepresentable, not rejected: the constructor refuses to build one."""
    from muster.core.evidence.requests import EvidenceTarget
    from muster.core.results import InvariantViolation
    from muster.core.values.classification import AcquisitionClass

    with pytest.raises(InvariantViolation):
        EvidenceTarget(SATURDAY_PAYABLE, AcquisitionClass.DERIVED, ("ANY",))


def test_fixing_an_established_variable_is_not_a_silent_no_op() -> None:
    from muster.core.results import InvariantViolation
    from muster.hinge.encode import sufficiency_query

    established = ravi.revision().established[0].ref
    with pytest.raises(InvariantViolation):
        sufficiency_query(ravi.analysis().projected, frozenset({established}))


def test_present_on_site_remains_open_so_the_case_cannot_be_settled_by_a_claim() -> None:
    assert present_on_site(ravi.RAVI, ravi.SATURDAY) in set(ravi.analysis().projected.unresolved())
