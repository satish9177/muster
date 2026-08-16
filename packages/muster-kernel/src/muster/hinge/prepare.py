"""Validation before any query is issued.

Everything that could make an answer meaningless is checked here, and each
failure is a typed rejection rather than a degraded run:

* the revision pins exactly this bundle;
* every declared instance matches the authenticated predicate schema exactly --
  sort, domain, layer, acquisition class -- because a case that could choose
  those could label a normative conclusion as an attestable record;
* **every constraint mentioning a normative variable is re-derived from the
  pinned bundle and must reproduce byte-for-byte.**  So is every ``EntailedBy``
  fact.  This is the constraint-channel barrier: it is not enough to restrict
  which justifications may carry a normative fact, because a caller who can
  submit an arbitrary constraint can force the same outcome while leaving the
  established set clean;
* the program is closed over the declared instances;
* the backend has declared it can decide this fragment;
* the case is inside the configured size bound.

The size bound is mandatory and has no default.  An unbounded default turns a
quadratic classification into an outage, and an invented constant is theatre;
the number belongs to a benchmark, and until there is one the operator supplies
it or the kernel does not start.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.actions import validate_action_schema
from muster.core.case.constraints import Constraint, PolicyEntailmentDeriv
from muster.core.case.facts import EntailedBy, EstablishedFact
from muster.core.case.revision import CaseRevision
from muster.core.expr.ir import freevars
from muster.core.results import Err, Ok, Result
from muster.core.values.classification import AcquisitionClass, EvidenceLayer
from muster.core.values.scalars import sort_of, value_in_domain
from muster.core.values.sorts import EnumDomain, domain_is_finite
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import encode
from muster.policy.entailment import check_binders_are_disjoint
from muster.policy.manifest import LoadedBundle
from muster.policy.materialise import materialise
from muster.policy.predicates import PredicateSpec, validate_predicate_schema
from muster.policy.program import compile_program
from muster.solve.verdict import FragmentCapabilities


class PrepareFailure(Enum):
    POLICY_PIN_MISMATCH = "PolicyPinMismatch"
    PREDICATE_SCHEMA_MISMATCH = "PredicateSchemaMismatch"
    INVALID_PREDICATE_SCHEMA = "InvalidPredicateSchema"
    INVALID_ACTION_SCHEMA = "InvalidActionSchema"
    LAYER_FLOW_VIOLATION = "LayerFlowViolation"
    ENTAILMENT_VALIDATION_FAILED = "EntailmentValidationFailed"
    PROGRAM_NOT_CLOSED = "ProgramNotClosed"
    MALFORMED_PROGRAM = "MalformedProgram"
    VALUE_OUT_OF_DOMAIN = "ValueOutOfDomain"
    UNSUPPORTED_DOMAIN = "UnsupportedDomain"
    UNSUPPORTED_FRAGMENT = "UnsupportedFragment"
    UNSUPPORTED_CASE_SIZE = "UnsupportedCaseSize"
    BINDER_SHADOWS_ARGUMENT = "BinderShadowsArgument"


@dataclass(frozen=True, slots=True)
class PrepareRejection:
    failure: PrepareFailure
    detail: str


@dataclass(frozen=True, slots=True)
class EngineLimits:
    """Deterministic bounds on the analysis, supplied by the operator.

    There is no default for ``max_unresolved`` on purpose: absent
    configuration is a startup failure, not an unbounded run.

    A backend's own budget is not here.  It is meaningless to a backend
    that does not enumerate, and the kernel already learns whatever it
    needs about it from ``capabilities()``.
    """

    max_unresolved: int
    reachable_action_cap: int


@dataclass(frozen=True, slots=True)
class PreparedCase:
    """A revision that has been validated against its bundle."""

    revision: CaseRevision
    bundle: LoadedBundle
    specs: dict[SymbolRef, PredicateSpec]
    limits: EngineLimits

    def unresolved(self) -> tuple[SymbolRef, ...]:
        return self.revision.unresolved()


def prepare(
    revision: CaseRevision,
    bundle: LoadedBundle,
    capabilities: FragmentCapabilities,
    limits: EngineLimits,
) -> Result[PreparedCase, PrepareRejection]:
    if revision.bundle_pin != bundle.digest():
        return Err(
            PrepareRejection(
                PrepareFailure.POLICY_PIN_MISMATCH,
                f"revision pins {revision.bundle_pin}, bundle is {bundle.digest()}",
            )
        )

    schema_ok = validate_predicate_schema(bundle.predicate_schema)
    if isinstance(schema_ok, Err):
        return Err(PrepareRejection(PrepareFailure.INVALID_PREDICATE_SCHEMA, str(schema_ok.error)))
    action_ok = validate_action_schema(bundle.action_schema)
    if isinstance(action_ok, Err):
        return Err(PrepareRejection(PrepareFailure.INVALID_ACTION_SCHEMA, str(action_ok.error)))

    binders_ok = check_binders_are_disjoint(bundle.entailment_rules, revision.declared)
    if isinstance(binders_ok, Err):
        return Err(PrepareRejection(PrepareFailure.BINDER_SHADOWS_ARGUMENT, str(binders_ok.error)))

    specs: dict[SymbolRef, PredicateSpec] = {}
    for ref in revision.declared:
        spec = bundle.predicate_schema.spec_for(ref)
        if spec is None:
            #  The schema is authenticated; a declaration it does not describe
            #  is a case asserting a shape the policy authority never approved.
            return Err(PrepareRejection(PrepareFailure.PREDICATE_SCHEMA_MISMATCH, str(ref)))
        if not domain_is_finite(spec.domain) and capabilities.requires_finite_domains:
            return Err(PrepareRejection(PrepareFailure.UNSUPPORTED_DOMAIN, str(ref)))
        specs[ref] = spec

    for fact in revision.established:
        spec = specs.get(fact.ref)
        if spec is None:
            return Err(PrepareRejection(PrepareFailure.PREDICATE_SCHEMA_MISMATCH, str(fact.ref)))
        if sort_of(fact.value) != spec.value_sort or not value_in_domain(fact.value, spec.domain):
            return Err(
                PrepareRejection(PrepareFailure.VALUE_OUT_OF_DOMAIN, f"{fact.ref} = {fact.value}")
            )

    layered = _check_layer_flow(revision, specs)
    if isinstance(layered, Err):
        return layered

    entailment = _check_entailment(revision, bundle, specs)
    if isinstance(entailment, Err):
        return entailment

    closed = _check_program_closure(revision, bundle)
    if isinstance(closed, Err):
        return closed

    sorts = {ref: spec.value_sort for ref, spec in specs.items()}
    enum_domains = {
        ref: spec.domain for ref, spec in specs.items() if isinstance(spec.domain, EnumDomain)
    }
    compiled = compile_program(bundle.program, bundle.action_schema, sorts, enum_domains)
    if isinstance(compiled, Err):
        return Err(PrepareRejection(PrepareFailure.MALFORMED_PROGRAM, str(compiled.error)))

    unresolved = revision.unresolved()
    if len(unresolved) > limits.max_unresolved:
        #  Told, not timed out. A silent timeout is the worst available answer.
        return Err(
            PrepareRejection(
                PrepareFailure.UNSUPPORTED_CASE_SIZE,
                f"{len(unresolved)} unresolved variables exceeds the permitted "
                f"{limits.max_unresolved}",
            )
        )

    if capabilities.max_enumerated_assignments < 1:
        return Err(PrepareRejection(PrepareFailure.UNSUPPORTED_FRAGMENT, "backend has no budget"))

    return Ok(PreparedCase(revision, bundle, specs, limits))


def _check_layer_flow(
    revision: CaseRevision, specs: dict[SymbolRef, PredicateSpec]
) -> Result[None, PrepareRejection]:
    """Which justification may carry which layer, and which derivation may
    mention one.

    Two halves, and both are needed.  The *fact* half is the original barrier: a
    normative proposition may only be justified by an entailment, and a derived
    proposition may not be attested at all.  The *constraint* half closes the
    bypass that made the first half illusory -- restricting justifications alone
    leaves the constraint channel open, so a caller could submit
    ``shift_payable_under_policy(Sat) = true`` as a well-typed constraint, keep
    the established set clean, and still force the payment in every admissible
    world.
    """
    for fact in revision.established:
        spec = specs.get(fact.ref)
        if spec is None:  # pragma: no cover - checked before this point
            continue
        attested = not isinstance(fact.justification, EntailedBy)
        if not attested:
            continue
        if spec.layer is EvidenceLayer.NORMATIVE:
            return Err(
                PrepareRejection(
                    PrepareFailure.LAYER_FLOW_VIOLATION,
                    f"{fact.ref} is NORMATIVE and cannot be attested by anyone",
                )
            )
        if spec.acquisition is not AcquisitionClass.ATTESTABLE:
            return Err(
                PrepareRejection(
                    PrepareFailure.LAYER_FLOW_VIOLATION,
                    f"{fact.ref} is DERIVED and cannot be attested",
                )
            )

    for constraint in revision.constraints:
        mentions_normative = any(
            specs[ref].layer is EvidenceLayer.NORMATIVE
            for ref in freevars(constraint.formula)
            if ref in specs
        )
        if mentions_normative and not isinstance(constraint.derivation, PolicyEntailmentDeriv):
            return Err(
                PrepareRejection(
                    PrepareFailure.LAYER_FLOW_VIOLATION,
                    f"{constraint.label} mentions a normative variable "
                    f"with derivation {type(constraint.derivation).__name__}",
                )
            )
    return Ok(None)


def _check_entailment(
    revision: CaseRevision,
    bundle: LoadedBundle,
    specs: dict[SymbolRef, PredicateSpec],
) -> Result[None, PrepareRejection]:
    """Re-derive every normative artifact from the pinned bundle and compare.

    Validation is recomputation, not inspection.  A forged ``EntailedBy`` names
    a rule that resolves and premises that exist, so checking the shape proves
    nothing; reproducing the exact octets from the authenticated rules and the
    attested facts proves everything the mode claims.
    """
    attested = tuple(
        fact for fact in revision.established if not isinstance(fact.justification, EntailedBy)
    )
    derived = tuple(
        fact for fact in revision.established if isinstance(fact.justification, EntailedBy)
    )

    for fact in derived:
        justification = fact.justification
        if not isinstance(justification, EntailedBy):  # pragma: no cover - filtered above
            continue
        if justification.manifest_digest != revision.bundle_pin:
            return Err(
                PrepareRejection(
                    PrepareFailure.ENTAILMENT_VALIDATION_FAILED,
                    f"{fact.ref} cites manifest {justification.manifest_digest}",
                )
            )
        spec = specs.get(fact.ref)
        if spec is None or spec.layer is not EvidenceLayer.NORMATIVE:
            return Err(
                PrepareRejection(
                    PrepareFailure.ENTAILMENT_VALIDATION_FAILED,
                    f"{fact.ref} is entailed but not normative",
                )
            )

    known = {fact.ref: fact.value for fact in attested}
    known_facts = {fact.ref: fact for fact in attested}
    recomputed = materialise(
        rules=bundle.entailment_rules,
        declared=revision.declared,
        known=known,
        known_facts=known_facts,
        schema=bundle.predicate_schema,
        manifest_digest=revision.bundle_pin,
    )
    if isinstance(recomputed, Err):
        return Err(
            PrepareRejection(PrepareFailure.ENTAILMENT_VALIDATION_FAILED, str(recomputed.error))
        )

    if _octets(derived) != _octets(recomputed.value.facts):
        return Err(
            PrepareRejection(
                PrepareFailure.ENTAILMENT_VALIDATION_FAILED,
                "entailed facts do not reproduce from the pinned bundle",
            )
        )

    carried = tuple(
        constraint
        for constraint in revision.constraints
        if isinstance(constraint.derivation, PolicyEntailmentDeriv)
    )
    if _octets(carried) != _octets(recomputed.value.constraints):
        return Err(
            PrepareRejection(
                PrepareFailure.ENTAILMENT_VALIDATION_FAILED,
                "entailment constraints do not reproduce from the pinned bundle",
            )
        )

    return Ok(None)


def _check_program_closure(
    revision: CaseRevision, bundle: LoadedBundle
) -> Result[None, PrepareRejection]:
    declared = set(revision.declared)
    missing = sorted(str(ref) for ref in bundle.program.free_symbols() - declared)
    if missing:
        #  A static property of the case, not something to discover with a
        #  tautological sufficiency query at analysis time.
        return Err(PrepareRejection(PrepareFailure.PROGRAM_NOT_CLOSED, ", ".join(missing)))
    return Ok(None)


def _octets(items: tuple[EstablishedFact, ...] | tuple[Constraint, ...]) -> tuple[bytes, ...]:
    return tuple(sorted(encode(item.to_node()) for item in items))
