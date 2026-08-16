"""Entailment materialisation: the single pass, with an explicit derivation mode.

For each normative conclusion the pass looks at *every* rule concluding it, and
the mode it records selects which check a validator must later run.  That is the
correction: one materialiser with two behaviours needs two validations, and the
Phase-0.7 version demanded recomputing an open disjunction it could not evaluate.

    IMPLICATION GROUP
      fired rules agree on a value          -> FACT,       RULE_FIRED
      a rule is not yet evaluable           -> CONSTRAINT  premise -> (c = value)

    DEFINITION GROUP
      every rule closed                     -> FACT,       FULL_EVALUATION
      some closed rule's premise is true    -> FACT true,  WITNESS_DISJUNCT
      otherwise                             -> CONSTRAINT  c <-> (or of premises)

``WITNESS_DISJUNCT`` cites the *complete* set of evaluable-true rules, so there
is no "pick one" ambiguity and no claim at all about the rules it does not cite.

One pass suffices, and not by assumption: a premise may only be OBSERVATION or
RECORD (E-7), so no normative conclusion can be another rule's premise and there
is nothing for a second pass to discover.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from muster.core.case.constraints import Constraint, PolicyEntailmentDeriv
from muster.core.case.facts import DerivationMode, EntailedBy, EstablishedFact, Modality
from muster.core.case.labels import constraint_label
from muster.core.expr.evaluate import evaluate, evaluate_bool
from muster.core.expr.ir import Binary, BinaryOp, Leaf, NAry, NAryOp
from muster.core.expr.terms import Term
from muster.core.results import Err, Ok, Result
from muster.core.values.classification import EvidenceLayer
from muster.core.values.scalars import Value, VBool
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import NAtom
from muster.policy.entailment import (
    DefinitionRule,
    EntailmentRules,
    Instance,
    instantiate,
    modality_of,
    premise_symbols,
    rule_id_of,
)
from muster.policy.predicates import PredicateSchema

LABEL_PREFIX_ENTAILMENT = "C-ENT"


class MaterialisationFailure(Enum):
    NORMATIVE_DERIVATION_CONFLICT = "NORMATIVE_DERIVATION_CONFLICT"
    MODALITY_CONFLICT = "MODALITY_CONFLICT"
    EVALUATION_STUCK = "EVALUATION_STUCK"
    PREMISE_NOT_BOOLEAN = "PREMISE_NOT_BOOLEAN"
    CONCLUSION_NOT_NORMATIVE = "CONCLUSION_NOT_NORMATIVE"
    PREMISE_IS_NORMATIVE = "PREMISE_IS_NORMATIVE"
    UNKNOWN_PREDICATE = "UNKNOWN_PREDICATE"


@dataclass(frozen=True, slots=True)
class MaterialisationError:
    failure: MaterialisationFailure
    detail: str


@dataclass(frozen=True, slots=True)
class Materialisation:
    facts: tuple[EstablishedFact, ...]
    constraints: tuple[Constraint, ...]


def materialise(
    *,
    rules: EntailmentRules,
    declared: tuple[SymbolRef, ...],
    known: Mapping[SymbolRef, Value],
    known_facts: Mapping[SymbolRef, EstablishedFact],
    schema: PredicateSchema,
    manifest_digest: Digest,
) -> Result[Materialisation, MaterialisationError]:
    """Run the pass over every declared normative conclusion."""
    groups = _group_by_conclusion(rules, declared)
    facts: list[EstablishedFact] = []
    constraints: list[Constraint] = []

    for conclusion in sorted(groups, key=lambda ref: encode(ref.to_node())):
        group = groups[conclusion]
        checked = _check_group_layers(group, conclusion, schema)
        if isinstance(checked, Err):
            return checked

        modalities = {modality_of(instance.rule) for instance in group}
        if len(modalities) != 1:
            return Err(
                MaterialisationError(MaterialisationFailure.MODALITY_CONFLICT, str(conclusion))
            )

        produced = (
            _implication_group(group, conclusion, known, known_facts, manifest_digest)
            if modalities == {Modality.IMPLICATION}
            else _definition_group(group, conclusion, known, known_facts, manifest_digest)
        )
        if isinstance(produced, Err):
            return produced
        facts.extend(produced.value.facts)
        constraints.extend(produced.value.constraints)

    return Ok(Materialisation(tuple(facts), tuple(constraints)))


def _group_by_conclusion(
    rules: EntailmentRules, declared: tuple[SymbolRef, ...]
) -> dict[SymbolRef, list[Instance]]:
    groups: dict[SymbolRef, list[Instance]] = {}
    for rule in rules.rules:
        for ref in declared:
            bound = instantiate(rule, ref)
            if isinstance(bound, Err):
                continue
            groups.setdefault(ref, []).append(bound.value)
    return groups


def _check_group_layers(
    group: list[Instance], conclusion: SymbolRef, schema: PredicateSchema
) -> Result[None, MaterialisationError]:
    """E-6 and E-7, checked before anything is derived rather than after."""
    spec = schema.spec_for(conclusion)
    if spec is None:
        return Err(MaterialisationError(MaterialisationFailure.UNKNOWN_PREDICATE, str(conclusion)))
    if spec.layer is not EvidenceLayer.NORMATIVE:
        return Err(
            MaterialisationError(MaterialisationFailure.CONCLUSION_NOT_NORMATIVE, str(conclusion))
        )
    for instance in group:
        for premise_ref in premise_symbols(instance):
            premise_spec = schema.spec_for(premise_ref)
            if premise_spec is None:
                return Err(
                    MaterialisationError(MaterialisationFailure.UNKNOWN_PREDICATE, str(premise_ref))
                )
            if premise_spec.layer is EvidenceLayer.NORMATIVE:
                #  A normative premise would make entailment chain, and would
                #  make one pass incomplete.  It is forbidden, so it is not.
                return Err(
                    MaterialisationError(
                        MaterialisationFailure.PREMISE_IS_NORMATIVE, str(premise_ref)
                    )
                )
    return Ok(None)


def _evaluable(instance: Instance, known: Mapping[SymbolRef, Value]) -> bool:
    return premise_symbols(instance) <= set(known)


def _premise_digests(
    instances: list[Instance], known_facts: Mapping[SymbolRef, EstablishedFact]
) -> tuple[Digest, ...]:
    """``digests(reads(R))``, ascending by digest octets.

    Constructed exactly, from the symbols the cited rules actually read, so two
    implementations cite the same set for the same inputs.
    """
    reads: set[SymbolRef] = set()
    for instance in instances:
        reads |= premise_symbols(instance)
    found = [known_facts[ref].digest() for ref in reads if ref in known_facts]
    return tuple(sorted(found, key=lambda digest: digest.octets))


def _rule_ids(instances: list[Instance]) -> tuple[str, ...]:
    """The cited set, in canonical order -- every collection uses one rule."""
    unique = {rule_id_of(instance.rule) for instance in instances}
    return tuple(sorted(unique, key=lambda rule_id: encode(NAtom(rule_id))))


def _implication_group(
    group: list[Instance],
    conclusion: SymbolRef,
    known: Mapping[SymbolRef, Value],
    known_facts: Mapping[SymbolRef, EstablishedFact],
    manifest_digest: Digest,
) -> Result[Materialisation, MaterialisationError]:
    fired: list[Instance] = []
    deferred: list[Instance] = []
    for instance in group:
        if not _evaluable(instance, known):
            deferred.append(instance)
            continue
        holds = evaluate_bool(instance.premise, known)
        if isinstance(holds, Err):
            return Err(
                MaterialisationError(MaterialisationFailure.PREMISE_NOT_BOOLEAN, str(holds.error))
            )
        if holds.value:
            fired.append(instance)

    facts: list[EstablishedFact] = []
    constraints: list[Constraint] = []

    if fired:
        values: dict[bytes, Value] = {}
        for instance in fired:
            if instance.conclusion_value is None:  # pragma: no cover - modality guarantees it
                continue
            produced = evaluate(instance.conclusion_value, known)
            if isinstance(produced, Err):
                return Err(
                    MaterialisationError(
                        MaterialisationFailure.EVALUATION_STUCK, str(produced.error)
                    )
                )
            values[encode(produced.value.to_node())] = produced.value
        if len(values) > 1:
            #  Two rules that both fired and disagree is a policy defect, and
            #  picking either one would hide it behind a plausible answer.
            return Err(
                MaterialisationError(
                    MaterialisationFailure.NORMATIVE_DERIVATION_CONFLICT,
                    f"{conclusion}: {len(values)} distinct values",
                )
            )
        value = next(iter(values.values()))
        facts.append(
            EstablishedFact(
                conclusion,
                value,
                EntailedBy(
                    manifest_digest,
                    Modality.IMPLICATION,
                    DerivationMode.RULE_FIRED,
                    _rule_ids(fired),
                    _premise_digests(fired, known_facts),
                ),
            )
        )

    for instance in deferred:
        if instance.conclusion_value is None:  # pragma: no cover - modality guarantees it
            continue
        constraints.append(
            Constraint(
                #  One deferred rule per constraint, so the label carries the
                #  rule id: two rules concluding the same variable must not
                #  collide on a label the revision requires to be unique.
                constraint_label(
                    f"{LABEL_PREFIX_ENTAILMENT}-{rule_id_of(instance.rule)}", conclusion
                ),
                Binary(
                    BinaryOp.IMPLIES,
                    instance.premise,
                    Binary(BinaryOp.EQ, Leaf(conclusion), instance.conclusion_value),
                ),
                PolicyEntailmentDeriv(
                    manifest_digest,
                    Modality.IMPLICATION,
                    (rule_id_of(instance.rule),),
                    None,
                ),
            )
        )

    return Ok(Materialisation(tuple(facts), tuple(constraints)))


def _definition_group(
    group: list[Instance],
    conclusion: SymbolRef,
    known: Mapping[SymbolRef, Value],
    known_facts: Mapping[SymbolRef, EstablishedFact],
    manifest_digest: Digest,
) -> Result[Materialisation, MaterialisationError]:
    evaluable = [instance for instance in group if _evaluable(instance, known)]

    if len(evaluable) == len(group):
        holds = False
        for instance in group:
            outcome = evaluate_bool(instance.premise, known)
            if isinstance(outcome, Err):
                return Err(
                    MaterialisationError(
                        MaterialisationFailure.PREMISE_NOT_BOOLEAN, str(outcome.error)
                    )
                )
            holds = holds or outcome.value
        return Ok(
            Materialisation(
                (
                    EstablishedFact(
                        conclusion,
                        VBool(holds),
                        EntailedBy(
                            manifest_digest,
                            Modality.DEFINITION,
                            DerivationMode.FULL_EVALUATION,
                            _rule_ids(group),
                            _premise_digests(group, known_facts),
                        ),
                    ),
                ),
                (),
            )
        )

    witnesses: list[Instance] = []
    for instance in evaluable:
        outcome = evaluate_bool(instance.premise, known)
        if isinstance(outcome, Err):
            return Err(
                MaterialisationError(MaterialisationFailure.PREMISE_NOT_BOOLEAN, str(outcome.error))
            )
        if outcome.value:
            witnesses.append(instance)

    if witnesses:
        return Ok(
            Materialisation(
                (
                    EstablishedFact(
                        conclusion,
                        VBool(True),
                        EntailedBy(
                            manifest_digest,
                            Modality.DEFINITION,
                            DerivationMode.WITNESS_DISJUNCT,
                            _rule_ids(witnesses),
                            _premise_digests(witnesses, known_facts),
                        ),
                    ),
                ),
                (),
            )
        )

    #  Nothing is decidable yet, so the definition materialises as a constraint
    #  and the conclusion stays unresolved.  This is the branch that lets a case
    #  close on a lower bound without ever establishing the exact value.
    disjunction = _disjoin([instance.premise for instance in group])
    ratification = _ratification_ref(group)
    return Ok(
        Materialisation(
            (),
            (
                Constraint(
                    constraint_label(LABEL_PREFIX_ENTAILMENT, conclusion),
                    Binary(BinaryOp.IFF, Leaf(conclusion), disjunction),
                    PolicyEntailmentDeriv(
                        manifest_digest,
                        Modality.DEFINITION,
                        _rule_ids(group),
                        ratification,
                    ),
                ),
            ),
        )
    )


def _disjoin(premises: list[Term]) -> Term:
    return premises[0] if len(premises) == 1 else NAry(NAryOp.OR, tuple(premises))


def _ratification_ref(group: list[Instance]) -> Digest | None:
    for instance in group:
        if isinstance(instance.rule, DefinitionRule):
            return instance.rule.exhaustiveness_ratification_ref
    return None
