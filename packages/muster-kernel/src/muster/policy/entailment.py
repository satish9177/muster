"""Entailment rules: the only artifacts permitted to move a normative variable.

Two modalities, and the difference is not cosmetic:

* ``ImplicationRule`` compiles to ``premise -> conclusion``.  It is one-way.
  ``present and scheduled -> worked`` does not license ``not present -> not
  worked``, and compiling it as a biconditional would smuggle in an
  exhaustiveness claim nobody ratified.
* ``DefinitionRule`` compiles to ``c <-> (premise_1 or premise_2 or ...)`` over
  *all* rules concluding ``c``, and only where exhaustiveness has been ratified
  separately, by digest, inside the bundle.

A definition is legitimate exactly when the ratifier is the authority on the
conclusion.  No policy authority is the authority on whether someone worked --
remote work and off-badge work refute any enumeration.  It *is* the authority on
what its own policy pays for.  That is why the workforce conclusion is
``shift_payable_under_policy`` and not ``worked``: the biconditional is a
stipulative definition inside the pinned bundle, which is the only kind of
biconditional a ratifier can honestly sign.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.case.facts import Modality
from muster.core.expr.ir import freevars, map_leaves
from muster.core.expr.terms import Term, term_node
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.symbols import SymbolRef, SymbolRefTemplate
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NInt, Node, NRec, NSeq, NTagged
from muster.core.wire.shape import atoms

TAG_IMPLICATION_RULE = "ImplicationRule/v1"
TAG_DEFINITION_RULE = "DefinitionRule/v1"
TAG_ENTAILMENT_RULES = "EntailmentRules/v1"


@dataclass(frozen=True, slots=True)
class ImplicationRule:
    rule_id: str
    binder_args: tuple[str, ...]
    conclusion: SymbolRefTemplate
    premise: Term
    conclusion_value: Term

    def to_node(self) -> NRec:
        return NRec(
            TAG_IMPLICATION_RULE,
            (
                NAtom(self.rule_id),
                atoms(self.binder_args),
                self.conclusion.to_node(),
                term_node(self.premise),
                term_node(self.conclusion_value),
            ),
        )


@dataclass(frozen=True, slots=True)
class DefinitionRule:
    rule_id: str
    binder_args: tuple[str, ...]
    conclusion: SymbolRefTemplate
    premise: Term
    exhaustiveness_ratification_ref: Digest

    def to_node(self) -> NRec:
        return NRec(
            TAG_DEFINITION_RULE,
            (
                NAtom(self.rule_id),
                atoms(self.binder_args),
                self.conclusion.to_node(),
                term_node(self.premise),
                self.exhaustiveness_ratification_ref.to_node(),
            ),
        )


type EntailmentRule = ImplicationRule | DefinitionRule


def rule_node(rule: EntailmentRule) -> Node:
    match rule:
        case ImplicationRule():
            return NTagged("Implication", rule.to_node())
        case DefinitionRule():
            return NTagged("Definition", rule.to_node())


def rule_id_of(rule: EntailmentRule) -> str:
    return rule.rule_id


def modality_of(rule: EntailmentRule) -> Modality:
    return Modality.IMPLICATION if isinstance(rule, ImplicationRule) else Modality.DEFINITION


@dataclass(frozen=True, slots=True)
class EntailmentRules:
    schema_version: int
    rules: tuple[EntailmentRule, ...]

    def __post_init__(self) -> None:
        ids = [rule_id_of(rule) for rule in self.rules]
        if len(set(ids)) != len(ids):
            raise InvariantViolation("entailment rule ids are unique")

    def to_node(self) -> NRec:
        return NRec(
            TAG_ENTAILMENT_RULES,
            (NInt(self.schema_version), NSeq(tuple(rule_node(rule) for rule in self.rules))),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.ENTAILMENT_RULES, self.to_node())

    def rule(self, rule_id: str) -> EntailmentRule | None:
        for candidate in self.rules:
            if rule_id_of(candidate) == rule_id:
                return candidate
        return None


class BindingFailure(Enum):
    BINDER_SHADOWS_ARGUMENT = "BINDER_SHADOWS_ARGUMENT"
    ARITY_MISMATCH = "ARITY_MISMATCH"
    PREMISE_MENTIONS_BINDER = "PREMISE_MENTIONS_BINDER"


@dataclass(frozen=True, slots=True)
class BindingError:
    failure: BindingFailure
    detail: str


@dataclass(frozen=True, slots=True)
class Instance:
    """One rule under one binding of its binders to concrete arguments."""

    rule: EntailmentRule
    conclusion: SymbolRef
    premise: Term
    conclusion_value: Term | None


def instantiate(rule: EntailmentRule, conclusion: SymbolRef) -> Result[Instance, BindingError]:
    """Bind a rule's binders positionally against a concrete conclusion.

    Substitution is exact-match on binder name in argument position.  The
    ambiguity that would otherwise create -- an argument atom that happens to
    equal a binder name -- is removed mechanically by
    :func:`check_binders_are_disjoint`, not left to naming discipline.
    """
    template = rule.conclusion
    if template.predicate_id != conclusion.predicate_id or len(template.args_or_binders) != len(
        conclusion.args
    ):
        return Err(BindingError(BindingFailure.ARITY_MISMATCH, str(conclusion)))

    binding: dict[str, str] = {}
    for position, slot in enumerate(template.args_or_binders):
        argument = conclusion.args[position]
        if slot in rule.binder_args:
            if binding.setdefault(slot, argument) != argument:
                return Err(BindingError(BindingFailure.ARITY_MISMATCH, str(conclusion)))
        elif slot != argument:
            return Err(BindingError(BindingFailure.ARITY_MISMATCH, str(conclusion)))

    premise = substitute(rule.premise, binding)
    value = (
        substitute(rule.conclusion_value, binding) if isinstance(rule, ImplicationRule) else None
    )
    residual = [ref for ref in freevars(premise) if set(ref.args) & set(rule.binder_args)]
    if residual:
        return Err(
            BindingError(BindingFailure.PREMISE_MENTIONS_BINDER, str(sorted(map(str, residual))))
        )
    return Ok(Instance(rule, conclusion, premise, value))


def substitute(term: Term, binding: dict[str, str]) -> Term:
    """Replace binder names in every leaf's argument positions."""
    return map_leaves(
        term, lambda ref: SymbolRef(ref.predicate_id, tuple(binding.get(a, a) for a in ref.args))
    )


def check_binders_are_disjoint(
    rules: EntailmentRules, declared: tuple[SymbolRef, ...]
) -> Result[EntailmentRules, BindingError]:
    """No declared instance may use an argument atom that is also a binder name.

    Substitution is by name, so an overlap would make one signed bundle
    instantiate two different ways.  Rejecting the overlap at load time is
    cheaper than carrying a scoping discipline nobody can check by reading.
    """
    binders = {binder for rule in rules.rules for binder in rule.binder_args}
    for ref in declared:
        clash = set(ref.args) & binders
        if clash:
            return Err(
                BindingError(BindingFailure.BINDER_SHADOWS_ARGUMENT, f"{ref}: {sorted(clash)}")
            )
    return Ok(rules)


def premise_symbols(instance: Instance) -> frozenset[SymbolRef]:
    """``reads(r)`` -- every symbol the rule consults for this binding.

    The conclusion value counts for an implication, and does not exist for a
    definition, which is exactly why the two modalities cite different premise
    sets.
    """
    found = freevars(instance.premise)
    if instance.conclusion_value is not None:
        found |= freevars(instance.conclusion_value)
    return found
