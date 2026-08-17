"""The logical projection of a case -- the only thing the kernel receives.

Principals, claims, roles, evidence layers, acquisition classes, source classes
and interest do not cross this boundary.  What crosses is symbols, sorts,
domains, established values, formulas and opaque assertion identifiers.  Not
branching on provenance is not the same as not receiving it, so the kernel does
not receive it.

**Sorts and domains are not fields of this record.**  They are determined by
``predicate_schema_digest``, which is: the schema is authenticated, a case may
not choose a sort for a predicate, and ``prepare`` rejects any declaration that
does not match the pinned schema exactly.  So the digest binds the sorts of
every symbol in ``universe`` transitively, and carrying them again would let two
values of this record disagree about one predicate.  The in-memory
``ProjectedCase`` that the oracle consumes pairs this record with the
declarations resolved from that schema.

Constraint labels are unique here, as they are in the revision this is projected
from.  They have to be: the encoder turns each one into an assertion label, and
a query cannot carry two assertions under one label.  Stating the rule on the
value that carries the constraints, rather than only where a query is finally
assembled, is what keeps the failure next to the mistake -- and it is why
duplicate labels reaching a solver query is a programmer defect rather than
something case data can cause.  Case data meets the same rule far earlier:
``rebuild`` reports a repeated label as a typed ``DuplicateConstraintLabel``
value on the public path, and ``CaseRevision`` refuses to hold one at all.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.case.constraints import Constraint, constraint_seq
from muster.core.case.facts import EstablishedFact, fact_seq
from muster.core.results import InvariantViolation
from muster.core.values.scalars import Value
from muster.core.values.symbols import SymbolRef, symbol_seq
from muster.core.wire.codec import is_canonically_ordered
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NRec

TAG_LOGICAL_CASE = "LogicalCase/v1"


@dataclass(frozen=True, slots=True)
class LogicalCase:
    universe: tuple[SymbolRef, ...]
    known: tuple[EstablishedFact, ...]
    constraints: tuple[Constraint, ...]
    decision_program_digest: Digest
    action_schema_digest: Digest
    predicate_schema_digest: Digest

    def __post_init__(self) -> None:
        declared = set(self.universe)
        for fact in self.known:
            if fact.ref not in declared:
                raise InvariantViolation(f"{fact.ref} is established but not declared")
        if not is_canonically_ordered(self.universe, lambda ref: ref.to_node()):
            raise InvariantViolation("universe is not in canonical order")
        if not is_canonically_ordered(self.known, lambda fact: fact.to_node()):
            raise InvariantViolation("known facts are not in canonical order")
        if not is_canonically_ordered(self.constraints, lambda item: item.to_node()):
            raise InvariantViolation("constraints are not in canonical order")
        labels = [constraint.label for constraint in self.constraints]
        if len(set(labels)) != len(labels):
            raise InvariantViolation("constraint labels are unique within a logical case")

    def to_node(self) -> NRec:
        return NRec(
            TAG_LOGICAL_CASE,
            (
                symbol_seq(self.universe),
                fact_seq(self.known),
                constraint_seq(self.constraints),
                self.decision_program_digest.to_node(),
                self.action_schema_digest.to_node(),
                self.predicate_schema_digest.to_node(),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.LOGICAL_CASE, self.to_node())

    def assignment(self) -> dict[SymbolRef, Value]:
        return {fact.ref: fact.value for fact in self.known}

    def unresolved(self) -> tuple[SymbolRef, ...]:
        settled = {fact.ref for fact in self.known}
        return tuple(ref for ref in self.universe if ref not in settled)
