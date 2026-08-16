"""Projecting a prepared case into what the kernel is allowed to see.

Layer, acquisition class, permitted source classes, and every trace of who said
what stay on this side of the boundary.  What crosses is symbols, sorts,
domains, established values, formulas and digests.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.actions import ActionSchema
from muster.core.analysis.logical_case import LogicalCase
from muster.core.results import InvariantViolation
from muster.core.values.sorts import Domain, Sort
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import canonical_order
from muster.hinge.prepare import PreparedCase
from muster.policy.program import DecisionProgram


@dataclass(frozen=True, slots=True)
class SymbolDeclaration:
    """A symbol's logical shape. Nothing about where its value would come from."""

    ref: SymbolRef
    sort: Sort
    domain: Domain


@dataclass(frozen=True, slots=True)
class ProjectedCase:
    """The kernel's input: a logical case plus the declarations it presupposes.

    The declarations are not a second source of truth.  They are resolved from
    the predicate schema whose digest the logical case already pins, so the
    identity of the case determines them and carrying them here is a convenience
    for the encoder rather than an additional input.
    """

    logical: LogicalCase
    declarations: tuple[SymbolDeclaration, ...]
    program: DecisionProgram
    action_schema: ActionSchema

    def __post_init__(self) -> None:
        #  The logical case names the policy by digest; these two fields
        #  are the policy itself. Nothing downstream re-checks that they
        #  correspond, so a mismatched pair would produce a certificate
        #  claiming an action is invariant under policy P while every
        #  query and every evaluation ran against P'.
        if self.program.digest() != self.logical.decision_program_digest:
            raise InvariantViolation("the projected program is not the one the logical case pins")
        if self.action_schema.digest() != self.logical.action_schema_digest:
            raise InvariantViolation(
                "the projected action schema is not the one the logical case pins"
            )

    def unresolved(self) -> tuple[SymbolRef, ...]:
        return self.logical.unresolved()


def project(prepared: PreparedCase) -> ProjectedCase:
    revision = prepared.revision
    bundle = prepared.bundle
    declarations = canonical_order(
        (
            SymbolDeclaration(ref, spec.value_sort, spec.domain)
            for ref, spec in prepared.specs.items()
        ),
        lambda declaration: declaration.ref.to_node(),
    )
    logical = LogicalCase(
        universe=revision.declared,
        known=revision.established,
        constraints=revision.constraints,
        decision_program_digest=bundle.program.digest(),
        action_schema_digest=bundle.action_schema.digest(),
        predicate_schema_digest=bundle.predicate_schema.digest(),
    )
    return ProjectedCase(logical, declarations, bundle.program, bundle.action_schema)
