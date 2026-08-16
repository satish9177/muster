"""One encoded specimen of every wire type this milestone produces.

Used to check tags and arities against the frozen inventory by reading them
back out of real octets, rather than against a table somebody typed.
"""

from __future__ import annotations

from collections.abc import Iterator

from muster.core.evidence.relations import (
    ClosedLowerBound,
    ClosedUpperBound,
    EnumSubset,
    ExactValue,
    relation_node,
)
from muster.core.evidence.transcript import entry_node
from muster.core.values.scalars import VEnum, VInt
from muster.core.wire.nodes import Node
from muster.hinge.encode import feasibility_query, sufficiency_query
from tests.support import ravi


def every_specimen() -> Iterator[Node]:
    """Encoded specimens, covering the bundle, the case and the analysis."""
    bundle = ravi.bundle()
    yield bundle.signed_manifest.to_node()
    yield bundle.program.to_node()
    yield bundle.entailment_rules.to_node()
    yield bundle.predicate_schema.to_node()
    yield bundle.action_schema.to_node()
    yield bundle.admissibility_descriptors.to_node()
    yield bundle.disclosure_policy.to_node()
    yield bundle.ratifications.to_node()

    case = ravi.case_file()
    yield case.construction.to_node()
    yield case.authorization_context.to_node()
    for entry in case.entries:
        yield entry_node(entry)

    analysis = ravi.analysis()
    yield analysis.revision.to_node()
    yield analysis.certificate.to_node()
    yield analysis.projected.logical.to_node()
    yield feasibility_query(analysis.projected).to_node()
    yield sufficiency_query(
        analysis.projected, frozenset(analysis.projected.unresolved()[:1])
    ).to_node()

    #  Relation variants the Ravi transcript does not exercise. The lowering
    #  table is complete, so the types are too.
    yield relation_node(ExactValue(VInt(1)))
    yield relation_node(ClosedLowerBound(VInt(1)))
    yield relation_node(ClosedUpperBound(VInt(2)))
    yield relation_node(EnumSubset((VEnum("colour", "RED"), VEnum("colour", "BLUE"))))
