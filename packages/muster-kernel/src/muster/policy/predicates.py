"""The authenticated predicate schema.

Sort, domain, layer, acquisition class and permitted source classes are declared
*here*, inside the signed bundle -- never by whoever builds a case.  Without
that, a case builder could label ``shift_payable_under_policy`` as a
RECORD/ATTESTABLE predicate and a generic kernel would have no way to detect the
lie.  ``prepare`` rejects any case declaration that does not match this schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.results import Err, Ok, Result
from muster.core.values.classification import AcquisitionClass, EvidenceLayer
from muster.core.values.sorts import Domain, Sort, domain_matches_sort
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import canonical_set
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NInt, NRec, NSeq
from muster.core.wire.shape import atom_or_none, atoms, option_node

TAG_PREDICATE_SPEC = "PredicateSpec/v1"
TAG_PREDICATE_SCHEMA = "PredicateSchema/v1"


@dataclass(frozen=True, slots=True)
class PredicateSpec:
    """One predicate, as the signed bundle declares it.

    ``resource_scope_kinds`` is the milestone-E addition and it is the input to
    Q-12(d): the kinds of resource an authority grant over this predicate must
    enumerate.  It is declared here, per predicate, because that is what the
    ratified check reads -- coordinates come "from the bundle's declared
    ``arg_kinds`` **for the predicate**, and from the signed
    ``CaseConstructionRecord`` for case-level coordinates".

    Resolution is mechanical.  For each declared kind, if the predicate's own
    argument list carries it, the value is the argument -- so
    ``accepted_quantity(PO-4471)`` scoped by ``PURCHASE_ORDER`` needs a grant
    over that exact purchase order.  If it does not, the value comes from the
    case's own coordinates -- so ``present_on_site(RAVI, SAT)`` scoped by
    ``SITE`` needs a grant over the site the officer wrote into the
    construction record.  If neither supplies it, **the coordinate is
    undeterminable and authority is refused**; there is no reading in which a
    missing coordinate means "any".

    Declaring it per predicate rather than per bundle is what keeps the layer
    generic.  A payroll system is scoped by employer and a badge reader by
    site, in one bundle, without either scoping rule appearing in code.
    """

    predicate_id: str
    arg_kinds: tuple[str, ...]
    value_sort: Sort
    domain: Domain
    layer: EvidenceLayer
    acquisition: AcquisitionClass
    permitted_source_classes: tuple[str, ...]
    resource_scope_kinds: tuple[str, ...] = ()
    measurement_class: str | None = None

    def to_node(self) -> NRec:
        return NRec(
            TAG_PREDICATE_SPEC,
            (
                NAtom(self.predicate_id),
                atoms(self.arg_kinds),
                self.value_sort.to_node(),
                self.domain.to_node(),
                NAtom(self.layer.value),
                NAtom(self.acquisition.value),
                canonical_set(NAtom(source) for source in self.permitted_source_classes),
                canonical_set(NAtom(kind) for kind in self.resource_scope_kinds),
                option_node(atom_or_none(self.measurement_class)),
            ),
        )


class SchemaFailure(Enum):
    DUPLICATE_PREDICATE = "DUPLICATE_PREDICATE"
    DOMAIN_SORT_MISMATCH = "DOMAIN_SORT_MISMATCH"
    NORMATIVE_IS_ATTESTABLE = "NORMATIVE_IS_ATTESTABLE"
    ATTESTABLE_WITHOUT_SOURCE = "ATTESTABLE_WITHOUT_SOURCE"
    DERIVED_WITH_SOURCE = "DERIVED_WITH_SOURCE"
    #  An attestable predicate that declares no resource scope kind could never
    #  be authorized -- Q-12(d) refuses an empty coordinate set -- so a bundle
    #  declaring one is declaring a predicate no source can ever attest.  Caught
    #  when the bundle loads rather than as a silent per-receipt refusal.
    ATTESTABLE_WITHOUT_RESOURCE_SCOPE = "ATTESTABLE_WITHOUT_RESOURCE_SCOPE"
    #  The mirror of ``DERIVED_WITH_SOURCE``: a derived predicate carrying an
    #  authority-shaped field that nothing will ever read.
    DERIVED_WITH_RESOURCE_SCOPE = "DERIVED_WITH_RESOURCE_SCOPE"
    DUPLICATE_RESOURCE_SCOPE_KIND = "DUPLICATE_RESOURCE_SCOPE_KIND"


@dataclass(frozen=True, slots=True)
class SchemaError:
    failure: SchemaFailure
    detail: str


@dataclass(frozen=True, slots=True)
class PredicateSchema:
    schema_version: int
    predicates: tuple[PredicateSpec, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_PREDICATE_SCHEMA,
            (
                NInt(self.schema_version),
                NSeq(tuple(spec.to_node() for spec in self.predicates)),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.PREDICATE_SCHEMA, self.to_node())

    def spec(self, predicate_id: str) -> PredicateSpec | None:
        for candidate in self.predicates:
            if candidate.predicate_id == predicate_id:
                return candidate
        return None

    def spec_for(self, ref: SymbolRef) -> PredicateSpec | None:
        found = self.spec(ref.predicate_id)
        if found is None or len(found.arg_kinds) != len(ref.args):
            return None
        return found


def validate_predicate_schema(schema: PredicateSchema) -> Result[PredicateSchema, SchemaError]:
    """Reject a schema that could not carry the barrier it exists to carry."""
    seen: set[str] = set()
    for spec in schema.predicates:
        if spec.predicate_id in seen:
            return Err(SchemaError(SchemaFailure.DUPLICATE_PREDICATE, spec.predicate_id))
        seen.add(spec.predicate_id)

        if not domain_matches_sort(spec.domain, spec.value_sort):
            return Err(SchemaError(SchemaFailure.DOMAIN_SORT_MISMATCH, spec.predicate_id))

        #  The barrier, in the schema rather than in a runtime check: a
        #  normative conclusion is DERIVED, so no evidence target can name it
        #  and no attestation can carry it.
        if (
            spec.layer is EvidenceLayer.NORMATIVE
            and spec.acquisition is AcquisitionClass.ATTESTABLE
        ):
            return Err(SchemaError(SchemaFailure.NORMATIVE_IS_ATTESTABLE, spec.predicate_id))

        if spec.acquisition is AcquisitionClass.ATTESTABLE and not spec.permitted_source_classes:
            return Err(SchemaError(SchemaFailure.ATTESTABLE_WITHOUT_SOURCE, spec.predicate_id))

        if spec.acquisition is AcquisitionClass.DERIVED and spec.permitted_source_classes:
            #  A derived predicate with permitted sources is a contradiction
            #  that would eventually be read as permission by something.
            return Err(SchemaError(SchemaFailure.DERIVED_WITH_SOURCE, spec.predicate_id))

        if spec.acquisition is AcquisitionClass.ATTESTABLE and not spec.resource_scope_kinds:
            return Err(
                SchemaError(SchemaFailure.ATTESTABLE_WITHOUT_RESOURCE_SCOPE, spec.predicate_id)
            )

        if spec.acquisition is AcquisitionClass.DERIVED and spec.resource_scope_kinds:
            return Err(SchemaError(SchemaFailure.DERIVED_WITH_RESOURCE_SCOPE, spec.predicate_id))

        if len(set(spec.resource_scope_kinds)) != len(spec.resource_scope_kinds):
            return Err(SchemaError(SchemaFailure.DUPLICATE_RESOURCE_SCOPE_KIND, spec.predicate_id))

    return Ok(schema)
