"""Actions and the action schema.

Structural equality of payloads is not action equality.  A constant payment
carrying a diagnostic memo that varies with an unresolved quantity would read as
divergent although the executor ignores the memo; two structurally equal
payloads can execute differently under different executor defaults.  So the
schema declares, per kind, which fields are *consequential*, and equality is
tag equality plus equality of the consequential fields only --
:func:`consequential_of` is where that projection happens, once.

An ``Action`` always carries every declared field of its kind, in declared
order: an absent optional takes its declared default, and failing that the
derived filler.  "Absent" therefore has one representation rather than two.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.scalars import (
    Value,
    derived_filler,
    render,
    sort_of,
    value_in_domain,
    value_node,
)
from muster.core.values.sorts import Domain, Sort, domain_matches_sort
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NBool, NInt, NRec, NSeq
from muster.core.wire.shape import option_node

TAG_ACTION_FIELD = "ActionField/v1"
TAG_ACTION = "Action/v1"
TAG_CONSEQUENTIAL_ACTION = "ConsequentialAction/v1"
TAG_FIELD_SPEC = "FieldSpec/v1"
TAG_ACTION_KIND_SPEC = "ActionKindSpec/v1"
TAG_ACTION_SCHEMA = "ActionSchema/v1"


class Consequentiality(Enum):
    CONSEQUENTIAL = "CONSEQUENTIAL"
    DIAGNOSTIC = "DIAGNOSTIC"


@dataclass(frozen=True, slots=True)
class ActionField:
    name: str
    value: Value

    def to_node(self) -> NRec:
        return NRec(TAG_ACTION_FIELD, (NAtom(self.name), self.value.to_node()))


@dataclass(frozen=True, slots=True)
class Action:
    """A complete description of what would be done. Never an instruction."""

    kind: str
    fields: tuple[ActionField, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACTION,
            (NAtom(self.kind), NSeq(tuple(field.to_node() for field in self.fields))),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.ACTION, self.to_node())


@dataclass(frozen=True, slots=True)
class ConsequentialAction:
    """The projection actions are compared by.

    It carries the schema digest it was projected under, so two projections made
    under different schema versions are different values rather than
    accidentally equal ones.
    """

    action_schema_digest: Digest
    kind: str
    consequential_fields: tuple[ActionField, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_CONSEQUENTIAL_ACTION,
            (
                self.action_schema_digest.to_node(),
                NAtom(self.kind),
                NSeq(tuple(field.to_node() for field in self.consequential_fields)),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.CONSEQUENTIAL_ACTION, self.to_node())

    def render(self) -> str:
        rendered = ", ".join(
            f"{field.name}={render(field.value)}" for field in self.consequential_fields
        )
        return f"{self.kind}({rendered})"


@dataclass(frozen=True, slots=True)
class FieldSpec:
    name: str
    sort: Sort
    bounds: Domain
    consequentiality: Consequentiality
    required: bool
    default: Value | None = None

    def to_node(self) -> NRec:
        return NRec(
            TAG_FIELD_SPEC,
            (
                NAtom(self.name),
                self.sort.to_node(),
                self.bounds.to_node(),
                NAtom(self.consequentiality.value),
                NBool(self.required),
                option_node(None if self.default is None else value_node(self.default)),
            ),
        )

    def filler(self) -> Value:
        return self.default if self.default is not None else derived_filler(self.sort, self.bounds)


@dataclass(frozen=True, slots=True)
class ActionKindSpec:
    kind: str
    fields: tuple[FieldSpec, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACTION_KIND_SPEC,
            (NAtom(self.kind), NSeq(tuple(spec.to_node() for spec in self.fields))),
        )

    def consequential(self) -> tuple[FieldSpec, ...]:
        return tuple(
            spec for spec in self.fields if spec.consequentiality is Consequentiality.CONSEQUENTIAL
        )


class ActionSchemaFailure(Enum):
    DUPLICATE_KIND = "DUPLICATE_KIND"
    DUPLICATE_FIELD = "DUPLICATE_FIELD"
    NO_KINDS = "NO_KINDS"
    DOMAIN_SORT_MISMATCH = "DOMAIN_SORT_MISMATCH"
    DEFAULT_OUT_OF_DOMAIN = "DEFAULT_OUT_OF_DOMAIN"
    FIELD_SORT_CONFLICT = "FIELD_SORT_CONFLICT"
    NO_CONSEQUENTIAL_FIELD = "NO_CONSEQUENTIAL_FIELD"
    UNKNOWN_KIND = "UNKNOWN_KIND"


@dataclass(frozen=True, slots=True)
class ActionSchemaError:
    failure: ActionSchemaFailure
    detail: str


@dataclass(frozen=True, slots=True)
class ActionSchema:
    """A versioned discriminated union of the actions a policy may propose."""

    schema_id: str
    schema_version: int
    kinds: tuple[ActionKindSpec, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_ACTION_SCHEMA,
            (
                NAtom(self.schema_id),
                NInt(self.schema_version),
                NSeq(tuple(kind.to_node() for kind in self.kinds)),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.ACTION_SCHEMA, self.to_node())

    def kind_spec(self, kind: str) -> ActionKindSpec | None:
        for spec in self.kinds:
            if spec.kind == kind:
                return spec
        return None

    def kind_enum_id(self) -> str:
        """The enum a query uses to talk about which kind an action has.

        Derived from the schema id rather than fixed, so two schemas in one
        query cannot silently share a kind enumeration.
        """
        return f"{self.schema_id}.kind"

    def kind_members(self) -> tuple[str, ...]:
        return tuple(spec.kind for spec in self.kinds)


def validate_action_schema(schema: ActionSchema) -> Result[ActionSchema, ActionSchemaError]:
    """Reject a schema that could not support a total, deterministic comparison.

    Duplicate kinds are the sharp one: with two ``PAY`` entries the projection
    is ambiguous and the same case can read as ``Divergent`` or ``Invariant``
    depending on which entry a lookup happened to find first.
    """
    if not schema.kinds:
        return Err(ActionSchemaError(ActionSchemaFailure.NO_KINDS, schema.schema_id))

    seen_kinds: set[str] = set()
    field_sorts: dict[str, Sort] = {}
    for spec in schema.kinds:
        if spec.kind in seen_kinds:
            return Err(ActionSchemaError(ActionSchemaFailure.DUPLICATE_KIND, spec.kind))
        seen_kinds.add(spec.kind)

        if not spec.consequential():
            #  Without one, every action of this kind is equal to every other,
            #  and divergence in the payment amount would read as invariance.
            return Err(ActionSchemaError(ActionSchemaFailure.NO_CONSEQUENTIAL_FIELD, spec.kind))

        seen_fields: set[str] = set()
        for field in spec.fields:
            if field.name in seen_fields:
                return Err(
                    ActionSchemaError(
                        ActionSchemaFailure.DUPLICATE_FIELD, f"{spec.kind}.{field.name}"
                    )
                )
            seen_fields.add(field.name)

            if not domain_matches_sort(field.bounds, field.sort):
                return Err(
                    ActionSchemaError(
                        ActionSchemaFailure.DOMAIN_SORT_MISMATCH, f"{spec.kind}.{field.name}"
                    )
                )
            if field.default is not None and not value_in_domain(field.default, field.bounds):
                return Err(
                    ActionSchemaError(
                        ActionSchemaFailure.DEFAULT_OUT_OF_DOMAIN, f"{spec.kind}.{field.name}"
                    )
                )

            #  A field name shared by two kinds must denote one sort: the
            #  cross-world field selector has a single branch per kind and every
            #  branch must agree, or the comparison would be ill-typed.
            existing = field_sorts.get(field.name)
            if existing is not None and existing != field.sort:
                return Err(ActionSchemaError(ActionSchemaFailure.FIELD_SORT_CONFLICT, field.name))
            field_sorts[field.name] = field.sort

    return Ok(schema)


def complete_action(
    schema: ActionSchema, kind: str, supplied: dict[str, Value]
) -> Result[Action, ActionSchemaError]:
    """Build an action carrying every declared field of its kind, in order."""
    spec = schema.kind_spec(kind)
    if spec is None:
        return Err(ActionSchemaError(ActionSchemaFailure.UNKNOWN_KIND, kind))
    fields: list[ActionField] = []
    for field in spec.fields:
        value = supplied.get(field.name, field.filler())
        if sort_of(value) != field.sort or not value_in_domain(value, field.bounds):
            return Err(
                ActionSchemaError(
                    ActionSchemaFailure.DEFAULT_OUT_OF_DOMAIN, f"{kind}.{field.name}={value}"
                )
            )
        fields.append(ActionField(field.name, value))
    return Ok(Action(kind, tuple(fields)))


def consequential_of(schema: ActionSchema, action: Action) -> ConsequentialAction:
    """Project an action onto the fields the executor actually acts on."""
    spec = schema.kind_spec(action.kind)
    if spec is None:
        raise InvariantViolation(f"action kind {action.kind} is not in schema {schema.schema_id}")
    keep = {field.name for field in spec.consequential()}
    return ConsequentialAction(
        schema.digest(),
        action.kind,
        tuple(field for field in action.fields if field.name in keep),
    )
