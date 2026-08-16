"""Declarative schema language for the MUSTER Phase-1 wire contract.

NON-PRODUCTION SPECIFICATION MATERIAL.

One registry is the single source of truth.  Tag tables, arity tables, digest-kind
tables, signing bodies and the type inventory are *derived* from it -- never
maintained by hand in parallel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Iterator, Mapping, Sequence

from .nodes import (
    Atom,
    Bool,
    Bytes,
    Digest,
    Int,
    Node,
    Rec,
    Seq,
    SetV,
    Tagged,
    Unit,
)


class SchemaError(Exception):
    """Raised when a value does not conform to its declared type."""


class RegistryError(Exception):
    """Raised when the registry itself is inconsistent."""


# --------------------------------------------------------------------------
# type expressions
# --------------------------------------------------------------------------


class TypeExpr:
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class Prim(TypeExpr):
    """UNIT | BOOL | INT | ATOM | BYTES | DIGEST."""

    name: str


@dataclass(frozen=True, slots=True)
class AtomIn(TypeExpr):
    """An ATOM constrained to a closed, declared vocabulary."""

    vocabulary: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AtomMax(TypeExpr):
    """An ATOM with a declared maximum length, shorter than the 128 the codec allows.

    Needed wherever an atom is EMBEDDED in a longer atom: a 128-character
    `Constraint.label` is a legal atom that makes the derived assertion label
    `"C:" || label || ":L"` a 132-character atom, which is not.
    """

    max_length: int


@dataclass(frozen=True, slots=True)
class BytesLen(TypeExpr):
    """BYTES with an exact declared octet length."""

    length: int


@dataclass(frozen=True, slots=True)
class SeqOf(TypeExpr):
    element: TypeExpr
    min_count: int = 0


@dataclass(frozen=True, slots=True)
class SetOf(TypeExpr):
    element: TypeExpr
    min_count: int = 0


@dataclass(frozen=True, slots=True)
class OptOf(TypeExpr):
    element: TypeExpr


@dataclass(frozen=True, slots=True)
class Ref(TypeExpr):
    name: str


UNIT = Prim("UNIT")
BOOL = Prim("BOOL")
INT = Prim("INT")
ATOM = Prim("ATOM")
BYTES = Prim("BYTES")
DIGEST = Prim("DIGEST")


# --------------------------------------------------------------------------
# declarations
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FieldDecl:
    name: str
    type: TypeExpr
    note: str = ""


@dataclass(frozen=True, slots=True)
class SigningSpec:
    """Where the authority of a signed artifact lives.

    ``signature_field``   the field of this record holding the Signature.
    ``body``              the field whose canonical encoding is the signed preimage,
                          or ``"@self_without_signature"`` meaning the same record
                          with the signature field replaced by a hole.
    ``key_ref_path``      dotted path, from this record, to the *single*
                          authoritative signer key reference.  It MUST resolve to a
                          position inside the signed body.
    ``domain``            digest domain-separation kind for the signed preimage.
    """

    signature_field: str
    body: str
    key_ref_path: str
    domain: str


SELF_BODY = "@self_without_signature"


@dataclass(frozen=True, slots=True)
class TypeDecl:
    name: str
    kind: str  # "record" | "union" | "alias"
    tag: str | None = None
    fields: tuple[FieldDecl, ...] = ()
    variants: tuple[tuple[str, TypeExpr], ...] = ()
    alias_of: TypeExpr | None = None
    digest_kind: str | None = None
    persistence: str = "embedded"  # persisted | embedded | derived | transient
    signing: SigningSpec | None = None
    commitment_eligible: bool = False
    unique_by: tuple[tuple[str, tuple[str, ...]], ...] = ()
    note: str = ""

    @property
    def arity(self) -> int:
        return len(self.fields)


@dataclass
class Registry:
    types: dict[str, TypeDecl] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)

    def add(self, decl: TypeDecl) -> TypeDecl:
        if decl.name in self.types:
            raise RegistryError(f"duplicate type name {decl.name}")
        self.types[decl.name] = decl
        self.order.append(decl.name)
        return decl

    def __getitem__(self, name: str) -> TypeDecl:
        try:
            return self.types[name]
        except KeyError as exc:
            raise RegistryError(f"unknown type {name}") from exc

    def __contains__(self, name: str) -> bool:
        return name in self.types

    def __iter__(self) -> Iterator[TypeDecl]:
        for name in self.order:
            yield self.types[name]

    def resolve(self, expr: TypeExpr) -> TypeExpr:
        """Follow aliases to a structural type expression."""
        seen: set[str] = set()
        while isinstance(expr, Ref):
            decl = self[expr.name]
            if decl.kind != "alias":
                return expr
            if expr.name in seen:
                raise RegistryError(f"alias cycle at {expr.name}")
            seen.add(expr.name)
            assert decl.alias_of is not None
            expr = decl.alias_of
        return expr


# --------------------------------------------------------------------------
# validation of a value against a declared type
# --------------------------------------------------------------------------


def validate(reg: Registry, node: Node, expr: TypeExpr, path: str = "$") -> None:
    expr = reg.resolve(expr)

    if isinstance(expr, Prim):
        _validate_prim(node, expr, path)
        return

    if isinstance(expr, AtomIn):
        if not isinstance(node, Atom):
            raise SchemaError(f"{path}: expected ATOM, got {type(node).__name__}")
        if node.value not in expr.vocabulary:
            raise SchemaError(
                f"{path}: atom {node.value!r} outside declared vocabulary "
                f"{list(expr.vocabulary)}"
            )
        return

    if isinstance(expr, AtomMax):
        if not isinstance(node, Atom):
            raise SchemaError(f"{path}: expected ATOM, got {type(node).__name__}")
        if len(node.value) > expr.max_length:
            raise SchemaError(
                f"{path}: atom is {len(node.value)} characters, declared maximum "
                f"is {expr.max_length}"
            )
        return

    if isinstance(expr, BytesLen):
        if not isinstance(node, Bytes):
            raise SchemaError(f"{path}: expected BYTES, got {type(node).__name__}")
        if len(node.value) != expr.length:
            raise SchemaError(
                f"{path}: expected {expr.length} octets, got {len(node.value)}"
            )
        return

    if isinstance(expr, SeqOf):
        if not isinstance(node, Seq):
            raise SchemaError(f"{path}: expected SEQ, got {type(node).__name__}")
        if len(node.items) < expr.min_count:
            raise SchemaError(
                f"{path}: SEQ requires at least {expr.min_count} elements, "
                f"got {len(node.items)}"
            )
        for i, item in enumerate(node.items):
            validate(reg, item, expr.element, f"{path}[{i}]")
        return

    if isinstance(expr, SetOf):
        if not isinstance(node, SetV):
            raise SchemaError(f"{path}: expected SET, got {type(node).__name__}")
        if len(node.items) < expr.min_count:
            raise SchemaError(
                f"{path}: SET requires at least {expr.min_count} elements, "
                f"got {len(node.items)}"
            )
        for i, item in enumerate(node.items):
            validate(reg, item, expr.element, f"{path}{{{i}}}")
        return

    if isinstance(expr, OptOf):
        if not isinstance(node, Tagged):
            raise SchemaError(f"{path}: expected Option TAGGED, got {type(node).__name__}")
        if node.variant == "None":
            if not isinstance(node.value, Unit):
                raise SchemaError(f"{path}: None payload must be UNIT")
            return
        if node.variant == "Some":
            validate(reg, node.value, expr.element, f"{path}.Some")
            return
        raise SchemaError(f"{path}: Option variant must be None|Some, got {node.variant!r}")

    if isinstance(expr, Ref):
        decl = reg[expr.name]
        if decl.kind == "record":
            _validate_record(reg, node, decl, path)
            return
        if decl.kind == "union":
            _validate_union(reg, node, decl, path)
            return
        raise RegistryError(f"{path}: alias {expr.name} not resolved")

    raise RegistryError(f"{path}: unhandled type expression {expr!r}")


def _validate_prim(node: Node, expr: Prim, path: str) -> None:
    expected = {
        "UNIT": Unit,
        "BOOL": Bool,
        "INT": Int,
        "ATOM": Atom,
        "BYTES": Bytes,
        "DIGEST": Digest,
    }[expr.name]
    if not isinstance(node, expected):
        raise SchemaError(
            f"{path}: expected {expr.name}, got {type(node).__name__}"
        )


def _validate_record(reg: Registry, node: Node, decl: TypeDecl, path: str) -> None:
    if not isinstance(node, Rec):
        raise SchemaError(f"{path}: expected REC {decl.tag}, got {type(node).__name__}")
    if node.tag != decl.tag:
        raise SchemaError(f"{path}: expected record tag {decl.tag!r}, got {node.tag!r}")
    if len(node.fields) != decl.arity:
        raise SchemaError(
            f"{path}: record {decl.tag} declares arity {decl.arity}, "
            f"encoded arity is {len(node.fields)}"
        )
    for value, fdecl in zip(node.fields, decl.fields):
        validate(reg, value, fdecl.type, f"{path}.{fdecl.name}")
    _check_uniqueness(reg, node, decl, path)


def _check_uniqueness(reg: Registry, node: Rec, decl: TypeDecl, path: str) -> None:
    from .nodes import encode  # local import: codec is the only serialiser

    names = [f.name for f in decl.fields]
    for coll_field, key_fields in decl.unique_by:
        idx = names.index(coll_field)
        coll = node.fields[idx]
        if not isinstance(coll, (Seq, SetV)):
            raise SchemaError(f"{path}.{coll_field}: uniqueness declared on a non-collection")
        seen: dict[bytes, int] = {}
        for i, element in enumerate(coll.items):
            key = _project_key(reg, element, key_fields)
            raw = b"|".join(encode(k) for k in key)
            if raw in seen:
                raise SchemaError(
                    f"{path}.{coll_field}: duplicate key {key_fields} at indices "
                    f"{seen[raw]} and {i}"
                )
            seen[raw] = i


def _project_key(reg: Registry, element: Node, key_fields: Sequence[str]) -> list[Node]:
    out: list[Node] = []
    for spec in key_fields:
        cursor: Node = element
        for step in spec.split("."):
            # A union wrapper is transparent for key projection: unwrap until a
            # record can answer the step.
            while isinstance(cursor, Tagged):
                cursor = cursor.value
            if not isinstance(cursor, Rec):
                raise SchemaError(f"cannot project {spec!r} out of {type(cursor).__name__}")
            decl = _decl_for_tag(reg, cursor.tag)
            names = [f.name for f in decl.fields]
            if step not in names:
                raise SchemaError(f"record {cursor.tag} has no field {step!r}")
            cursor = cursor.fields[names.index(step)]
        out.append(cursor)
    return out


def _decl_for_tag(reg: Registry, tag: str) -> TypeDecl:
    for decl in reg:
        if decl.kind == "record" and decl.tag == tag:
            return decl
    raise RegistryError(f"no declaration for record tag {tag!r}")


def _validate_union(reg: Registry, node: Node, decl: TypeDecl, path: str) -> None:
    if not isinstance(node, Tagged):
        raise SchemaError(
            f"{path}: expected TAGGED for union {decl.name}, got {type(node).__name__}"
        )
    table = dict(decl.variants)
    if node.variant not in table:
        raise SchemaError(
            f"{path}: {node.variant!r} is not a variant of {decl.name} "
            f"(declared: {sorted(table)})"
        )
    validate(reg, node.value, table[node.variant], f"{path}<{node.variant}>")


# --------------------------------------------------------------------------
# derived tables
# --------------------------------------------------------------------------


def record_tags(reg: Registry) -> list[tuple[str, str, int]]:
    return [
        (d.name, d.tag or "", d.arity) for d in reg if d.kind == "record"
    ]


def digest_kinds(reg: Registry) -> dict[str, str]:
    out: dict[str, str] = {}
    for d in reg:
        if d.digest_kind:
            if d.digest_kind in out:
                raise RegistryError(
                    f"digest kind {d.digest_kind} claimed by {out[d.digest_kind]} and {d.name}"
                )
            out[d.digest_kind] = d.name
    return out


def referenced_types(reg: Registry, expr: TypeExpr) -> Iterable[str]:
    if isinstance(expr, Ref):
        yield expr.name
    elif isinstance(expr, (SeqOf, SetOf, OptOf)):
        yield from referenced_types(reg, expr.element)


def render_type(reg: Registry, expr: TypeExpr) -> str:
    if isinstance(expr, Prim):
        return expr.name
    if isinstance(expr, AtomIn):
        return "ATOM<" + "|".join(expr.vocabulary) + ">"
    if isinstance(expr, AtomMax):
        return f"ATOM[<={expr.max_length}]"
    if isinstance(expr, BytesLen):
        return f"BYTES[{expr.length}]"
    if isinstance(expr, SeqOf):
        suffix = f"^>={expr.min_count}" if expr.min_count else ""
        return f"SEQ[{render_type(reg, expr.element)}]{suffix}"
    if isinstance(expr, SetOf):
        suffix = f"^>={expr.min_count}" if expr.min_count else ""
        return f"SET[{render_type(reg, expr.element)}]{suffix}"
    if isinstance(expr, OptOf):
        return f"Option[{render_type(reg, expr.element)}]"
    if isinstance(expr, Ref):
        return expr.name
    raise RegistryError(f"unrenderable {expr!r}")


def render_grammar(reg: Registry) -> str:
    lines: list[str] = []
    for decl in reg:
        if decl.kind == "alias":
            assert decl.alias_of is not None
            lines.append(f"{decl.name:<28} = {render_type(reg, decl.alias_of)}")
        elif decl.kind == "record":
            inner = ", ".join(
                f"{render_type(reg, f.type)} {f.name}" for f in decl.fields
            )
            lines.append(f'{decl.name:<28} = REC("{decl.tag}", {decl.arity}, [{inner}])')
        else:
            first = True
            for vname, vtype in decl.variants:
                head = f"{decl.name:<28} = " if first else " " * 28 + " | "
                lines.append(f'{head}TAGGED("{vname}", {render_type(reg, vtype)})')
                first = False
    return "\n".join(lines)
