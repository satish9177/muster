"""The canonical solver query, with world-qualified leaves.

A self-composed query talks about two worlds at once, so the world qualification
has to live on the *leaf*.  Attaching a side to a whole formula cannot express
``q_left = q_right``, which is precisely what fixing a variable means, and a
query that cannot express it silently answers a different question.

Sharing is structural rather than asserted: a symbol that is already established
is declared once on side ``S`` and both lowerings point at that one variable.
There is no extra equality for an implementation to forget to emit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.expr.ir import Expr, ExprFamily, expr_node, read_expr
from muster.core.results import InvariantViolation
from muster.core.values.sorts import Domain, Sort, read_domain, read_sort
from muster.core.values.symbols import SymbolRef, read_symbol_ref
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, Node, NRec, NSeq
from muster.core.wire.shape import atoms, read_atom, read_rec

TAG_QUERY_VAR = "QueryVar/v1"
TAG_QUERY_DECL = "QueryDecl/v1"
TAG_LABELED_ASSERTION = "LabeledAssertion/v1"
TAG_ENUM_DECLARATION = "EnumDeclaration/v1"
TAG_SOLVER_QUERY = "SolverQuery/v1"

MAX_ASSERTION_LABEL_OCTETS = 120


class WorldSide(Enum):
    SINGLE = "S"
    LEFT = "L"
    RIGHT = "R"


class QueryKind(Enum):
    FEASIBILITY = "FEASIBILITY"
    INVARIANCE = "INVARIANCE"
    SUFFICIENCY = "SUFFICIENCY"


@dataclass(frozen=True, slots=True)
class QueryVar:
    side: WorldSide
    ref: SymbolRef

    def to_node(self) -> NRec:
        return NRec(TAG_QUERY_VAR, (NAtom(self.side.value), self.ref.to_node()))

    def __str__(self) -> str:
        return f"{self.side.value}#{self.ref}"


type QTerm = Expr[QueryVar]


def _read_query_var(node: Node) -> QueryVar:
    side, ref = read_rec(node, TAG_QUERY_VAR, 2)
    return QueryVar(WorldSide(read_atom(side)), read_symbol_ref(ref))


QUERY_FAMILY: ExprFamily[QueryVar] = ExprFamily(
    leaf_tag="QVar",
    prefix="Q",
    encode_leaf=lambda var: var.to_node(),
    decode_leaf=_read_query_var,
)


def qterm_node(term: QTerm) -> Node:
    return expr_node(term, QUERY_FAMILY)


def read_qterm(node: Node) -> QTerm:
    return read_expr(node, QUERY_FAMILY)


def qterm_digest(term: QTerm) -> Digest:
    return digest_node(DigestKind.QUERY_TERM, qterm_node(term))


@dataclass(frozen=True, slots=True)
class QueryDecl:
    side: WorldSide
    ref: SymbolRef
    sort: Sort
    domain: Domain

    def var(self) -> QueryVar:
        return QueryVar(self.side, self.ref)

    def to_node(self) -> NRec:
        return NRec(
            TAG_QUERY_DECL,
            (
                NAtom(self.side.value),
                self.ref.to_node(),
                self.sort.to_node(),
                self.domain.to_node(),
            ),
        )


@dataclass(frozen=True, slots=True)
class LabeledAssertion:
    """A formula and the label a reader can recompute for themselves.

    Source-derived labels are the only ones a certificate ever shows; internal
    encoding labels stay query-scoped, so an unsatisfiable core cannot be read
    as though it named the user's own constraints when it does not.
    """

    label: str
    formula: QTerm

    def __post_init__(self) -> None:
        if not self.label or len(self.label.encode("utf-8")) > MAX_ASSERTION_LABEL_OCTETS:
            raise InvariantViolation(f"assertion label out of range: {self.label!r}")

    def to_node(self) -> NRec:
        return NRec(TAG_LABELED_ASSERTION, (NAtom(self.label), qterm_node(self.formula)))


@dataclass(frozen=True, slots=True)
class EnumDeclaration:
    """The declared member order of an enum the query mentions.

    Without it an enum literal has no canonical index and two conforming
    backends can disagree about what identical octets denote.
    """

    enum_id: str
    members: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.members:
            raise InvariantViolation(f"enum {self.enum_id} declares no members")

    def to_node(self) -> NRec:
        return NRec(TAG_ENUM_DECLARATION, (NAtom(self.enum_id), atoms(self.members)))


@dataclass(frozen=True, slots=True)
class SolverQuery:
    kind: QueryKind
    logical_case_digest: Digest
    enums: tuple[EnumDeclaration, ...]
    declarations: tuple[QueryDecl, ...]
    assertions: tuple[LabeledAssertion, ...]

    def __post_init__(self) -> None:
        keys = [(decl.side, decl.ref) for decl in self.declarations]
        if len(set(keys)) != len(keys):
            raise InvariantViolation("query declarations are unique by (side, ref)")
        labels = [assertion.label for assertion in self.assertions]
        if len(set(labels)) != len(labels):
            raise InvariantViolation("assertion labels are unique within a query")
        enum_ids = [enum.enum_id for enum in self.enums]
        if len(set(enum_ids)) != len(enum_ids):
            raise InvariantViolation("enum declarations are unique by enum id")

    def to_node(self) -> NRec:
        return NRec(
            TAG_SOLVER_QUERY,
            (
                NAtom(self.kind.value),
                self.logical_case_digest.to_node(),
                NSeq(tuple(enum.to_node() for enum in self.enums)),
                NSeq(tuple(decl.to_node() for decl in self.declarations)),
                NSeq(tuple(assertion.to_node() for assertion in self.assertions)),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.SOLVER_QUERY, self.to_node())


def read_query_decl(node: Node) -> QueryDecl:
    side, ref, sort, domain = read_rec(node, TAG_QUERY_DECL, 4)
    return QueryDecl(
        WorldSide(read_atom(side)), read_symbol_ref(ref), read_sort(sort), read_domain(domain)
    )
