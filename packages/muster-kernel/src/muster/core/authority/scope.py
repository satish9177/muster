"""``ResourceScope`` -- one enumerated resource coordinate.

A grant covers exactly what it enumerates.  There is no ``*``, no ``ANY``, no
``ALL_SITES`` and no "empty means everything": the only way a grant reaches a
resource is for that resource's exact coordinate to be a member of its scope
set, compared by equality over the pair.

**Why equality and not a prefix rule.**  ``site-1`` is a prefix of ``site-10``.
A containment rule would hand the holder of a grant over the first an authority
over the second that nobody wrote down, and the mistake is invisible until a
site is named with a digit added.  So matching is set membership over the whole
pair, and the regression that says so is named after the trap.

**Why wildcard tokens are refused at construction.**  ``scope_value`` is an
ATOM, so a wildcard *spelling* is representable even though a wildcard
*meaning* is not.  Refusing the spellings costs nothing and removes the reading
where a publisher believed one worked -- an authority field that silently means
"nothing" is as dangerous as one that silently means "everything".
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from muster.core.results import InvariantViolation
from muster.core.wire.codec import canonical_set
from muster.core.wire.nodes import NAtom, Node, NRec, NSet
from muster.core.wire.shape import read_atom, read_rec, read_set

TAG_RESOURCE_SCOPE = "ResourceScope/v1"

#: Spellings a publisher might reach for meaning "everything".  None of them is
#: a wildcard here, so each is refused rather than stored as a literal nobody
#: will ever match.  The list is closed and small on purpose: it is a guard
#: against a mistaken author, not a sanitiser for a hostile one -- a hostile
#: publisher is already inside the signing boundary and is answered by the
#: signature over the snapshot, not by a token filter.
WILDCARD_SPELLINGS: frozenset[str] = frozenset(
    {"*", "**", "ANY", "any", "ALL", "all", "_ANY_", "_ALL_", "ALL_SITES", "any_predicate"}
)


@dataclass(frozen=True, slots=True)
class ResourceScope:
    """One ``(kind, value)`` coordinate: ``(SITE, SITE_A)``, ``(PURCHASE_ORDER, PO-4471)``."""

    scope_kind: str
    scope_value: str

    def __post_init__(self) -> None:
        if not self.scope_kind or not self.scope_value:
            raise InvariantViolation("a resource scope names a kind and a value")
        if self.scope_kind in WILDCARD_SPELLINGS or self.scope_value in WILDCARD_SPELLINGS:
            raise InvariantViolation(
                f"a resource scope is enumerated, never a wildcard: "
                f"({self.scope_kind}, {self.scope_value})"
            )

    def to_node(self) -> NRec:
        return NRec(TAG_RESOURCE_SCOPE, (NAtom(self.scope_kind), NAtom(self.scope_value)))

    def __str__(self) -> str:
        return f"({self.scope_kind}, {self.scope_value})"


def read_resource_scope(node: Node) -> ResourceScope:
    scope_kind, scope_value = read_rec(node, TAG_RESOURCE_SCOPE, 2)
    return ResourceScope(read_atom(scope_kind), read_atom(scope_value))


def scope_set(scopes: Iterable[ResourceScope]) -> NSet:
    """A canonically ordered, duplicate-free set of coordinates."""
    return canonical_set(scope.to_node() for scope in scopes)


def read_scope_set(node: Node, minimum: int = 0) -> tuple[ResourceScope, ...]:
    return read_set(node, read_resource_scope, minimum=minimum)
