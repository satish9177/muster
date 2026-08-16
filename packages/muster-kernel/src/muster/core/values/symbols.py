"""Proposition identity.

A ``SymbolRef`` names one proposition instance: ``present_on_site(Ravi, Sat)``.
The kernel never interprets a predicate id or an argument -- they exist only to
distinguish propositions from one another, which is exactly what makes the
kernel's semantic outputs invariant under consistent renaming.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.results import Result
from muster.core.wire.codec import encode
from muster.core.wire.digests import DigestKind, digest_node
from muster.core.wire.nodes import NAtom, Node, NRec, NSeq
from muster.core.wire.shape import (
    WireError,
    atoms,
    decoded,
    read_atom,
    read_rec,
    read_seq,
)

TAG_SYMBOL_REF = "SymbolRef/v1"
TAG_SYMBOL_REF_TEMPLATE = "SymbolRefTemplate/v1"


@dataclass(frozen=True, slots=True, order=False)
class SymbolRef:
    """A concrete proposition instance: a predicate applied to argument atoms."""

    predicate_id: str
    args: tuple[str, ...] = ()

    def to_node(self) -> NRec:
        return NRec(TAG_SYMBOL_REF, (NAtom(self.predicate_id), atoms(self.args)))

    def key(self) -> str:
        """The 64-character assertion key used to label solver assertions."""
        return digest_node(DigestKind.SYMBOL_REF, self.to_node()).hex

    def octets(self) -> bytes:
        return encode(self.to_node())

    def __str__(self) -> str:
        return f"{self.predicate_id}({', '.join(self.args)})" if self.args else self.predicate_id


@dataclass(frozen=True, slots=True)
class SymbolRefTemplate:
    """A proposition shape whose argument positions may name rule binders."""

    predicate_id: str
    args_or_binders: tuple[str, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_SYMBOL_REF_TEMPLATE, (NAtom(self.predicate_id), atoms(self.args_or_binders))
        )

    def instantiate(self, binding: dict[str, str]) -> SymbolRef:
        """Substitute binder names positionally; other positions stay literal."""
        return SymbolRef(
            self.predicate_id,
            tuple(binding.get(arg, arg) for arg in self.args_or_binders),
        )


def read_symbol_ref(node: Node) -> SymbolRef:
    predicate_id, args = read_rec(node, TAG_SYMBOL_REF, 2)
    return SymbolRef(read_atom(predicate_id), read_seq(args, read_atom))


def decode_symbol_ref(node: Node) -> Result[SymbolRef, WireError]:
    return decoded(lambda: read_symbol_ref(node))


def read_symbol_ref_template(node: Node) -> SymbolRefTemplate:
    predicate_id, args = read_rec(node, TAG_SYMBOL_REF_TEMPLATE, 2)
    return SymbolRefTemplate(read_atom(predicate_id), read_seq(args, read_atom))


def symbol_seq(refs: tuple[SymbolRef, ...]) -> NSeq:
    return NSeq(tuple(ref.to_node() for ref in refs))
