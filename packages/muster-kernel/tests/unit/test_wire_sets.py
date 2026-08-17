"""SET encoding: verified against the written grammar, not against a vector.

The frozen corpus contains no SET.  Every one of the sixteen vectors decodes
into a tree of records, sequences, atoms, integers and digests, and none of them
exercises tag ``0x08`` -- :func:`test_no_frozen_vector_exercises_the_set_tag`
asserts exactly that, so the limitation is a checked fact rather than a caveat
somebody has to remember.

What can honestly be claimed is therefore **grammar-verified and
property-tested**, and both halves are done here:

* *Grammar-verified.*  The frozen schema inventory states, field by field,
  which record fields are ``SET[...]`` and which are ``SEQ[...]``.  This module
  parses that declaration and holds real production octets against it, so a
  field that shipped as a sequence where the grammar says set fails -- which is
  precisely the class of defect no round-trip test can see, because a sequence
  round-trips perfectly well.
* *Property-tested.*  Membership is semantic and order is not, so the octets
  must be a function of the member set alone: ascending, deduplicated, and
  independent of the order a caller discovered the members in.

What is **not** claimed is conformance to an authoritative SET vector.  There
is none, and manufacturing one by regenerating the frozen corpus would be
validating the implementation against itself.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from muster.core.results import Err, Ok
from muster.core.wire.codec import canonical_set, decode, encode
from muster.core.wire.nodes import (
    TAG_SEQ,
    TAG_SET,
    NAtom,
    Node,
    NRec,
    NSeq,
    NSet,
    NTagged,
)
from tests.conftest import GOLDEN_VECTORS, GoldenVector
from tests.support.specimens import every_specimen

#  ``TypeName = REC("Tag/v1", arity, [Type name, Type name, ...])`` -- the
#  frozen grammar's own notation, read rather than restated.
GRAMMAR = re.compile(r'REC\("(?P<tag>[^"]+)",\s*(?P<arity>\d+),\s*\[(?P<fields>.*)\]\)')


def _split_fields(text: str) -> list[str]:
    """Top-level commas only: ``SEQ[Arm]`` does not separate two fields.

    Depth is square and round brackets alone.  The grammar also writes angle
    brackets -- ``ATOM<A|B>`` for a closed atom set, ``ATOM[<=100]`` for a
    length bound, ``^>=1`` for a minimum count -- and none of those can contain
    a comma, so counting them would only get the nesting wrong.
    """
    fields: list[str] = []
    depth = 0
    current = ""
    for character in text:
        if character in "[(":
            depth += 1
        elif character in "])":
            depth -= 1
        if character == "," and depth == 0:
            fields.append(current.strip())
            current = ""
            continue
        current += character
    if current.strip():
        fields.append(current.strip())
    return fields


def _declared_fields() -> dict[str, list[str]]:
    """Every frozen record tag, with the declared type of each field."""
    text = (GOLDEN_VECTORS / "schema_inventory.md").read_text(encoding="utf-8")
    grammar = text.split("## Full grammar")[1]
    declared: dict[str, list[str]] = {}
    for match in GRAMMAR.finditer(grammar):
        fields = _split_fields(match.group("fields"))
        assert len(fields) == int(match.group("arity")), match.group("tag")
        #  ``SEQ[ATOM] members`` -- the declared type is everything but the name.
        declared[match.group("tag")] = [field.rsplit(" ", 1)[0] for field in fields]
    return declared


DECLARED = _declared_fields()


def _records(node: Node) -> list[NRec]:
    match node:
        case NRec(_, fields):
            return [node, *(found for field in fields for found in _records(field))]
        case NTagged(_, payload):
            return _records(payload)
        case NSeq(items):
            return [found for item in items for found in _records(item)]
        case NSet(members):
            return [found for member in members for found in _records(member)]
        case _:
            return []


def test_the_frozen_grammar_declares_set_fields_at_all() -> None:
    """A parse that found no SET would make the check below vacuous."""
    sets = [
        (tag, field)
        for tag, fields in DECLARED.items()
        for field in fields
        if field.startswith("SET")
    ]
    assert len(sets) >= 4, sets


def test_every_production_set_field_is_encoded_as_a_set() -> None:
    """The defect no round-trip can see: a set that shipped as a sequence.

    Checked over real encoded values rather than over the type definitions, so
    a field whose ``to_node`` disagreed with its declaration is caught where it
    actually reaches the wire.
    """
    checked = 0
    for specimen in every_specimen():
        for record in _records(specimen):
            declared = DECLARED.get(record.tag)
            if declared is None:
                continue
            assert len(record.fields) == len(declared), record.tag
            for field, kind in zip(record.fields, declared, strict=True):
                if kind.startswith("SET"):
                    assert isinstance(field, NSet), f"{record.tag}: {kind} is not a set"
                    checked += 1
                elif kind.startswith("SEQ"):
                    assert isinstance(field, NSeq), f"{record.tag}: {kind} is not a sequence"
    assert checked > 0, "no production specimen exercised a declared SET field"


def test_no_frozen_vector_exercises_the_set_tag(golden_vectors: dict[str, GoldenVector]) -> None:
    """The stated limitation, asserted rather than remembered.

    If a future corpus regeneration adds one, this fails and the claim above
    can be strengthened from grammar-verified to vector-verified.
    """
    for vector in golden_vectors.values():
        decoded = decode(vector.octets)
        assert isinstance(decoded, Ok), vector.name
        assert not _sets(decoded.value), f"{vector.name} now contains a SET"


def _sets(node: Node) -> list[NSet]:
    match node:
        case NSet(members):
            return [node, *(found for member in members for found in _sets(member))]
        case NRec(_, fields):
            return [found for field in fields for found in _sets(field)]
        case NTagged(_, payload):
            return _sets(payload)
        case NSeq(items):
            return [found for item in items for found in _sets(item)]
        case _:
            return []


#  ---- framing --------------------------------------------------------------


def test_a_set_is_framed_exactly_as_a_sequence_under_a_different_tag() -> None:
    """The grammar gives both a tag octet and a 32-bit count, and nothing else
    distinguishes them, so an implementation cannot have invented a length."""
    ordered = canonical_set((NAtom("alpha"), NAtom("beta")))
    #  The sequence takes the members the set settled on, so what is left to
    #  differ is the framing and nothing else.
    as_set = encode(ordered)
    as_seq = encode(NSeq(ordered.members))
    assert as_set[0] == TAG_SET
    assert as_seq[0] == TAG_SEQ
    assert as_set[1:] == as_seq[1:]
    assert as_set[1:5] == (2).to_bytes(4, "big")


#  ---- the properties a set has and a sequence does not ---------------------

atoms = st.lists(st.text(min_size=0, max_size=8), min_size=0, max_size=6)


@given(members=atoms)
def test_the_octets_depend_only_on_the_member_set(members: list[str]) -> None:
    forwards = canonical_set(NAtom(text) for text in members)
    backwards = canonical_set(NAtom(text) for text in reversed(members))
    doubled = canonical_set(NAtom(text) for text in members + members)
    assert encode(forwards) == encode(backwards)
    assert encode(forwards) == encode(doubled)


@given(members=atoms)
def test_members_are_strictly_ascending_by_canonical_octets(members: list[str]) -> None:
    built = canonical_set(NAtom(text) for text in members)
    encoded = [encode(member) for member in built.members]
    assert encoded == sorted(encoded)
    assert len(set(encoded)) == len(encoded)
    assert len(built.members) == len(set(members))


@given(members=atoms)
def test_a_canonical_set_round_trips_through_the_decoder(members: list[str]) -> None:
    built = canonical_set(NAtom(text) for text in members)
    decoded = decode(encode(built))
    assert isinstance(decoded, Ok)
    assert decoded.value == built
    assert encode(decoded.value) == encode(built)


@given(members=st.lists(st.text(min_size=1, max_size=4), min_size=2, max_size=5, unique=True))
def test_the_decoder_refuses_every_non_ascending_permutation(members: list[str]) -> None:
    """Two spellings of one set would give one value two digests."""
    ordered = canonical_set(NAtom(text) for text in members)
    if len(ordered.members) < 2:  # pragma: no cover - filtered by uniqueness
        return
    swapped = (ordered.members[1], ordered.members[0], *ordered.members[2:])
    octets = bytes([TAG_SET]) + len(swapped).to_bytes(4, "big")
    octets += b"".join(encode(member) for member in swapped)
    outcome = decode(octets)
    assert isinstance(outcome, Err)


@pytest.mark.parametrize("count", [0, 1, 2, 5])
def test_a_set_of_any_size_encodes_and_decodes(count: int) -> None:
    built = canonical_set(NAtom(f"member-{index}") for index in range(count))
    assert len(built.members) == count
    decoded = decode(encode(built))
    assert isinstance(decoded, Ok)
    assert decoded.value == built
