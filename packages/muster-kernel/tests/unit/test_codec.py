"""The codec: canonical in one direction, fail-closed in the other."""

from __future__ import annotations

import pytest

from muster.core.results import Err, InvariantViolation, Ok
from muster.core.wire.codec import (
    DecodeFailure,
    canonical_order,
    canonical_set,
    decode,
    encode,
    is_canonically_ordered,
)
from muster.core.wire.digests import Digest, DigestKind, digest_octets
from muster.core.wire.nodes import (
    MAX_ATOM_OCTETS,
    MAX_NESTING_DEPTH,
    TAG_TAGGED,
    TAG_UNIT,
    NAtom,
    NBool,
    NBytes,
    NDigest,
    NInt,
    Node,
    NRec,
    NSeq,
    NSet,
    NTagged,
    NUnit,
)

SPECIMENS: tuple[Node, ...] = (
    NUnit(),
    NBool(True),
    NBool(False),
    NInt(0),
    NInt(-1),
    NInt(127),
    NInt(128),
    NInt(-128),
    NInt(-129),
    NInt(2**200),
    NAtom(""),
    NAtom("shift_payable_under_policy"),
    NAtom("naïve ünïcode"),
    NBytes(b""),
    NBytes(bytes(range(32))),
    NSeq(()),
    NSeq((NInt(1), NAtom("two"))),
    NTagged("Some", NInt(3)),
    NRec("SymbolRef/v1", (NAtom("p"), NSeq((NAtom("a"),)))),
    NDigest(bytes(32)),
)


@pytest.mark.parametrize("node", SPECIMENS, ids=lambda node: type(node).__name__)
def test_round_trip(node: Node) -> None:
    decoded = decode(encode(node))
    assert isinstance(decoded, Ok)
    assert decoded.value == node
    assert encode(decoded.value) == encode(node)


def test_encoding_is_stable_across_calls() -> None:
    node = NRec("A/v1", (NSeq((NInt(1), NInt(2))), NAtom("x")))
    assert encode(node) == encode(node)


def test_integers_are_minimal_two_s_complement() -> None:
    assert encode(NInt(0)) == b"\x04\x01\x00"
    assert encode(NInt(1)) == b"\x04\x01\x01"
    assert encode(NInt(-1)) == b"\x04\x01\xff"
    assert encode(NInt(127)) == b"\x04\x01\x7f"
    assert encode(NInt(128)) == b"\x04\x02\x00\x80"
    assert encode(NInt(-128)) == b"\x04\x01\x80"


def test_non_minimal_integer_is_rejected() -> None:
    """Two spellings of one value would give one value two digests."""
    padded = b"\x04\x02\x00\x01"
    outcome = decode(padded)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.NON_MINIMAL_INT


def test_unknown_tag_octet_is_rejected() -> None:
    outcome = decode(b"\xfe")
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.UNKNOWN_TAG_OCTET


def test_trailing_octets_are_rejected() -> None:
    """An artifact is exactly its encoding: a suffix is a second artifact."""
    outcome = decode(encode(NUnit()) + b"\x01")
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.TRAILING_OCTETS


def test_truncated_input_is_rejected() -> None:
    octets = encode(NRec("A/v1", (NInt(1), NInt(2))))
    outcome = decode(octets[:-1])
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.TRUNCATED


def test_declared_length_beyond_the_input_is_refused_before_allocating() -> None:
    hostile = b"\x06\xff\xff\xff\xff"
    outcome = decode(hostile)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.LENGTH_EXCEEDS_INPUT


def test_invalid_utf8_atom_is_rejected() -> None:
    outcome = decode(b"\x05\x01\xff")
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.ATOM_NOT_UTF8


def test_record_without_its_separator_is_rejected() -> None:
    octets = bytearray(encode(NRec("A/v1", (NInt(1),))))
    separator = octets.index(0x00, 2)
    octets[separator] = 0x01
    outcome = decode(bytes(octets))
    assert isinstance(outcome, Err)
    assert outcome.error.failure in {
        DecodeFailure.RECORD_SEPARATOR_MISSING,
        DecodeFailure.ARITY_OUT_OF_RANGE,
        DecodeFailure.UNKNOWN_TAG_OCTET,
        DecodeFailure.TRUNCATED,
    }


def test_unsupported_digest_algorithm_is_rejected() -> None:
    octets = bytearray(encode(NDigest(bytes(32))))
    octets[1] = 0x02
    outcome = decode(bytes(octets))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.UNSUPPORTED_DIGEST_ALGORITHM


def test_atom_beyond_the_declared_length_cannot_be_encoded() -> None:
    with pytest.raises(InvariantViolation):
        encode(NAtom("a" * (MAX_ATOM_OCTETS + 1)))


def test_integer_beyond_the_declared_range_cannot_be_encoded() -> None:
    with pytest.raises(InvariantViolation):
        encode(NInt(2**300))


def test_sets_are_canonical_regardless_of_construction_order() -> None:
    members = (NAtom("gamma"), NAtom("alpha"), NAtom("beta"))
    assert encode(canonical_set(members)) == encode(canonical_set(reversed(members)))


def test_sets_collapse_equal_members() -> None:
    assert canonical_set((NAtom("a"), NAtom("a"))) == canonical_set((NAtom("a"),))


def test_unordered_set_octets_are_rejected() -> None:
    """A producer that did not order its set did not produce a canonical value."""
    unordered = b"\x08\x00\x00\x00\x02" + encode(NAtom("b")) + encode(NAtom("a"))
    outcome = decode(unordered)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.SET_NOT_CANONICAL


def test_duplicate_set_members_are_rejected() -> None:
    duplicated = b"\x08\x00\x00\x00\x02" + encode(NAtom("a")) + encode(NAtom("a"))
    outcome = decode(duplicated)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.SET_NOT_CANONICAL


def test_encoding_an_unordered_set_is_a_programmer_error() -> None:
    with pytest.raises(InvariantViolation):
        encode(NSet((NAtom("b"), NAtom("a"))))


def test_canonical_order_is_independent_of_input_order() -> None:
    items = [NInt(3), NInt(1), NInt(2)]
    ordered = canonical_order(items, lambda node: node)
    assert ordered == canonical_order(reversed(items), lambda node: node)
    assert is_canonically_ordered(ordered, lambda node: node)


def test_digest_domains_separate() -> None:
    """The same octets under two domains are two different digests."""
    octets = encode(NAtom("x"))
    assert digest_octets(DigestKind.ACTION, octets) != digest_octets(DigestKind.TERM, octets)


def test_digest_is_thirty_two_octets() -> None:
    with pytest.raises(InvariantViolation):
        Digest(b"short")


#  ---- nesting depth -------------------------------------------------------
#
#  The decoder is recursive, and before this bound existed a few kilobytes of
#  octets raised ``RecursionError`` out of ``decode`` -- which promises a
#  ``Result``.  It mattered because Milestone F made the first caller that
#  hands this function octets written by a party the architecture treats as
#  untrusted: a source answering an assignment, over a transport that caps the
#  response at a megabyte.  Four octets buy one level, so the cap was never the
#  control.


def _nested(levels: int) -> bytes:
    """``levels`` of ``NTagged`` wrapping one unit, built as octets.

    Built at the octet level rather than with ``encode``, because encoding a
    node this deep would hit the same recursion from the other side -- and the
    thing under test is what a *decoder* does with octets somebody else wrote.
    """
    body = bytearray()
    for _ in range(levels):
        body.append(TAG_TAGGED)
        body += encode(NAtom("x"))
    body.append(TAG_UNIT)
    return bytes(body)


def test_a_value_nested_to_the_bound_still_decodes() -> None:
    """The bound is generous: real artifacts nest around thirteen levels."""
    outcome = decode(_nested(MAX_NESTING_DEPTH - 1))
    assert isinstance(outcome, Ok), outcome


def test_a_value_nested_past_the_bound_is_refused_rather_than_raised() -> None:
    outcome = decode(_nested(MAX_NESTING_DEPTH))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.NESTING_TOO_DEEP


def test_octets_that_would_exhaust_the_stack_are_a_value_and_not_an_exception() -> None:
    """The reproduction: twelve kilobytes, well inside every transport cap."""
    hostile = _nested(3_000)
    assert len(hostile) < 256 * 1024
    outcome = decode(hostile)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DecodeFailure.NESTING_TOO_DEEP


def test_the_bound_is_over_depth_and_not_over_breadth() -> None:
    """A wide artifact is ordinary; a deep one is not.  Only one is refused."""
    wide = NSeq(tuple(NInt(index) for index in range(2_000)))
    assert isinstance(decode(encode(wide)), Ok)
