"""Properties of the codec and of the sufficiency relation.

Two kinds of test, and the difference is stated rather than blurred.
Hypothesis *samples*: it does not prove a property over an input space, so the
codec properties below are evidence, not proof.  The sufficiency properties are
**bounded exhaustive** -- the Ravi case has three unresolved variables, so all
eight subsets are enumerated and the result is complete over that case.
"""

from __future__ import annotations

from itertools import combinations

from hypothesis import given, settings
from hypothesis import strategies as st

from muster.core.results import Err, Ok
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import canonical_order, canonical_set, decode, encode
from muster.core.wire.nodes import (
    MAX_INT_OCTETS,
    NAtom,
    NBool,
    NBytes,
    NDigest,
    NInt,
    Node,
    NRec,
    NSeq,
    NTagged,
    NUnit,
)
from muster.hinge.oracle import Insufficient, Oracle, OracleUnknown, Sufficient
from tests.support import ravi

_INT_LIMIT = 1 << (8 * MAX_INT_OCTETS - 1)

_atoms = st.text(max_size=40)
_ints = st.integers(min_value=-_INT_LIMIT, max_value=_INT_LIMIT - 1)


def _leaves() -> st.SearchStrategy[Node]:
    return st.one_of(
        st.just(NUnit()),
        st.booleans().map(NBool),
        _ints.map(NInt),
        _atoms.map(NAtom),
        st.binary(max_size=40).map(NBytes),
        st.binary(min_size=32, max_size=32).map(NDigest),
    )


def _nodes() -> st.SearchStrategy[Node]:
    return st.recursive(
        _leaves(),
        lambda children: st.one_of(
            st.lists(children, max_size=4).map(lambda items: NSeq(tuple(items))),
            st.tuples(_atoms, children).map(lambda pair: NTagged(pair[0], pair[1])),
            st.tuples(_atoms, st.lists(children, max_size=4)).map(
                lambda pair: NRec(pair[0], tuple(pair[1]))
            ),
            st.lists(children, max_size=4).map(canonical_set),
        ),
        max_leaves=12,
    )


@settings(max_examples=300, deadline=None)
@given(_nodes())
def test_encoding_round_trips(node: Node) -> None:
    decoded = decode(encode(node))
    assert isinstance(decoded, Ok)
    assert decoded.value == node


@settings(max_examples=300, deadline=None)
@given(_nodes())
def test_encoding_is_the_only_encoding(node: Node) -> None:
    """Decoding then re-encoding reproduces the octets exactly."""
    octets = encode(node)
    decoded = decode(octets)
    assert isinstance(decoded, Ok)
    assert encode(decoded.value) == octets


@settings(max_examples=200, deadline=None)
@given(st.lists(_leaves(), max_size=6))
def test_canonical_order_is_a_function_of_the_set(items: list[Node]) -> None:
    forwards = canonical_order(items, lambda node: node)
    backwards = canonical_order(reversed(items), lambda node: node)
    assert forwards == backwards


@settings(max_examples=200, deadline=None)
@given(st.lists(_leaves(), max_size=6))
def test_canonical_sets_ignore_construction_order_and_duplicates(items: list[Node]) -> None:
    doubled = [*items, *items]
    assert encode(canonical_set(items)) == encode(canonical_set(reversed(doubled)))


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=-_INT_LIMIT, max_value=_INT_LIMIT - 1))
def test_integers_have_exactly_one_encoding(value: int) -> None:
    octets = encode(NInt(value))
    decoded = decode(octets)
    assert isinstance(decoded, Ok)
    assert decoded.value == NInt(value)
    #  Any wider spelling of the same value is refused.
    body = octets[2:]
    padded = bytes([0xFF if value < 0 else 0x00]) + body
    assert isinstance(decode(bytes([0x04, len(padded)]) + padded), Err)


def _sufficiency_map() -> dict[frozenset[SymbolRef], bool | None]:
    """``Sufficient(S)`` for every subset of the unresolved set."""
    projected = ravi.analysis().projected
    oracle = Oracle(ravi.backend(), projected)
    unresolved = projected.unresolved()
    answers: dict[frozenset[SymbolRef], bool | None] = {}
    for size in range(len(unresolved) + 1):
        for subset in combinations(unresolved, size):
            verdict = oracle.sufficiency(frozenset(subset))
            match verdict:
                case Sufficient():
                    answers[frozenset(subset)] = True
                case Insufficient():
                    answers[frozenset(subset)] = False
                case OracleUnknown():
                    answers[frozenset(subset)] = None
    return answers


def test_sufficiency_is_monotone_over_every_subset() -> None:
    """``Sufficient(S)`` implies ``Sufficient(S + {v})`` -- exhaustively, here.

    Deletion-based minimisation is only sound because of this, so it is checked
    rather than assumed.
    """
    answers = _sufficiency_map()
    for subset, sufficient in answers.items():
        if sufficient is not True:
            continue
        for larger, larger_sufficient in answers.items():
            if subset < larger:
                assert larger_sufficient is True, (subset, larger)


def test_every_deletion_query_was_conclusive() -> None:
    """Irredundance is only claimed when nothing was inconclusive."""
    assert None not in _sufficiency_map().values()


def test_the_empty_set_is_not_sufficient_but_no_single_variable_is_necessary() -> None:
    """The correlation trap, stated as a property of this case.

    If any variable were necessary, dropping it would leave an insufficient set.
    None does -- and the empty set is still insufficient, so evidence is
    required and no per-variable flag can say so.
    """
    projected = ravi.analysis().projected
    unresolved = frozenset(projected.unresolved())
    answers = _sufficiency_map()

    assert answers[frozenset()] is False
    for variable in unresolved:
        assert answers[unresolved - {variable}] is True


def test_the_selected_support_is_sufficient_and_irredundant() -> None:
    from muster.core.analysis.planning import ProvenIrredundantSupport

    support = ravi.analysis().planning.record.support
    assert isinstance(support, ProvenIrredundantSupport)
    answers = _sufficiency_map()
    members = frozenset(support.members)
    assert answers[members] is True
    for member in members:
        assert answers[members - {member}] is False
