"""The typed readers are the inverses of the encoders that were already frozen.

A durable store holds canonical octets and nothing else, so a process that
restarts has to be able to turn octets back into the values ``rebuild`` takes.
The readers added for that are checked here against the encoders they invert,
and the property is deliberately stated over **octets** rather than over
objects:

    encode(node(read(decode(octets)))) == octets

Object equality is the wrong assertion, and asserting it would be a mistake
that happens to pass on this corpus.  A field encoded as a *set* -- a party's
competences, an enum subset, an evidence target's source classes -- comes back
in canonical order rather than in the order it was authored in.  The canonical
octets are what every digest, signature and commitment ever covered, so octet
fidelity is the property that matters and object identity is not one the
encoder ever promised.

Digest stability is asserted alongside, because that is the consequence
anything depends on: a receipt read back out of a store is the same member of
the same transcript prefix it was when it went in.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from muster.core.analysis.planning import EvidenceRequested
from muster.core.case.revision import (
    TranscriptPrefix,
    read_authorization_context,
    read_transcript_prefix,
)
from muster.core.evidence.relations import (
    ClosedLowerBound,
    ClosedUpperBound,
    EnumSubset,
    ExactValue,
    read_relation,
    relation_node,
)
from muster.core.evidence.requests import EvidenceRequest, EvidenceTarget, read_evidence_request
from muster.core.evidence.transcript import (
    PartyRecord,
    TranscriptEntry,
    entry_digest,
    entry_node,
    read_case_construction,
    read_entry,
    read_party_record,
)
from muster.core.results import Err, Ok
from muster.core.values.classification import AcquisitionClass
from muster.core.values.scalars import VEnum, VInt
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import decode, encode
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import NAtom, NRec, NTagged, NUnit
from muster.core.wire.shape import decoded as as_result
from tests.support import ravi


def _read_entry(octets: bytes) -> TranscriptEntry:
    node = decode(octets)
    assert isinstance(node, Ok), node
    return read_entry(node.value)


#  ---- the artifacts a restart cannot do without --------------------------


def test_every_fixture_entry_survives_the_store_round_trip() -> None:
    """Twenty real entries, through octets and back, byte for byte."""
    entries = ravi.case_file().entries
    assert len(entries) > 1
    for entry in entries:
        octets = encode(entry_node(entry))
        recovered = _read_entry(octets)
        assert encode(entry_node(recovered)) == octets
        assert entry_digest(recovered) == entry_digest(entry)


def test_the_attested_fixture_entries_survive_too() -> None:
    """The attested variant carries receipt shapes the plain one does not."""
    entries = ravi.attested_case_file().entries
    assert entries
    for entry in entries:
        octets = encode(entry_node(entry))
        assert encode(entry_node(_read_entry(octets))) == octets


def test_the_construction_record_survives_and_keeps_its_digest() -> None:
    record = ravi.case_file().construction
    octets = encode(record.to_node())
    node = decode(octets)
    assert isinstance(node, Ok), node
    recovered = read_case_construction(node.value)
    assert encode(recovered.to_node()) == octets
    assert recovered.digest() == record.digest()


def test_the_authorization_context_survives() -> None:
    context = ravi.case_file().authorization_context
    octets = encode(context.to_node())
    node = decode(octets)
    assert isinstance(node, Ok), node
    recovered = read_authorization_context(node.value)
    assert recovered == context
    assert recovered.digest() == context.digest()


def test_a_transcript_prefix_survives_so_a_revision_can_be_replayed() -> None:
    """The prefix digest is a hash of a digest list; nothing else recovers the list."""
    digests = sorted(
        (entry_digest(entry) for entry in ravi.case_file().entries), key=lambda d: d.octets
    )
    prefix = TranscriptPrefix("tenant", "case", tuple(digests))
    octets = encode(prefix.to_node())
    node = decode(octets)
    assert isinstance(node, Ok), node
    recovered = read_transcript_prefix(node.value)
    assert recovered == prefix
    assert recovered.digest() == prefix.digest()


def test_an_evidence_request_survives_with_its_identity() -> None:
    """The request id *is* the digest, so a stored request must read back as one."""
    outcome = ravi.analysis().certificate.planning.planning_outcome
    assert isinstance(outcome, EvidenceRequested)
    request = outcome.request

    octets = encode(request.to_node())
    node = decode(octets)
    assert isinstance(node, Ok), node
    recovered = read_evidence_request(node.value)
    assert recovered == request
    assert recovered.digest() == request.digest()


#  ---- the set-valued fields, where object equality is the wrong assertion --


def test_a_set_valued_field_returns_canonically_ordered_and_not_as_authored() -> None:
    """States the exception rather than hiding behind a corpus that avoids it.

    The two members are the same length on purpose.  Canonical order is over
    *encoded* octets, and an atom's encoding is length-prefixed, so ``zebra``
    sorts before ``aardvark`` -- shorter first -- and a pair chosen for its
    alphabet rather than its length would not reorder at all.
    """
    unordered = PartyRecord("tenant", "principal", "ROLE", ("zebra", "apple"))
    octets = encode(unordered.to_node())
    node = decode(octets)
    assert isinstance(node, Ok), node
    recovered = read_party_record(node.value)

    assert recovered.competences != unordered.competences
    assert set(recovered.competences) == set(unordered.competences)
    assert encode(recovered.to_node()) == octets


def test_an_enum_subset_round_trips_through_its_canonical_set() -> None:
    relation = EnumSubset((VEnum("colour", "red"), VEnum("colour", "blue")))
    octets = encode(relation_node(relation))
    node = decode(octets)
    assert isinstance(node, Ok), node
    assert encode(relation_node(read_relation(node.value))) == octets


#  ---- fail-closed --------------------------------------------------------


def test_an_unknown_entry_variant_is_refused_rather_than_skipped() -> None:
    """``Retraction`` and ``Declaration`` carry semantics nothing here implements.

    Reading one and ignoring its meaning would produce a revision that is
    wrong; refusing it produces one that does not exist.
    """
    refused = as_result(lambda: read_entry(NTagged("Retraction", NUnit())))
    assert isinstance(refused, Err)
    assert refused.error.failure.value == "UNKNOWN_VARIANT"


def test_a_record_of_the_wrong_arity_is_refused() -> None:
    truncated = NRec("CaseConstructionRecord/v1", (NAtom("tenant"),))
    refused = as_result(lambda: read_case_construction(truncated))
    assert isinstance(refused, Err)
    assert refused.error.failure.value == "ARITY_MISMATCH"


def test_a_record_carrying_the_wrong_tag_is_refused() -> None:
    """The tag is checked, so a certificate cannot be read as a construction record."""
    refused = as_result(lambda: read_transcript_prefix(NRec("Nope/v1", ())))
    assert isinstance(refused, Err)
    assert refused.error.failure.value == "UNKNOWN_TYPE_TAG"


#  ---- generated relations and requests -----------------------------------

_values = st.one_of(
    st.integers(min_value=-1000, max_value=1000).map(VInt),
    st.sampled_from(["red", "green", "blue"]).map(lambda member: VEnum("colour", member)),
)


@given(_values)
@settings(max_examples=60, deadline=None)
def test_a_generated_relation_round_trips(value: VInt | VEnum) -> None:
    for relation in (ExactValue(value), ClosedLowerBound(value), ClosedUpperBound(value)):
        octets = encode(relation_node(relation))
        node = decode(octets)
        assert isinstance(node, Ok), node
        assert encode(relation_node(read_relation(node.value))) == octets


@given(
    st.lists(st.text(min_size=1, max_size=12), min_size=1, max_size=4, unique=True),
    st.lists(st.text(min_size=1, max_size=12), min_size=1, max_size=3, unique=True),
)
@settings(max_examples=40, deadline=None)
def test_a_generated_evidence_request_round_trips(args: list[str], sources: list[str]) -> None:
    request = EvidenceRequest(
        tenant_id="tenant",
        case_id="case",
        revision_semantic_digest=Digest(b"\x11" * 32),
        targets=(
            EvidenceTarget(
                SymbolRef("predicate", tuple(args)),
                AcquisitionClass.ATTESTABLE,
                tuple(sources),
            ),
        ),
    )
    octets = encode(request.to_node())
    node = decode(octets)
    assert isinstance(node, Ok), node
    recovered = read_evidence_request(node.value)
    assert encode(recovered.to_node()) == octets
    assert recovered.digest() == request.digest()
