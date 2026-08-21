"""The frozen corpus may grow. It may not move without saying so.

``golden_vectors.json`` is **generated**.  ``run_spec.py`` recomputes every
vector from the reference registry and writes the file, so a change to a wire
type silently rewrites the corpus and every test that reads the corpus goes on
passing.  That is the right way for the artifact to be produced -- hand-edited
expected digests are how a corpus stops describing anything -- and it leaves one
gap that matters:

    a milestone can move a *previously frozen* vector and truthfully report
    "corpus regenerated, all checks pass", because everything it is compared
    against was regenerated with it.

Milestone E moved nine of sixteen.  Every one of them moved for a ratified
reason -- three artifacts gained a field that check Q-12 requires, and the rest
are digests of digests of those -- and the audit that established it was written
by hand, once, and would not survive the next milestone.

**What this file is.**  A ledger, maintained by hand, of every vector the corpus
has ever frozen: its octets, and the milestone that last moved it with the
ratified cause named.  It is *not* generated, and that is the whole design: a
future change that moves a frozen vector fails here, and the only way to make it
pass is to edit this file -- which puts the movement, and a stated cause, in the
diff a reviewer reads.

**What it is not.**  It is not a claim that the octets are correct; the round
trip in ``test_golden_vectors`` and the reference implementation are what say
that.  It is the claim that nothing moves *quietly*.  The distinction is the one
the milestone-D and milestone-E transition audits were both written to make, and
this is the standing form of it, so the next one does not have to be discovered.

**Why the octets and not the digests.**  A digest tells a reviewer that
something changed.  The octets tell them *what*, and structural comparison
against the previous entry is what turns "the manifest moved" into "the manifest
moved in field 7 and nowhere else".  A ledger of digests would have caught
milestone E's change and said nothing useful about it.
"""

from __future__ import annotations

import pytest

from muster.core.results import Ok
from muster.core.wire.codec import canonical_set, decode
from muster.core.wire.nodes import NAtom, NBytes, NDigest, Node, NRec, NSeq, NSet, NTagged
from tests.conftest import GoldenVector

pytestmark = pytest.mark.golden

#  ---- the ledger ----------------------------------------------------------
#
#  name -> (last milestone that moved it, ratified cause, octets as hex)
#
#  A vector that has never moved carries the milestone that introduced it.
#  Adding a row is how a milestone freezes a new vector; changing a row is how
#  it moves an old one, and the cause column is not decoration -- an entry
#  whose cause reads "tests were failing" is the finding this file exists to
#  surface.
#
#  The seven that milestone E did **not** touch are recorded by their pre-E
#  octets, taken from the corpus as commit ac6dc37 published it.  That is what
#  makes their rows evidence rather than a restatement of today's tree: they
#  were transcribed from the previous milestone's artifact, and they still
#  match.

_PHASE_08 = "Phase 0.8"
_MILESTONE_E = "Milestone E"

#  Milestone E's three root causes, from section 12.4:
#
#  (1) PredicateSpec gains ``resource_scope_kinds`` -- Q-12(d) resolves a
#      proposition's resource coordinates from the bundle's declared kinds, so
#      the schema has to declare them.  Moves PREDICATE_SCHEMA, and with it
#      every artifact that pins one.
#  (2) CaseConstructionRecord gains ``case_scope_coordinates`` -- Q-12(d) reads
#      case-level coordinates "from the signed CaseConstructionRecord".
#  (3) AuthorizationContext renames ``key_registry_snapshot_digest`` to
#      ``authority_registry_snapshot_digest`` -- section 12.4.2, verbatim.
#
#  Section 12.4.5 states the consequence in advance: "**The golden-vector
#  corpus digest changes.** Every count quoted in this document ... must be
#  re-generated, not hand-edited, when the delta lands."
_SCHEMA_GAINED_SCOPE_KINDS = "12.4.3 Q-12(d): PredicateSpec gains resource_scope_kinds"
_CONSTRUCTION_GAINED_COORDINATES = (
    "12.4.3 Q-12(d): CaseConstructionRecord gains case_scope_coordinates"
)
_CONTEXT_PIN_RENAMED = "12.4.2: AuthorizationContext pin renamed to the authority registry"
_DOWNSTREAM = "derived: a digest of an artifact moved by the three causes above"

LEDGER: dict[str, tuple[str, str]] = {
    #  Untouched since Phase 0.8. Transcribed from the pre-E corpus.
    "V-01-SymbolRef": (_PHASE_08, "frozen"),
    "V-02-NestedTerm": (_PHASE_08, "frozen"),
    "V-03-SolverQuery": (_PHASE_08, "frozen"),
    "V-04-Action": (_PHASE_08, "frozen"),
    "V-05-ConsequentialAction": (_PHASE_08, "frozen"),
    "V-08-InterestAssessment": (_PHASE_08, "frozen"),
    "V-11-DisclosurePolicy": (_PHASE_08, "frozen"),
    #  Moved by milestone E, each with its cause.
    "V-06-AcquisitionPayload": (_MILESTONE_E, _SCHEMA_GAINED_SCOPE_KINDS),
    "V-07-VerificationReceiptSigningBody": (_MILESTONE_E, _SCHEMA_GAINED_SCOPE_KINDS),
    "V-09-CaseRevision": (
        _MILESTONE_E,
        f"{_SCHEMA_GAINED_SCOPE_KINDS}; {_CONSTRUCTION_GAINED_COORDINATES}; {_CONTEXT_PIN_RENAMED}",
    ),
    "V-10-BundleManifest": (_MILESTONE_E, _SCHEMA_GAINED_SCOPE_KINDS),
    "V-12-CommitmentEnvelope": (_MILESTONE_E, _DOWNSTREAM),
    "V-13-SignedCommitmentEnvelope": (_MILESTONE_E, _DOWNSTREAM),
    "V-14-ParticipantView": (_MILESTONE_E, _DOWNSTREAM),
    "V-15-CommitmentLeaf": (_MILESTONE_E, _DOWNSTREAM),
    "V-16-CommitmentRoot": (_MILESTONE_E, _DOWNSTREAM),
}

#  The octets each ledger row stands for, hex, exactly as the corpus publishes
#  them.  Kept in a second table only because the causes above are long enough
#  that interleaving them with 2000-character hex strings would make neither
#  readable.
OCTETS: dict[str, str] = {}

#: The octets a *moved* vector had before the milestone that moved it, from
#: ``frozen_corpus_superseded.txt``.  Only moved vectors have an entry.
SUPERSEDED: dict[str, str] = {}


def _load_octets() -> None:
    """Populate ``OCTETS`` from the frozen file beside this module.

    A separate file rather than a literal, because a 2001-octet vector as a
    Python string is unreviewable and would be scrolled past.  The file is
    written **once per movement, by hand**, and is not produced by
    ``run_spec.py`` -- which is the property that makes it evidence.
    """
    from pathlib import Path

    tables = (
        (OCTETS, "frozen_corpus.txt"),
        (SUPERSEDED, "frozen_corpus_superseded.txt"),
    )
    for table, filename in tables:
        frozen = Path(__file__).with_name(filename)
        for line in frozen.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            vector, _, octets = stripped.partition(" ")
            table[vector] = octets


_load_octets()


def _members(node: NSeq | NSet) -> tuple[Node, ...]:
    """The children of an ordered sequence or of a canonical set.

    Two field names for one idea, and the distinction is load-bearing
    everywhere else: order is semantic in one and canonical in the other. Here
    it is not -- a shape comparison walks children -- so the two are read
    through one function rather than through a field name that happens to
    exist on only one of them.
    """
    return node.items if isinstance(node, NSeq) else node.members


def _shape_differences(previous: Node, current: Node, path: str = "") -> list[str]:
    """Every way two encodings differ that is **not** a digest or hash value.

    A moved frozen vector is legitimate when what moved inside it is a digest:
    an artifact it pins gained a ratified field, so the pin changed and nothing
    else did.  It is a very different event when a tag, an arity, an atom, an
    integer or a set membership moves -- that is the *shape* of a frozen type
    changing, and no amount of "the corpus was regenerated" makes it routine.

    So this returns the differences that are not digest-shaped.  An empty list
    is the claim "only pins moved", stated over the decoded trees rather than
    over a hex diff, and it is the claim milestone E made in prose.
    """
    if type(previous) is not type(current):
        return [f"{path}: {type(previous).__name__} became {type(current).__name__}"]
    match previous, current:
        case NRec(), NRec():
            assert isinstance(current, NRec)
            if previous.tag != current.tag:
                return [f"{path}: tag {previous.tag} became {current.tag}"]
            if len(previous.fields) != len(current.fields):
                return [
                    f"{path}/{previous.tag}: arity {len(previous.fields)} "
                    f"became {len(current.fields)}"
                ]
            return [
                difference
                for index, (was, now) in enumerate(
                    zip(previous.fields, current.fields, strict=True)
                )
                for difference in _shape_differences(was, now, f"{path}/{previous.tag}[{index}]")
            ]
        case NTagged(), NTagged():
            assert isinstance(current, NTagged)
            if previous.tag != current.tag:
                return [f"{path}: variant {previous.tag} became {current.tag}"]
            return _shape_differences(previous.payload, current.payload, f"{path}/{previous.tag}")
        case ((NSeq() | NSet()), (NSeq() | NSet())):
            assert isinstance(current, NSeq | NSet)
            #  Through ``_members`` rather than ``.items``: a sequence holds
            #  ``items`` and a set holds ``members``, and reading one field off
            #  both worked only because no *moved* vector has yet differed
            #  inside a set. The first one that does would have raised
            #  ``AttributeError`` here -- out of the diagnostic whose whole job
            #  is to say what moved, at the moment somebody needed it to.
            was_members, now_members = _members(previous), _members(current)
            if len(was_members) != len(now_members):
                return [f"{path}: {len(was_members)} members became {len(now_members)}"]
            return [
                difference
                for index, (was, now) in enumerate(zip(was_members, now_members, strict=True))
                for difference in _shape_differences(was, now, f"{path}[{index}]")
            ]
        case NDigest(), NDigest():
            #  A pin moved. That is the whole permitted class of change.
            return []
        case NBytes(), NBytes():
            assert isinstance(current, NBytes)
            if previous.value == current.value:
                return []
            #  Two shapes of octet string move for the same reason a pin does.
            #
            #  A **32-octet** value is a hash: a merkle root, a salted field
            #  commitment, an HMAC signature. It is a function of things that
            #  moved, not a thing somebody chose.
            #
            #  A value that **decodes to a digest** is a pin that was disclosed
            #  as a value rather than referenced as a field -- a participant
            #  view carries ``revision.bundle_pin`` this way, as the 34 octets
            #  ``0b 01 <32>``. Decoding it is the honest test; matching on the
            #  length 34 would be matching on a coincidence of the encoding.
            if len(previous.value) == len(current.value) == 32:
                return []
            was, now = decode(previous.value), decode(current.value)
            if (
                isinstance(was, Ok)
                and isinstance(now, Ok)
                and isinstance(was.value, NDigest)
                and isinstance(now.value, NDigest)
            ):
                return []
            return [f"{path}: {len(previous.value)} content octets changed"]
        case _:
            if previous != current:
                return [f"{path}: {previous!r} became {current!r}"]
            return []


def test_the_ledger_covers_the_corpus_exactly(
    golden_vectors: dict[str, GoldenVector],
) -> None:
    """Every vector has a row, and every row has a vector.

    An equality rather than a subset, in both directions.  A subset check would
    let a milestone add a vector and never record it, and the next one would
    move it unnoticed -- which is the same gap one level down.
    """
    assert set(LEDGER) == set(golden_vectors), (
        "the ledger and the corpus disagree about which vectors exist: "
        f"only in ledger {sorted(set(LEDGER) - set(golden_vectors))}, "
        f"only in corpus {sorted(set(golden_vectors) - set(LEDGER))}"
    )
    assert set(OCTETS) == set(LEDGER), sorted(set(OCTETS) ^ set(LEDGER))


def test_no_previously_frozen_vector_has_moved(
    golden_vectors: dict[str, GoldenVector],
) -> None:
    """**The standing regression.**

    If this fails, a vector the corpus had already frozen now encodes to
    different octets.  That is not necessarily wrong -- milestone E moved nine
    of them legitimately -- but it is never something to absorb by regenerating
    the corpus.  The fix is to update the row here *and* record the ratified
    clause that caused it, so the movement appears in a diff with a reason
    beside it rather than as a changed number in a generated file.
    """
    moved = [
        name
        for name, vector in sorted(golden_vectors.items())
        if vector.octets.hex() != OCTETS[name]
    ]
    assert not moved, (
        f"previously frozen vectors moved: {moved}. This is not a test to update -- "
        "record the movement in LEDGER with the ratified clause that caused it."
    )


def test_every_moved_vector_names_a_cause_and_not_a_test_failure() -> None:
    """A cause column nobody fills in is a cause column that is not a control.

    Cheap, and it is the check that keeps the ledger from decaying into a
    second copy of the corpus.  A row that moved must say why, and "why" must
    point at a clause rather than at a symptom.
    """
    forbidden = ("test", "failing", "fix", "update", "regenerat")
    for name, (milestone, cause) in sorted(LEDGER.items()):
        assert cause, name
        if milestone == _PHASE_08:
            continue
        lowered = cause.lower()
        for needle in forbidden:
            assert needle not in lowered, (
                f"{name} was moved for {cause!r}, which describes a symptom rather than "
                "a ratified cause"
            )


def test_the_ledger_octets_are_what_the_production_codec_reads(
    golden_vectors: dict[str, GoldenVector],
) -> None:
    """The ledger holds real encodings, not arbitrary hex.

    Without this a corrupted ledger entry would be indistinguishable from a
    moved vector, and the failure above would point at the wrong file.
    """
    for name in sorted(OCTETS):
        octets = bytes.fromhex(OCTETS[name])
        decoded = decode(octets)
        assert isinstance(decoded, Ok), f"{name}: the ledger entry does not decode"
        assert golden_vectors[name].type_name, name


def test_the_superseded_table_holds_exactly_the_moved_vectors() -> None:
    """A predecessor row exists for every vector the ledger says moved, and only those.

    An equality, so a milestone cannot record a movement in ``LEDGER`` and skip
    the predecessor octets that make the movement inspectable -- which is the
    step that turns this from a tripwire into an audit.
    """
    moved = {name for name, (milestone, _) in LEDGER.items() if milestone != _PHASE_08}
    assert set(SUPERSEDED) == moved, sorted(set(SUPERSEDED) ^ moved)


def test_a_moved_vector_changed_only_the_pins_inside_it(
    golden_vectors: dict[str, GoldenVector],
) -> None:
    """**The structural half of the audit, and the part a digest cannot state.**

    For every vector that moved, decode what it was and what it is and compare
    the two trees.  The movement must be confined to digest-valued leaves and
    32-octet hashes -- pins, merkle roots, salted commitments, signatures.

    That is the difference between "three artifacts gained a ratified field, so
    everything that pins them re-hashed" and "a frozen wire type quietly changed
    shape".  Both produce a new corpus digest and both look identical in a
    regenerated file; only one of them is allowed, and this is what tells them
    apart.
    """
    for name in sorted(SUPERSEDED):
        was = decode(bytes.fromhex(SUPERSEDED[name]))
        now = decode(golden_vectors[name].octets)
        assert isinstance(was, Ok), f"{name}: the superseded entry does not decode"
        assert isinstance(now, Ok), f"{name}: the current vector does not decode"
        differences = _shape_differences(was.value, now.value)
        assert not differences, f"{name} changed shape, not only its pins: {differences}"


def test_the_moved_vectors_really_did_move(
    golden_vectors: dict[str, GoldenVector],
) -> None:
    """The superseded rows are predecessors, not copies of the current octets.

    Without this, ``test_a_moved_vector_changed_only_the_pins_inside_it`` would
    pass vacuously the moment somebody regenerated the superseded file from
    today's tree -- which is precisely the self-confirming comparison this whole
    module exists to prevent, reintroduced one file along.
    """
    for name in sorted(SUPERSEDED):
        assert SUPERSEDED[name] != golden_vectors[name].octets.hex(), (
            f"{name}: the superseded octets are today's octets, so the "
            "comparison against them proves nothing"
        )


def test_the_diagnostic_survives_a_set_that_moved() -> None:
    """A set is a shape this comparison walks, and it must report rather than raise.

    The path exists for a movement that has not happened yet: no vector moved
    so far has differed *inside* a set, so the branch that reads a set's
    children has never run on one. It read ``.items``, which only a sequence
    has -- so the first milestone to move a set inside a frozen vector would
    have got an ``AttributeError`` from the tool it was relying on to tell it
    what had moved.

    Both cases are asserted, because reporting a difference is only half of it:
    a comparison that reported one for two equal sets would fail every future
    milestone for nothing.
    """
    was = canonical_set((NAtom("HR_PAYROLL_SYSTEM"), NAtom("SITE_ACCESS_CONTROL")))
    widened = canonical_set(
        (NAtom("HR_PAYROLL_SYSTEM"), NAtom("SITE_ACCESS_CONTROL"), NAtom("ANYBODY_AT_ALL"))
    )

    assert _shape_differences(was, was) == []
    assert _shape_differences(NSeq(()), NSeq(())) == []

    grew = _shape_differences(was, widened, "permitted_source_classes")
    assert grew == ["permitted_source_classes: 2 members became 3"]

    swapped = canonical_set((NAtom("HR_PAYROLL_SYSTEM"), NAtom("SITE_B_ACCESS_CONTROL")))
    changed = _shape_differences(was, swapped, "permitted_source_classes")
    assert len(changed) == 1
    assert "SITE_ACCESS_CONTROL" in changed[0]
