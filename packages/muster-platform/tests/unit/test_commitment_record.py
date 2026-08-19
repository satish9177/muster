"""The path inventory and the extractor whose output *is* the leaf set.

The two properties worth stating separately, because they fail differently:

* the leaf set is a **function of the record**, so nothing between the kernel
  and the tree gets to choose what is committed;
* the path *names* are fixed in advance, so "this was not disclosed" is a
  statement about a known universe rather than about whatever a writer
  enumerated.

The collision case is the one worth being explicit about.  Two collection
members mapping to one path would silently drop a leaf, leaving a tree that is
internally consistent -- right ``leaf_count``, right root, every proof folds --
and no longer binding the whole record.  The extractor refuses it rather than
resolving it, and the revision refuses to exist in that shape at all, so the
defence is doubled and the second half is asserted below.
"""

from __future__ import annotations

from functools import cache

import pytest

from muster.core.results import Err, InvariantViolation, Ok
from muster.core.wire.codec import decode, encode
from muster.core.wire.nodes import NAtom, NInt
from muster.platform.commit.paths import (
    CERTIFICATE_SCHEMA_VERSION,
    DYNAMIC_PREFIXES,
    INVENTORY,
    STATIC_PATHS,
    PathFailure,
    Presence,
    check_segments,
    extract,
    is_dynamic,
    is_optional_in_record,
    path_in_inventory,
    presence_of,
)
from muster.platform.commit.record import InternalAnalysisRecord
from muster.platform.commit.salts import CaseSalt
from support.commitment import CommittedFixture, committed_case

SALT = CaseSalt(bytes(range(32)))

TENANT = "tenant-record"
CASE = "case-record"


@cache
def _fixture() -> CommittedFixture:
    """One durable, committed Ravi case, built through the real commands."""
    return committed_case(tenant_id=TENANT, case_id=CASE)


def _record() -> InternalAnalysisRecord:
    return _fixture().committed.record


#  ---- the inventory ---------------------------------------------------------


def test_every_inventory_path_satisfies_the_grammar() -> None:
    for spec in INVENTORY:
        assert check_segments(spec.path), spec.path


def test_the_inventory_has_no_duplicate_paths() -> None:
    paths = [spec.path for spec in INVENTORY]
    assert len(set(paths)) == len(paths)


def test_a_dynamic_path_is_accepted_only_at_the_declared_width_and_charset() -> None:
    prefix = DYNAMIC_PREFIXES[0]
    assert path_in_inventory(f"{prefix}.{'a' * 64}")
    assert not path_in_inventory(f"{prefix}.{'a' * 63}")
    assert not path_in_inventory(f"{prefix}.{'a' * 65}")
    assert not path_in_inventory(f"{prefix}.{'g' * 64}")
    assert not path_in_inventory(f"{prefix}.{'A' * 64}")


def test_a_path_outside_the_inventory_is_unknown() -> None:
    assert not path_in_inventory("kernel.outcome.everything")
    assert not path_in_inventory("case")
    assert not path_in_inventory("")
    assert presence_of("kernel.outcome.everything") is None


def test_presence_is_declared_for_every_static_path() -> None:
    for path in STATIC_PATHS:
        assert presence_of(path) is not None


def test_only_the_full_action_is_optional_in_the_record() -> None:
    """The reader-side required set leans on this being exactly one path."""
    optional = [spec.path for spec in INVENTORY if spec.optional_in_record]
    assert optional == ["action.full"]
    assert is_optional_in_record("action.full")
    assert not is_optional_in_record("kernel.outcome.action")


def test_a_dynamic_prefix_is_a_prefix_and_not_a_leaf() -> None:
    for prefix in DYNAMIC_PREFIXES:
        assert not is_dynamic(prefix)
        assert is_dynamic(f"{prefix}.{'0' * 64}")


#  ---- the extractor ---------------------------------------------------------


def test_the_leaf_set_is_exactly_the_extractor_output() -> None:
    extracted = _record().committed()
    assert isinstance(extracted, Ok), extracted
    committed = extracted.value
    assert len(committed.values) == len(set(committed.paths))
    for path in committed.paths:
        assert path_in_inventory(path), path


def test_the_extractor_is_canonically_ordered() -> None:
    extracted = _record().committed()
    assert isinstance(extracted, Ok), extracted
    paths = extracted.value.paths
    assert list(paths) == sorted(paths, key=lambda path: encode(NAtom(path)))


def test_every_always_present_path_is_committed() -> None:
    extracted = _record().committed()
    assert isinstance(extracted, Ok), extracted
    committed = set(extracted.value.paths)
    for spec in INVENTORY:
        if spec.presence is Presence.ALWAYS and not spec.dynamic:
            assert spec.path in committed, spec.path


def test_the_divergent_outcome_commits_its_own_paths_and_no_others() -> None:
    extracted = _record().committed()
    assert isinstance(extracted, Ok), extracted
    committed = set(extracted.value.paths)
    assert {"kernel.outcome.reachable", "kernel.outcome.left", "kernel.outcome.right"} <= committed
    for absent in ("kernel.outcome.action", "kernel.outcome.witness", "action.full"):
        assert absent not in committed


def test_the_committed_octets_are_the_values_own_encoding() -> None:
    revision = _record().revision
    extracted = _record().committed()
    assert isinstance(extracted, Ok), extracted
    committed = extracted.value
    assert committed.octets_at("case.tenant_id") == encode(NAtom(revision.tenant_id))
    assert committed.octets_at("case.case_id") == encode(NAtom(revision.case_id))
    assert committed.octets_at("certificate.schema_version") == encode(
        NInt(CERTIFICATE_SCHEMA_VERSION)
    )
    #  And they decode: a committed value is a wire value, not an opaque blob.
    for _path, octets in committed.values:
        assert isinstance(decode(octets), Ok)


def test_a_certificate_from_another_schema_version_is_refused() -> None:
    from dataclasses import replace

    record = _record()
    other = replace(record.certificate, certificate_schema_version=2)
    result = extract(certificate=other, revision=record.revision, full_action_octets=None)
    assert isinstance(result, Err)
    assert result.error.failure is PathFailure.UNSUPPORTED_SCHEMA_VERSION


def test_a_record_whose_certificate_cites_another_revision_is_unrepresentable() -> None:
    """The commitment binds one record. Two halves of two cases is not one."""
    from dataclasses import replace

    record = _record()
    mismatched = replace(record.revision, as_of=record.revision.as_of + 1)
    with pytest.raises(InvariantViolation):
        InternalAnalysisRecord(
            certificate=record.certificate,
            revision=mismatched,
            full_action=None,
            salt=SALT,
        )


def test_the_record_never_prints_its_salt() -> None:
    """A traceback or a log line is the likeliest way for a secret to escape."""
    record = _record()
    printed = repr(record)
    assert "redacted" in printed
    assert record.salt.octets.hex() not in printed
    assert "redacted" in repr(record.salt)
    assert record.salt.octets.hex() not in str(record.salt)


def test_a_case_salt_is_exactly_thirty_two_octets() -> None:
    with pytest.raises(InvariantViolation):
        CaseSalt(bytes(31))
    with pytest.raises(InvariantViolation):
        CaseSalt(bytes(33))


def test_a_colliding_dynamic_path_is_unrepresentable_upstream() -> None:
    """The segment is injective because the collection it digests is unique.

    A dynamic segment is a digest of a member's identifying key, so two members
    sharing that key would share a path.  ``CaseRevision`` refuses to hold two
    such members at all -- established facts unique by ``ref``, constraints by
    ``label``, non-effects by ``(rule_id, subject)`` -- which is the same three
    keys the segments are built from.  The extractor's own refusal is the
    backstop for anything that reached it another way.
    """
    from dataclasses import replace

    revision = _record().revision
    with pytest.raises(InvariantViolation):
        replace(revision, established=(revision.established[0], revision.established[0]))
    with pytest.raises(InvariantViolation):
        replace(revision, constraints=(revision.constraints[0], revision.constraints[0]))
    with pytest.raises(InvariantViolation):
        replace(revision, non_effects=(revision.non_effects[0], revision.non_effects[0]))
