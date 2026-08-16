"""Round-trip, canonicality and rejection of every non-canonical accepting path."""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from muster_spec import fixtures as F
from muster_spec import scenario as S
from muster_spec.nodes import (
    Atom,
    Bool,
    Bytes,
    CodecError,
    Digest,
    Int,
    Rec,
    Seq,
    SetV,
    Tagged,
    Unit,
    decode,
    encode,
    int_to_minimal,
)
from muster_spec.registry import REG
from muster_spec.schema import Ref, SchemaError, validate

SPECIMENS = [
    ("SymbolRef", F.Q_REF),
    ("Action", F.PAY_ACTION),
    ("ConsequentialAction", F.PAY_CONSEQUENTIAL),
    ("ActionSchema", F.ACTION_SCHEMA),
    ("PredicateSchema", F.PREDICATE_SCHEMA),
    ("DecisionProgram", F.DECISION_PROGRAM),
    ("AcquisitionPayload", S.ACQUISITION_PAYLOAD),
    ("VerificationReceipt", S.VERIFICATION_RECEIPT),
    ("InterestAssessment", S.INTEREST_ASSESSMENT),
    ("CaseConstructionRecord", S.CASE_CONSTRUCTION),
    ("CaseRevision", S.CASE_REVISION),
    ("RevisionLineage", S.REVISION_LINEAGE),
    ("BundleManifest", S.BUNDLE_MANIFEST),
    ("SignedManifest", S.SIGNED_MANIFEST),
    ("DisclosurePolicy", S.DISCLOSURE_POLICY),
    ("RatificationSet", S.RATIFICATION_SET),
    ("EvidenceRequest", S.EVIDENCE_REQUEST),
    ("AuthorizationContext", S.AUTHORIZATION_CONTEXT),
    ("RebuildInputs", S.REBUILD_INPUTS),
    ("LogicalCase", S.LOGICAL_CASE),
    ("KernelAnalysisRecord", S.KERNEL_RECORD),
    ("PlanningRecord", S.PLANNING_RECORD),
    ("DiagnosticAnnex", S.DIAGNOSTIC_ANNEX),
    ("AnalysisCertificate", S.ANALYSIS_CERTIFICATE),
    ("InternalAnalysisRecord", S.INTERNAL_RECORD),
    ("CommitmentEnvelope", S.COMMITMENT_ENVELOPE),
    ("SignedCommitmentEnvelope", S.SIGNED_ENVELOPE),
    ("ParticipantView", S.WAREHOUSE_VIEW),
    ("ParticipantView", S.AUDITOR_VIEW),
]


@pytest.mark.parametrize("name,node", SPECIMENS, ids=[f"{n}-{i}" for i, (n, _) in enumerate(SPECIMENS)])
def test_specimen_validates_against_its_declared_type(name, node):
    validate(REG, node, Ref(name))


@pytest.mark.parametrize("name,node", SPECIMENS, ids=[f"{n}-{i}" for i, (n, _) in enumerate(SPECIMENS)])
def test_ENCODER_ROUNDTRIP(name, node):
    raw = encode(node)
    assert decode(raw) == node
    # The second direction rejects any non-canonical accepting path.
    assert encode(decode(raw)) == raw


def test_canonicality_set_order_is_construction_independent():
    a = SetV([Atom("b"), Atom("a"), Atom("c")])
    b = SetV([Atom("c"), Atom("b"), Atom("a")])
    assert encode(a) == encode(b)


def test_NON_MINIMAL_INT_REJECTED():
    good = encode(Int(97))
    assert good == bytes([0x04, 0x01, 0x61])
    bad = bytes([0x04, 0x02, 0x00, 0x61])  # 97 in two octets
    with pytest.raises(CodecError, match="non-minimal"):
        decode(bad)


def test_zero_has_exactly_one_encoding():
    assert encode(Int(0)) == bytes([0x04, 0x01, 0x00])
    assert int_to_minimal(0) == b"\x00"


def test_NON_ASCII_ATOM_REJECTED():
    with pytest.raises(CodecError):
        Atom("café")
    raw = bytes([0x05, 0x04]) + "café".encode("utf-8")[:4]
    with pytest.raises(CodecError):
        decode(raw)


def test_ARITY_MISMATCH_REJECTED():
    short = Rec("SymbolRef/v1", [Atom("q")])
    with pytest.raises(SchemaError, match="arity"):
        validate(REG, short, Ref("SymbolRef"))


def test_unsorted_set_rejected_on_decode():
    body = encode(Atom("b")) + encode(Atom("a"))
    raw = bytes([0x08]) + (2).to_bytes(4, "big") + body
    with pytest.raises(CodecError, match="ascending"):
        decode(raw)


def test_duplicate_set_element_rejected_on_decode():
    body = encode(Atom("a")) * 2
    raw = bytes([0x08]) + (2).to_bytes(4, "big") + body
    with pytest.raises(CodecError, match="duplicate"):
        decode(raw)


def test_trailing_octets_rejected():
    with pytest.raises(CodecError, match="trailing"):
        decode(encode(Atom("a")) + b"\x01")


def test_unknown_primitive_tag_rejected():
    with pytest.raises(CodecError, match="unknown primitive tag"):
        decode(bytes([0xFE]))


def test_unknown_digest_algorithm_rejected():
    with pytest.raises(CodecError):
        decode(bytes([0x0B, 0x02]) + b"\x00" * 32)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(st.integers(min_value=-(2**80), max_value=2**80))
def test_integer_encoding_is_a_bijection(n):
    assert decode(encode(Int(n))) == Int(n)
    assert encode(decode(encode(Int(n)))) == encode(Int(n))


@settings(max_examples=200)
@given(st.binary(max_size=64))
def test_bytes_roundtrip(b):
    assert decode(encode(Bytes(b))) == Bytes(b)


def test_option_has_no_omission_form():
    from muster_spec.nodes import none, some

    assert encode(none()) != encode(some(Unit()))
    assert decode(encode(none())).variant == "None"


def test_record_tag_change_changes_bytes():
    a = Rec("Bin/v1", [Tagged("LitInt", Int(1)), Tagged("LitInt", Int(2))])
    b = Rec("QBin/v1", [Tagged("LitInt", Int(1)), Tagged("LitInt", Int(2))])
    assert encode(a) != encode(b)


def test_EMBEDDED_ATOM_OVERFLOW_REJECTED():
    """A 128-character constraint label is a legal ATOM but an illegal derived label.

    `"C:" || label || ":L"` would be 132 characters, which the codec cannot encode,
    so a valid-looking constraint would make its own query unrepresentable.
    """
    from muster_spec.nodes import CodecError
    from muster_spec.schema import SchemaError

    long_label = "C" * 128
    assert Atom(long_label)  # legal in isolation
    with pytest.raises(CodecError):
        Atom("C:" + long_label + ":L")

    bad = Rec(
        "Constraint/v1",
        [
            Atom(long_label),
            F.T.ge(F.T.var(F.Q_REF), F.T.lit(("int", 1))),
            Tagged("Structural", Rec("StructuralDeriv/v1", [F.PREDICATE_SCHEMA_DIGEST])),
        ],
    )
    with pytest.raises(SchemaError, match="declared maximum"):
        validate(REG, bad, Ref("Constraint"))

    ok = Rec("Constraint/v1", [Atom("C" * 100), bad.fields[1], bad.fields[2]])
    validate(REG, ok, Ref("Constraint"))
    assert Atom("C:" + "C" * 100 + ":L")
