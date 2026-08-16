"""[B9/N1/B11] Pinned disclosure, view privacy, and what inference is honestly conceded."""

from __future__ import annotations

import pytest

from muster_spec import fixtures as F
from muster_spec import scenario as S
from muster_spec.digests import digest_node
from muster_spec.disclosure import (
    DisclosurePolicyConflict,
    DisclosurePolicyIncomplete,
    UnacknowledgedInferenceDisclosure,
    UnknownCommitmentPath,
    action_kind_of,
    build_participant_view,
    resolve_entry,
    validate_policy,
    verify_view,
)
from muster_spec.nodes import Atom, Bool, Int, Rec, Seq, Tagged, encode, none, some
from muster_spec.registry import REG
from muster_spec.schema import Ref, validate

RATIFIED = {S.INFERENCE_ACK_DIGEST.raw}


def test_policy_validates():
    validate_policy(S.DISCLOSURE_POLICY, RATIFIED)
    validate(REG, S.DISCLOSURE_POLICY, Ref("DisclosurePolicy"))


def test_DISCLOSURE_POLICY_CONFLICT_FAILS_LOAD():
    """Two entries on one key -- never resolved by order, entry order or recency."""
    duplicate = S.disclosure_entry("DIVERGENT", None, "WAREHOUSE", "NOTIFICATION", ["case.case_id"])
    policy = Rec(
        "DisclosurePolicy/v1",
        [Int(1), Seq([S.WAREHOUSE_DIVERGENT, duplicate])],
    )
    with pytest.raises(DisclosurePolicyConflict):
        validate_policy(policy, RATIFIED)


def test_duplicate_key_is_also_rejected_structurally():
    from muster_spec.schema import SchemaError

    duplicate = S.disclosure_entry("DIVERGENT", None, "WAREHOUSE", "NOTIFICATION", ["case.case_id"])
    policy = Rec("DisclosurePolicy/v1", [Int(1), Seq([S.WAREHOUSE_DIVERGENT, duplicate])])
    with pytest.raises(SchemaError, match="duplicate key"):
        validate(REG, policy, Ref("DisclosurePolicy"))


def test_UNACKNOWLEDGED_INFERENCE_FAILS_LOAD():
    entry = S.disclosure_entry(
        "INVARIANT", "PAY", "SUPPLIER", "NOTIFICATION",
        ["kernel.outcome.action"], reveals_sensitive=True, ack=None,
    )
    with pytest.raises(UnacknowledgedInferenceDisclosure):
        validate_policy(Rec("DisclosurePolicy/v1", [Int(1), Seq([entry])]), RATIFIED)


def test_unresolvable_acknowledgement_fails_load():
    entry = S.disclosure_entry(
        "INVARIANT", "PAY", "SUPPLIER", "NOTIFICATION",
        ["kernel.outcome.action"], reveals_sensitive=True,
        ack=digest_node("RATIFICATION_RECORD", Atom("does-not-exist")),
    )
    with pytest.raises(UnacknowledgedInferenceDisclosure, match="does not resolve"):
        validate_policy(Rec("DisclosurePolicy/v1", [Int(1), Seq([entry])]), RATIFIED)


def test_unknown_path_in_a_policy_fails_load():
    entry = S.disclosure_entry("DIVERGENT", None, "X", "Y", ["kernel.outcome.secret_quantity"])
    with pytest.raises(UnknownCommitmentPath):
        validate_policy(Rec("DisclosurePolicy/v1", [Int(1), Seq([entry])]), RATIFIED)


# --------------------------------------------------------------------------
# [N1b] the key is total over AnalysisOutcome
# --------------------------------------------------------------------------


def test_action_kind_is_Some_exactly_for_INVARIANT():
    invariant = Tagged(
        "Invariant",
        Rec("InvariantOutcome/v1", [F.PAY_CONSEQUENTIAL, Rec("World/v1", [Seq([])]),
                                    digest_node("SOLVER_QUERY", Atom("q"))]),
    )
    assert action_kind_of(invariant).variant == "Some"
    for variant in (S.OUTCOME,
                    Tagged("Infeasible", Rec("InfeasibleOutcome/v1", [Seq([])])),
                    Tagged("Indeterminate", Rec("IndeterminateOutcome/v1", [Atom("BUDGET")]))):
        assert action_kind_of(variant).variant == "None"


def test_action_kind_Some_on_a_non_invariant_entry_fails_load():
    entry = S.disclosure_entry("DIVERGENT", "PAY", "X", "Y", ["case.case_id"])
    with pytest.raises(DisclosurePolicyIncomplete, match="Some iff"):
        validate_policy(Rec("DisclosurePolicy/v1", [Int(1), Seq([entry])]), RATIFIED)


def test_missing_entry_is_incomplete_not_a_default():
    with pytest.raises(DisclosurePolicyIncomplete):
        resolve_entry(S.DISCLOSURE_POLICY, S.OUTCOME, "STRANGER", "NOTIFICATION")


def test_every_outcome_class_can_be_keyed():
    """Infeasible and Indeterminate name no action; the key still resolves."""
    outcomes = {
        "INFEASIBLE": Tagged("Infeasible", Rec("InfeasibleOutcome/v1", [Seq([Atom("C-ATT-1")])])),
        "INDETERMINATE": Tagged("Indeterminate", Rec("IndeterminateOutcome/v1", [Atom("BUDGET")])),
    }
    entries = [
        S.disclosure_entry(cls, None, "AUDITOR", "AUDIT", ["case.case_id"])
        for cls in outcomes
    ]
    policy = Rec("DisclosurePolicy/v1", [Int(1), Seq(entries)])
    validate_policy(policy, RATIFIED)
    for cls, outcome in outcomes.items():
        assert resolve_entry(policy, outcome, "AUDITOR", "AUDIT").fields[0].value == cls


# --------------------------------------------------------------------------
# privacy negatives
# --------------------------------------------------------------------------


TRUST = dict(keyring=F.KEYRING, policy=S.DISCLOSURE_POLICY, trusted_signer="key-muster-1")


def accept(view) -> list[str]:
    return verify_view(view, TRUST["keyring"], TRUST["policy"],
                       trusted_signer=TRUST["trusted_signer"])


def test_views_verify():
    assert accept(S.WAREHOUSE_VIEW) == []
    assert accept(S.AUDITOR_VIEW) == []


def test_OUTCOME_TAG_NOT_FORCED():
    """[B11] The outcome tag is an ordinary leaf, disclosed only when permitted."""
    raw = encode(S.WAREHOUSE_VIEW)
    assert encode(Atom("kernel.outcome.tag")) not in raw
    assert encode(Atom("DIVERGENT")) not in raw
    # The AUDITOR entry does permit it.
    assert encode(Atom("kernel.outcome.tag")) in encode(S.AUDITOR_VIEW)


@pytest.mark.parametrize(
    "path",
    ["kernel.outcome.tag", "kernel.outcome.reachable", "kernel.outcome.left",
     "kernel.outcome.right", "revision.declared", "kernel.logical_case_digest"],
)
def test_undisclosed_value_bytes_are_absent_from_the_warehouse_view(path):
    committed = S.COMMITTED[path]
    assert committed not in encode(S.WAREHOUSE_VIEW), path


def test_the_disputed_quantity_never_appears_in_the_warehouse_view():
    """The Rs 62,370.00 / Rs 63,000.00 amounts and the bound 99 stay hidden."""
    raw = encode(S.WAREHOUSE_VIEW)
    for probe in (Int(6_237_000), Int(6_300_000), Int(99), Int(120)):
        assert encode(probe) not in raw


def test_participant_view_embeds_no_certificate_and_no_salt():
    raw = encode(S.WAREHOUSE_VIEW)
    assert encode(S.ANALYSIS_CERTIFICATE) not in raw
    assert encode(S.INTERNAL_RECORD) not in raw
    assert F.SALT_CASE not in raw
    assert encode(S.CASE_REVISION) not in raw


def test_disclosed_salts_are_path_specific_not_the_case_secret():
    disclosures = S.WAREHOUSE_VIEW.fields[4]
    for d in disclosures.items:
        assert d.fields[2].value != F.SALT_CASE
        assert len(d.fields[2].value) == 32


def test_view_names_the_exact_entry_it_applied():
    entry = resolve_entry(S.DISCLOSURE_POLICY, S.OUTCOME, "WAREHOUSE", "NOTIFICATION")
    assert S.WAREHOUSE_VIEW.fields[3] == digest_node("DISCLOSURE_ENTRY", entry)


def test_UNAUTHENTICATED_VIEW_IS_REJECTED():
    """Merkle consistency is not provenance: every leaf can prove membership in a
    tree the reader has no reason to trust."""
    from muster_spec.nodes import Bytes
    from muster_spec.signing import verify_record

    forged_envelope = Rec(
        "SignedCommitmentEnvelope/v1",
        [S.COMMITMENT_ENVELOPE,
         Rec("Signature/v1", [Atom("HMAC-SHA256-SPEC-STANDIN"), Bytes(bytes(32))])],
    )
    assert verify_record(REG, F.KEYRING, forged_envelope, "SignedCommitmentEnvelope") is False
    view = Rec("ParticipantView/v1", [forged_envelope, *S.WAREHOUSE_VIEW.fields[1:]])
    failures = accept(view)
    assert any("signature does not verify" in f for f in failures), failures


def test_VIEW_SIGNED_BY_AN_UNTRUSTED_KEY_IS_REJECTED():
    failures = verify_view(S.WAREHOUSE_VIEW, F.KEYRING, S.DISCLOSURE_POLICY,
                           trusted_signer="key-somebody-else")
    assert any("not the trusted signer" in f for f in failures), failures


def test_OVER_DISCLOSURE_BEYOND_THE_NAMED_ENTRY_IS_REJECTED():
    """The reader-side variant of B11/N1.

    A view built from the AUDITOR entry but labelled with the WAREHOUSE entry
    digest discloses seven extra paths, including the outcome tag and the
    reachable action set.  Every leaf proves membership, so membership checking
    alone accepts it.
    """
    wh_entry = resolve_entry(S.DISCLOSURE_POLICY, S.OUTCOME, "WAREHOUSE", "NOTIFICATION")
    over = build_participant_view(
        S.TREE, S.SIGNED_ENVELOPE, S.AUDITOR_DIVERGENT, "WAREHOUSE", "NOTIFICATION", None
    )
    mislabelled = Rec(
        "ParticipantView/v1",
        [over.fields[0], Atom("WAREHOUSE"), Atom("NOTIFICATION"),
         digest_node("DISCLOSURE_ENTRY", wh_entry), over.fields[4], none()],
    )
    permitted = {p.value for p in wh_entry.fields[6].items}
    disclosed = {d.fields[0].value for d in mislabelled.fields[4].items}
    assert disclosed - permitted, "the probe must actually over-disclose"
    assert "kernel.outcome.tag" in disclosed - permitted

    failures = accept(mislabelled)
    assert failures
    for extra in sorted(disclosed - permitted):
        assert any(repr(extra) in f and "does not permit" in f for f in failures), extra


def test_VIEW_CLAIMING_A_DIFFERENT_AUDIENCE_THAN_ITS_ENTRY_IS_REJECTED():
    aud_entry = resolve_entry(S.DISCLOSURE_POLICY, S.OUTCOME, "AUDITOR", "AUDIT")
    view = Rec(
        "ParticipantView/v1",
        [S.AUDITOR_VIEW.fields[0], Atom("WAREHOUSE"), Atom("NOTIFICATION"),
         digest_node("DISCLOSURE_ENTRY", aud_entry), S.AUDITOR_VIEW.fields[4], none()],
    )
    failures = accept(view)
    assert any("but the view claims" in f for f in failures), failures


def test_VIEW_NAMING_AN_ENTRY_OUTSIDE_THE_PINNED_POLICY_IS_REJECTED():
    stranger = S.disclosure_entry("DIVERGENT", None, "WAREHOUSE", "NOTIFICATION",
                                  ["case.tenant_id", "case.case_id", "bundle.manifest_digest",
                                   "revision.bundle_pin", "kernel.outcome.tag"])
    view = Rec(
        "ParticipantView/v1",
        [S.WAREHOUSE_VIEW.fields[0], Atom("WAREHOUSE"), Atom("NOTIFICATION"),
         digest_node("DISCLOSURE_ENTRY", stranger), S.WAREHOUSE_VIEW.fields[4], none()],
    )
    failures = accept(view)
    assert any("resolves to 0 entries" in f for f in failures), failures


def test_VIEW_AGAINST_A_DIFFERENT_POLICY_IS_REJECTED():
    other_policy = Rec("DisclosurePolicy/v1", [S.DISCLOSURE_POLICY.fields[0],
                                               Seq([S.WAREHOUSE_DIVERGENT])])
    failures = verify_view(S.WAREHOUSE_VIEW, F.KEYRING, other_policy,
                           trusted_signer="key-muster-1")
    assert any("different disclosure policy" in f for f in failures), failures


def test_TAMPERED_LEAF_VALUE_IS_REJECTED():
    from muster_spec.nodes import Bytes

    ds = list(S.WAREHOUSE_VIEW.fields[4].items)
    d = ds[0]
    ds[0] = Rec("Disclosure/v1", [d.fields[0], Bytes(encode(Atom("BETA"))), d.fields[2], d.fields[3]])
    view = Rec("ParticipantView/v1", [*S.WAREHOUSE_VIEW.fields[:4], Seq(ds),
                                      S.WAREHOUSE_VIEW.fields[5]])
    failures = accept(view)
    assert any("inclusion proof does not verify" in f for f in failures), failures


def test_inference_is_recorded_rather_than_denied():
    """Where the action itself determines a private input, the view says so."""
    entry = S.SUPPLIER_INVARIANT
    assert entry.fields[4].value is True
    assert entry.fields[5].variant == "Some"
    view = build_participant_view(
        S.TREE, S.SIGNED_ENVELOPE, entry, "SUPPLIER", "NOTIFICATION",
        "DISCLOSED_ACTION_DETERMINES_A_SENSITIVE_INPUT",
    )
    assert view.fields[5].variant == "Some"
