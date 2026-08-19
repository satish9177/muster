"""The disclosure policy as data, and the interpreter that refuses to guess.

Every test here is about the policy being *authoritative*.  A missing entry is
a refusal rather than an empty view, two entries under one key are refused
rather than ordered, and a policy that names a path the inventory cannot
produce never gets to decide anything at all -- it is rejected when it is
pinned, not when it first over-discloses.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.core.results import Err, InvariantViolation, Ok
from muster.core.wire.digests import Digest
from muster.platform.commit.paths import CERTIFICATE_SCHEMA_VERSION
from muster.platform.disclose.policy import (
    OUTCOME_CLASSES,
    PolicyFailure,
    action_kind_of,
    entry_digest,
    find_entry_by_digest,
    resolve_entry,
    validate_policy,
)
from muster.policy.artifacts import DisclosureEntry, DisclosurePolicy, RatificationSet
from support.commitment import CommittedFixture, committed_case, workforce_policy

TENANT = "tenant-policy"
CASE = "case-policy"


@pytest.fixture(scope="module")
def divergent() -> CommittedFixture:
    return committed_case(tenant_id=TENANT, case_id=CASE)


@pytest.fixture(scope="module")
def invariant() -> CommittedFixture:
    return committed_case(tenant_id=f"{TENANT}-inv", case_id=f"{CASE}-inv", attested=True)


def _empty_ratifications() -> RatificationSet:
    return RatificationSet(schema_version=1, records=())


def _entry(**overrides: object) -> DisclosureEntry:
    base: dict[str, object] = {
        "outcome_class": "DIVERGENT",
        "action_kind": None,
        "audience_class": "WORKER",
        "disclosure_context": "NOTIFICATION",
        "reveals_sensitive_input": False,
        "inference_acknowledgement_ref": None,
        "permitted_paths": ("case.case_id",),
    }
    base.update(overrides)
    return DisclosureEntry(**base)  # type: ignore[arg-type]


def _policy(*entries: DisclosureEntry) -> DisclosurePolicy:
    return DisclosurePolicy(schema_version=CERTIFICATE_SCHEMA_VERSION, entries=entries)


#  ---- validation, which happens when the policy is pinned -------------------


def test_the_pinned_workforce_policy_validates(divergent: CommittedFixture) -> None:
    bundle = divergent.committed.bundle
    assert isinstance(
        validate_policy(bundle.disclosure_policy, ratifications=bundle.ratifications), Ok
    )


def test_a_policy_naming_a_path_outside_the_inventory_is_refused() -> None:
    policy = _policy(_entry(permitted_paths=("kernel.outcome.everything",)))
    result = validate_policy(policy, ratifications=_empty_ratifications())
    assert isinstance(result, Err)
    assert result.error.failure is PolicyFailure.UNKNOWN_COMMITMENT_PATH


def test_two_entries_under_one_key_never_reach_the_interpreter() -> None:
    """Refused twice: the type refuses to hold them, and the validator says so.

    Both matter. The type stops a policy being *built* that way; the validator
    is what a policy decoded from octets goes through, and octets can carry
    anything.
    """
    with pytest.raises(InvariantViolation):
        _policy(_entry(), _entry())

    #  Constructed around the type's own check, the way a decoder would.
    conflicting = object.__new__(DisclosurePolicy)
    object.__setattr__(conflicting, "schema_version", 1)
    object.__setattr__(conflicting, "entries", (_entry(), _entry()))
    result = validate_policy(conflicting, ratifications=_empty_ratifications())
    assert isinstance(result, Err)
    assert result.error.failure is PolicyFailure.ENTRY_CONFLICT


def test_an_action_kind_is_present_exactly_for_an_invariant_entry() -> None:
    """[N1b] Otherwise the entry can never be selected and discloses nothing."""
    for policy in (
        _policy(_entry(outcome_class="DIVERGENT", action_kind="PAY")),
        _policy(_entry(outcome_class="INVARIANT", action_kind=None)),
    ):
        result = validate_policy(policy, ratifications=_empty_ratifications())
        assert isinstance(result, Err)
        assert result.error.failure is PolicyFailure.ACTION_KIND_MISMATCH

    accepted = _policy(_entry(outcome_class="INVARIANT", action_kind="PAY"))
    assert isinstance(validate_policy(accepted, ratifications=_empty_ratifications()), Ok)


def test_an_outcome_class_outside_the_closed_set_is_refused() -> None:
    result = validate_policy(
        _policy(_entry(outcome_class="MAYBE")), ratifications=_empty_ratifications()
    )
    assert isinstance(result, Err)
    assert result.error.failure is PolicyFailure.UNKNOWN_OUTCOME_CLASS


def test_the_closed_set_is_the_four_outcome_classes() -> None:
    assert {"INVARIANT", "DIVERGENT", "INFEASIBLE", "INDETERMINATE"} == OUTCOME_CLASSES


def test_a_disclosure_by_inference_needs_a_resolvable_acknowledgement() -> None:
    """L-11: a policy may reveal by inference, and somebody has to have said so."""
    unacknowledged = _policy(_entry(reveals_sensitive_input=True))
    result = validate_policy(unacknowledged, ratifications=_empty_ratifications())
    assert isinstance(result, Err)
    assert result.error.failure is PolicyFailure.UNACKNOWLEDGED_INFERENCE

    dangling = _policy(
        _entry(reveals_sensitive_input=True, inference_acknowledgement_ref=Digest(bytes(32)))
    )
    result = validate_policy(dangling, ratifications=_empty_ratifications())
    assert isinstance(result, Err)
    assert result.error.failure is PolicyFailure.UNACKNOWLEDGED_INFERENCE


def test_an_acknowledgement_that_resolves_in_the_bundle_is_accepted(
    divergent: CommittedFixture,
) -> None:
    ratifications = divergent.committed.bundle.ratifications
    ratified = ratifications.records[0].digest()
    policy = _policy(_entry(reveals_sensitive_input=True, inference_acknowledgement_ref=ratified))
    assert isinstance(validate_policy(policy, ratifications=ratifications), Ok)


#  ---- resolution ------------------------------------------------------------


def test_the_action_kind_is_some_exactly_for_an_invariant_outcome(
    divergent: CommittedFixture, invariant: CommittedFixture
) -> None:
    assert action_kind_of(divergent.committed.record.certificate.kernel.outcome) is None
    assert action_kind_of(invariant.committed.record.certificate.kernel.outcome) == "PAY"


def test_every_ratified_audience_resolves_on_both_outcomes(
    divergent: CommittedFixture, invariant: CommittedFixture
) -> None:
    policy = workforce_policy()
    for fixture in (divergent, invariant):
        outcome = fixture.committed.record.certificate.kernel.outcome
        for audience, context in (
            ("WORKER", "NOTIFICATION"),
            ("EMPLOYER", "NOTIFICATION"),
            ("SITE", "NOTIFICATION"),
            ("AUDITOR", "AUDIT"),
        ):
            resolved = resolve_entry(
                policy, outcome=outcome, audience_class=audience, disclosure_context=context
            )
            assert isinstance(resolved, Ok), (audience, context, resolved)
            assert resolved.value.audience_class == audience


def test_a_missing_entry_is_a_refusal_and_not_an_empty_disclosure(
    divergent: CommittedFixture,
) -> None:
    outcome = divergent.committed.record.certificate.kernel.outcome
    result = resolve_entry(
        workforce_policy(),
        outcome=outcome,
        audience_class="WORKER",
        disclosure_context="AUDIT",
    )
    assert isinstance(result, Err)
    assert result.error.failure is PolicyFailure.ENTRY_MISSING


def test_an_audience_with_no_row_is_refused_rather_than_defaulted(
    divergent: CommittedFixture,
) -> None:
    outcome = divergent.committed.record.certificate.kernel.outcome
    result = resolve_entry(
        workforce_policy(),
        outcome=outcome,
        audience_class="REGULATOR",
        disclosure_context="NOTIFICATION",
    )
    assert isinstance(result, Err)
    assert result.error.failure is PolicyFailure.ENTRY_MISSING


def test_an_entry_is_found_by_the_digest_a_view_names() -> None:
    policy = workforce_policy()
    for entry in policy.entries:
        found = find_entry_by_digest(policy, entry_digest(entry))
        assert isinstance(found, Ok)
        assert found.value == entry


def test_an_entry_from_another_policy_does_not_resolve() -> None:
    """Policy substitution, caught at the lookup the view depends on."""
    stranger = _entry(audience_class="STRANGER")
    result = find_entry_by_digest(workforce_policy(), entry_digest(stranger))
    assert isinstance(result, Err)
    assert result.error.failure is PolicyFailure.ENTRY_MISSING


def test_the_entry_digest_moves_with_every_field() -> None:
    """The identity a view names has to cover everything the entry decides."""
    base = _entry()
    for mutated in (
        replace(base, audience_class="EMPLOYER"),
        replace(base, disclosure_context="AUDIT"),
        replace(base, outcome_class="INFEASIBLE"),
        replace(base, reveals_sensitive_input=True),
        replace(base, permitted_paths=("case.case_id", "case.tenant_id")),
    ):
        assert entry_digest(mutated) != entry_digest(base)
