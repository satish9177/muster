"""Guards on what may be admitted, and on what a bundle may leave unenforced.

Four of these cover corrections made after review, and each one was a fail-open:

* a receipt was admitted regardless of the validity window it was signed for;
* a descriptor the build cannot interpret was skipped in silence, applying a
  pinned bundle only in part while the certificate cited it whole;
* a descriptor's declared measurement procedures were read by nothing;
* two bounds on one proposition collided on a constraint label and took the
  whole rebuild down with an uncaught exception.

The fifth is the bundle-coherence check that makes the third impossible to ship
by accident.
"""

from __future__ import annotations

import dataclasses

import pytest

from muster.admissibility.derive import (
    REASON_PROCEDURE_NOT_ADMISSIBLE,
    REASON_RECEIPT_EXPIRED,
    AdmissibilitySnapshot,
    DerivationFailure,
    derive,
)
from muster.application.rebuild import RebuildFailure, rebuild, transcript_prefix
from muster.core.authority.check import AuthorityView
from muster.core.evidence.solicitation import SolicitationView
from muster.core.evidence.transcript import Attestation, Statement
from muster.core.results import Err, Ok
from muster.core.values.times import HalfOpenInterval
from muster.domains.workforce.bundle import (
    admissibility_descriptors,
    on_site_duration,
    workforce_bundle,
)
from muster.policy.artifacts import AdmissibilityDescriptor, AdmissibilityDescriptors
from muster.policy.manifest import BundleFailure, load_bundle
from tests.support import ravi


def _snapshot(**changes: object) -> AdmissibilitySnapshot:
    case = ravi.case_file()
    base = AdmissibilitySnapshot(
        tenant_id=case.construction.tenant_id,
        case_id=case.construction.case_id,
        as_of=case.as_of,
        declared=ravi.revision().declared,
        entries=case.entries,
    )
    return dataclasses.replace(base, **changes)  # type: ignore[arg-type]


def _authority(snapshot: AdmissibilitySnapshot) -> AuthorityView:
    """The case's own pinned authority, at the snapshot's tenant and instant.

    Taken from the fixture rather than minted, so a guard test that changed the
    tenant finds Q-12(c) refusing it -- which is the correct answer and one of
    the things these tests are for.
    """
    case = ravi.case_file()
    return AuthorityView(
        snapshot=case.authority_snapshot,
        revocation=case.revocation_snapshot,
        tenant_id=snapshot.tenant_id,
        authorization_policy_version=(case.authorization_context.authorization_policy_version),
        case_scope_coordinates=case.construction.case_scope_coordinates,
        as_of=snapshot.as_of,
    )


def _derive(snapshot: AdmissibilitySnapshot, descriptors: object | None = None) -> object:
    bundle = ravi.bundle()
    return derive(
        snapshot,
        descriptors if descriptors is not None else bundle.admissibility_descriptors,  # type: ignore[arg-type]
        bundle.predicate_schema,
        bundle.predicate_schema.digest(),
        _authority(snapshot),
        #  Nothing solicited: these cases test the bundle half of Q-12(a), and
        #  an empty view narrows nothing -- which is the reading a case that
        #  issued no requests has.
        SolicitationView.of(snapshot.tenant_id, snapshot.case_id, ()),
    )


def test_the_unmodified_snapshot_admits_its_receipts() -> None:
    """The control."""
    outcome = _derive(_snapshot())
    assert isinstance(outcome, Ok)
    assert outcome.value.facts


#  ---- receipt validity ----------------------------------------------------


def test_a_receipt_is_refused_outside_the_window_it_was_signed_for() -> None:
    """Judged against ``as_of``, so the decision replays identically forever."""
    latest = max(
        entry.receipt.payload.validity.end or 0
        for entry in ravi.case_file().entries
        if isinstance(entry, Attestation)
    )
    outcome = _derive(_snapshot(as_of=latest))
    assert isinstance(outcome, Ok)
    assert not outcome.value.facts
    assert all(
        effect.reason == REASON_RECEIPT_EXPIRED
        for effect in outcome.value.non_effects
        if effect.rule_id.startswith("AttestedRelation")
    )


def test_a_receipt_is_admitted_at_the_last_instant_of_its_window() -> None:
    """``[start, end)``: admitted at the microsecond before expiry, refused at it."""
    entry = next(e for e in ravi.case_file().entries if isinstance(e, Attestation))
    end = entry.receipt.payload.validity.end
    assert end is not None

    admitted = _derive(_snapshot(as_of=end - 1))
    refused = _derive(_snapshot(as_of=end))
    assert isinstance(admitted, Ok)
    assert isinstance(refused, Ok)
    assert len(admitted.value.facts) > len(refused.value.facts)


def test_an_expired_receipt_leaves_a_recorded_non_effect_rather_than_silence() -> None:
    outcome = _derive(_snapshot(as_of=1))
    assert isinstance(outcome, Ok)
    reasons = {effect.reason for effect in outcome.value.non_effects}
    assert REASON_RECEIPT_EXPIRED in reasons


#  ---- descriptors the build cannot interpret ------------------------------


def test_a_rule_the_build_does_not_implement_is_refused_not_skipped() -> None:
    """Skipping it would apply the pinned bundle in part and break replay."""
    extended = AdmissibilityDescriptors(
        schema_version=1,
        descriptors=(
            *admissibility_descriptors().descriptors,
            AdmissibilityDescriptor(
                rule_id="OpposedBracket",
                rule_version=1,
                rule_kind="PRESUMPTION",
                grouping_key="PROPOSITION",
                admissible_procedures=("PARTY_STATEMENT",),
                max_temporal_gap=0,
            ),
        ),
    )
    outcome = _derive(_snapshot(), extended)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DerivationFailure.UNINTERPRETABLE_DESCRIPTOR
    assert outcome.error.detail == "OpposedBracket"


@pytest.mark.parametrize(
    ("field", "value"),
    [("rule_kind", "SOMETHING_ELSE"), ("grouping_key", "RECEIPT"), ("max_temporal_gap", 60)],
)
def test_a_descriptor_setting_the_build_would_ignore_is_refused(field: str, value: object) -> None:
    """A declared setting that no code reads is how an authority field
    comes to authorize nothing."""
    descriptors = admissibility_descriptors()
    changed = tuple(
        dataclasses.replace(descriptor, **{field: value})  # type: ignore[arg-type]
        if descriptor.rule_id == "AttestedRelation"
        else descriptor
        for descriptor in descriptors.descriptors
    )
    outcome = _derive(_snapshot(), AdmissibilityDescriptors(1, changed))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DerivationFailure.UNINTERPRETABLE_DESCRIPTOR


def test_a_procedure_the_descriptor_does_not_admit_produces_no_fact() -> None:
    """``admissible_procedures`` is read, so narrowing it changes the outcome."""
    descriptors = admissibility_descriptors()
    narrowed = tuple(
        dataclasses.replace(descriptor, admissible_procedures=("PAYROLL_RECORD",))
        if descriptor.rule_id == "AttestedRelation"
        else descriptor
        for descriptor in descriptors.descriptors
    )
    outcome = _derive(_snapshot(), AdmissibilityDescriptors(1, narrowed))
    assert isinstance(outcome, Ok)
    reasons = {effect.reason for effect in outcome.value.non_effects}
    assert REASON_PROCEDURE_NOT_ADMISSIBLE in reasons


def test_a_bundle_whose_descriptor_does_not_admit_its_own_schema_is_refused() -> None:
    """Otherwise every receipt for that predicate is refused, silently."""
    bundle = ravi.bundle()
    narrowed = AdmissibilityDescriptors(
        schema_version=1,
        descriptors=tuple(
            dataclasses.replace(descriptor, admissible_procedures=("PAYROLL_RECORD",))
            if descriptor.rule_id == "AttestedRelation"
            else descriptor
            for descriptor in bundle.admissibility_descriptors.descriptors
        ),
    )
    outcome = load_bundle(
        signed_manifest=bundle.signed_manifest,
        program=bundle.program,
        entailment_rules=bundle.entailment_rules,
        predicate_schema=bundle.predicate_schema,
        action_schema=bundle.action_schema,
        admissibility_descriptors=narrowed,
        disclosure_policy=bundle.disclosure_policy,
        ratifications=bundle.ratifications,
    )
    assert isinstance(outcome, Err)
    assert outcome.error.failure in {
        BundleFailure.MEASUREMENT_PROCEDURE_NOT_ADMITTED,
        BundleFailure.SUBARTIFACT_DIGEST_MISMATCH,
    }


def test_the_shipped_bundle_loads() -> None:
    """The coherence check must not be refusing the bundle it ships with."""
    assert workforce_bundle().manifest.policy_id == "workforce-demo"


#  ---- tenant and case isolation -------------------------------------------


def test_an_attestation_from_another_tenant_is_refused() -> None:
    outcome = _derive(_snapshot(tenant_id="BETA"))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DerivationFailure.CROSS_TENANT_ARTIFACT


def test_an_attestation_for_another_case_is_refused() -> None:
    outcome = _derive(_snapshot(case_id="CASE-OTHER"))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DerivationFailure.CASE_MISMATCH


def test_a_statement_from_another_tenant_is_refused() -> None:
    """A separate code path from the attestation branch, so a separate test."""
    statements = tuple(e for e in ravi.case_file().entries if isinstance(e, Statement))
    assert statements
    outcome = _derive(_snapshot(tenant_id="BETA", entries=statements))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is DerivationFailure.CROSS_TENANT_ARTIFACT


#  ---- two bounds on one proposition ---------------------------------------


def test_two_attested_bounds_on_one_proposition_do_not_collide() -> None:
    """This used to leave ``rebuild`` through an uncaught ``InvariantViolation``."""
    from muster.core.evidence.relations import ClosedLowerBound, ClosedUpperBound
    from muster.core.values.scalars import VInt

    case = ravi.case_file()
    template = next(
        entry
        for entry in case.entries
        if isinstance(entry, Attestation)
        and entry.receipt.payload.proposition.predicate_id == "on_site_duration"
    )
    duration = on_site_duration(ravi.RAVI, ravi.SATURDAY)

    def bounded(relation: object, nonce: int) -> Attestation:
        payload = dataclasses.replace(
            template.receipt.payload,
            proposition=duration,
            relation=relation,  # type: ignore[arg-type]
            nonce=bytes([nonce]) + bytes(15),
        )
        return Attestation(dataclasses.replace(template.receipt, payload=payload))

    entries = (
        *case.entries,
        bounded(ClosedLowerBound(VInt(240)), 1),
        bounded(ClosedUpperBound(VInt(600)), 2),
    )
    bundle = ravi.bundle()
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, entries)
    built = rebuild(
        case.rebuild_inputs(bundle.digest(), prefix.digest()),
        case.construction,
        entries,
        bundle,
        case.authorization_context,
        case.authority_snapshot,
        case.revocation_snapshot,
        case.solicitations,
    )
    assert isinstance(built, Ok), built
    labels = [
        constraint.label
        for constraint in built.value.constraints
        if str(duration) in constraint.label
    ]
    assert len(labels) == len(set(labels))
    assert len([label for label in labels if label.startswith("C-ATT")]) == 2


#  ---- authorization context ------------------------------------------------


def test_a_revision_cannot_be_built_under_a_lapsed_authorization_context() -> None:
    case = ravi.case_file()
    bundle = ravi.bundle()
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    lapsed = dataclasses.replace(
        case.authorization_context,
        context_validity=HalfOpenInterval(1, 2),
    )
    inputs = dataclasses.replace(
        case.rebuild_inputs(bundle.digest(), prefix.digest()),
        authorization_context_digest=lapsed.digest(),
    )
    built = rebuild(
        inputs,
        case.construction,
        case.entries,
        bundle,
        lapsed,
        case.authority_snapshot,
        case.revocation_snapshot,
        case.solicitations,
    )
    assert isinstance(built, Err)
    assert built.error.failure is RebuildFailure.AUTHORIZATION_CONTEXT_NOT_VALID


def test_the_authorization_context_must_be_the_one_the_inputs_pin() -> None:
    """Changing what a key may say changes the revision digest -- so the
    context handed to rebuild must be the one the inputs name."""
    case = ravi.case_file()
    bundle = ravi.bundle()
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    other = dataclasses.replace(case.authorization_context, authorization_policy_version=99)
    built = rebuild(
        case.rebuild_inputs(bundle.digest(), prefix.digest()),
        case.construction,
        case.entries,
        bundle,
        other,
        case.authority_snapshot,
        case.revocation_snapshot,
        case.solicitations,
    )
    assert isinstance(built, Err)
    assert built.error.failure is RebuildFailure.AUTHORIZATION_CONTEXT_DIGEST_MISMATCH
