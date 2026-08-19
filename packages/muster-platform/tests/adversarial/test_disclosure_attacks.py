"""Named security regressions for the reader-side contract.

Each test here is an attack that a **membership-only** verifier accepts.  That
is the point of the file: every one of these views has perfect inclusion proofs
for every leaf it carries, because the writer that produced the material was
correct and something downstream moved it.  A verifier that folds proofs and
stops accepts all of them.

Three of these are historical: Phase 0.8's adversarial review found a verifier
that accepted an invalid envelope signature, one that accepted an ``AUDITOR``
view relabelled as another audience, and one that accepted seven leaves beyond
what the entry it named permitted -- including the outcome tag, to an audience
whose whole entry exists to withhold it.  They are permanent regressions here.

Every attack runs through the **real public path**: the view is produced by
``get_my_view``, mutated as an adversary could mutate it in transit, and handed
to ``verify_view`` with the reader context a genuine recipient would hold.
"""

from __future__ import annotations

from dataclasses import replace
from functools import cache

import pytest

from muster.core.results import Err
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import NAtom
from muster.platform.commit.envelope import SignedCommitmentEnvelope
from muster.platform.commit.paths import is_dynamic
from muster.platform.commit.publish import CommitmentFailureReason, read_commitment
from muster.platform.commit.tree import ProofSide
from muster.platform.disclose.policy import entry_digest
from muster.platform.disclose.queries import DisclosureFailure, get_my_view
from muster.platform.disclose.verify import (
    ReaderContext,
    VerificationFailure,
    accepted,
    verify_view,
)
from muster.platform.disclose.views import Disclosure, ParticipantView, View
from muster.policy.artifacts import DisclosureEntry, DisclosurePolicy
from support.commitment import (
    AUDIT,
    AUDITOR_PRINCIPAL,
    EMPLOYER,
    MUSTER_KEY,
    NOTIFICATION,
    NOW,
    OTHER_KEY,
    SITE,
    WORKER,
    CommittedFixture,
    committed_case,
    directory_for,
    reader,
    signing_pair,
    view_for,
    workforce_policy,
)

TENANT = "tenant-attack"
OTHER_TENANT = "tenant-attack-other"
CASE = "case-attack"
OTHER_CASE = "case-attack-other"


@cache
def _case() -> CommittedFixture:
    return committed_case(tenant_id=TENANT, case_id=CASE)


@cache
def _other_case() -> CommittedFixture:
    """A second case in the same tenant, committed under its own salt."""
    return committed_case(tenant_id=TENANT, case_id=OTHER_CASE)


@cache
def _other_tenant() -> CommittedFixture:
    """The same case identifier under a different tenant."""
    return committed_case(tenant_id=OTHER_TENANT, case_id=CASE)


@cache
def _later_revision() -> CommittedFixture:
    """The same case, same construction, a longer transcript -- so r2, not r1.

    The two Ravi fixtures share a construction record and an authorization
    context and differ only in what the site attested, so committing the second
    produces a *different revision of the same case*: same salt, same case
    commitment, different revision commitment.  That is exactly the material a
    cross-revision proof is built from.
    """
    return committed_case(tenant_id=TENANT, case_id=CASE, attested=True)


def _worker_view() -> View:
    return view_for(_case(), WORKER, NOTIFICATION)


def _auditor_view() -> View:
    return view_for(_case(), AUDITOR_PRINCIPAL, AUDIT)


def _reader(
    audience: str, context: str, *, tenant: str = TENANT, case: str = CASE
) -> ReaderContext:
    from muster.platform.disclose.audience import AudienceClass, DisclosureContext

    return reader(
        policy=workforce_policy(),
        pins=replace(_case().pins, tenant_id=tenant, case_id=case),
        audience=AudienceClass(audience),
        context=DisclosureContext(context),
    )


def _failures(view: View, audience: str, context: str, **where: str) -> set[VerificationFailure]:
    return {failure.failure for failure in verify_view(view, _reader(audience, context, **where))}


#  ---- the baseline every attack is measured against -------------------------


def test_an_untouched_view_verifies_for_its_own_audience() -> None:
    """Without this, every rejection below could be a rejection of everything."""
    for principal, audience, context in (
        (WORKER, "WORKER", "NOTIFICATION"),
        (EMPLOYER, "EMPLOYER", "NOTIFICATION"),
        (SITE, "SITE", "NOTIFICATION"),
        (AUDITOR_PRINCIPAL, "AUDITOR", "AUDIT"),
    ):
        view = view_for(_case(), principal, NOTIFICATION if context == "NOTIFICATION" else AUDIT)
        failures = verify_view(view, _reader(audience, context))
        assert accepted(failures), (audience, failures)


#  ---- the named regressions -------------------------------------------------


def test_INVALID_ENVELOPE_SIGNATURE_REJECTED() -> None:
    """Every leaf still proves. Membership is not provenance.

    Phase 0.8's verifier accepted this: the tree was consistent, so nothing
    objected that MUSTER had not produced it.
    """
    view = _worker_view()
    signature = view.envelope.signature
    forged = replace(signature, octets=signature.octets[:-1] + bytes([signature.octets[-1] ^ 1]))
    tampered = replace(view, envelope=SignedCommitmentEnvelope(view.envelope.envelope, forged))
    assert VerificationFailure.ENVELOPE_SIGNATURE_INVALID in _failures(
        tampered, "WORKER", "NOTIFICATION"
    )


def test_a_signature_from_another_key_is_rejected() -> None:
    """Signer substitution: a real signature, over these octets, by somebody else."""
    from muster.platform.commit.envelope import signing_preimage

    view = _worker_view()
    stranger, _verifier = signing_pair(OTHER_KEY)
    elsewhere = stranger.sign(signing_preimage(view.envelope.envelope))
    tampered = replace(view, envelope=SignedCommitmentEnvelope(view.envelope.envelope, elsewhere))
    assert VerificationFailure.ENVELOPE_SIGNATURE_INVALID in _failures(
        tampered, "WORKER", "NOTIFICATION"
    )


def test_an_envelope_naming_an_untrusted_signer_is_rejected() -> None:
    """And rejected as untrusted rather than as corrupt: the two differ."""
    view = _worker_view()
    reattributed = replace(view.envelope.envelope, signer_key_ref=OTHER_KEY)
    tampered = replace(
        view, envelope=SignedCommitmentEnvelope(reattributed, view.envelope.signature)
    )
    context = replace(_reader("WORKER", "NOTIFICATION"), trusted_keys=frozenset({MUSTER_KEY}))
    found = {failure.failure for failure in verify_view(tampered, context)}
    assert VerificationFailure.SIGNER_NOT_TRUSTED in found


def test_AUDIENCE_RELABEL_REJECTED() -> None:
    """A worker view relabelled as the employer's, and the reverse.

    Relabelling alone leaves the named entry disagreeing with the claim, which
    is caught from the policy side; the reader's own expectation catches it
    from the other side. Both are asserted, because an attacker who fixed one
    would otherwise be through.
    """
    worker = _worker_view()
    relabelled = replace(worker, audience_class="EMPLOYER")
    found = _failures(relabelled, "EMPLOYER", "NOTIFICATION")
    assert VerificationFailure.AUDIENCE_RELABELLED in found

    #  ... and the same view offered to the worker it was built for, but
    #  claiming to be the employer's, fails the reader's own expectation.
    assert VerificationFailure.AUDIENCE_NOT_THE_READER in _failures(
        relabelled, "WORKER", "NOTIFICATION"
    )


def test_an_auditor_view_relabelled_as_a_worker_view_is_rejected() -> None:
    """The historical defect, in the direction that leaks the most.

    The auditor's eleven leaves include the outcome and the reachable action
    set. Relabelled to WORKER and pointed at the worker's entry, every leaf
    still proves -- and seven of them are paths that entry does not permit.
    """
    auditor = _auditor_view()
    worker_entry = next(
        entry
        for entry in workforce_policy().entries
        if (entry.audience_class, entry.outcome_class) == ("WORKER", "DIVERGENT")
    )
    relabelled = replace(
        auditor,
        audience_class="WORKER",
        disclosure_context="NOTIFICATION",
        disclosure_entry_digest=entry_digest(worker_entry),
    )
    found = _failures(relabelled, "WORKER", "NOTIFICATION")
    assert VerificationFailure.PATH_NOT_PERMITTED in found
    assert VerificationFailure.VIEW_SHAPE_WRONG_FOR_AUDIENCE in found


def test_a_site_view_relabelled_as_the_auditor_s_is_rejected() -> None:
    """Under-disclosure caught: the auditor's entry requires more than this."""
    site = _auditor_relabel_of(view_for(_case(), SITE, NOTIFICATION), "AUDITOR", "AUDIT")
    found = _failures(site, "AUDITOR", "AUDIT")
    assert VerificationFailure.REQUIRED_PATH_MISSING in found


def _auditor_relabel_of(view: View, audience: str, context: str) -> View:
    entry = next(
        entry
        for entry in workforce_policy().entries
        if (entry.audience_class, entry.disclosure_context, entry.outcome_class)
        == (audience, context, "DIVERGENT")
    )
    return replace(
        view,
        audience_class=audience,
        disclosure_context=context,
        disclosure_entry_digest=entry_digest(entry),
    )


def test_EXTRA_DISCLOSED_LEAF_REJECTED() -> None:
    """A real leaf, a real proof, and an entry that does not permit it.

    This is the Phase-0.8 reader-side defect exactly: the leaf belongs to the
    committed record, so membership holds, and disclosing it to this audience
    was never permitted.
    """
    worker = _worker_view()
    tree = _case().committed.commitment.tree
    forbidden = "kernel.outcome.reachable"
    opened = tree.disclosure_of(forbidden)
    assert opened is not None
    value, salt, proof = opened
    over = replace(
        worker, disclosures=(*worker.disclosures, Disclosure(forbidden, value, salt, proof))
    )
    found = _failures(over, "WORKER", "NOTIFICATION")
    assert VerificationFailure.PATH_NOT_PERMITTED in found
    #  And it really was a valid proof, so nothing else objected.
    assert VerificationFailure.INCLUSION_NOT_PROVED not in found


def test_UNAUTHORIZED_AUDIENCE_FIELD_REJECTED() -> None:
    """Even the auditor is not permitted everything the record commits."""
    auditor = _auditor_view()
    tree = _case().committed.commitment.tree
    withheld = "kernel.outcome.left"
    opened = tree.disclosure_of(withheld)
    assert opened is not None
    value, salt, proof = opened
    over = replace(
        auditor, disclosures=(*auditor.disclosures, Disclosure(withheld, value, salt, proof))
    )
    assert VerificationFailure.PATH_NOT_PERMITTED in _failures(over, "AUDITOR", "AUDIT")


def test_a_permitted_leaf_removed_where_the_policy_requires_it_is_rejected() -> None:
    """Under-disclosure is a defect too, and a quiet one."""
    auditor = _auditor_view()
    thinned = replace(auditor, disclosures=auditor.disclosures[:-1])
    assert VerificationFailure.REQUIRED_PATH_MISSING in _failures(thinned, "AUDITOR", "AUDIT")


def test_CROSS_CASE_PROOF_REJECTED() -> None:
    """A leaf from another case of the same tenant, under this case's envelope."""
    worker = _worker_view()
    other = _other_case().committed.commitment.tree
    opened = other.disclosure_of("case.tenant_id")
    assert opened is not None
    value, salt, proof = opened
    transplanted = replace(
        worker,
        disclosures=tuple(
            Disclosure("case.tenant_id", value, salt, proof)
            if disclosure.path == "case.tenant_id"
            else disclosure
            for disclosure in worker.disclosures
        ),
    )
    assert VerificationFailure.INCLUSION_NOT_PROVED in _failures(
        transplanted, "WORKER", "NOTIFICATION"
    )


def test_an_envelope_from_one_case_with_leaves_from_another_is_rejected() -> None:
    """The whole view swapped, envelope and all, into another case's reader."""
    elsewhere = view_for(_other_case(), WORKER, NOTIFICATION)
    found = _failures(elsewhere, "WORKER", "NOTIFICATION")
    assert VerificationFailure.CASE_MISMATCH in found


def test_CROSS_REVISION_PROOF_REJECTED() -> None:
    """The same case, a later revision, and a proof that must not travel.

    Both commitments share a tenant, a case and a case salt. Only the revision
    commitment differs -- and it is bound into every leaf, so the transplanted
    leaf fails when it is recomputed rather than when the root is compared.
    """
    worker = _worker_view()
    later = _later_revision().committed.commitment
    assert later.envelope.case_commitment == _case().committed.commitment.envelope.case_commitment
    assert (
        later.envelope.revision_commitment
        != _case().committed.commitment.envelope.revision_commitment
    )

    opened = later.tree.disclosure_of("case.case_id")
    assert opened is not None
    value, salt, proof = opened
    transplanted = replace(
        worker,
        disclosures=tuple(
            Disclosure("case.case_id", value, salt, proof)
            if disclosure.path == "case.case_id"
            else disclosure
            for disclosure in worker.disclosures
        ),
    )
    assert VerificationFailure.INCLUSION_NOT_PROVED in _failures(
        transplanted, "WORKER", "NOTIFICATION"
    )


def test_DISCLOSURE_POLICY_SUBSTITUTION_REJECTED() -> None:
    """A permissive policy at the writer, a strict one at the reader.

    The envelope pins the policy it was committed under, so a reader holding a
    different policy detects the substitution instead of resolving against it.
    """
    worker = _worker_view()
    permissive = DisclosurePolicy(
        schema_version=1,
        entries=tuple(
            replace(entry, permitted_paths=(*entry.permitted_paths, "kernel.outcome.left"))
            for entry in workforce_policy().entries
        ),
    )
    context = replace(_reader("WORKER", "NOTIFICATION"), policy=permissive)
    found = {failure.failure for failure in verify_view(worker, context)}
    assert VerificationFailure.POLICY_SUBSTITUTED in found
    #  And the entry the view names does not resolve in the substitute either.
    assert VerificationFailure.ENTRY_NOT_IN_POLICY in found


def test_a_policy_with_the_same_entries_in_another_order_is_a_different_pin() -> None:
    """Same rows, different digest: the envelope pins octets, not a set."""
    reordered = DisclosurePolicy(
        schema_version=1, entries=tuple(reversed(workforce_policy().entries))
    )
    context = replace(_reader("WORKER", "NOTIFICATION"), policy=reordered)
    found = {failure.failure for failure in verify_view(_worker_view(), context)}
    assert VerificationFailure.POLICY_SUBSTITUTED in found


def test_ROOT_SUBSTITUTION_REJECTED() -> None:
    worker = _worker_view()
    other_root = _other_case().committed.commitment.envelope.root
    swapped = replace(worker.envelope.envelope, root=other_root)
    tampered = replace(
        worker, envelope=SignedCommitmentEnvelope(swapped, worker.envelope.signature)
    )
    found = _failures(tampered, "WORKER", "NOTIFICATION")
    assert VerificationFailure.ENVELOPE_SIGNATURE_INVALID in found
    assert VerificationFailure.INCLUSION_NOT_PROVED in found


def test_a_leaf_count_substitution_is_rejected() -> None:
    """The count is inside the root record, so folding to the top is not enough."""
    worker = _worker_view()
    envelope = worker.envelope.envelope
    lied = replace(envelope, leaf_count=envelope.leaf_count - 1)
    tampered = replace(worker, envelope=SignedCommitmentEnvelope(lied, worker.envelope.signature))
    assert VerificationFailure.INCLUSION_NOT_PROVED in _failures(tampered, "WORKER", "NOTIFICATION")


def test_LEAF_VALUE_MUTATION_REJECTED() -> None:
    worker = _worker_view()
    first = worker.disclosures[0]
    mutated = replace(first, value_octets=encode(NAtom("something-else")))
    tampered = replace(worker, disclosures=(mutated, *worker.disclosures[1:]))
    assert VerificationFailure.INCLUSION_NOT_PROVED in _failures(tampered, "WORKER", "NOTIFICATION")


def test_a_one_bit_salt_mutation_is_rejected() -> None:
    worker = _worker_view()
    first = worker.disclosures[0]
    mutated = replace(first, salt=first.salt[:-1] + bytes([first.salt[-1] ^ 1]))
    tampered = replace(worker, disclosures=(mutated, *worker.disclosures[1:]))
    assert VerificationFailure.INCLUSION_NOT_PROVED in _failures(tampered, "WORKER", "NOTIFICATION")


def test_LEAF_PATH_MUTATION_REJECTED() -> None:
    """Moving a value from one path to another, which the leaf preimage binds."""
    worker = _worker_view()
    paths = [disclosure.path for disclosure in worker.disclosures]
    swapped = replace(worker.disclosures[0], path=paths[1])
    tampered = replace(worker, disclosures=(swapped, *worker.disclosures[1:]))
    found = _failures(tampered, "WORKER", "NOTIFICATION")
    assert VerificationFailure.INCLUSION_NOT_PROVED in found
    assert VerificationFailure.DUPLICATE_DISCLOSED_PATH in found


def test_a_path_outside_the_inventory_is_rejected() -> None:
    worker = _worker_view()
    invented = replace(worker.disclosures[0], path="kernel.outcome.everything")
    tampered = replace(worker, disclosures=(invented, *worker.disclosures[1:]))
    found = _failures(tampered, "WORKER", "NOTIFICATION")
    assert VerificationFailure.PATH_NOT_IN_INVENTORY in found


def test_PROOF_DIRECTION_MUTATION_REJECTED() -> None:
    """Concatenation order is semantic: ``node(L,R)`` is not ``node(R,L)``."""
    auditor = _auditor_view()
    target = next(disclosure for disclosure in auditor.disclosures if len(disclosure.proof) > 0)
    flipped = tuple(
        replace(step, side=ProofSide.LEFT if step.side is ProofSide.RIGHT else ProofSide.RIGHT)
        for step in target.proof
    )
    tampered = replace(
        auditor,
        disclosures=tuple(
            replace(disclosure, proof=flipped) if disclosure is target else disclosure
            for disclosure in auditor.disclosures
        ),
    )
    assert VerificationFailure.INCLUSION_NOT_PROVED in _failures(tampered, "AUDITOR", "AUDIT")


def test_a_truncated_or_extended_proof_is_rejected() -> None:
    auditor = _auditor_view()
    target = next(disclosure for disclosure in auditor.disclosures if len(disclosure.proof) > 1)
    for proof in (target.proof[:-1], (*target.proof, target.proof[0])):
        tampered = replace(
            auditor,
            disclosures=tuple(
                replace(disclosure, proof=proof) if disclosure is target else disclosure
                for disclosure in auditor.disclosures
            ),
        )
        assert VerificationFailure.INCLUSION_NOT_PROVED in _failures(tampered, "AUDITOR", "AUDIT")


def test_a_sibling_mutation_is_rejected() -> None:
    auditor = _auditor_view()
    target = next(disclosure for disclosure in auditor.disclosures if len(disclosure.proof) > 0)
    step = target.proof[0]
    mutated = replace(step, sibling=step.sibling[:-1] + bytes([step.sibling[-1] ^ 1]))
    tampered = replace(
        auditor,
        disclosures=tuple(
            replace(disclosure, proof=(mutated, *disclosure.proof[1:]))
            if disclosure is target
            else disclosure
            for disclosure in auditor.disclosures
        ),
    )
    assert VerificationFailure.INCLUSION_NOT_PROVED in _failures(tampered, "AUDITOR", "AUDIT")


def test_a_duplicate_disclosure_is_rejected() -> None:
    worker = _worker_view()
    doubled = replace(worker, disclosures=(*worker.disclosures, worker.disclosures[0]))
    assert VerificationFailure.DUPLICATE_DISCLOSED_PATH in _failures(
        doubled, "WORKER", "NOTIFICATION"
    )


def test_more_disclosures_than_leaves_is_rejected() -> None:
    """A tree cannot have fewer leaves than the view opens."""
    worker = _worker_view()
    envelope = worker.envelope.envelope
    shrunk = replace(envelope, leaf_count=1)
    tampered = replace(worker, envelope=SignedCommitmentEnvelope(shrunk, worker.envelope.signature))
    assert VerificationFailure.MORE_DISCLOSURES_THAN_LEAVES in _failures(
        tampered, "WORKER", "NOTIFICATION"
    )


def test_an_entry_outside_the_pinned_policy_is_rejected() -> None:
    """A view naming an entry nobody ratified: no permitted set, no disclosure."""
    worker = _worker_view()
    invented = DisclosureEntry(
        outcome_class="DIVERGENT",
        action_kind=None,
        audience_class="WORKER",
        disclosure_context="NOTIFICATION",
        reveals_sensitive_input=False,
        inference_acknowledgement_ref=None,
        permitted_paths=tuple(disclosure.path for disclosure in worker.disclosures),
    )
    tampered = replace(worker, disclosure_entry_digest=entry_digest(invented))
    assert VerificationFailure.ENTRY_NOT_IN_POLICY in _failures(tampered, "WORKER", "NOTIFICATION")


#  ---- tenant isolation ------------------------------------------------------


def test_the_same_case_identifier_under_two_tenants_is_two_commitments() -> None:
    here = _case().committed.commitment.envelope
    elsewhere = _other_tenant().committed.commitment.envelope
    assert here.case_id == elsewhere.case_id
    assert here.tenant_id != elsewhere.tenant_id
    assert here.case_commitment != elsewhere.case_commitment
    assert here.revision_commitment != elsewhere.revision_commitment
    assert here.root != elsewhere.root


def test_a_view_from_another_tenant_is_rejected_by_the_reader() -> None:
    """Same signer, wrong tenant: a valid signature is not evidence about which."""
    elsewhere = view_for(_other_tenant(), WORKER, NOTIFICATION)
    found = _failures(elsewhere, "WORKER", "NOTIFICATION")
    assert VerificationFailure.TENANT_MISMATCH in found


def test_a_leaf_from_another_tenant_does_not_prove_here() -> None:
    worker = _worker_view()
    other = _other_tenant().committed.commitment.tree
    opened = other.disclosure_of("case.case_id")
    assert opened is not None
    value, salt, proof = opened
    transplanted = replace(
        worker,
        disclosures=tuple(
            Disclosure("case.case_id", value, salt, proof)
            if disclosure.path == "case.case_id"
            else disclosure
            for disclosure in worker.disclosures
        ),
    )
    assert VerificationFailure.INCLUSION_NOT_PROVED in _failures(
        transplanted, "WORKER", "NOTIFICATION"
    )


#  ---- the salt -------------------------------------------------------------


def test_CASE_SALT_NEVER_DISCLOSED() -> None:
    """Not in any view, not in the envelope, not in any disclosed salt.

    Checked over the encoded octets rather than field by field, because the
    claim is about what leaves the boundary rather than about which field
    somebody remembered to omit.
    """
    salt = _case().committed.record.salt.octets
    for principal, context in (
        (WORKER, NOTIFICATION),
        (EMPLOYER, NOTIFICATION),
        (SITE, NOTIFICATION),
        (AUDITOR_PRINCIPAL, AUDIT),
    ):
        view = view_for(_case(), principal, context)
        assert salt not in encode(view.to_node())
        assert salt not in encode(view.envelope.to_node())
        for disclosure in view.disclosures:
            assert disclosure.salt != salt


def test_a_disclosed_salt_is_path_specific_and_says_nothing_about_another_leaf() -> None:
    """A participant holding one salt cannot test a guess at another leaf."""
    auditor = _auditor_view()
    salts = [disclosure.salt for disclosure in auditor.disclosures]
    assert len(set(salts)) == len(salts)

    tree = _case().committed.commitment.tree
    disclosed = {disclosure.path for disclosure in auditor.disclosures}
    withheld = [path for path in tree.paths if path not in disclosed]
    assert withheld
    for path in withheld:
        opened = tree.disclosure_of(path)
        assert opened is not None
        assert opened[1] not in salts


def test_an_undisclosed_value_cannot_be_confirmed_without_its_salt() -> None:
    """The oracle [B11] removes, stated as the attack it removes.

    The attacker knows the path, guesses the value correctly, and holds every
    proof the view gave them. Without the field salt the leaf does not
    recompute, so the guess cannot be confirmed.
    """
    from muster.platform.commit.tree import verify_inclusion

    tree = _case().committed.commitment.tree
    worker = _worker_view()
    disclosed = {disclosure.path for disclosure in worker.disclosures}
    target = next(path for path in tree.paths if path not in disclosed)
    opened = tree.disclosure_of(target)
    assert opened is not None
    true_value, true_salt, proof = opened

    for guess in (worker.disclosures[0].salt, bytes(32), true_salt[::-1]):
        assert not verify_inclusion(
            binding=tree.binding,
            root_binding=tree.root_binding,
            leaf_count=tree.leaf_count,
            root=tree.root,
            path=target,
            value_octets=true_value,
            salt=guess,
            proof=proof,
        )
    #  With the real salt it does, so the test is about the salt and not about
    #  the value being unguessable.
    assert verify_inclusion(
        binding=tree.binding,
        root_binding=tree.root_binding,
        leaf_count=tree.leaf_count,
        root=tree.root,
        path=target,
        value_octets=true_value,
        salt=true_salt,
        proof=proof,
    )


def test_neither_raw_digest_appears_in_any_view() -> None:
    """[B11] The envelope carries keyed commitments, never the digests they stand for."""
    record = _case().committed.record
    raw = (record.revision.digest().octets, record.revision.construction_digest.octets)
    for principal, context in (
        (WORKER, NOTIFICATION),
        (EMPLOYER, NOTIFICATION),
        (SITE, NOTIFICATION),
        (AUDITOR_PRINCIPAL, AUDIT),
    ):
        octets = encode(view_for(_case(), principal, context).to_node())
        for digest in raw:
            assert digest not in octets


#  ---- the query boundary ----------------------------------------------------


def test_a_stranger_cannot_tell_an_existing_case_from_one_that_does_not_exist() -> None:
    """Existence is a disclosure, so the two refusals must be indistinguishable.

    Four internal states reach this answer -- absent, unreadable, not a party,
    and a role the caller does not hold. A caller who can tell them apart
    enumerates the tenant's case identifiers, and for cases they *are* party to
    learns whether a commitment has been published yet.
    """
    from support.commitment import STRANGER

    def _refused(principal: object, case_id: str) -> object:
        result = get_my_view(
            _case().service,
            tenant_id=TENANT,
            principal=principal,  # type: ignore[arg-type]
            case_id=case_id,
            context=NOTIFICATION,
            acting_as=None,
        )
        assert isinstance(result, Err), result
        return result.error

    real = _refused(STRANGER, CASE)
    imagined = _refused(STRANGER, "no-such-case")
    assert real == imagined
    assert real.failure is DisclosureFailure.CASE_NOT_VISIBLE  # type: ignore[attr-defined]

    #  And a party naming a role that is not theirs learns no more than a
    #  stranger does: the refusal is the same value and the same detail.
    assert _refused_acting_as() == real


def _refused_acting_as() -> object:
    result = get_my_view(
        _case().service,
        tenant_id=TENANT,
        principal=WORKER,
        case_id=CASE,
        context=NOTIFICATION,
        acting_as="AUDITOR",
    )
    assert isinstance(result, Err), result
    return result.error


def test_a_participant_cannot_ask_for_the_auditor_s_context() -> None:
    """No entry for (WORKER, AUDIT), and a missing entry is a refusal."""
    result = get_my_view(
        _case().service,
        tenant_id=TENANT,
        principal=WORKER,
        case_id=CASE,
        context=AUDIT,
        acting_as=None,
    )
    assert isinstance(result, Err)
    assert result.error.failure is DisclosureFailure.NOT_DISCLOSABLE


def test_a_case_with_no_commitment_yields_no_view_rather_than_an_empty_one() -> None:
    """The revision is head and uncommitted, which is early rather than wrong."""
    from muster.platform.adapters.memory import MemoryDatabase
    from muster.platform.casework.commands import append_transcript_entry, open_case
    from muster.platform.disclose.queries import DisclosureService
    from support.commitment import commitment, directory_for
    from support.ravi import ravi as ravi_case

    database = MemoryDatabase()
    case = ravi_case("tenant-uncommitted", "case-uncommitted")
    work = commitment(database)
    open_case(
        work.casework,
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=case.authorization_context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )
    for entry in case.entries:
        append_transcript_entry(
            work.casework,
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            entry=entry,
            now=NOW,
        )

    absent = read_commitment(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(absent, Err)
    assert absent.error.failure is CommitmentFailureReason.COMMITMENT_ABSENT

    service = DisclosureService(commitment=work, directory=directory_for("tenant-uncommitted"))
    result = get_my_view(
        service,
        tenant_id=case.tenant_id,
        principal=WORKER,
        case_id=case.case_id,
        context=NOTIFICATION,
        acting_as=None,
    )
    assert isinstance(result, Err)
    assert result.error.failure is DisclosureFailure.COMMITMENT_REFUSED


@pytest.mark.parametrize(
    "principal,audience,context",
    [
        (WORKER, "WORKER", NOTIFICATION),
        (EMPLOYER, "EMPLOYER", NOTIFICATION),
        (SITE, "SITE", NOTIFICATION),
    ],
)
def test_no_participant_view_carries_a_leaf_another_audience_alone_may_see(
    principal: object, audience: str, context: object
) -> None:
    """The disclosure policy is the only authority, and it is asserted as one."""
    view = view_for(_case(), principal, context)  # type: ignore[arg-type]
    entry = next(
        entry
        for entry in workforce_policy().entries
        if (entry.audience_class, entry.outcome_class) == (audience, "DIVERGENT")
    )
    assert {disclosure.path for disclosure in view.disclosures} <= set(entry.permitted_paths)


#  ---- regressions for the findings an adversarial review raised -------------


@cache
def _invariant_case() -> CommittedFixture:
    """The attested Ravi case, committed. An invariant outcome, not a divergent one.

    Every named regression above ran against the divergent fixture until a
    review pointed out that the whole invariant shape -- the only one carrying
    an action kind, an action leaf and a witness -- was untested, and that two
    of the sharpest attacks need an audience with more than one policy row.
    """
    return committed_case(tenant_id=f"{TENANT}-inv", case_id=f"{CASE}-inv", attested=True)


def _failures_for(
    view: View, fixture: CommittedFixture, audience: str, context: str
) -> set[VerificationFailure]:
    from muster.platform.disclose.audience import AudienceClass, DisclosureContext

    context_value = reader(
        policy=workforce_policy(),
        pins=fixture.pins,
        audience=AudienceClass(audience),
        context=DisclosureContext(context),
    )
    return {failure.failure for failure in verify_view(view, context_value)}


def _row(audience: str, outcome_class: str) -> DisclosureEntry:
    return next(
        entry
        for entry in workforce_policy().entries
        if (entry.audience_class, entry.outcome_class) == (audience, outcome_class)
    )


def test_ENTRY_DOWNGRADE_REJECTED() -> None:
    """The entry a view names must govern the record that view shows.

    Found by review, and accepted before the fix. Every audience whose policy
    keys on outcome class has one row per class, so a writer holding an
    invariant record could name the *divergent* row -- which permits less --
    drop the leaves that row does not permit, and hand over a view in which
    every leaf proves, the envelope verifies, the audience matches and the
    required set is satisfied. The required set is derived from the named
    entry, so naming a thinner one shrank it, and the worker never saw the
    action they were paid under.
    """
    invariant = _invariant_case()
    honest = view_for(invariant, WORKER, NOTIFICATION)
    assert "kernel.outcome.action" in {disclosure.path for disclosure in honest.disclosures}

    downgraded = replace(
        honest,
        disclosures=tuple(
            disclosure
            for disclosure in honest.disclosures
            if disclosure.path != "kernel.outcome.action"
        ),
        disclosure_entry_digest=entry_digest(_row("WORKER", "DIVERGENT")),
    )
    assert VerificationFailure.ENTRY_NOT_FOR_THIS_OUTCOME in _failures_for(
        downgraded, invariant, "WORKER", "NOTIFICATION"
    )


def test_an_auditor_view_cannot_be_downgraded_to_a_thinner_row_either() -> None:
    """The same lever, aimed at the audience where it would matter most."""
    invariant = _invariant_case()
    honest = view_for(invariant, AUDITOR_PRINCIPAL, AUDIT)
    downgraded = replace(
        honest,
        disclosures=tuple(
            disclosure
            for disclosure in honest.disclosures
            if disclosure.path != "kernel.outcome.action"
        ),
        disclosure_entry_digest=entry_digest(_row("AUDITOR", "DIVERGENT")),
    )
    assert VerificationFailure.ENTRY_NOT_FOR_THIS_OUTCOME in _failures_for(
        downgraded, invariant, "AUDITOR", "AUDIT"
    )


def test_an_honest_invariant_view_verifies_for_every_audience() -> None:
    """The baseline the two tests above are measured against."""
    invariant = _invariant_case()
    for principal, audience, context in (
        (WORKER, "WORKER", NOTIFICATION),
        (EMPLOYER, "EMPLOYER", NOTIFICATION),
        (SITE, "SITE", NOTIFICATION),
        (AUDITOR_PRINCIPAL, "AUDITOR", AUDIT),
    ):
        view = view_for(invariant, principal, context)
        failures = _failures_for(view, invariant, audience, context.value)
        assert not failures, (audience, failures)


def test_EXTRA_DISCLOSED_LEAF_REJECTED_on_an_invariant_outcome() -> None:
    """The witness is committed on an invariant outcome and permitted to nobody."""
    invariant = _invariant_case()
    honest = view_for(invariant, AUDITOR_PRINCIPAL, AUDIT)
    opened = invariant.committed.commitment.tree.disclosure_of("kernel.outcome.witness")
    assert opened is not None
    value, salt, proof = opened
    over = replace(
        honest,
        disclosures=(
            *honest.disclosures,
            Disclosure("kernel.outcome.witness", value, salt, proof),
        ),
    )
    assert VerificationFailure.PATH_NOT_PERMITTED in _failures_for(
        over, invariant, "AUDITOR", "AUDIT"
    )


def test_VIEW_REPLAY_REJECTED() -> None:
    """A superseded view is internally perfect and is not the current state.

    Found by review. The reader held no revision expectation, so a view of r1
    verified indefinitely after r2 became head -- letting a participant present
    "this case is still undecided" as a fully verifying signed artifact after
    it had been decided.
    """
    old = _worker_view()
    later = _later_revision()
    assert (
        later.committed.commitment.envelope.revision_commitment
        != _case().committed.commitment.envelope.revision_commitment
    )
    current = replace(
        _reader("WORKER", "NOTIFICATION"),
        revision_commitment=later.committed.commitment.envelope.revision_commitment,
    )
    assert VerificationFailure.REVISION_NOT_CURRENT in {
        failure.failure for failure in verify_view(old, current)
    }


def test_a_construction_record_cannot_mint_the_operator_role() -> None:
    """An operator role is not a role in any case, so a case may not grant one.

    Found by review. A case officer naming a party ``AUDITOR`` gave that
    principal the widest audience in the system -- an auditor view with the
    outcome, the action and the rebuild coordinates -- with no directory entry
    and every downstream check passing, because the view really was an
    auditor's.
    """
    from muster.platform.disclose.audience import AUDITOR, resolve_audience, roles_of

    construction = _case().case.construction
    forged = replace(
        construction,
        parties=tuple(replace(party, role_in_case=AUDITOR) for party in construction.parties),
    )
    directory = directory_for(TENANT)
    assert roles_of(SITE, construction=forged, directory=directory) == frozenset()
    assert isinstance(
        resolve_audience(SITE, construction=forged, directory=directory, acting_as=None), Err
    )


def test_a_principal_authoritative_in_one_tenant_is_not_a_party_in_another() -> None:
    """The tenant a query names is the caller's argument; the issuer is not.

    Found by review. A party record's tenant is stamped from the tenant the
    read was opened under, so comparing the two proved nothing, and one console
    issuer shared across tenants let a subject resolve to the same-named party
    of any tenant. The issuer is per tenant now.
    """
    from muster.platform.disclose.audience import roles_of

    construction = _other_tenant().case.construction
    assert roles_of(WORKER, construction=construction, directory=directory_for(TENANT)) == (
        frozenset()
    )
    assert roles_of(
        WORKER, construction=construction, directory=directory_for(OTHER_TENANT)
    ) == frozenset({"WORKER"})


def test_no_commitment_value_prints_a_salt_or_the_record_it_committed() -> None:
    """Found by review: the field salts were in every default repr.

    A reader who obtains one field salt can confirm a guess at the leaf it
    blinds -- the level-0 sibling hash is already in the proof they hold -- so
    a salt in a log line or a traceback restores the oracle the salt exists to
    remove.
    """
    committed = _case().committed
    printed = repr(committed) + repr(committed.commitment) + repr(committed.commitment.tree)
    assert "redacted" in printed
    assert committed.record.salt.octets.hex() not in printed
    for salt in committed.commitment.tree.salts:
        assert salt.hex() not in printed
    for _path, octets in committed.commitment.tree.record.values:
        if len(octets) > 8:
            assert octets.hex() not in printed


def test_an_over_long_proof_is_refused_before_it_is_folded() -> None:
    """Work an adversary chose the size of, bounded by the tree it claims to be in."""
    from muster.platform.commit.tree import proof_bound, verify_inclusion

    tree = _case().committed.commitment.tree
    path = tree.paths[0]
    opened = tree.disclosure_of(path)
    assert opened is not None
    value, salt, proof = opened
    assert len(proof) <= proof_bound(tree.leaf_count)

    padded = proof * 7
    assert len(padded) > proof_bound(tree.leaf_count)
    assert not verify_inclusion(
        binding=tree.binding,
        root_binding=tree.root_binding,
        leaf_count=tree.leaf_count,
        root=tree.root,
        path=path,
        value_octets=value,
        salt=salt,
        proof=padded,
    )


def test_an_empty_proof_is_refused_where_the_tree_has_more_than_one_leaf() -> None:
    from muster.platform.commit.tree import verify_inclusion

    tree = _case().committed.commitment.tree
    assert tree.leaf_count > 1
    path = tree.paths[0]
    opened = tree.disclosure_of(path)
    assert opened is not None
    value, salt, _proof = opened
    assert not verify_inclusion(
        binding=tree.binding,
        root_binding=tree.root_binding,
        leaf_count=tree.leaf_count,
        root=tree.root,
        path=path,
        value_octets=value,
        salt=salt,
        proof=(),
    )


#  ---- residual channels, pinned so they are known rather than discovered ----


def test_the_entry_a_view_names_reveals_its_outcome_class_and_nothing_more() -> None:
    """A bound on the privacy claim, asserted rather than assumed.

    A view names the entry it applied, and an entry's identity covers the whole
    frozen record -- ``outcome_class`` and ``action_kind`` included. So a
    recipient who holds the pinned policy can tell which outcome class the case
    is in even when no leaf disclosed it: the site's four paths exclude the
    outcome tag, and its two rows still have two digests.

    This is a property of the frozen four-part key, not of this build, and it
    cannot be closed here. What *is* checked is the bound: the site learns the
    class and learns nothing of its content. The action, the amount, the
    witness and the reachable set are all absent from its view, and from the
    entry it names.
    """
    divergent = view_for(_case(), SITE, NOTIFICATION)
    invariant = view_for(_invariant_case(), SITE, NOTIFICATION)

    #  Same paths, both times: the disclosure itself distinguishes nothing.
    assert {disclosure.path for disclosure in divergent.disclosures} == {
        disclosure.path for disclosure in invariant.disclosures
    }
    #  And the entry identity does, which is the channel.
    assert divergent.disclosure_entry_digest != invariant.disclosure_entry_digest

    #  The bound: nothing about the outcome's content reaches the site, in the
    #  view or in the entry it names.
    for view, fixture in ((divergent, _case()), (invariant, _invariant_case())):
        shown = {disclosure.path for disclosure in view.disclosures}
        assert not shown & {
            "kernel.outcome.tag",
            "kernel.outcome.action",
            "kernel.outcome.witness",
            "kernel.outcome.reachable",
            "kernel.outcome.left",
            "kernel.outcome.right",
            "action.full",
        }
        octets = encode(view.to_node())
        for withheld in ("kernel.outcome.action", "kernel.outcome.reachable"):
            committed = fixture.committed.commitment.tree.record.octets_at(withheld)
            if committed is not None and len(committed) > 8:
                assert committed not in octets


def test_a_proof_shape_reveals_a_position_and_never_a_value() -> None:
    """The other bound, for the other channel.

    Leaves sit in canonical path order, so a disclosure's proof sides and the
    committed leaf count determine that leaf's index -- and therefore how many
    undisclosed leaves sort before it. Two records the policy renders
    identically to the site are therefore distinguishable by shape.

    Recorded here as an asserted fact rather than left to be found. What the
    channel carries is counts and adjacency; what it does not carry is any
    value, and no dynamic path segment is anything but a digest, so it never
    says *which* proposition a counted leaf was about.
    """
    divergent = view_for(_case(), SITE, NOTIFICATION)
    invariant = view_for(_invariant_case(), SITE, NOTIFICATION)
    shapes = {
        view.audience_class: {
            disclosure.path: tuple(step.side for step in disclosure.proof)
            for disclosure in view.disclosures
        }
        for view in (divergent, invariant)
    }
    assert shapes  # both built; the two records differ in size, so shapes may differ

    #  The bound: every dynamic path in either record is a digest segment, so a
    #  position that is learnable never names the item that occupies it.
    for fixture in (_case(), _invariant_case()):
        for path in fixture.committed.commitment.tree.paths:
            if is_dynamic(path):
                segment = path.rsplit(".", 1)[1]
                assert len(segment) == 64
                assert set(segment) <= set("0123456789abcdef")


#  ---- regressions for the final independent review --------------------------


def test_AN_AUDITOR_IN_ONE_TENANT_IS_NOT_AN_AUDITOR_IN_ANOTHER() -> None:
    """The widest audience in the system was the one role granted globally.

    Found by the final review, and the sharper half of a defect this suite had
    already half-fixed: the *party* issuer was made per tenant and the operator
    set beside it was left flat. A directory scoped to one tenant therefore
    resolved its auditors inside every other tenant the deployment served --
    and the reader side did not object, because the reader and the envelope
    agreed on the same wrong tenant.
    """
    from muster.platform.disclose.audience import AUDITOR, resolve_audience, roles_of

    elsewhere = _other_tenant().case.construction
    assert (
        roles_of(AUDITOR_PRINCIPAL, construction=elsewhere, directory=directory_for(TENANT))
        == frozenset()
    )
    assert roles_of(
        AUDITOR_PRINCIPAL, construction=elsewhere, directory=directory_for(OTHER_TENANT)
    ) == frozenset({AUDITOR})

    #  And end to end: a directory authoritative only here grants nothing there.
    from muster.platform.disclose.queries import DisclosureService

    scoped = DisclosureService(
        commitment=_other_tenant().service.commitment, directory=directory_for(TENANT)
    )
    refused = get_my_view(
        scoped,
        tenant_id=OTHER_TENANT,
        principal=AUDITOR_PRINCIPAL,
        case_id=CASE,
        context=AUDIT,
        acting_as=None,
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is DisclosureFailure.CASE_NOT_VISIBLE

    assert isinstance(
        resolve_audience(
            AUDITOR_PRINCIPAL,
            construction=elsewhere,
            directory=directory_for(TENANT),
            acting_as=AUDITOR,
        ),
        Err,
    )


def test_BUNDLE_SUBSTITUTION_REJECTED() -> None:
    """A disclosure policy is one subartifact of a bundle, not the bundle.

    Found by the final review. Two bundles with identical policy octets have
    identical policy digests and may differ in admissibility descriptors, the
    predicate schema and the action schema -- so pinning the policy alone let a
    reader accept a decision taken under a rulebook they never saw.
    """
    from dataclasses import replace as _replace

    worker = _worker_view()
    honest = _reader("WORKER", "NOTIFICATION")
    assert not {failure.failure for failure in verify_view(worker, honest)}

    elsewhere = _replace(honest, bundle_manifest_digest=Digest(bytes(range(32, 64))))
    found = {failure.failure for failure in verify_view(worker, elsewhere)}
    assert VerificationFailure.BUNDLE_SUBSTITUTED in found
    #  And the policy check does *not* fire, which is the whole point: the two
    #  bundles agree about the policy and disagree about everything else.
    assert VerificationFailure.POLICY_SUBSTITUTED not in found


def test_a_disclosed_bundle_pin_that_contradicts_the_envelope_is_rejected() -> None:
    """Two of the site's four leaves exist so a reader can make this comparison."""
    employer = view_for(_case(), EMPLOYER, NOTIFICATION)
    disclosed = {disclosure.path for disclosure in employer.disclosures}
    assert {"bundle.manifest_digest", "revision.bundle_pin"} <= disclosed

    elsewhere = _other_case()
    swapped = replace(
        employer.envelope.envelope,
        bundle_manifest_digest=Digest(bytes(range(64, 96))),
    )
    tampered = replace(
        employer, envelope=SignedCommitmentEnvelope(swapped, employer.envelope.signature)
    )
    found = {
        failure.failure
        for failure in verify_view(
            tampered,
            replace(
                _reader("EMPLOYER", "NOTIFICATION"),
                bundle_manifest_digest=Digest(bytes(range(64, 96))),
            ),
        )
    }
    assert VerificationFailure.DISCLOSED_PIN_CONTRADICTS_ENVELOPE in found
    assert elsewhere is not None


def test_a_policy_whose_rows_a_reader_cannot_tell_apart_is_refused_at_pin_time() -> None:
    """The residual hole in the entry-downgrade fix, closed where it can be.

    The reader ties the named entry to the record through the outcome tag. For
    an audience that is never shown the tag both bindings are vacuous, so a
    writer picks whichever of that audience's rows permits least. No
    reader-side check can catch it, so the policy is refused instead: rows an
    audience cannot distinguish must permit the same paths.
    """
    from muster.platform.disclose.policy import PolicyFailure, validate_policy
    from muster.policy.artifacts import DisclosureEntry, DisclosurePolicy, RatificationSet

    def _row(outcome: str, action: str | None, paths: tuple[str, ...]) -> DisclosureEntry:
        return DisclosureEntry(
            outcome_class=outcome,
            action_kind=action,
            audience_class="SITE",
            disclosure_context="NOTIFICATION",
            reveals_sensitive_input=False,
            inference_acknowledgement_ref=None,
            permitted_paths=paths,
        )

    undecidable = DisclosurePolicy(
        schema_version=1,
        entries=(
            _row("DIVERGENT", None, ("case.case_id",)),
            _row("INVARIANT", "PAY", ("case.case_id", "revision.as_of")),
        ),
    )
    refused = validate_policy(undecidable, ratifications=RatificationSet(1, ()))
    assert isinstance(refused, Err)
    assert refused.error.failure is PolicyFailure.ROW_SET_NOT_READER_DECIDABLE

    #  Two ways out, and both are accepted: permit the same paths, or disclose
    #  the tag so a reader can decide which row governs.
    same = DisclosurePolicy(
        schema_version=1,
        entries=(
            _row("DIVERGENT", None, ("case.case_id",)),
            _row("INVARIANT", "PAY", ("case.case_id",)),
        ),
    )
    assert not isinstance(validate_policy(same, ratifications=RatificationSet(1, ())), Err)

    decidable = DisclosurePolicy(
        schema_version=1,
        entries=(
            _row("DIVERGENT", None, ("case.case_id", "kernel.outcome.tag")),
            _row("INVARIANT", "PAY", ("case.case_id", "kernel.outcome.tag", "revision.as_of")),
        ),
    )
    assert not isinstance(validate_policy(decidable, ratifications=RatificationSet(1, ())), Err)


def test_the_pinned_workforce_policy_is_reader_decidable() -> None:
    """And the bundle this milestone ships satisfies the rule it just added."""
    from muster.platform.disclose.policy import validate_policy

    bundle = _case().committed.bundle
    assert not isinstance(
        validate_policy(bundle.disclosure_policy, ratifications=bundle.ratifications), Err
    )


def test_an_inference_notice_must_be_the_notice_and_not_merely_a_string() -> None:
    """Presence is not content: some other string satisfies "a notice is here"
    and tells its recipient nothing."""
    from muster.platform.disclose.views import INFERENCE_NOTICE

    worker = _worker_view()
    assert isinstance(worker, ParticipantView)
    assert worker.inference_notice is None
    invented = replace(worker, inference_notice="ALL IS WELL")
    assert VerificationFailure.INFERENCE_NOTICE_WRONG in _failures(
        invented, "WORKER", "NOTIFICATION"
    )
    assert INFERENCE_NOTICE != "ALL IS WELL"
