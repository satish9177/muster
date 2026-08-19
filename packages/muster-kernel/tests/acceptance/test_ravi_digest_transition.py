"""The audit for the four Ravi digests milestone D moved, and why they had to.

Four frozen anchors moved when the workforce bundle's disclosure policy gained
the ratified employer, site and auditor entries: the manifest, the Ravi
revision, its logical case and its certificate.  Updating four constants and
asserting they are now different numbers proves nothing at all -- it is exactly
what decision-semantic drift would also look like.  So this file reconstructs
the bundle **as it stood before**, and establishes the transition structurally.

    1  the reconstruction reproduces all four previously recorded digests, so
       it is the previous bundle rather than an approximation of one.  **This
       is the load-bearing test.**  Under collision resistance, reproducing the
       previous manifest digest fixes all seventeen manifest fields -- so every
       decision-semantic subartifact the previous bundle committed to is
       exactly the one today's bundle commits to, and the previous disclosure
       policy is exactly the one reconstructed here.  The tests after it read
       that conclusion out; they do not establish it independently, and they
       are labelled so

    2  the reconstruction differs from today's manifest in exactly one field,
       which together with (1) says the *previous* manifest did too

    3  the previous disclosure policy's digest is the one the previous manifest
       committed to, and it is the two worker entries unedited

    4  the previous revision is the current revision with one digest
       substituted -- the manifest pin, in all seven places it appears: the
       revision's own, five entailed facts' and one constraint's -- compared as
       octets, not as fields somebody remembered to check

    5  the previous certificate is the current one with six digests
       substituted: the manifest, the revision, the logical case, three query
       digests and the sufficiency handle.  Every one is a pin or a handle
       *derived from* the manifest.  Nothing else moves by a single octet.

    6  every decision-semantic input and output is equal as a value: the
       normative policy, the known facts, the unresolved propositions, the
       constraint set, the candidate actions, the sufficiency argument and the
       classification -- for the divergent case and for the attested one that
       closes as invariant

    7  and the *guard*, which lives in ``test_determinism`` beside the anchors
       it qualifies rather than here: a bundle-pin-blind digest of the decision
       core, which a disclosure policy cannot move and which any change to what
       Ravi decides does move.  This file shows that the previous bundle and
       the current one produce the same one, which is the audit's conclusion;
       that file keeps it standing after this audit is forgotten.
"""

from __future__ import annotations

from dataclasses import replace
from functools import cache

from muster.application.case_file import CaseFile
from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.analysis.outcomes import Divergent, Invariant, outcome_class
from muster.core.analysis.planning import EvidenceRequested, ProvenIrredundantSupport
from muster.core.case.revision import CaseRevision
from muster.core.results import Ok
from muster.core.wire.codec import encode
from muster.domains.workforce import bundle as workforce
from muster.policy.artifacts import DisclosurePolicy
from muster.policy.manifest import LoadedBundle, SignedManifest, load_bundle
from tests.acceptance.test_determinism import (
    RAVI_ATTESTED_CERTIFICATE_CORE,
    RAVI_CERTIFICATE_CORE,
    RAVI_CERTIFICATE_DIGEST,
    RAVI_DECISION_CORE,
    RAVI_LOGICAL_CASE_DIGEST,
    RAVI_REVISION_DIGEST,
    WORKFORCE_DECISION_ARTIFACTS,
    WORKFORCE_MANIFEST_DIGEST,
    decision_core,
)
from tests.support import ravi

#  What the four anchors were before milestone D. Recorded in abbreviated form
#  beside the constants they replaced; written out in full here, because this
#  file is the thing that has to reproduce them.
PREVIOUS_MANIFEST_DIGEST = "a6f51be4d74e3470fdba490d9d7e9ba0b79fbee5daf399a43f9692ee81dc4b11"
PREVIOUS_REVISION_DIGEST = "51438b713114d3becc772a840a49f8b46c8cd213adf74d237cb10dd8bdec34a7"
PREVIOUS_LOGICAL_CASE_DIGEST = "14729c8dbca70a6ea3272b025af278c74ce77fac1714ab59f458fc8952a64e8e"
PREVIOUS_CERTIFICATE_DIGEST = "53f6f155a2fe67f0725671e2b9e3163c7bb4a531892db73b5e55109837b56a23"

#  The one manifest field that moved, as it stood before.  Not an independent
#  observation: it is *determined* by ``PREVIOUS_MANIFEST_DIGEST`` and the
#  sixteen fields that did not move, because a manifest digest commits to all
#  seventeen.  Written down so that the reconstruction has something to be
#  wrong against -- an edited worker entry changes this number, and then the
#  manifest digest below it no longer reproduces either.
PREVIOUS_DISCLOSURE_POLICY_DIGEST = (
    "85cdfb4bac8732130aa0576b69aa3d06c316e8a7817b69df25e5044b373a2a63"
)


#  ---- the bundle as it stood before -----------------------------------------


@cache
def previous_bundle() -> LoadedBundle:
    """The workforce bundle with only the two entries it had before milestone D.

    Reconstructed rather than checked in.  Every other artifact is taken from
    the module unchanged -- which is the point: if any of them had moved, this
    would not reproduce the previous manifest digest, and the first test below
    would fail instead of the audit quietly proving something weaker.

    Two things this object is not.  Its manifest signature is the current
    bundle's, carried over a manifest with a different digest, so it covers
    nothing it contains; ``load_bundle`` verifies subartifact digests and not
    the signature, and a digest audit never asks.  And it is built *from* the
    current manifest by ``replace``, so any comparison of its fields against
    today's is a comparison of a copy with its original.  What makes it
    historical is one thing only: it reproduces the four digests this
    repository recorded before the change.
    """
    policy = workforce.disclosure_policy()
    worker_only = DisclosurePolicy(
        schema_version=policy.schema_version,
        entries=tuple(entry for entry in policy.entries if entry.audience_class == "WORKER"),
    )
    current = ravi.bundle()
    loaded = load_bundle(
        signed_manifest=SignedManifest(
            replace(current.manifest, disclosure_policy_digest=worker_only.digest()),
            current.signed_manifest.signature,
        ),
        program=workforce.decision_program(ravi.RAVI),
        entailment_rules=workforce.entailment_rules(),
        predicate_schema=workforce.predicate_schema(),
        action_schema=workforce.action_schema(),
        admissibility_descriptors=workforce.admissibility_descriptors(),
        disclosure_policy=worker_only,
        ratifications=workforce.ratifications(),
    )
    assert isinstance(loaded, Ok), loaded
    return loaded.value


def _revision(bundle: LoadedBundle, case: CaseFile) -> CaseRevision:
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    built = rebuild(
        case.rebuild_inputs(bundle.digest(), prefix.digest()),
        case.construction,
        case.entries,
        bundle,
        case.authorization_context,
    )
    assert isinstance(built, Ok), built
    return built.value


def _analysis(bundle: LoadedBundle, case: CaseFile) -> tuple[CaseRevision, CaseAnalysis]:
    revision = _revision(bundle, case)
    produced = analyse_revision(revision, bundle, ravi.backend(), ravi.limits())
    assert isinstance(produced, Ok), produced
    return revision, produced.value


@cache
def _before() -> tuple[CaseRevision, CaseAnalysis]:
    return _analysis(previous_bundle(), ravi.case_file())


@cache
def _after() -> tuple[CaseRevision, CaseAnalysis]:
    return _analysis(ravi.bundle(), ravi.case_file())


#  ---- 1. the reconstruction is the previous bundle --------------------------


def test_the_reconstruction_reproduces_every_previously_recorded_digest() -> None:
    """Four numbers, and the reason the rest of this file means anything.

    A reconstruction that merely loaded would prove only that the loader
    accepts it.  These four say it is the bundle that produced the digests this
    repository recorded before the change -- so what follows is a comparison
    between two real states of the system rather than between the current one
    and a guess at its history.
    """
    before_revision, before_analysis = _before()
    assert previous_bundle().digest().hex == PREVIOUS_MANIFEST_DIGEST
    assert before_revision.digest().hex == PREVIOUS_REVISION_DIGEST
    assert before_analysis.projected.logical.digest().hex == PREVIOUS_LOGICAL_CASE_DIGEST
    assert before_analysis.certificate.digest().hex == PREVIOUS_CERTIFICATE_DIGEST

    #  And the four the repository holds now, from the module that freezes them.
    after_revision, after_analysis = _after()
    assert ravi.bundle().digest().hex == WORKFORCE_MANIFEST_DIGEST
    assert after_revision.digest().hex == RAVI_REVISION_DIGEST
    assert after_analysis.projected.logical.digest().hex == RAVI_LOGICAL_CASE_DIGEST
    assert after_analysis.certificate.digest().hex == RAVI_CERTIFICATE_DIGEST


#  ---- 2 and 3. what actually changed ----------------------------------------


def test_exactly_one_manifest_field_moved() -> None:
    """Seventeen fields, sixteen equal, and the seventeenth names the change.

    **What this does not prove.**  ``previous_bundle`` is built by ``replace``
    over today's manifest, so a field-by-field comparison against today's is a
    comparison of a copy with its original: the set below would be a singleton
    however the bundle had changed.  Stated rather than deleted, because the
    statement it *does* make is needed -- the reconstruction changes exactly one
    field -- and combining it with the previous manifest digest being reproduced
    is what upgrades it into a claim about history.

    So the substantive check here is the other one: today's decision-semantic
    subartifacts are the ones frozen in ``test_determinism``, which is not a
    tautology and fails the moment a rule changes.
    """
    before = previous_bundle().manifest
    after = ravi.bundle().manifest
    moved = {name for name in before.__slots__ if getattr(before, name) != getattr(after, name)}
    assert moved == {"disclosure_policy_digest"}

    #  Against recorded numbers rather than against a copy of themselves.
    assert {
        name: getattr(after, name).hex for name in WORKFORCE_DECISION_ARTIFACTS
    } == WORKFORCE_DECISION_ARTIFACTS


def test_the_disclosure_policy_was_appended_to_and_never_edited() -> None:
    """The previous policy is the current one's first two entries, octet for octet.

    The entry comparison below is again a statement about the reconstruction:
    ``after.entries[:2] == before.entries`` holds because ``before`` was sliced
    out of ``after``.  What rules out an *edited* worker row is the digest --
    an edit changes ``worker_only.digest()``, which is the one manifest field
    the reconstruction sets, so the previous manifest digest stops reproducing
    and the whole audit fails at test 1.

    Recording the previous policy digest separately makes that failure legible
    instead of leaving it to be inferred from a manifest digest that moved.
    """
    before = previous_bundle().disclosure_policy
    after = ravi.bundle().disclosure_policy
    assert before.digest().hex == PREVIOUS_DISCLOSURE_POLICY_DIGEST
    assert len(before.entries) == 2
    assert len(after.entries) == 8
    assert after.entries[:2] == before.entries
    assert {entry.audience_class for entry in before.entries} == {"WORKER"}
    assert {entry.audience_class for entry in after.entries[2:]} == {
        "EMPLOYER",
        "SITE",
        "AUDITOR",
    }
    assert before.schema_version == after.schema_version


#  ---- 4 and 5. the transition, as octets ------------------------------------


def test_the_revision_is_the_same_record_under_a_different_bundle_pin() -> None:
    """One substitution, seven occurrences, and an exact match.

    The manifest digest occurs seven times in this record and the places are
    worth naming: once as the revision's own ``bundle_pin``, five times inside
    the ``EntailedBy`` justification of each derived fact, and once in the
    provenance of the entailed constraint.  Anything derived under a rulebook
    says which rulebook, which is why one policy entry moves seven digests
    inside one artifact.

    Substituting the old manifest digest for the new one everywhere it occurs
    reproduces the previous revision's canonical encoding exactly, so **no other
    octet of the record differs**: not a fact, not a value, not a rule
    identifier, not a premise, not a constraint, not a non-effect, not a
    declaration.
    """
    before_revision, _ = _before()
    after_revision, _ = _after()
    after_octets = encode(after_revision.to_node())

    assert after_octets.count(ravi.bundle().digest().octets) == 7
    substituted = after_octets.replace(
        ravi.bundle().digest().octets, previous_bundle().digest().octets
    )
    assert substituted == encode(before_revision.to_node())


def test_the_certificate_moves_only_where_it_cites_something_that_moved() -> None:
    """Six substitutions, each one a pin or a handle, and an exact match.

    The manifest, the revision it produced, the logical case projected from that
    revision, the three solver queries asked about that logical case, and the
    sufficiency handle naming one more.  Every one of the six is an identity
    that moves when the manifest moves.  With all six substituted the two
    certificates are the same octets, so the answer -- the outcome, the worlds,
    the plan, the support, the fingerprint -- did not move at all.

    Two of those are worth being precise about.  The logical-case digest, the
    query digests and the handle are digests *of case-derived content*, so
    substituting them makes this test blind to a change in the projection or in
    the query encoder: a semantically different query at position *i* would be
    substituted away by the positional pairing below.  That gap is closed by
    test 1, not by this one -- reproducing the previously recorded logical-case
    and certificate digests **under today's code** pins both to their
    pre-change behaviour.  The substitutions are all 32 octets for 32 octets, so
    nothing shifts; and a collision between a substituted-in value and a later
    search value would break the final equality rather than repair it.
    """
    before_revision, before_analysis = _before()
    after_revision, after_analysis = _after()
    before_certificate = before_analysis.certificate
    after_certificate = after_analysis.certificate

    substituted = encode(after_certificate.to_node())
    for after_pin, before_pin in _pins(
        after_revision, after_analysis, before_revision, before_analysis
    ):
        substituted = substituted.replace(after_pin, before_pin)
    assert substituted == encode(before_certificate.to_node())


def _pins(
    after_revision: CaseRevision,
    after_analysis: CaseAnalysis,
    before_revision: CaseRevision,
    before_analysis: CaseAnalysis,
) -> tuple[tuple[bytes, bytes], ...]:
    """The six identities that move, paired new-to-old and named."""
    before_support = before_analysis.certificate.planning.support
    after_support = after_analysis.certificate.planning.support
    assert isinstance(before_support, ProvenIrredundantSupport)
    assert isinstance(after_support, ProvenIrredundantSupport)
    queries = tuple(
        (after.octets, before.octets)
        for after, before in zip(
            after_analysis.certificate.kernel.query_digests,
            before_analysis.certificate.kernel.query_digests,
            strict=True,
        )
    )
    return (
        (ravi.bundle().digest().octets, previous_bundle().digest().octets),
        (after_revision.digest().octets, before_revision.digest().octets),
        (
            after_analysis.projected.logical.digest().octets,
            before_analysis.projected.logical.digest().octets,
        ),
        *queries,
        (after_support.sufficiency_handle.octets, before_support.sufficiency_handle.octets),
    )


#  ---- 6. nothing a decision depends on, and nothing it produced -------------


def test_no_decision_semantic_input_moved() -> None:
    """The normative policy, the known facts and the open questions, as values."""
    before_revision, _ = _before()
    after_revision, _ = _after()

    #  The normative policy, against the digests frozen in ``test_determinism``
    #  rather than against the copy the reconstruction was made from. The
    #  previous bundle committed to these same six -- that is test 1's
    #  conclusion, by collision resistance on the manifest -- so equality here
    #  is equality across the transition and not with itself.
    manifest = ravi.bundle().manifest
    assert {
        name: getattr(manifest, name).hex for name in WORKFORCE_DECISION_ARTIFACTS
    } == WORKFORCE_DECISION_ARTIFACTS

    #  Ravi's known facts and the propositions still open.
    #
    #  Facts and values are compared directly.  Their *justifications* are
    #  compared with the manifest substituted, because five of the twenty-two
    #  facts are entailed and an entailed fact records the rulebook it was
    #  derived under -- so demanding raw equality there would be demanding that
    #  a derived fact forget where it came from.
    assert [(fact.ref, fact.value) for fact in before_revision.established] == [
        (fact.ref, fact.value) for fact in after_revision.established
    ]
    for before_fact, after_fact in zip(
        before_revision.established, after_revision.established, strict=True
    ):
        assert encode(after_fact.to_node()).replace(
            ravi.bundle().digest().octets, previous_bundle().digest().octets
        ) == encode(before_fact.to_node())
    assert before_revision.unresolved() == after_revision.unresolved()
    assert before_revision.declared == after_revision.declared
    assert before_revision.non_effects == after_revision.non_effects
    assert before_revision.authorizability == after_revision.authorizability
    #  The Saturday threshold is a constraint of the decision program, and the
    #  constraint set is equal once the manifest each one cites is set aside --
    #  which the octet test above establishes for the whole record at once.
    assert len(before_revision.constraints) == len(after_revision.constraints)


def test_no_decision_semantic_output_moved() -> None:
    """The classification, the candidate actions, the plan and the support."""
    _, before_analysis = _before()
    _, after_analysis = _after()
    before_certificate = before_analysis.certificate
    after_certificate = after_analysis.certificate

    before_outcome = before_certificate.kernel.outcome
    after_outcome = after_certificate.kernel.outcome
    assert outcome_class(before_outcome) == outcome_class(after_outcome) == "DIVERGENT"
    assert isinstance(before_outcome, Divergent)
    assert isinstance(after_outcome, Divergent)
    #  Candidate consequential actions, and the two worlds that separate them.
    assert before_outcome.reachable == after_outcome.reachable
    assert before_outcome.left == after_outcome.left
    assert before_outcome.right == after_outcome.right

    assert before_certificate.kernel.fingerprint == after_certificate.kernel.fingerprint
    assert before_certificate.kernel.determinism_class == after_certificate.kernel.determinism_class

    #  Evidence sufficiency: the same plan, naming the same targets.
    before_plan = before_certificate.planning.planning_outcome
    after_plan = after_certificate.planning.planning_outcome
    assert isinstance(before_plan, EvidenceRequested)
    assert isinstance(after_plan, EvidenceRequested)
    assert before_plan.request.targets == after_plan.request.targets

    #  And the irredundance argument: the same members, proved the same way.
    before_support = before_certificate.planning.support
    after_support = after_certificate.planning.support
    assert isinstance(before_support, ProvenIrredundantSupport)
    assert isinstance(after_support, ProvenIrredundantSupport)
    assert before_support.members == after_support.members
    assert before_support.deletion_witnesses == after_support.deletion_witnesses


def test_the_attested_case_still_closes_as_invariant_with_the_same_action() -> None:
    """The other half of the Ravi story, which a policy change must not touch.

    Divergence is what the case looks like before the Saturday observations
    arrive.  With them, it closes -- and closing is the outcome that authorizes
    an action, so it is the one where drift would matter most.
    """
    _, before_analysis = _analysis(previous_bundle(), ravi.attested_case_file())
    _, after_analysis = _analysis(ravi.bundle(), ravi.attested_case_file())

    before_outcome = before_analysis.certificate.kernel.outcome
    after_outcome = after_analysis.certificate.kernel.outcome
    assert isinstance(before_outcome, Invariant)
    assert isinstance(after_outcome, Invariant)
    assert before_outcome.action == after_outcome.action
    assert before_outcome.witness == after_outcome.witness


#  ---- 7. the guard, shown to be unmoved by this transition ------------------


def test_the_decision_core_is_the_same_under_both_bundles() -> None:
    """The audit's conclusion, as one comparison.

    ``decision_core`` is the Ravi record and certificate with every
    bundle-derived identity masked out.  The constants it is checked against
    live in ``test_determinism``, beside the four anchors they qualify, because
    they have to outlive this file: a future transition of the same shape will
    move those four anchors again, and these are what says whether it also
    moved a decision.

    Here they are checked *twice over* -- under the bundle as it stood before
    and under the bundle as it stands now -- which is the thing this audit
    exists to establish and which no single-state test can say.
    """
    before = decision_core(*_before(), previous_bundle())
    after = decision_core(*_after(), ravi.bundle())

    assert before == after
    assert after == (RAVI_DECISION_CORE, RAVI_CERTIFICATE_CORE)


def test_the_attested_decision_core_is_the_same_under_both_bundles() -> None:
    """The same, for the outcome that authorizes an action."""
    attested = ravi.attested_case_file()
    before_revision, before_analysis = _analysis(previous_bundle(), attested)
    after_revision, after_analysis = _analysis(ravi.bundle(), attested)

    _, before_core = decision_core(before_revision, before_analysis, previous_bundle())
    _, after_core = decision_core(after_revision, after_analysis, ravi.bundle())

    assert before_core == after_core
    assert after_core == RAVI_ATTESTED_CERTIFICATE_CORE
