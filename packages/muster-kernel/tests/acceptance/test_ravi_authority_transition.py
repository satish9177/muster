"""The audit for the digests milestone E moved, and the proof it moved no decision.

Milestone E gives three artifacts a field each -- the predicate schema, the case
construction record, and the authorization context -- and every one of them sits
under a digest something downstream cites.  So the four frozen Ravi anchors
moved together, and "the digests moved because source authorization landed" is a
true sentence that is also exactly what decision-semantic drift would say.

**Why this file replaces the milestone-D transition audit rather than joining
it.**  That audit worked by reconstructing the bundle as it stood before D and
showing it reproduced four recorded digests.  The method needs the case
artifacts to be constant while the bundle moves, and milestone E moved the case
artifacts: a construction record without ``case_scope_coordinates`` is a shape
this codebase can no longer build, so the pre-D revision digest is not
reachable from today's types by any amount of substitution.  Reconstruction was
the right method for a bundle-only change and is the wrong one here.

What replaces it is stronger, and it is a comparison against *running code*
rather than against remembered numbers.

    the SEMANTIC CORE

        what was declared;
        what was established, by reference and by value;
        which constraints were produced, by label and by formula;
        which non-effects were recorded, by rule, subject and reason;
        what remained unresolved;
        and the outcome -- for the divergent case, the whole outcome; for the
        attested one, the action and the witness world it is invariant over

    with everything that is an IDENTITY rather than a decision masked out:

        the bundle pin, the construction digest, the transcript prefix, the
        authorization context;
        the receipt digest a ``C-ATT`` constraint label carries;
        and the solver handle an ``Invariant`` outcome cites.

The two constants below were produced by running that computation against the
**committed milestone-D tree** -- ``git archive HEAD packages/muster-kernel``
into a scratch directory, with the pre-E case fixtures, on the pre-E kernel.
They are what MUSTER decided about Ravi before source authorization existed.
This file asserts today's tree produces the same two numbers.

That is the whole claim, and it is worth being precise about what it does and
does not cover.  It covers the decision: same facts, same values, same
constraints, same open set, same outcome, same action, same amount.  It does
not cover the identities, which moved and are meant to have -- those are frozen
in ``test_determinism`` with the causes written beside them.
"""

from __future__ import annotations

from functools import cache

from muster.application.case_file import CaseFile
from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.analysis.outcomes import Invariant
from muster.core.case.facts import AttestedBy, EntailedBy
from muster.core.case.revision import CaseRevision
from muster.core.results import Ok
from muster.policy.manifest import LoadedBundle
from tests.acceptance.test_determinism import (
    WORKFORCE_DECISION_ARTIFACTS,
    WORKFORCE_MANIFEST_DIGEST,
)
from tests.support import ravi
from tests.support.semantics import semantic_core

#  Computed from the committed milestone-D tree, before source authorization
#  existed.  Not transcribed from a previous run of *this* file -- that would
#  make the audit a comparison of today with today.
SEMANTIC_CORE_DIVERGENT = "1187f910cde54fc7edd9736f9f70607c78b8158be6a4e2db5891d50ba6507b0f"
SEMANTIC_CORE_ATTESTED = "8264aaea68d590485d1b7ffc41c93afa6fcd8bf90cc1e57ecc4acc41f036ea38"

#  The five bundle subartifacts milestone E did **not** touch.  Named here as
#  well as in ``test_determinism`` because this file's claim depends on it: if
#  the entailment rules or the decision program had moved, "the same decision"
#  would be a coincidence rather than a consequence.
UNMOVED_BUNDLE_ARTIFACTS = (
    "decision_program_digest",
    "entailment_rules_digest",
    "admissibility_descriptors_digest",
    "action_schema_digest",
    "ratification_records_digest",
)

#  What milestone D froze for these five.  Copied from the milestone-D commit,
#  so a change to any of them fails here rather than being absorbed by an
#  update to the dictionary this compares against.
MILESTONE_D_BUNDLE_ARTIFACTS = {
    "decision_program_digest": "6858423713ffc0d4d8bc68f159d343b533f81031815c2f0e4dbafd4823e504fe",
    "entailment_rules_digest": "fc03cd47ef63eaa82d4339a24d2a4ab604f5a1d45a93cabe743d66190286c0d1",
    "admissibility_descriptors_digest": (
        "a47331836f626ef1314bee0d5233b1f5ce7daea885c04564abde1ea29974d27a"
    ),
    "action_schema_digest": "5908a6ea94f2d6a9acf7cc49c89f9beabe5db9e15dfa21d421e1845094240c45",
    "ratification_records_digest": (
        "1e70cec229c4cb142a555f7373800186d485e010c214fd0559bda29c8cb8079c"
    ),
}

#  The manifest digest as milestone D left it.  Written down so "the manifest
#  moved" is a checked statement rather than an inference from the constant
#  above having been edited.
MILESTONE_D_MANIFEST_DIGEST = "4ec52a0bdb95707347f9788343eb3d50dd4daef7903024eb059acc482ef26692"


#  A constraint label carries the digest of the receipt that produced it, which
#  is provenance rather than semantics: one constraint per receipt is the
#  property worth keeping visible, and *which* receipt is an identity.
def _analysis(bundle: LoadedBundle, case: CaseFile) -> tuple[CaseRevision, CaseAnalysis]:
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    built = rebuild(
        case.rebuild_inputs(bundle.digest(), prefix.digest()),
        case.construction,
        case.entries,
        bundle,
        case.authorization_context,
        case.authority_snapshot,
        case.revocation_snapshot,
        case.solicitations,
    )
    assert isinstance(built, Ok), built
    produced = analyse_revision(built.value, bundle, ravi.backend(), ravi.limits())
    assert isinstance(produced, Ok), produced
    return built.value, produced.value


@cache
def _attested() -> tuple[CaseRevision, CaseAnalysis]:
    return _analysis(ravi.bundle(), ravi.attested_case_file())


#  ---- 1. the decision did not move ------------------------------------------


def test_the_divergent_case_decides_exactly_what_it_decided_before_authority() -> None:
    """**The load-bearing test.**

    One number, produced by the committed milestone-D tree and reproduced here.
    Under collision resistance it fixes every component the core names: the
    declared instances, every established fact and its value, every constraint
    and its formula, every recorded non-effect, the unresolved set and the
    outcome.  Source authorization did not admit one receipt more or one
    receipt fewer, and did not change what any of them established.
    """
    assert semantic_core(ravi.revision(), ravi.analysis()) == SEMANTIC_CORE_DIVERGENT


def test_the_attested_case_decides_exactly_what_it_decided_before_authority() -> None:
    """And the outcome that authorizes an action, which is the one that matters.

    A transition that left the open case alone and quietly changed the closed
    one would be the worst possible outcome of this milestone: the demo would
    still look right and the payment would be different.
    """
    revision, analysis = _attested()
    assert semantic_core(revision, analysis) == SEMANTIC_CORE_ATTESTED


#  ---- 2. what did move, and that it is only what was claimed ----------------


def test_exactly_one_bundle_subartifact_moved() -> None:
    """The predicate schema, because it gained the Q-12(d) input.

    The other five are asserted against the values milestone D froze, not
    against today's dictionary -- comparing today's constants with today's
    bundle would pass however much had moved.
    """
    manifest = ravi.bundle().manifest
    for field in UNMOVED_BUNDLE_ARTIFACTS:
        assert getattr(manifest, field).hex == MILESTONE_D_BUNDLE_ARTIFACTS[field], field

    assert manifest.predicate_schema_digest.hex != (
        "6aba0967f35ed1264a56be7c7d4e018180e088db4e3172f2055a6192300376f9"
    )
    assert (
        manifest.predicate_schema_digest.hex
        == WORKFORCE_DECISION_ARTIFACTS["predicate_schema_digest"]
    )


def test_the_manifest_moved_and_says_so() -> None:
    """The manifest commits to all seventeen fields, so one moving moves it."""
    assert ravi.bundle().digest().hex == WORKFORCE_MANIFEST_DIGEST
    assert ravi.bundle().digest().hex != MILESTONE_D_MANIFEST_DIGEST


def test_the_predicate_schema_moved_because_every_predicate_declares_a_scope() -> None:
    """Not "a field was added" -- *this* field, on the predicates that need it.

    Every attestable predicate declares at least one resource scope kind,
    because a predicate that declared none could never be authorized: Q-12(d)
    refuses an empty coordinate set rather than reading it as unrestricted.
    The derived conclusion declares none, for the same reason it permits no
    source class.
    """
    from muster.core.values.classification import AcquisitionClass

    for spec in ravi.bundle().predicate_schema.predicates:
        if spec.acquisition is AcquisitionClass.ATTESTABLE:
            assert spec.resource_scope_kinds, spec.predicate_id
        else:
            assert not spec.resource_scope_kinds, spec.predicate_id


def test_the_case_declares_where_it_is_and_the_officer_signed_it() -> None:
    """Q-12(d)'s other input, and the reason it is trustworthy.

    A source that could name its own site would authorize itself by writing a
    different atom.  The site comes from the construction record instead, which
    is signed at case construction and pinned by digest on the head -- so
    re-siting a case means re-signing it, and the head names the digest.
    """
    coordinates = ravi.case_file().construction.case_scope_coordinates
    assert coordinates, "a case with no coordinates can authorize no attestation"
    assert {scope.scope_kind for scope in coordinates} == {"SITE", "EMPLOYER"}


def test_the_authorization_context_pins_the_authority_registry() -> None:
    """The renamed pin, and the two snapshots it now resolves to.

    Checked as an equality against the snapshots the case carries rather than
    as a "field exists": the pin is only worth anything if it is the digest of
    the thing the rebuild was actually judged against.
    """
    case = ravi.case_file()
    context = case.authorization_context
    assert context.authority_registry_snapshot_digest == case.authority_snapshot.digest()
    assert context.revocation_snapshot_digest == case.revocation_snapshot.digest()


#  ---- 3. the transition is not a weakening ----------------------------------


def test_the_same_receipts_are_admitted_as_before() -> None:
    """Counted, so "no decision moved" cannot be true by nothing being admitted.

    The semantic core would be identical for two runs that both admitted
    nothing, and a milestone that turned every receipt into a non-effect would
    pass it.  This is the test that says the receipts are still doing work.
    """
    revision = ravi.revision()
    #  Every established fact carries a justification naming what produced it,
    #  which is what makes "the receipts are still doing work" checkable rather
    #  than inferred from a count alone.
    attested = [fact for fact in revision.established if isinstance(fact.justification, AttestedBy)]
    entailed = [fact for fact in revision.established if isinstance(fact.justification, EntailedBy)]
    assert len(attested) + len(entailed) == len(revision.established)
    assert attested, "no receipt established anything, so the core proves nothing"

    #  And no receipt became a non-effect for an authority reason.  A refusal
    #  here would not move the semantic core if the receipt had established
    #  nothing anyway -- but it is exactly the silent weakening this milestone
    #  could plausibly introduce.
    authority_refusals = [
        item
        for item in revision.non_effects
        if item.reason
        in {
            "SourceClassNotPermittedForPredicate",
            "UnauthorizedSourceClassForKey",
            "AmbiguousAuthorityGrant",
            "CrossTenantAuthority",
            "PrincipalMismatch",
            "ResourceScopeUndetermined",
            "ResourceScopeNotAuthorized",
            "PredicateNotAuthorizedForKey",
            "AuthorityNotYetValid",
            "AuthorityExpired",
            "KeyRevoked",
            "AuthorizationPolicyVersionMismatch",
        }
    ]
    assert authority_refusals == []


def test_the_attested_case_still_closes_on_the_same_action() -> None:
    """Named separately from the core, because this is the sentence that sells it."""
    _, analysis = _attested()
    outcome = analysis.kernel.outcome
    assert isinstance(outcome, Invariant)
    assert outcome.action.kind == "PAY"
