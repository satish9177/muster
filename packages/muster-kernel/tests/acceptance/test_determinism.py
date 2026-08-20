"""Determinism, anchored and checked across processes.

Comparing a run to itself inside one process proves almost nothing: a canonical
ordering that is deterministic-but-wrong passes, and one that depends on string
hashing passes too, because the seed is fixed for the life of the interpreter.

So there are three checks here.  A **frozen anchor**: the Ravi artifacts have
these digests, and any change to a canonical ordering, a digest domain or a
derivation moves them.  A **cross-process** comparison under different
``PYTHONHASHSEED`` values, which is what catches an ordering that quietly came
from a set or a dict.  And a **bundle-pin-blind anchor** over the decision core,
which is the one that survives a legitimate bundle change.

The third exists because the first is not enough on its own.  Every artifact
downstream of a bundle cites the bundle, so adding a disclosure audience -- a
change that decides nothing -- moves all four anchors at once, and "the digests
moved because the bundle moved" becomes a true sentence that also happens to be
what real drift would say.  The blind anchor is the same record and certificate
with every bundle-derived identity masked out: a pin change leaves it exactly
where it is, and a change to what Ravi *decides* moves it whatever else moved
alongside.  It lives here, beside the anchors it qualifies, rather than in the
one-off audit of any particular transition.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from muster.application.pipeline import CaseAnalysis
from muster.core.analysis.planning import ProvenIrredundantSupport
from muster.core.case.revision import CaseRevision
from muster.core.wire.codec import encode
from muster.policy.manifest import LoadedBundle
from tests.conftest import PACKAGE_ROOT
from tests.support import ravi

#  Frozen for this milestone. If a change is deliberate, these move with it and
#  the move is visible in the diff -- which is the point.
#
#  **Moved by milestone E, and the move is larger than milestone D's.**  Source
#  authorization needs three inputs that did not exist, and each is inside an
#  artifact a digest already covered:
#
#    * the predicate schema gained ``resource_scope_kinds`` -- the kinds of
#      resource an authority grant over a predicate must enumerate, which is
#      what Q-12(d) resolves against.  One manifest field moves, and exactly
#      one: the other five decision-semantic subartifacts below are
#      byte-identical to what milestone D froze;
#    * the case construction record gained ``case_scope_coordinates`` -- where
#      the case *is*, signed by the officer who opened it, so the resource
#      Q-12(d) checks comes from an artifact no source could author;
#    * ``AuthorizationContext.key_registry_snapshot_digest`` became
#      ``authority_registry_snapshot_digest``, pinning a snapshot that answers
#      "may this key say this" rather than one that answered "does this key
#      exist".
#
#  Every receipt pins the predicate schema, so every receipt digest moved; the
#  revision pins the construction record and the context, so it moved; and the
#  logical case and certificate cite the revision.  Four anchors, one cause
#  each, and none of them a decision.
#
#  **No decision moved, and that is proven rather than asserted.**
#  ``test_ravi_authority_transition`` computes a *semantic core* -- the
#  established facts by reference and value, the constraints by label and
#  formula, the recorded non-effects, the unresolved set and the outcome, with
#  every pin, provenance digest and solver handle masked -- and shows it is
#  byte-identical to the value the committed milestone-D tree produces for both
#  fixtures.  Ravi is still divergent, the plan still names both Saturday
#  observations, and the attested revision still closes as invariant on the
#  same action for the same amount.
#
#  Previous values, in order: 2361f323..., 9036cf41..., 473a0772..., 4ec52a0b...
#  Before milestone D they were 51438b71..., 14729c8d..., 53f6f155..., a6f51be4...
#  The certificate had moved once before that, in milestone B, when the encoder
#  started binding every enum a query mentions rather than only the ones a
#  declared variable carried: d819536b9f3345368231f65c125494b84726fdcb80612dbd34a2f539a7f6b359.
RAVI_REVISION_DIGEST = "2d816f8cfbe383c04825468f989ff1f7c442fc880fedeaf1cbba38f159d623df"
RAVI_LOGICAL_CASE_DIGEST = "5580388ae7041a6ef27976025a1341dc33f443bb7c57fc15c9146451f5dd53e2"
RAVI_CERTIFICATE_DIGEST = "7ab7e4329e9ceec3f520b4308ac13dea1bd12bffeaca8579715775727c23583e"
WORKFORCE_MANIFEST_DIGEST = "7c9925f56115795434d1dfc8348ada133b0bddba6eed7dffb224c3a2f4cde6b8"

HASH_SEEDS = ("0", "1", "99991")

#  The decision core: the Ravi record and certificate with every
#  bundle-derived identity masked out.
#
#  **Two of the three did not move at milestone E**, and the third moved for a
#  reason the anchor was never built to absorb.  ``blind`` masks *bundle*
#  identities, because milestone D's transition was a bundle change; milestone
#  E also changed two artifacts the case owns -- the construction record and
#  every receipt -- and those are inside the revision's encoding, unmasked and
#  correctly so.  An anchor that masked the construction digest would stop
#  seeing a case rebound to another site, which is the last thing this
#  milestone should make invisible.
#
#  So the certificate cores stand where milestone D left them, which is a
#  strong statement on its own: the certificate's decision content is
#  byte-identical across a transition that moved its digest.  And
#  ``RAVI_DECISION_CORE`` moves once, with
#  ``test_ravi_authority_transition``'s semantic core standing behind it --
#  that anchor *is* blind to provenance, and it did not move.
#
#  A future change that moves the four anchors above and leaves these three
#  alone is a pin transition.  One that moves the semantic core is a change to
#  what Ravi decides, whatever else it claims to be.
#  Previous: 5d930b2bce38392162094470b6d0c0b9cc7b343fddf317d9431348249872136a
RAVI_DECISION_CORE = "f678d20f040c34748484eead272e829aebde5a33268cd1f1bbc246892bdbb7ff"
RAVI_CERTIFICATE_CORE = "c6d5536ce263499222b19c3051ab4a09bbaccbf9df557f07e095e3c233b7c031"
RAVI_ATTESTED_CERTIFICATE_CORE = "a6a75a08538176fe6ab6139788ff2c2da0cc4fb6ef05949fd3cc0a21d4fdd025"

#  The decision-semantic subartifacts of the workforce bundle, frozen
#  individually.  The manifest digest above already commits to all of them,
#  and naming them separately is what makes a *bundle* change legible: a
#  transition that moves the manifest and leaves these six alone changed
#  something other than the rules.
WORKFORCE_DECISION_ARTIFACTS = {
    "decision_program_digest": "6858423713ffc0d4d8bc68f159d343b533f81031815c2f0e4dbafd4823e504fe",
    "entailment_rules_digest": "fc03cd47ef63eaa82d4339a24d2a4ab604f5a1d45a93cabe743d66190286c0d1",
    "admissibility_descriptors_digest": (
        "a47331836f626ef1314bee0d5233b1f5ce7daea885c04564abde1ea29974d27a"
    ),
    #  The one that moved at milestone E, and the only one.  It gained
    #  ``resource_scope_kinds`` per predicate -- the Q-12(d) input -- and
    #  nothing else in the bundle changed by an octet.
    #  Previous: 6aba0967f35ed1264a56be7c7d4e018180e088db4e3172f2055a6192300376f9
    "predicate_schema_digest": "defae5552e3a1f8642b44f2c60a335bc8a4664c505987a13cd8358aaeb05f7ae",
    "action_schema_digest": "5908a6ea94f2d6a9acf7cc49c89f9beabe5db9e15dfa21d421e1845094240c45",
    "ratification_records_digest": (
        "1e70cec229c4cb142a555f7373800186d485e010c214fd0559bda29c8cb8079c"
    ),
}


def test_the_bundle_has_its_frozen_digest() -> None:
    """The manifest pins every subartifact, so this moves if any of them does."""
    assert ravi.bundle().digest().hex == WORKFORCE_MANIFEST_DIGEST


def test_the_revision_has_its_frozen_digest() -> None:
    """The identity every downstream artifact cites.

    A reversed sort key inside a premise-digest list, or a collection ordered by
    discovery rather than canonically, changes this and nothing else would
    notice.
    """
    assert ravi.revision().digest().hex == RAVI_REVISION_DIGEST


def test_the_logical_case_and_certificate_have_their_frozen_digests() -> None:
    analysis = ravi.analysis()
    assert analysis.projected.logical.digest().hex == RAVI_LOGICAL_CASE_DIGEST
    assert analysis.certificate.digest().hex == RAVI_CERTIFICATE_DIGEST


#  ---- the bundle-pin-blind anchor ------------------------------------------


def blind(octets: bytes, pins: tuple[bytes, ...]) -> str:
    """This artifact's encoding with every bundle-derived identity masked out.

    Each pin gets a *distinct* placeholder rather than a common one, so that two
    pins exchanging places is a change this still sees.

    Every pin must actually occur.  Without that check a refactor that changed
    how an identity is embedded -- a digest carried in a differently framed
    record, say -- would make the substitution a silent no-op, the anchor would
    move, and the move would read as drift when it is a pin transition after
    all.  That is the failure that teaches people to update constants.
    """
    for index, pin in enumerate(pins):
        assert pin in octets, f"pin {index} does not occur, so blinding it is a no-op"
        octets = octets.replace(pin, bytes([index + 1]) * 32)
    return hashlib.sha256(octets).hexdigest()


def decision_core(
    revision: CaseRevision, analysis: CaseAnalysis, bundle: LoadedBundle
) -> tuple[str, str]:
    """The blinded record and certificate, and the identities that get masked.

    Six identities, and they are not all pins in the same sense.  The manifest
    and the revision digest are pure identity.  The logical-case digest, the
    query digests and the sufficiency handle are digests *of case-derived
    content* -- masking them is what makes the anchor survive a bundle change,
    and it is also what makes the anchor blind to a change in the projection or
    the query encoder.  That gap is closed by the frozen anchors above, which
    pin both under today's code.
    """
    support = analysis.certificate.planning.support
    pins = (
        bundle.digest().octets,
        revision.digest().octets,
        analysis.projected.logical.digest().octets,
        *(digest.octets for digest in analysis.certificate.kernel.query_digests),
        *(
            (support.sufficiency_handle.octets,)
            if isinstance(support, ProvenIrredundantSupport)
            else ()
        ),
    )
    return (
        blind(encode(revision.to_node()), pins[:1]),
        blind(encode(analysis.certificate.to_node()), pins),
    )


def test_the_ravi_decision_core_has_its_frozen_blind_anchor() -> None:
    """What a bundle change must not move, and drift cannot avoid moving."""
    assert decision_core(ravi.revision(), ravi.analysis(), ravi.bundle()) == (
        RAVI_DECISION_CORE,
        RAVI_CERTIFICATE_CORE,
    )


def test_the_attested_ravi_decision_core_has_its_frozen_blind_anchor() -> None:
    """The same guard for the outcome that authorizes an action."""
    from muster.application.pipeline import analyse_revision
    from muster.application.rebuild import rebuild, transcript_prefix
    from muster.core.results import Ok

    case = ravi.attested_case_file()
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    built = rebuild(
        case.rebuild_inputs(ravi.bundle().digest(), prefix.digest()),
        case.construction,
        case.entries,
        ravi.bundle(),
        case.authorization_context,
        case.authority_snapshot,
        case.revocation_snapshot,
        case.solicitations,
    )
    assert isinstance(built, Ok), built
    produced = analyse_revision(built.value, ravi.bundle(), ravi.backend(), ravi.limits())
    assert isinstance(produced, Ok), produced
    _, certificate_core = decision_core(built.value, produced.value, ravi.bundle())
    assert certificate_core == RAVI_ATTESTED_CERTIFICATE_CORE


def test_the_decision_semantic_artifacts_have_their_frozen_digests() -> None:
    """Six numbers the manifest already commits to, named so a change is legible.

    The manifest digest moves whenever any subartifact does, which makes it a
    perfect anchor and a useless explanation.  These six say *which* -- so a
    transition that moves the manifest and leaves all six standing is one that
    changed something other than the rules, and one that moves any of them is
    a change to the rules whatever the commit message says.
    """
    manifest = ravi.bundle().manifest
    assert {
        name: getattr(manifest, name).hex for name in WORKFORCE_DECISION_ARTIFACTS
    } == WORKFORCE_DECISION_ARTIFACTS


def _run(case: Path, seed: str) -> str:
    environment = dict(os.environ)
    environment["PYTHONHASHSEED"] = seed
    environment["PYTHONPATH"] = str(PACKAGE_ROOT / "src")
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "muster.application.cli",
            "analyse",
            "--case",
            str(case),
            "--config",
            str(ravi.LIMITS_FILE),
        ],
        capture_output=True,
        text=True,
        env=environment,
        check=True,
        cwd=str(PACKAGE_ROOT),
    )
    return completed.stdout


@pytest.mark.parametrize(
    "case",
    ["ravi-saturday.json", "ravi-saturday-attested.json", "ravi-saturday-forged-normative.json"],
)
def test_the_report_is_identical_across_processes_and_hash_seeds(case: str) -> None:
    """An ordering that came from a set would differ between these runs."""
    path = ravi.CASE_FILE.parent / case
    outputs = {seed: _run(path, seed) for seed in HASH_SEEDS}
    first = outputs[HASH_SEEDS[0]]
    assert first.strip()
    for seed, output in outputs.items():
        assert output == first, f"PYTHONHASHSEED={seed} produced a different report"


def test_the_anchored_digests_appear_in_the_report() -> None:
    """The report and the in-process artifacts agree, so neither can drift alone."""
    report = _run(ravi.CASE_FILE, "0")
    assert RAVI_REVISION_DIGEST in report
    assert RAVI_LOGICAL_CASE_DIGEST in report
    assert RAVI_CERTIFICATE_DIGEST in report
    assert WORKFORCE_MANIFEST_DIGEST in report
