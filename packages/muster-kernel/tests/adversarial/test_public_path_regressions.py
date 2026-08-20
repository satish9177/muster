"""Permanent regressions for the two defects this milestone actually had.

Both are driven through the **real public path** -- a case file, the CLI's own
entry point, the rendered report -- rather than through a helper, because both
defects were reachable from that path and a helper-level test would not have
caught either.

**A. An attested value for a NORMATIVE/DERIVED predicate never becomes an
established fact.**  ``prepare`` originally accepted one: the forged fact landed
in the *attested* partition, was fed back in as an input to re-derivation, and
therefore reproduced.  The case would have read ``Invariant(PAY 5,100)`` on a
source's say-so.

**B. The report preserves the acquisition class.**  It originally derived the
"where would this come from" column from the *plan*, so on an invariant case --
where nothing is requested -- it described an attestable observation as
un-attestable.  The report is an auditable artifact; a false statement in it is
a defect even when the decision is right.
"""

from __future__ import annotations

from functools import cache

from muster.application.case_file import load_case_file
from muster.application.cli import EXIT_OK, main, render
from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.analysis.outcomes import Divergent
from muster.core.case.facts import EntailedBy
from muster.core.results import Ok
from muster.domains.workforce.bundle import (
    PREDICATE_PAYABLE,
    on_site_duration,
    present_on_site,
    shift_payable,
)
from tests.acceptance.test_ravi_attested import attested_analysis
from tests.conftest import FIXTURES
from tests.support import ravi

FORGED_CASE = FIXTURES / "ravi-saturday-forged-normative.json"


@cache
def forged_analysis() -> CaseAnalysis:
    """The Ravi case plus a signed attestation asserting the policy conclusion."""
    loaded = load_case_file(FORGED_CASE)
    assert isinstance(loaded, Ok), loaded
    case = loaded.value
    bundle = ravi.bundle()
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
    return produced.value


#  ---- A. attested normative fact ----------------------------------------


def test_an_attested_normative_value_never_becomes_a_fact() -> None:
    established = {fact.ref for fact in forged_analysis().revision.established}
    assert shift_payable(ravi.RAVI, ravi.SATURDAY) not in established


def test_the_refused_attestation_is_recorded_rather_than_dropped() -> None:
    """Evidence that fails validation must have no effect *and* leave a trace.

    **The reason moved at milestone E, and the barrier did not.**  Section
    12.4.3 fixes the order as Q-9, Q-10, Q-12(a)…(f), Q-4…Q-8, Q-11, first
    failure reported -- so authority is now asked before the layer barrier, and
    a forged normative attestation is refused on Q-12(a) rather than Q-8.  It
    is refused on Q-12(a) because a normative conclusion is DERIVED, so the
    pinned schema permits *no* source class for it and the set the claimed
    class is tested against is empty.

    Nothing about the barrier weakened, and the test above this one is what
    says so: the value never becomes a fact.  What changed is which of two
    refusals is the *first* one, and the ordering is the specification -- two
    conforming implementations have to report the same rejection, not merely a
    rejection.  ``test_normative_barrier`` covers the other half directly: an
    attestation that clears authority completely is still refused on Q-8.
    """
    non_effects = forged_analysis().revision.non_effects
    refusals = [
        effect
        for effect in non_effects
        if effect.subject == str(shift_payable(ravi.RAVI, ravi.SATURDAY))
    ]
    assert len(refusals) == 1
    assert refusals[0].reason == "SourceClassNotPermittedForPredicate"


def test_the_forged_attestation_changes_no_outcome() -> None:
    """A source's word about a policy conclusion moves nothing at all."""
    forged = forged_analysis()
    honest = ravi.analysis()
    assert isinstance(forged.kernel.outcome, Divergent)
    assert set(forged.projected.unresolved()) == set(honest.projected.unresolved())
    assert {target.proposition for target in forged.acquirable} == {
        target.proposition for target in honest.acquirable
    }


def test_no_normative_fact_carries_anything_but_an_entailment() -> None:
    """Checked over every case this milestone can analyse, not just the forged one."""
    for analysis in (ravi.analysis(), attested_analysis(), forged_analysis()):
        for fact in analysis.revision.established:
            if fact.ref.predicate_id == PREDICATE_PAYABLE:
                assert isinstance(fact.justification, EntailedBy)


def test_the_cli_accepts_the_forged_case_and_still_decides_nothing_new() -> None:
    """The attack is refused inside a run that otherwise completes normally."""
    assert main(["analyse", "--case", str(FORGED_CASE), "--config", str(ravi.LIMITS_FILE)]) == (
        EXIT_OK
    )


#  ---- B. the report preserves the acquisition class ----------------------


def test_the_report_marks_a_derived_predicate_as_unattestable() -> None:
    report = "\n".join(render(ravi.analysis(), ravi.bundle()))
    line = _unresolved_line(report, str(shift_payable(ravi.RAVI, ravi.SATURDAY)))
    assert "DERIVED" in line
    assert "not attestable by anyone" in line


def test_the_report_never_calls_an_attestable_observation_unattestable() -> None:
    """The exact defect: on an invariant case nothing is requested, and the
    duration is still perfectly attestable."""
    report = "\n".join(render(attested_analysis(), ravi.bundle()))
    line = _unresolved_line(report, str(on_site_duration(ravi.RAVI, ravi.SATURDAY)))
    assert "SITE_ACCESS_CONTROL" in line
    assert "not attestable" not in line
    assert "DERIVED" not in line


def test_the_report_distinguishes_requested_from_merely_acquirable() -> None:
    divergent = "\n".join(render(ravi.analysis(), ravi.bundle()))
    invariant = "\n".join(render(attested_analysis(), ravi.bundle()))

    assert "(requested)" in _unresolved_line(
        divergent, str(present_on_site(ravi.RAVI, ravi.SATURDAY))
    )
    assert "(acquirable, not requested)" in _unresolved_line(
        invariant, str(on_site_duration(ravi.RAVI, ravi.SATURDAY))
    )


def test_the_report_does_not_claim_necessity_was_computed_when_it_was_not() -> None:
    report = "\n".join(render(attested_analysis(), ravi.bundle()))
    assert "not computed" in report
    assert "none -- and evidence is still required" not in report


def test_every_unresolved_variable_appears_in_the_report_exactly_once() -> None:
    for analysis in (ravi.analysis(), attested_analysis(), forged_analysis()):
        report = "\n".join(render(analysis, ravi.bundle()))
        for ref in analysis.projected.unresolved():
            assert len(_unresolved_lines(report, str(ref))) == 1


def _unresolved_lines(report: str, needle: str) -> list[str]:
    body = report.split("unresolved (")[1].split("\n\n", maxsplit=1)[0]
    return [line for line in body.splitlines() if line.strip().startswith(needle)]


def _unresolved_line(report: str, needle: str) -> str:
    lines = _unresolved_lines(report, needle)
    assert len(lines) == 1, f"{needle} appears {len(lines)} times"
    return lines[0]
