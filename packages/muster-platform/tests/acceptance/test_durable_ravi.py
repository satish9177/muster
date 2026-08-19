"""The durable Ravi case: the database must not move a single answer.

This is the milestone's whole claim, reduced to four hexadecimal constants.
They are copied from the kernel's own determinism anchor -- transcribed here by
hand rather than imported, so that a change to either file has to be made twice
and cannot be made by accident -- and the assertion is that a case which has
been opened, appended to, committed, closed, reopened in a fresh process-level
object, rebuilt from nothing but stored canonical octets and re-analysed by the
production kernel produces *exactly* those digests.

The replay phases deliberately do not touch the fixture.  ``case_status``
resolves the head's own transcript prefix out of the store, fetches the entries
that prefix names, decodes them, rebuilds and re-analyses.  If a single octet
had been altered on the way in or out, the revision digest would move and this
would say so.
"""

from __future__ import annotations

import pytest

from muster.core.analysis.outcomes import Divergent, outcome_class
from muster.core.analysis.planning import EvidenceRequested
from muster.core.results import Err, Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import advance_case
from muster.platform.casework.commands import case_status
from muster.platform.orchestration.decisions import Dispatch
from muster.platform.orchestration.status import CaseStatus
from support import ravi
from support.fixtures import append_all, count_content, open_ravi, prune_derived, reset_tenant

pytestmark = pytest.mark.postgres

#  Frozen in packages/muster-kernel/tests/acceptance/test_determinism.py.
#  Transcribed, not imported: two copies that must agree is the point.
#
#  Moved once, deliberately, by milestone D: the workforce bundle's disclosure
#  policy gained the ratified employer, site and auditor entries.  A disclosure
#  entry is bundle data, the manifest commits to the policy's digest, a revision
#  pins the manifest, and an entailed constraint cites the manifest it was
#  derived under -- so the manifest, the revision, the logical case and the
#  certificate all move together.  **No decision moved**: Ravi is still
#  divergent, the plan still names both Saturday observations, and the attested
#  revision still closes as invariant.
RAVI_REVISION_DIGEST = "2361f3237bb622302f1057b720cd19e312c0466b1819143bc420965849eaffa0"
RAVI_LOGICAL_CASE_DIGEST = "9036cf41b6aec3ea5a38836df6a72063b980dbb9357d5e5b6efe06b3f1b733eb"
RAVI_CERTIFICATE_DIGEST = "473a0772f20524f6d7daf685e4b345086366b5983f5d183fbf5daa516b92191d"
WORKFORCE_MANIFEST_DIGEST = "4ec52a0bdb95707347f9788343eb3d50dd4daef7903024eb059acc482ef26692"


@pytest.fixture(autouse=True)
def _fresh_fixture_tenant(migrated_dsn: str) -> None:
    """Start from nothing, under the fixture's own identity.

    The rest of the suite isolates tests by inventing a tenant per test. These
    cannot: a revision's digest covers its tenant, so only the fixture's own
    tenant reproduces the frozen numbers. So they share one identity and each
    one clears it first.
    """
    reset_tenant(migrated_dsn, ravi.FIXTURE_TENANT)


def test_the_ravi_case_survives_a_round_trip_through_postgresql(
    migrated_dsn: str,
) -> None:
    """Eleven steps, one answer, and no model, HTTP, cloud, agent or gate."""
    case = ravi.unbound()

    #  1-2. Create the durable case and append the whole known transcript.
    first = ravi.casework(SqlDatabase(migrated_dsn))
    head = open_ravi(first, case)
    assert head.revision_digest is None  # nothing analysed yet

    advanced = append_all(first, case, now=ravi.NOW)
    assert advanced.published
    assert advanced.head.revision_digest is not None
    assert advanced.head.revision_digest.hex == RAVI_REVISION_DIGEST
    assert advanced.head.certificate_digest is not None
    assert advanced.head.certificate_digest.hex == RAVI_CERTIFICATE_DIGEST
    assert advanced.head.inputs.bundle_manifest_digest.hex == WORKFORCE_MANIFEST_DIGEST

    #  The milestone-B semantic result, unchanged: divergent, and a plan naming
    #  both Saturday observations.
    assert outcome_class(advanced.analysis.kernel.outcome) == "DIVERGENT"
    assert isinstance(advanced.analysis.kernel.outcome, Divergent)
    assert advanced.analysis.kernel.logical_case_digest.hex == RAVI_LOGICAL_CASE_DIGEST
    assert isinstance(advanced.decision, Dispatch)
    requested = {str(target.proposition) for target in advanced.decision.request.targets}
    assert requested == {"present_on_site(RAVI, SAT)", "on_site_duration(RAVI, SAT)"}

    #  3-4. Close everything and reopen. ``SqlDatabase`` holds no connection
    #  between transactions, so a new one shares nothing with the old.
    del first, advanced, head

    #  5-7. Rebuild from stored canonical artifacts alone and re-analyse.
    second = ravi.casework(SqlDatabase(migrated_dsn))
    replayed = case_status(second, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(replayed, Ok), replayed
    report = replayed.value
    assert report.analysis is not None
    assert report.analysis.revision.digest().hex == RAVI_REVISION_DIGEST
    assert report.analysis.certificate.digest().hex == RAVI_CERTIFICATE_DIGEST
    assert report.analysis.kernel.logical_case_digest.hex == RAVI_LOGICAL_CASE_DIGEST
    assert report.status is CaseStatus.AWAITING_EVIDENCE
    assert isinstance(report.analysis.certificate.planning.planning_outcome, EvidenceRequested)

    #  8-9. The derived artifacts are cached under their own digests, and the
    #  head names them. Advancing again finds nothing to do.
    settled = advance_case(second, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(settled, Ok), settled
    assert settled.value.published is False
    assert settled.value.head.revision_digest is not None
    assert settled.value.head.revision_digest.hex == RAVI_REVISION_DIGEST

    #  10-11. Reopen once more and reproduce the same semantic result.
    third = ravi.casework(SqlDatabase(migrated_dsn))
    again = case_status(third, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(again, Ok), again
    assert again.value.analysis is not None
    assert again.value.analysis.certificate.digest().hex == RAVI_CERTIFICATE_DIGEST
    assert again.value.status is report.status
    assert again.value.head == report.head


def test_deleting_the_derived_cache_costs_a_recomputation_and_no_truth(
    migrated_dsn: str,
) -> None:
    """Revisions and certificates are a cache. Pruning one must lose nothing.

    The foreign keys decide what is prunable: the inputs are referenced by the
    head and by membership and refuse to go, the derived artifacts are
    referenced by nothing and do. That is the authored/derived line, enforced
    by the schema rather than by a naming convention.
    """
    case = ravi.unbound()
    casework = ravi.casework(SqlDatabase(migrated_dsn))
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)

    assert count_content(migrated_dsn, case.tenant_id, "CASE_REVISION") >= 1
    assert count_content(migrated_dsn, case.tenant_id, "ANALYSIS_CERTIFICATE") >= 1

    pruned = prune_derived(migrated_dsn, case.tenant_id)
    assert pruned >= 2
    assert count_content(migrated_dsn, case.tenant_id, "CASE_REVISION") == 0
    assert count_content(migrated_dsn, case.tenant_id, "ANALYSIS_CERTIFICATE") == 0

    #  The head still names them, and the answer is still reachable, because it
    #  never depended on the cache.
    reopened = ravi.casework(SqlDatabase(migrated_dsn))
    report = case_status(reopened, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(report, Ok), report
    assert report.value.analysis is not None
    assert report.value.analysis.certificate.digest().hex == RAVI_CERTIFICATE_DIGEST
    assert report.value.status is CaseStatus.AWAITING_EVIDENCE


def test_the_authored_inputs_cannot_be_pruned(migrated_dsn: str) -> None:
    """The other half of the same line: losing an input loses the case.

    A delete that would leave a head unable to rebuild is refused by the
    database, not by a convention somebody has to follow.
    """
    import psycopg

    case = ravi.unbound()
    casework = ravi.casework(SqlDatabase(migrated_dsn))
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)

    for kind in ("CASE_CONSTRUCTION", "TRANSCRIPT_ENTRY", "TRANSCRIPT_PREFIX"):
        with psycopg.connect(migrated_dsn) as connection:  # noqa: SIM117
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                connection.execute(
                    "DELETE FROM store.content WHERE tenant_id = %s AND kind = %s",
                    (case.tenant_id, kind),
                )


def test_a_case_that_was_never_analysed_reports_intake_after_a_reopen(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    casework = ravi.casework(SqlDatabase(migrated_dsn))
    open_ravi(casework, ravi.ravi(tenant_id, case_id))

    reopened = ravi.casework(SqlDatabase(migrated_dsn))
    report = case_status(reopened, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(report, Ok), report
    assert report.value.status is CaseStatus.INTAKE
    assert report.value.analysis is None
    assert report.value.outstanding == ()


def test_an_expired_request_escalates_the_reopened_case(migrated_dsn: str) -> None:
    """The deadline is durable wall-clock intent, and it outlives the process.

    Nothing swept, nothing was written: the same durable state read at a later
    clock reading reports a different status, because the status is a function
    of the clock and was never a column.
    """
    case = ravi.unbound()
    casework = ravi.casework(SqlDatabase(migrated_dsn))
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)

    reopened = ravi.casework(SqlDatabase(migrated_dsn))
    before = case_status(reopened, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    after = case_status(
        reopened,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        now=ravi.ONE_HOUR.after(ravi.NOW),
    )
    assert isinstance(before, Ok) and isinstance(after, Ok)
    assert before.value.status is CaseStatus.AWAITING_EVIDENCE
    assert after.value.status is CaseStatus.ESCALATED
    #  Same head, same certificate: only the clock reading differed.
    assert before.value.head == after.value.head


def test_a_status_query_on_an_unopened_case_is_a_typed_absence(
    migrated_dsn: str, tenant_id: str
) -> None:
    casework = ravi.casework(SqlDatabase(migrated_dsn))
    missing = case_status(casework, tenant_id=tenant_id, case_id="nothing", now=ravi.NOW)
    assert isinstance(missing, Err)
    assert missing.error.failure.value == "UNKNOWN_CASE"
