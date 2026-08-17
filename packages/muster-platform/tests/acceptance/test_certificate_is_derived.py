"""A certificate that does not reproduce is a fact about the process, not the case.

The defect this file exists for: the status query treated the head's
``certificate_digest`` as durable truth and refused the whole case when a
replay produced a different one.  That is the wrong reading of what a
certificate is.  A certificate binds the *solver fingerprint* -- backend,
version, seed, logic, budget -- and the query digests, whose count depends on
the engine's action cap.  None of those is a rebuild input and none of them is
a stored column: they are properties of the process that ran the analysis.  So
raising an enumeration budget, or the reachable-action cap, changes the
certificate a replay produces, legitimately and by design -- and the previous
behaviour made every already-published case permanently unreadable the first
time an operator did it.

The correction is that ``CaseReport`` reports ``certificate_reproduced`` and
enforces nothing.  What is asserted here is that the durable case survives the
mismatch intact: the status is still readable and still correct, the head has
not moved, the transcript has not changed, the cached revision still verifies,
and the published certificate digest is still exactly what was certified at the
time -- because an auditor's question is "what did this process certify, and
under what", and rewriting either half to make them agree would destroy the
only answer.

**A revision that fails to replay is still fatal, and that asymmetry is the
point.**  A revision is a pure function of the rebuild inputs and the store, so
a mismatch there means one of those is not what it was.  A certificate is a
function of the process as well.  The two are treated differently because they
are different, and the last test here holds that line.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from muster.application.case_file import EngineConfiguration
from muster.core.results import Err, Ok
from muster.core.wire.codec import decode, encode
from muster.core.wire.digests import Digest, DigestKind
from muster.hinge.prepare import EngineLimits
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import Advanced, Casework, advance_case
from muster.platform.casework.commands import CaseReport, StatusFailure, case_status
from muster.platform.orchestration.status import CaseStatus
from muster.solve.backend import SolverBackend
from muster.solve.reference.bounded import BoundedEnumerationBackend
from support import ravi
from support.fixtures import append_all, head_row, open_ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres


def _wider_budget() -> SolverBackend:
    """The same backend under a bigger enumeration budget.

    The budget is inside ``SolverFingerprint``, which is inside the kernel
    analysis record, which is inside the certificate -- so this changes the
    certificate digest and changes nothing else. It is the smallest honest
    version of "an operator raised a bound".
    """
    return BoundedEnumerationBackend(ravi.configuration().enumeration_budget * 2)


def _wider_cap(casework: Casework) -> Casework:
    """The same control plane with a higher reachable-action cap.

    A different axis from the budget: the cap decides how many actions the
    engine reaches and therefore how many query digests the certificate
    carries. Both are engine configuration, neither is a rebuild input.
    """
    limits: EngineLimits = casework.limits
    return replace(
        casework, limits=EngineLimits(limits.max_unresolved, limits.reachable_action_cap * 2)
    )


@pytest.fixture
def case(tenant_id: str, case_id: str) -> RaviCase:
    return ravi.ravi(tenant_id, case_id, attested=True)


@pytest.fixture
def published(database: SqlDatabase, case: RaviCase) -> Advanced:
    """The case, made durable and published under the configured engine."""
    casework = ravi.casework(database)
    open_ravi(casework, case)
    return append_all(casework, case, now=ravi.NOW)


def _digests(published: Advanced) -> tuple[Digest, Digest]:
    """The published revision and certificate digests, narrowed once.

    Both are ``Digest | None`` on a head, because "opened and never analysed"
    is a real state -- it is not this one, and re-asserting that at every use
    would bury what each test is actually about.
    """
    revision, certificate = published.head.revision_digest, published.head.certificate_digest
    assert revision is not None
    assert certificate is not None
    return revision, certificate


def _report(casework: Casework, case: RaviCase) -> CaseReport:
    read = case_status(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(read, Ok), read
    return read.value


#  ---- the configuration really is what changed ------------------------------


def test_the_configured_engine_reproduces_its_own_certificate(
    database: SqlDatabase, case: RaviCase, published: Advanced
) -> None:
    """The control. Without it, ``False`` below would prove nothing.

    A reading under the same configuration reproduces the published digest
    exactly, so the mismatch in every other test in this file is caused by the
    configuration and not by replay being unreliable.
    """
    report = _report(ravi.casework(database), case)
    assert report.certificate_reproduced is True
    assert report.head.certificate_digest == published.head.certificate_digest


def test_a_wider_budget_changes_the_certificate_and_nothing_about_the_case(
    database: SqlDatabase, case: RaviCase, published: Advanced
) -> None:
    """The whole correction, in one case.

    Every assertion here failed on the previous implementation, which refused
    the read outright: the case would have been unreadable from the moment an
    operator raised a bound, with no way back except lowering it again.
    """
    reopened = ravi.casework(SqlDatabase(database.dsn), solver=_wider_budget)
    report = _report(reopened, case)

    #  1. The durable status is readable, and it is the right one.
    assert report.status is CaseStatus.PROPOSED
    assert report.analysis is not None

    #  2. The mismatch is reported, not enforced.
    assert report.certificate_reproduced is False
    assert report.analysis.certificate.digest() != published.head.certificate_digest

    #  3. The head still names what was certified at the time. The published
    #     digest is the audit record; overwriting it to match a later process's
    #     opinion would destroy the only thing it was for.
    assert report.head.certificate_digest == published.head.certificate_digest
    assert report.head.revision_digest == published.head.revision_digest
    assert report.head.revision_number == published.head.revision_number

    #  4. The revision is unchanged, because a revision is not a function of the
    #     engine. This is what makes the certificate the only thing that moved.
    assert report.analysis.revision.digest() == published.head.revision_digest


def test_the_flag_tracks_the_certificate_rather_than_the_configuration(
    database: SqlDatabase, case: RaviCase, published: Advanced
) -> None:
    """A changed bound that does not change the certificate reproduces it.

    The reachable-action cap is engine configuration in exactly the sense the
    budget is, and doubling it here changes nothing: this case reaches two
    queries, far under either cap, so the certificate is bit-identical and the
    flag says so. That is the difference between reporting "the certificate did
    not come back" and reporting "something in the configuration differs" --
    the second would be true of a great many reads that are perfectly fine, and
    an operator who could not tell them apart would learn to ignore both.
    """
    report = _report(_wider_cap(ravi.casework(SqlDatabase(database.dsn))), case)

    assert report.status is CaseStatus.PROPOSED
    assert report.certificate_reproduced is True
    assert report.head.revision_digest == published.head.revision_digest
    assert report.analysis is not None
    assert report.analysis.revision.digest() == published.head.revision_digest
    #  Two queries, so the caps on either side of this comparison were never
    #  the binding constraint. Asserted, because the test's meaning depends on
    #  it: if this case ever grew past the cap, the claim above would silently
    #  become the opposite one.
    assert len(report.analysis.kernel.query_digests) == 2
    assert ravi.configuration().limits.reachable_action_cap > 2


def test_no_persistence_integrity_failure_is_reported(
    database: SqlDatabase, case: RaviCase, published: Advanced
) -> None:
    """A derived artifact that did not reproduce is not corruption, and is not called it.

    ``REVISION_DIVERGED`` is reserved for a replay that produced a different
    *revision*, which really does mean an input or the store is not what it was.
    Reporting a certificate mismatch under that name would put an operator's
    configuration change and a corrupted store in the same bucket.
    """
    reopened = ravi.casework(SqlDatabase(database.dsn), solver=_wider_budget)
    read = case_status(reopened, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(read, Ok), read
    assert read.value.certificate_reproduced is False
    assert read.value.head.certificate_digest == published.head.certificate_digest
    assert StatusFailure.REVISION_DIVERGED.value not in repr(read)


def test_reading_under_a_changed_engine_mutates_nothing(
    database: SqlDatabase, case: RaviCase, published: Advanced, migrated_dsn: str
) -> None:
    """The read is a read. No head, transcript or revision is moved to make it agree.

    Compared row by row: the head's four durable columns, the whole membership
    set, and the cached revision octets. A "self-healing" implementation that
    republished under the new engine would pass every other test in this file
    and quietly rewrite history.
    """
    revision_digest, certificate_digest = _digests(published)
    before_head = head_row(migrated_dsn, case.tenant_id, case.case_id)
    with database.reading(case.tenant_id) as scope:
        before_members = scope.transcript.members(case.case_id)
        before_revision = scope.content.get(DigestKind.CASE_REVISION, revision_digest)
        before_certificate = scope.content.get(DigestKind.ANALYSIS_CERTIFICATE, certificate_digest)
    assert isinstance(before_members, Ok)
    assert isinstance(before_revision, Ok), before_revision
    assert isinstance(before_certificate, Ok), before_certificate

    reopened = ravi.casework(SqlDatabase(migrated_dsn), solver=_wider_budget)
    for _read in range(3):
        assert _report(reopened, case).certificate_reproduced is False

    assert head_row(migrated_dsn, case.tenant_id, case.case_id) == before_head
    with database.reading(case.tenant_id) as scope:
        after_members = scope.transcript.members(case.case_id)
        after_revision = scope.content.get(DigestKind.CASE_REVISION, revision_digest)
        after_certificate = scope.content.get(DigestKind.ANALYSIS_CERTIFICATE, certificate_digest)
    assert isinstance(after_members, Ok)
    assert after_members.value == before_members.value
    assert isinstance(after_revision, Ok)
    assert after_revision.value == before_revision.value
    assert isinstance(after_certificate, Ok)
    assert after_certificate.value == before_certificate.value


def test_the_stored_certificate_is_still_the_one_that_was_certified(
    database: SqlDatabase, case: RaviCase, published: Advanced
) -> None:
    """Cache and audit material, and still decodable as what it was.

    The point of keeping it is that an auditor can ask "what did this process
    certify, and under which solver" and get an answer that is not the current
    process's opinion. So the octets are decoded and their fingerprint read,
    rather than merely counted.
    """
    from muster.core.analysis.certificate import AnalysisCertificate
    from muster.core.wire.shape import read_rec

    _revision_digest, certificate_digest = _digests(published)
    with database.reading(case.tenant_id) as scope:
        stored = scope.content.get(DigestKind.ANALYSIS_CERTIFICATE, certificate_digest)
    assert isinstance(stored, Ok), stored

    node = decode(stored.value)
    assert isinstance(node, Ok), node
    #  Structural, not a full reader: the certificate has no decoder in this
    #  milestone, and asserting the tag and the round trip is what is available
    #  and what the claim needs.
    read_rec(node.value, "AnalysisCertificate/v1", 8)

    lived: AnalysisCertificate = published.analysis.certificate
    assert encode(lived.to_node()) == stored.value
    assert lived.kernel.fingerprint.budget == ravi.configuration().enumeration_budget


def test_a_revision_that_does_not_replay_is_still_fatal(
    database: SqlDatabase, case: RaviCase, published: Advanced, migrated_dsn: str
) -> None:
    """The asymmetry, held.

    A certificate mismatch is a fact about the process. A revision mismatch is
    a fact about the store or the inputs, and there is no configuration change
    that can cause one -- so it stays fatal. Produced here by forging the
    cached revision, which is the one thing that can make the two disagree
    without touching an input.
    """
    from support.fixtures import forge_content

    revision_digest, _certificate_digest = _digests(published)
    forged = encode(published.analysis.revision.to_node()) + b"\x00"
    forge_content(migrated_dsn, case.tenant_id, revision_digest, "CASE_REVISION", forged)

    refused = case_status(
        ravi.casework(database), tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is StatusFailure.REVISION_DIVERGED


@pytest.mark.usefixtures("published")
def test_the_report_carries_the_reproduction_flag_and_not_a_stored_certificate(
    database: SqlDatabase, case: RaviCase
) -> None:
    """The field that replaced the enforcement, named and typed.

    A ``CaseReport`` that still exposed a ``certificate_digest`` of its own
    would be a second copy of something the head already holds, and the first
    thing to do with two copies is compare them -- which is how the previous
    defect started.
    """
    from dataclasses import fields

    report = _report(ravi.casework(database), case)
    names = {field.name for field in fields(report)}
    assert "certificate_reproduced" in names
    assert "certificate_digest" not in names
    assert isinstance(report.certificate_reproduced, bool)


def test_an_unanalysed_case_reports_reproduction_rather_than_a_mismatch(
    database: SqlDatabase, case: RaviCase
) -> None:
    """A case with no certificate has nothing that failed to reproduce.

    ``True`` rather than ``False`` for intake, because ``False`` would read as
    "the certificate did not come back" about a case that never had one -- and
    an operator scanning for mismatches would find every new case in the list.
    """
    casework = ravi.casework(database)
    open_ravi(casework, case)
    report = _report(casework, case)
    assert report.status is CaseStatus.INTAKE
    assert report.analysis is None
    assert report.certificate_reproduced is True


def test_a_case_published_under_a_wider_budget_advances_normally_afterwards(
    database: SqlDatabase, case: RaviCase, published: Advanced
) -> None:
    """The mismatch does not stop the case from moving on.

    Re-driving under the wider engine reaches the same revision, so the head is
    already there and the advance is ``Idle`` -- a success. The certificate the
    head names stays the one that was published with it, because nothing
    republished.
    """
    reopened = ravi.casework(SqlDatabase(database.dsn), solver=_wider_budget)
    advanced = advance_case(reopened, tenant_id=case.tenant_id, case_id=case.case_id, now=ravi.NOW)
    assert isinstance(advanced, Ok), advanced
    assert advanced.value.published is False
    assert advanced.value.head.revision_digest == published.head.revision_digest
    assert advanced.value.head.certificate_digest == published.head.certificate_digest


def test_the_engine_configuration_is_not_a_rebuild_input(published: Advanced) -> None:
    """Stated as a property of the types, which is why the revision cannot move.

    ``RebuildInputs`` has eight fields and none of them is an engine bound. If
    one ever were, a configuration change would change the revision digest and
    the whole distinction this file is about would collapse.
    """
    from dataclasses import fields

    configured: EngineConfiguration = ravi.configuration()
    inputs = {field.name for field in fields(published.head.inputs)}
    assert inputs == {
        "tenant_id",
        "case_id",
        "construction_digest",
        "transcript_prefix_digest",
        "bundle_manifest_digest",
        "as_of",
        "mode",
        "authorization_context_digest",
    }
    for bound in ("enumeration_budget", "max_unresolved", "reachable_action_cap"):
        assert bound not in inputs
    assert configured.enumeration_budget > 0
