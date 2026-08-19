"""The durable Ravi disclosure: one record, four views, and no decision moved.

The eleven steps this milestone claims, run against a real database:

    1-2  open Ravi and append the whole transcript through the real commands
    3    take the published deterministic revision and its certificate
    4    build the internal record and commit it
    5    sign the envelope through the signing port
    6    generate every ratified audience view
    7    verify each one independently, as its recipient would
    8    assert each audience sees exactly what its entry permits
    9    assert no view carries the case salt
    10   close everything and reopen
    11   reproduce and verify again

The frozen milestone-B digests are asserted first and unchanged, because the
claim that matters most here is a negative one: **commitment and disclosure
consume the deterministic record and do not participate in deciding it.**  If
this milestone had moved the Ravi answer, these four constants would say so
before any of the disclosure assertions ran.
"""

from __future__ import annotations

import pytest

from muster.core.analysis.outcomes import Divergent, outcome_class
from muster.core.evidence.transcript import entry_digest
from muster.core.results import Err, Ok
from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import append_transcript_entry
from muster.platform.commit.publish import (
    CommitmentFailureReason,
    commit_case,
    read_commitment,
)
from muster.platform.disclose.audience import AudienceClass
from muster.platform.disclose.queries import (
    DisclosureFailure,
    DisclosureService,
    get_my_view,
)
from muster.platform.disclose.verify import ReaderContext, accepted, verify_view
from muster.platform.disclose.views import AuditorView, ParticipantView, View
from muster.platform.orchestration.decisions import Dispatch
from support import ravi
from support.commitment import (
    AUDIT,
    AUDITOR_PRINCIPAL,
    EMPLOYER,
    MUSTER_KEY,
    NOTIFICATION,
    SITE,
    WORKER,
    Pins,
    commitment,
    directory_for,
    reader,
)
from support.fixtures import append_all, open_ravi, reset_tenant

pytestmark = pytest.mark.postgres

#  Frozen in packages/muster-kernel/tests/acceptance/test_determinism.py.
#  Transcribed, not imported: two copies that must agree is the point.
RAVI_REVISION_DIGEST = "2361f3237bb622302f1057b720cd19e312c0466b1819143bc420965849eaffa0"
RAVI_CERTIFICATE_DIGEST = "473a0772f20524f6d7daf685e4b345086366b5983f5d183fbf5daa516b92191d"

#  What each audience is entitled to, transcribed from the pinned bundle so that
#  a policy change has to be made twice and cannot be made by accident.
EXPECTED = {
    "WORKER": {"case.tenant_id", "case.case_id", "kernel.outcome.tag"},
    "EMPLOYER": {
        "case.tenant_id",
        "case.case_id",
        "bundle.manifest_digest",
        "revision.bundle_pin",
        "kernel.outcome.tag",
    },
    "SITE": {
        "case.tenant_id",
        "case.case_id",
        "bundle.manifest_digest",
        "revision.bundle_pin",
    },
    "AUDITOR": {
        "case.tenant_id",
        "case.case_id",
        "certificate.schema_version",
        "bundle.manifest_digest",
        "revision.bundle_pin",
        "revision.as_of",
        "revision.mode",
        "revision.authorizability",
        "kernel.outcome.tag",
        "kernel.outcome.reachable",
        "kernel.determinism_class",
    },
}

AUDIENCES = (
    (WORKER, "WORKER", NOTIFICATION),
    (EMPLOYER, "EMPLOYER", NOTIFICATION),
    (SITE, "SITE", NOTIFICATION),
    (AUDITOR_PRINCIPAL, "AUDITOR", AUDIT),
)


@pytest.fixture(autouse=True)
def _fresh_fixture_tenant(migrated_dsn: str) -> None:
    reset_tenant(migrated_dsn, ravi.FIXTURE_TENANT)


def _service(dsn: str) -> DisclosureService:
    return DisclosureService(
        commitment=commitment(SqlDatabase(dsn)), directory=directory_for(ravi.FIXTURE_TENANT)
    )


def _revision_commitment(dsn: str, case: ravi.RaviCase) -> Digest:
    """What the reader independently holds about which revision is current."""
    read = read_commitment(
        commitment(SqlDatabase(dsn)), tenant_id=case.tenant_id, case_id=case.case_id
    )
    assert isinstance(read, Ok), read
    return read.value.commitment.envelope.revision_commitment


def _reader_for(
    case: ravi.RaviCase, audience: str, context: str, revision_commitment: Digest
) -> ReaderContext:
    from muster.domains.workforce.bundle import workforce_bundle
    from muster.platform.disclose.audience import DisclosureContext
    from support.commitment import workforce_policy

    return reader(
        policy=workforce_policy(),
        pins=Pins(
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            revision_commitment=revision_commitment,
            bundle_manifest_digest=workforce_bundle().digest(),
        ),
        audience=AudienceClass(audience),
        context=DisclosureContext(context),
    )


def _views(service: DisclosureService, case: ravi.RaviCase) -> dict[str, View]:
    produced: dict[str, View] = {}
    for principal, audience, context in AUDIENCES:
        result = get_my_view(
            service,
            tenant_id=case.tenant_id,
            principal=principal,
            case_id=case.case_id,
            context=context,
            acting_as=None,
        )
        assert isinstance(result, Ok), (audience, result)
        produced[audience] = result.value
    return produced


def test_the_ravi_case_discloses_four_views_and_moves_no_decision(
    migrated_dsn: str,
) -> None:
    case = ravi.unbound()

    #  1-2. The durable case, through the real commands.
    first = commitment(SqlDatabase(migrated_dsn))
    open_ravi(first.casework, case)
    advanced = append_all(first.casework, case, now=ravi.NOW)
    assert advanced.published

    #  3. The published deterministic revision, unchanged by anything here.
    assert advanced.head.revision_digest is not None
    assert advanced.head.revision_digest.hex == RAVI_REVISION_DIGEST
    assert advanced.head.certificate_digest is not None
    assert advanced.head.certificate_digest.hex == RAVI_CERTIFICATE_DIGEST
    assert outcome_class(advanced.analysis.kernel.outcome) == "DIVERGENT"
    assert isinstance(advanced.analysis.kernel.outcome, Divergent)
    assert isinstance(advanced.decision, Dispatch)
    requested = {str(target.proposition) for target in advanced.decision.request.targets}
    assert requested == {"present_on_site(RAVI, SAT)", "on_site_duration(RAVI, SAT)"}

    #  4-5. The internal record, its commitment, and the signed envelope.
    committed = commit_case(first, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(committed, Ok), committed
    published = committed.value
    assert published.published
    assert published.revision_digest.hex == RAVI_REVISION_DIGEST
    envelope = published.commitment.envelope
    assert envelope.tenant_id == case.tenant_id
    assert envelope.case_id == case.case_id
    assert envelope.signer_key_ref == MUSTER_KEY
    assert envelope.leaf_count == published.commitment.tree.leaf_count

    #  The commitment is over the whole record, not over what will be shown.
    committed_paths = set(published.commitment.tree.paths)
    for expected in EXPECTED.values():
        assert expected <= committed_paths

    #  6-8. Every ratified view, verified as its recipient would verify it.
    service = _service(migrated_dsn)
    views = _views(service, case)
    for _principal, audience, context in AUDIENCES:
        view = views[audience]
        failures = verify_view(
            view,
            _reader_for(case, audience, context.value, _revision_commitment(migrated_dsn, case)),
        )
        assert accepted(failures), (audience, failures)
        assert {disclosure.path for disclosure in view.disclosures} == EXPECTED[audience]

    #  The shapes the architecture ratified, and only those.
    assert isinstance(views["AUDITOR"], AuditorView)
    for audience in ("WORKER", "EMPLOYER", "SITE"):
        assert isinstance(views[audience], ParticipantView)

    #  The site sees that a case existed and which policy governed it, and not
    #  the outcome. This is the sharpest privacy claim in the walkthrough.
    assert "kernel.outcome.tag" not in EXPECTED["SITE"]
    site_octets = encode(views["SITE"].to_node())
    outcome_octets = published.commitment.tree.record.octets_at("kernel.outcome.tag")
    assert outcome_octets is not None
    assert outcome_octets not in site_octets

    #  9. No view carries the salt, in any direction.
    salt = published.record.salt.octets
    for view in views.values():
        assert salt not in encode(view.to_node())


def test_the_commitment_and_every_view_survive_a_restart(migrated_dsn: str) -> None:
    """10-11. Close, reopen, and reproduce -- from stored octets and a derived salt.

    Nothing about this depends on the previous process: the salt is re-derived
    rather than read, the tree is rebuilt from a replayed record, and the
    envelope is the one that was stored -- checked field by field against the
    envelope the record implies before it is used.
    """
    case = ravi.unbound()
    first = commitment(SqlDatabase(migrated_dsn))
    open_ravi(first.casework, case)
    append_all(first.casework, case, now=ravi.NOW)
    committed = commit_case(first, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(committed, Ok), committed
    before = committed.value
    before_views = {
        audience: encode(view.to_node())
        for audience, view in _views(_service(migrated_dsn), case).items()
    }

    del first, committed

    #  A completely fresh composition over the same database.
    second = commitment(SqlDatabase(migrated_dsn))
    reread = read_commitment(second, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(reread, Ok), reread
    after = reread.value

    #  The envelope is the same artifact, signature included: it was stored
    #  rather than re-signed, which is what makes it checkable twice.
    assert after.commitment.signed_envelope == before.commitment.signed_envelope
    assert after.commitment.tree.root == before.commitment.tree.root
    assert after.commitment.tree.leaves == before.commitment.tree.leaves
    assert after.record.salt == before.record.salt

    #  And every view reproduces octet for octet, because the only part that is
    #  not a function of the record is the stored signature.
    after_views = _views(_service(migrated_dsn), case)
    for audience, octets in before_views.items():
        assert encode(after_views[audience].to_node()) == octets

    for _principal, audience, context in AUDIENCES:
        failures = verify_view(
            after_views[audience],
            _reader_for(case, audience, context.value, _revision_commitment(migrated_dsn, case)),
        )
        assert accepted(failures), (audience, failures)


def test_committing_twice_keeps_the_first_envelope(migrated_dsn: str) -> None:
    """Idempotent by content: the artifact a participant already checked stands."""
    case = ravi.unbound()
    work = commitment(SqlDatabase(migrated_dsn))
    open_ravi(work.casework, case)
    append_all(work.casework, case, now=ravi.NOW)

    first = commit_case(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(first, Ok), first
    assert first.value.published

    second = commit_case(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(second, Ok), second
    assert not second.value.published
    assert second.value.commitment.signed_envelope == first.value.commitment.signed_envelope


def test_a_case_that_has_never_been_analysed_has_nothing_to_commit(
    migrated_dsn: str,
) -> None:
    case = ravi.unbound()
    work = commitment(SqlDatabase(migrated_dsn))
    open_ravi(work.casework, case)

    result = commit_case(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(result, Err)
    assert result.error.failure is CommitmentFailureReason.NOT_ANALYSED


def test_a_stored_envelope_that_is_not_the_one_the_record_implies_is_refused(
    migrated_dsn: str,
) -> None:
    """The row is immutable by contract; this is what happens if it is not in fact.

    Written past the repository on purpose -- no application code can produce
    this state -- because "the stored envelope is checked against the record"
    is only worth asserting if something can produce an envelope that is not.
    """
    import psycopg

    case = ravi.unbound()
    work = commitment(SqlDatabase(migrated_dsn))
    open_ravi(work.casework, case)
    append_all(work.casework, case, now=ravi.NOW)
    committed = commit_case(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(committed, Ok), committed

    #  Re-sign an envelope whose leaf count is a lie, and put it in the row.
    from dataclasses import replace

    from muster.platform.commit.envelope import sign_envelope

    honest = committed.value.commitment.envelope
    lying = sign_envelope(replace(honest, leaf_count=honest.leaf_count + 1), work.signer)
    with psycopg.connect(migrated_dsn) as connection:
        connection.execute(
            "UPDATE casework.case_commitment SET envelope = %s "
            "WHERE tenant_id = %s AND case_id = %s",
            (lying.octets(), case.tenant_id, case.case_id),
        )

    reread = read_commitment(
        commitment(SqlDatabase(migrated_dsn)),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
    )
    assert isinstance(reread, Err)
    assert reread.error.failure is CommitmentFailureReason.COMMITMENT_INCONSISTENT


def test_a_superseded_revision_becomes_unreachable_rather_than_stale(
    migrated_dsn: str,
) -> None:
    """No participant can fetch a view for a revision that is not head.

    The architecture states that property as "the envelope is inserted in the
    same transaction as the head compare-and-swap". This milestone commits in a
    separate, idempotent step *after* publication -- hashing and a signature do
    not belong inside a head swap -- and preserves the property on the reading
    side instead: every read resolves the head first and asks for the
    commitment that head's revision has.

    The two states that leaves are both safe and are both asserted here. A
    revision that has moved on is **unreachable**, not stale; a revision
    published a moment ago and not yet committed is **absent**, which is early
    rather than wrong. What cannot happen is a view of r1 after r2 is head.
    """
    case = ravi.unbound()
    work = commitment(SqlDatabase(migrated_dsn))
    open_ravi(work.casework, case)
    append_all(work.casework, case, now=ravi.NOW)

    first = commit_case(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(first, Ok), first
    r1 = first.value.revision_digest
    assert r1.hex == RAVI_REVISION_DIGEST

    #  The site attests, the head advances, and r1 is no longer head. The two
    #  fixtures share a construction record and the second is the first plus
    #  two entries, so this is genuinely r2 of the same case.
    attested = ravi.ravi(case.tenant_id, case.case_id, attested=True)
    known = {entry_digest(entry) for entry in case.entries}
    for entry in attested.entries:
        if entry_digest(entry) in known:
            continue
        appended = append_transcript_entry(
            work.casework,
            tenant_id=case.tenant_id,
            case_id=case.case_id,
            entry=entry,
            now=ravi.NOW,
        )
        assert isinstance(appended, Ok), appended

    with SqlDatabase(migrated_dsn).reading(case.tenant_id) as scope:
        head = scope.heads.read(case.case_id)
    assert isinstance(head, Ok), head
    r2 = head.value.revision_digest
    assert r2 is not None and r2 != r1

    #  r1's envelope is still in the table -- it is an immutable artifact and a
    #  true statement about r1 -- and nothing can reach it through the head.
    with SqlDatabase(migrated_dsn).reading(case.tenant_id) as scope:
        stored = scope.commitments.read(case.case_id, r1)
    assert isinstance(stored, Ok), stored

    absent = read_commitment(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(absent, Err)
    assert absent.error.failure is CommitmentFailureReason.COMMITMENT_ABSENT

    refused = get_my_view(
        _service(migrated_dsn),
        tenant_id=case.tenant_id,
        principal=WORKER,
        case_id=case.case_id,
        context=NOTIFICATION,
        acting_as=None,
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is DisclosureFailure.COMMITMENT_REFUSED

    #  And committing the new head makes it disclosable again, under a new
    #  envelope that binds a different revision commitment.
    second = commit_case(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(second, Ok), second
    assert second.value.revision_digest == r2
    assert (
        second.value.commitment.envelope.revision_commitment
        != first.value.commitment.envelope.revision_commitment
    )
    assert (
        second.value.commitment.envelope.case_commitment
        == first.value.commitment.envelope.case_commitment
    )

    served = _views(_service(migrated_dsn), case)
    for _principal, audience, context in AUDIENCES:
        failures = verify_view(
            served[audience],
            _reader_for(case, audience, context.value, _revision_commitment(migrated_dsn, case)),
        )
        assert accepted(failures), (audience, failures)


def _tamper(dsn: str, case: ravi.RaviCase, octets: bytes) -> None:
    """Write octets into the commitment row, past every repository.

    No application code can produce this state -- the table is insert-if-absent
    and has no update -- which is exactly why the tests below need to reach
    around it: "the stored envelope is checked against the record" is only
    worth asserting if something can produce an envelope that is not.
    """
    import psycopg

    with psycopg.connect(dsn) as connection:
        connection.execute(
            "UPDATE casework.case_commitment SET envelope = %s "
            "WHERE tenant_id = %s AND case_id = %s",
            (octets, case.tenant_id, case.case_id),
        )


def _committed(dsn: str) -> ravi.RaviCase:
    case = ravi.unbound()
    work = commitment(SqlDatabase(dsn))
    open_ravi(work.casework, case)
    append_all(work.casework, case, now=ravi.NOW)
    published = commit_case(work, tenant_id=case.tenant_id, case_id=case.case_id)
    assert isinstance(published, Ok), published
    return case


def test_a_stored_envelope_re_attributed_to_another_key_is_refused(
    migrated_dsn: str,
) -> None:
    """Found by review: the consistency check used to read the key ref from the row.

    An attacker with write access to the table re-signed the envelope under
    their own key and set ``signer_key_ref`` to match. The re-derivation took
    that reference *from the row*, so the comparison was tautological on
    exactly the field that moved: the row rebuilt to itself and was served as
    authentic, and ``commit_case`` adopted it as the result of a successful
    commit. The whole defence had been deferred to each participant's trusted
    key list.

    The reference is read from the row again now -- welding it to the current
    key made the read path refuse every commitment taken before a key rotation
    -- and what replaced the weld is two checks that do not have that cost. The
    reference must be one this control plane holds or has retired, and the
    signature must verify under it. Both forgeries below fail, and they fail
    with different names: an unheld key, and a signature that does not verify.
    """
    from dataclasses import replace

    from muster.platform.commit.envelope import (
        SignedCommitmentEnvelope,
        sign_envelope,
        signing_preimage,
    )
    from support.commitment import OTHER_KEY, signing_pair

    case = _committed(migrated_dsn)
    honest = read_commitment(
        commitment(SqlDatabase(migrated_dsn)),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
    )
    assert isinstance(honest, Ok), honest
    envelope = honest.value.commitment.envelope

    stranger, _verifier = signing_pair(OTHER_KEY)
    forged = sign_envelope(replace(envelope, signer_key_ref=OTHER_KEY), stranger)
    _tamper(migrated_dsn, case, forged.octets())

    refused = read_commitment(
        commitment(SqlDatabase(migrated_dsn)),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is CommitmentFailureReason.SIGNER_NOT_ACCEPTED

    #  The other shape, and the one the accepted-key check alone would miss:
    #  the envelope keeps MUSTER's key reference and carries a signature the
    #  stranger produced. Nothing about the reference is wrong; the signature
    #  is, and only verifying it says so.
    impersonated = SignedCommitmentEnvelope(envelope, stranger.sign(signing_preimage(envelope)))
    _tamper(migrated_dsn, case, impersonated.octets())

    unverified = read_commitment(
        commitment(SqlDatabase(migrated_dsn)),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
    )
    assert isinstance(unverified, Err)
    assert unverified.error.failure is CommitmentFailureReason.ENVELOPE_NOT_AUTHENTIC

    #  And the disclosure path refuses too, rather than serving the forgery.
    served = get_my_view(
        _service(migrated_dsn),
        tenant_id=case.tenant_id,
        principal=WORKER,
        case_id=case.case_id,
        context=NOTIFICATION,
        acting_as=None,
    )
    assert isinstance(served, Err)
    assert served.error.failure is DisclosureFailure.COMMITMENT_REFUSED


@pytest.mark.parametrize(
    "octets,what",
    [
        (b"\x01", "a unit where a record should be"),
        (b"\xff", "octets the codec cannot read at all"),
    ],
)
def test_a_malformed_stored_envelope_is_refused_rather_than_raising(
    migrated_dsn: str, octets: bytes, what: str
) -> None:
    """Found by review: a typed read raised straight out of the disclosure query.

    A one-byte row corruption turned a typed refusal into an unhandled
    exception on the participant-facing path -- a crash where the contract says
    ``COMMITMENT_ABSENT`` or ``COMMITMENT_INCONSISTENT``, and a difference an
    outsider can observe on a boundary that works hard elsewhere to make case
    existence unobservable.
    """
    case = _committed(migrated_dsn)
    _tamper(migrated_dsn, case, octets)

    refused = read_commitment(
        commitment(SqlDatabase(migrated_dsn)),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
    )
    assert isinstance(refused, Err), what
    assert refused.error.failure is CommitmentFailureReason.COMMITMENT_INCONSISTENT

    served = get_my_view(
        _service(migrated_dsn),
        tenant_id=case.tenant_id,
        principal=WORKER,
        case_id=case.case_id,
        context=NOTIFICATION,
        acting_as=None,
    )
    assert isinstance(served, Err), what
    assert served.error.failure is DisclosureFailure.COMMITMENT_REFUSED
