"""Source authority on the real admission path, against a real database.

Everything here goes through ``append_transcript_entry`` -- the production
command, the production admission, the production Q-12 -- and then looks at
PostgreSQL to see what is *there*.  The claim milestone E has to support is not
"the check returns an error"; it is **an unauthorized receipt never becomes
transcript membership**, and the only way to say that is to look.

Three things are checked after every refusal, and each closes a different door:

* the membership set is unchanged -- the transcript is append-only and nothing
  can take an entry back out, so an entry admitted in error is permanent;
* the content store holds no octets under the entry's digest -- refusing after
  writing would leave a content-addressed orphan that a later admission would
  find already present and skip;
* the head has not moved -- no revision cites the receipt, so no downstream
  artifact does either.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import psycopg
import pytest

from muster.core.evidence.transcript import Attestation, entry_digest
from muster.core.results import Err, Ok
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import AppendFailure, append_transcript_entry
from support import ravi
from support.authority import sign_construction, sign_receipt
from support.fixtures import open_ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

#  The Saturday site observation: the receipt the whole walkthrough turns on,
#  and the one every attack below rewrites.
SATURDAY_PRESENCE = 18


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


@pytest.fixture
def case(tenant_id: str, case_id: str) -> RaviCase:
    return ravi.ravi(tenant_id, case_id, attested=True)


def _opened(database: SqlDatabase, case: RaviCase) -> object:
    work = ravi.casework(database)
    open_ravi(work, case)
    return work


def _members(database: SqlDatabase, case: RaviCase) -> set[object]:
    with database.reading(case.tenant_id) as scope:
        members = scope.transcript.members(case.case_id)
    assert isinstance(members, Ok), members
    return set(members.value)


def _stored(dsn: str, case: RaviCase, digest: object) -> bool:
    with psycopg.connect(dsn) as connection:
        row = connection.execute(
            "SELECT 1 FROM store.content WHERE tenant_id = %s AND digest = %s",
            (case.tenant_id, digest.octets),  # type: ignore[attr-defined]
        ).fetchone()
    return row is not None


def _refused(
    database: SqlDatabase,
    dsn: str,
    case: RaviCase,
    entry: object,
    *,
    failure: AppendFailure,
    detail: str,
) -> None:
    """Offer an entry, require the named refusal, and require nothing to change."""
    work = _opened(database, case)
    before = _members(database, case)
    with database.reading(case.tenant_id) as scope:
        head_before = scope.heads.read(case.case_id)

    outcome = append_transcript_entry(
        work,  # type: ignore[arg-type]
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=entry,  # type: ignore[arg-type]
        now=ravi.NOW,
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is failure, outcome.error
    assert detail in outcome.error.detail, outcome.error.detail

    assert _members(database, case) == before
    assert not _stored(dsn, case, entry_digest(entry))  # type: ignore[arg-type]
    with database.reading(case.tenant_id) as scope:
        assert scope.heads.read(case.case_id) == head_before


def _rebound(case: RaviCase, index: int, **payload_changes: Any) -> Attestation:
    """The Saturday receipt with one payload field changed, re-signed honestly.

    Re-signed because the payload is what a signature covers: an attack that
    kept the old signature would be refused on authenticity, which is a
    different and much weaker claim than the one each test is making.
    """
    entry = case.entries[index]
    assert isinstance(entry, Attestation)
    return Attestation(
        sign_receipt(
            replace(entry.receipt, payload=replace(entry.receipt.payload, **payload_changes))
        )
    )


#  ---- the control -----------------------------------------------------------


def test_an_authorized_receipt_is_admitted(database: SqlDatabase, case: RaviCase) -> None:
    """Without this every refusal below could be refusing for its own reasons."""
    work = _opened(database, case)
    appended = append_transcript_entry(
        work,  # type: ignore[arg-type]
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=case.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(appended, Ok), appended
    assert appended.value.created
    assert entry_digest(case.entries[SATURDAY_PRESENCE]) in _members(database, case)


#  ---- the named regressions -------------------------------------------------


def test_UNAUTHORIZED_RECEIPT_NEVER_BECOMES_TRANSCRIPT_MEMBERSHIP(
    database: SqlDatabase, migrated_dsn: str, case: RaviCase
) -> None:
    """The milestone's headline property, checked against the database.

    A worker key signing the site observation.  The signature is real and
    verifies; the worker holds no grant for ``SITE_ACCESS_CONTROL``; the
    membership set, the content store and the head are all exactly as they
    were.
    """
    forged = _rebound(case, SATURDAY_PRESENCE, signer_key_ref="key-worker-ravi-1")
    _refused(
        database,
        migrated_dsn,
        case,
        forged,
        failure=AppendFailure.ADMISSION_REFUSED,
        detail="UnauthorizedSourceClassForKey",
    )


def test_VALID_SIGNATURE_WITHOUT_AUTHORITY_REJECTED(database: SqlDatabase, case: RaviCase) -> None:
    """Signed, verifiable, and inadmissible.

    Stated separately from the membership regression because it is the
    *sentence* milestone E exists to make true, and it deserves a test whose
    name is that sentence.  The verifier holds this key's public material -- so
    the refusal is not "unknown key", it is "not authorized", and the detail
    says which clause.
    """
    forged = _rebound(case, SATURDAY_PRESENCE, signer_key_ref="key-worker-ravi-1")
    work = _opened(database, case)

    #  Authenticity first, established independently of the admission path.
    from muster.core.evidence.signing import attestation_preimage
    from support.authority import source_verifier

    assert isinstance(forged, Attestation)
    assert source_verifier().verify(
        key_ref="key-worker-ravi-1",
        preimage=attestation_preimage(forged.receipt.payload),
        signature=forged.receipt.signature,
    )

    outcome = append_transcript_entry(
        work,  # type: ignore[arg-type]
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=forged,
        now=ravi.NOW,
    )
    assert isinstance(outcome, Err)
    assert outcome.error.failure is AppendFailure.ADMISSION_REFUSED
    assert "NOT_AUTHORIZED" in outcome.error.detail


def test_SITE_A_KEY_CANNOT_ATTEST_SITE_B_ON_THE_ADMISSION_PATH(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """Right key, right class, right predicate, right tenant -- wrong site.

    The case is re-sited by editing the *construction record*, which is where
    a case's coordinates live and which only an officer signs.  That is the
    honest construction: the attacker cannot move the site, so the test moves
    the case and offers the same receipt.
    """
    from muster.core.authority.scope import ResourceScope

    elsewhere = ravi.ravi(tenant_id, case_id, attested=True)
    elsewhere = replace(
        elsewhere,
        #  The officer sites this case at SITE-B, honestly and signed.  The
        #  attacker cannot move a coordinate, so the test moves the case.
        construction=sign_construction(
            replace(
                elsewhere.construction,
                case_scope_coordinates=(
                    ResourceScope("SITE", "SITE-B"),
                    ResourceScope("EMPLOYER", "EMPLOYER-1"),
                ),
            )
        ),
    )
    _refused(
        database,
        migrated_dsn,
        elsewhere,
        elsewhere.entries[SATURDAY_PRESENCE],
        failure=AppendFailure.ADMISSION_REFUSED,
        detail="ResourceScopeNotAuthorized",
    )


def test_WRONG_SOURCE_CLASS_REJECTED_AT_ADMISSION(
    database: SqlDatabase, migrated_dsn: str, case: RaviCase
) -> None:
    """The site key declaring itself a payroll system.

    ``source_class`` is inside the signed payload, so this is a receipt the
    site agent genuinely produced.  It selects which grant must exist and
    creates none, and the bundle refuses the class for this predicate first.
    """
    mislabelled = _rebound(case, SATURDAY_PRESENCE, source_class="HR_PAYROLL_SYSTEM")
    _refused(
        database,
        migrated_dsn,
        case,
        mislabelled,
        failure=AppendFailure.ADMISSION_REFUSED,
        detail="SourceClassNotPermittedForPredicate",
    )


def test_a_forged_signature_is_refused_before_authority_is_consulted(
    database: SqlDatabase, migrated_dsn: str, case: RaviCase
) -> None:
    """Authenticity is asked first, and its refusal says so.

    A payload naming the site key, signed by the worker's.  Both questions
    would refuse it; the one that answers is the first, because there is no
    point resolving the authority of a key that did not produce these octets.
    """
    entry = case.entries[SATURDAY_PRESENCE]
    assert isinstance(entry, Attestation)
    impostor = Attestation(sign_receipt(entry.receipt, key_ref="key-worker-ravi-1"))
    _refused(
        database,
        migrated_dsn,
        case,
        impostor,
        failure=AppendFailure.ADMISSION_REFUSED,
        detail="SIGNATURE_INVALID",
    )


def test_an_unsigned_receipt_is_refused(
    database: SqlDatabase, migrated_dsn: str, case: RaviCase
) -> None:
    """The milestone-A placeholder, now inadmissible.

    Worth its own test because it is the state every fixture in this repository
    was in until milestone E, and "signatures are carried, not verified" was a
    true statement about the system for four milestones.
    """
    from muster.core.wire.signature import Signature

    entry = case.entries[SATURDAY_PRESENCE]
    assert isinstance(entry, Attestation)
    unsigned = Attestation(
        replace(entry.receipt, signature=Signature("UNSIGNED-LOCAL-DEVELOPMENT", b""))
    )
    _refused(
        database,
        migrated_dsn,
        case,
        unsigned,
        failure=AppendFailure.ADMISSION_REFUSED,
        detail="SIGNATURE_INVALID",
    )


def test_REVOKED_GRANT_REJECTED_AT_ADMISSION(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """A case pinned to a revocation snapshot that names the site key.

    The receipt is untouched and its signature verifies exactly as before.
    What changed is the authority state the *case* pins, which is the only
    thing that could change without the source's cooperation.
    """
    from support import authority as AUTH

    case = ravi.ravi(tenant_id, case_id, attested=True)
    revoked = replace(
        case.revocation_snapshot,
        revoked_key_refs=("key-site-a-1",),
    )
    case = replace(
        case,
        revocation_snapshot=revoked,
        authorization_context=replace(
            case.authorization_context, revocation_snapshot_digest=revoked.digest()
        ),
    )
    assert AUTH.PUBLISHED_AT  # the support module is the one publishing below
    _refused(
        database,
        migrated_dsn,
        case,
        case.entries[SATURDAY_PRESENCE],
        failure=AppendFailure.ADMISSION_REFUSED,
        detail="KeyRevoked",
    )


def test_AUTHORIZATION_POLICY_VERSION_MISMATCH_REJECTED_AT_ADMISSION(
    database: SqlDatabase, migrated_dsn: str, case: RaviCase
) -> None:
    """A receipt claiming a policy version its case did not pin."""
    mismatched = _rebound(case, SATURDAY_PRESENCE, authorization_policy_version=99)
    _refused(
        database,
        migrated_dsn,
        case,
        mismatched,
        failure=AppendFailure.ADMISSION_REFUSED,
        detail="AuthorizationPolicyVersionMismatch",
    )


def test_AUTHORITY_SNAPSHOT_SUBSTITUTION_REJECTED(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """A newer, broader snapshot published after the case was opened.

    Published legitimately, by the real publisher, under the real key -- and
    entirely invisible to a case that pinned its predecessor.  There is no
    accessor anywhere in the control plane for "the current authority
    snapshot", so this is not a check that could be forgotten: it is a call
    that cannot be spelled.
    """
    from muster.core.authority.scope import ResourceScope
    from support import authority as AUTH

    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = _opened(database, case)

    #  A successor granting the worker key everything the site key holds.
    broader = AUTH.publish(
        database,
        tenant_id,
        grants=(
            *AUTH.workforce_grants(tenant_id),
            AUTH.grant(
                key_ref=AUTH.WORKER_KEY,
                principal_id=AUTH.WORKER,
                tenant_id=tenant_id,
                source_class=AUTH.SOURCE_SITE_ACCESS,
                predicates=("on_site_duration", "present_on_site"),
                scope=(ResourceScope("SITE", AUTH.SITE_A),),
            ),
        ),
        published_at=AUTH.PUBLISHED_AT + 1,
    )
    assert broader.snapshot.digest() != case.authority_snapshot.digest()

    #  The worker's receipt is still refused, because the case is decided under
    #  the snapshot it pinned and not under the newest one.
    forged = _rebound(case, SATURDAY_PRESENCE, signer_key_ref=AUTH.WORKER_KEY)
    outcome = append_transcript_entry(
        work,  # type: ignore[arg-type]
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=forged,
        now=ravi.NOW,
    )
    assert isinstance(outcome, Err), outcome
    assert "UnauthorizedSourceClassForKey" in outcome.error.detail


def test_CROSS_CASE_AUTHORITY_SNAPSHOT_REJECTED(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """A case may not even open on a snapshot that was never published.

    This used to be a rebuild-time claim: the case opened, and the *append*
    failed because the pin resolved to nothing.  Milestone E's open-case
    freshness gate moves the refusal one step earlier and makes it stronger --
    a pin nothing published is, in particular, not the pin currently in force,
    so the case never exists at all.  The old ending is kept as a separate
    test below, because "the pin cannot be resolved" remains a state a *live*
    case can reach and the fail-closed answer to it still has to be checked.
    """
    from muster.core.wire.digests import Digest

    case = ravi.ravi(tenant_id, case_id, attested=True)
    borrowed = replace(
        case,
        authorization_context=replace(
            case.authorization_context,
            authority_registry_snapshot_digest=Digest(bytes(range(32))),
        ),
    )
    work = ravi.casework(database)
    #  The case's own authority *is* published, so the tenant has authority in
    #  force and the refusal below is about this pin rather than about the
    #  tenant having no publisher at all.  Those are two different findings and
    #  a test that could not tell them apart would pass for the wrong reason.
    ravi.publish_authority(database, case)

    from muster.platform.casework.commands import OpenFailure, open_case

    opened = open_case(
        work,
        tenant_id=borrowed.tenant_id,
        construction=borrowed.construction,
        authorization_context=borrowed.authorization_context,
        policy_id=borrowed.policy_id,
        as_of=borrowed.as_of,
    )
    assert isinstance(opened, Err), opened
    assert opened.error.failure is OpenFailure.AUTHORITY_NOT_IN_FORCE
    assert "PUBLICATION_SUPERSEDED" in opened.error.detail

    #  And nothing was left behind: a case that may not open leaves no head.
    with database.reading(borrowed.tenant_id) as scope:
        head = scope.heads.read(borrowed.case_id)
    assert isinstance(head, Err), head


def test_a_pin_that_stops_resolving_fails_closed_rather_than_falling_back(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The rebuild-time half, reached the only way a live case can reach it.

    Not "falls back to the current one", not "proceeds without revocation" --
    an admission that cannot resolve the authority its case pinned has not
    established that any key is authorized, only that it does not know.

    Constructed by publishing a *successor*, which moves what is in force off
    this case's pin and so releases the row for deletion, and then removing the
    pinned snapshot behind the case's back.  That last step is an operator with
    SQL rather than anything the application can do -- which is the point: the
    application has no delete, and the check has to hold anyway.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = _opened(database, case)

    #  A successor, so the case's own snapshot is no longer the one in force and
    #  the publication state no longer references it.
    successor = _widened(case)
    ravi.publish_authority_snapshot_for(database, case.tenant_id, successor)

    pinned = case.authorization_context.authority_registry_snapshot_digest
    with psycopg.connect(migrated_dsn) as connection:
        connection.execute(
            "DELETE FROM authority.registry_snapshot WHERE tenant_id = %s AND snapshot_digest = %s",
            (case.tenant_id, pinned.octets),
        )

    outcome = append_transcript_entry(
        work,  # type: ignore[arg-type]
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=case.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is AppendFailure.SNAPSHOT_REFUSED
    assert "SNAPSHOT_NOT_BOUND" in outcome.error.detail
    assert entry_digest(case.entries[SATURDAY_PRESENCE]) not in _members(database, case)


def _widened(case: RaviCase) -> Any:
    """A different, validly-signed authority snapshot for the same tenant.

    Different by ``registry_id`` alone, which is enough to move the digest and
    nothing else -- the grants are the case's own, so publishing this changes
    what is *in force* without changing what any key may say.
    """
    return replace(case.authority_snapshot, registry_id=f"{case.authority_snapshot.registry_id}-2")


def test_a_receipt_answering_another_cases_request_is_refused(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The request-target half of Q-12(a), which needs a request to exist.

    A receipt citing a request identifier that resolves to a request another
    case issued.  The proposition and the source class are right; the request
    belongs to somebody else, and answering it here would let one case's
    solicitation admit evidence into another.
    """
    from muster.core.wire.digests import DigestKind
    from support.fixtures import append_all

    #  Drive a case to the point where it dispatches a request, and take the
    #  identifier it issued.
    donor = ravi.ravi(tenant_id, f"{case_id}-donor")
    work = _opened(database, donor)
    advanced = append_all(work, donor, now=ravi.NOW)  # type: ignore[arg-type]
    assert advanced.published
    with database.reading(tenant_id) as scope:
        outstanding = scope.requests.outstanding(donor.case_id)
    assert isinstance(outstanding, Ok)
    assert outstanding.value, "the donor case must have dispatched a request"
    donor_request = outstanding.value[0].request_id

    with database.reading(tenant_id) as scope:
        assert isinstance(scope.content.get(DigestKind.EVIDENCE_REQUEST, donor_request), Ok)

    receiver = ravi.ravi(tenant_id, case_id, attested=True)
    misdirected = _rebound(receiver, SATURDAY_PRESENCE, request_id=donor_request)
    _refused(
        database,
        migrated_dsn,
        receiver,
        misdirected,
        failure=AppendFailure.ADMISSION_REFUSED,
        detail="UNSOLICITED_REPLY",
    )
