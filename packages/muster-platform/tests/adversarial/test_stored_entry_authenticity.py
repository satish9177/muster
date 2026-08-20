"""A stored attestation is re-authenticated before it decides anything.

Milestone E's headline property is that **durable transcript membership is not
by itself sufficient to turn an attestation into consequential evidence**.
Check Q-12 is the half of that everyone looks at: it answers *may this key say
this, here, now*.  It presupposes an answer to a prior question -- *did this key
say it* -- and presupposing is not checking.

The gap this file closes: the rebuild path decoded a stored transcript entry,
bound it to the tenant and case, and handed its ``signer_key_ref`` straight to
Q-12(b) through (f) **without ever verifying the signature**.  A row inserted
past admission, naming a genuinely authorized key and carrying octets that
verify against nothing, therefore passed every authority clause -- because every
authority clause is about the key the payload *claims*, and nothing had
established that the claim was true.

That is not a theoretical shape.  Replacing every attestation signature in the
worked fixture with sixteen repetitions of ``deadbeef`` produced an identical
revision, an identical ``Invariant`` outcome, and an identical authorization to
pay 5,100.00 INR.

**The store is one of two doors and the other is an operator with SQL.**  That
sentence is not new here -- ``snapshot.py::_read_construction`` has always
re-verified the officer signature on the way out of the store and says exactly
that as its reason.  The construction record and the attestation are read four
lines apart by the same function; only one of them was being checked.

The tests below use the door the argument names: they write to PostgreSQL
directly, which is what an operator, a compromised backup restore, or a defect
in some future ingest path can do, and which the application deliberately
cannot undo -- the content store has no delete.
"""

from __future__ import annotations

from dataclasses import replace

import psycopg
import pytest

from muster.core.evidence.transcript import Attestation, entry_digest, entry_node
from muster.core.results import Err, Ok
from muster.core.wire.codec import encode
from muster.core.wire.digests import DigestKind, digest_octets
from muster.core.wire.signature import Signature
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import advance_case
from muster.platform.casework.commands import case_status
from muster.platform.casework.snapshot import read_published
from support import authority as A
from support import ravi
from support.fixtures import open_ravi
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

SATURDAY_PRESENCE = 18

#  Sixteen repetitions of a word chosen so that a reader of a failure message
#  can see at a glance that nothing was ever meant to verify.
GARBAGE = Signature("ECDSA-P256-SHA256", b"\xde\xad\xbe\xef" * 16)


@pytest.fixture
def database(migrated_dsn: str) -> SqlDatabase:
    return SqlDatabase(migrated_dsn)


def _forged(case: RaviCase) -> Attestation:
    """The real Saturday presence receipt, with a signature that verifies for nobody.

    Everything else is untouched: the same authorized site key, the same
    proposition, the same schema pin, the same validity window, the same
    resource coordinates.  So every Q-12 clause passes on the payload's own
    terms and the *only* thing wrong with this entry is that the key it names
    did not produce it.  That is what makes it the right adversary here -- a
    receipt refused for some other reason would prove nothing about
    authenticity.
    """
    entry = case.entries[SATURDAY_PRESENCE]
    assert isinstance(entry, Attestation)
    return Attestation(replace(entry.receipt, signature=GARBAGE))


def _write_past_admission(dsn: str, case: RaviCase, entry: Attestation) -> None:
    """Insert the entry the way an operator with SQL would: octets, then membership.

    Deliberately not through ``append_transcript_entry``.  Admission verifies
    the signature and would refuse this -- correctly, and that refusal is
    already covered elsewhere.  The question here is what happens to an entry
    that is *already durable*, which is the only question the rebuild path can
    answer.
    """
    octets = encode(entry_node(entry))
    digest = digest_octets(DigestKind.TRANSCRIPT_ENTRY, octets)
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "INSERT INTO store.content (tenant_id, digest, kind, octets) "
            "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (case.tenant_id, digest.octets, DigestKind.TRANSCRIPT_ENTRY.value, octets),
        )
        connection.execute(
            "INSERT INTO casework.transcript_entry (tenant_id, case_id, entry_digest) "
            "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
            (case.tenant_id, case.case_id, digest.octets),
        )


def test_A_FORGED_RECEIPT_WRITTEN_PAST_ADMISSION_CANNOT_ESTABLISH_A_FACT(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The regression. A durable entry nobody signed decides nothing.

    Refused rather than ignored, and the difference matters: a rebuild that
    silently dropped the entry would leave the case advancing on a transcript
    that does not match its own membership set, which is a second defect. The
    read fails, the advance fails, and the head does not move.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, case)

    forged = _forged(case)
    _write_past_admission(migrated_dsn, case, forged)

    #  The membership row exists: the entry really is durable.
    with database.reading(tenant_id) as scope:
        members = scope.transcript.members(case_id)
    assert isinstance(members, Ok), members
    assert entry_digest(forged) in set(members.value)

    advanced = advance_case(work, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(advanced, Err), advanced
    assert "is not signed by" in str(advanced.error.detail)

    #  And the head never moved, so nothing downstream cites it.
    with database.reading(tenant_id) as scope:
        head = scope.heads.read(case_id)
    assert isinstance(head, Ok), head
    assert head.value.revision_digest is None


def test_the_same_receipt_signed_for_real_does_establish_the_fact(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The control. The refusal above is the signature and nothing else.

    Identical entry, identical key, identical everything -- with the signature
    the source actually produced. Without this the test above would pass with
    the rebuild refusing every receipt in the system.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, case)

    from muster.platform.casework.commands import append_transcript_entry

    admitted = append_transcript_entry(
        work,
        tenant_id=tenant_id,
        case_id=case_id,
        entry=case.entries[SATURDAY_PRESENCE],
        now=ravi.NOW,
    )
    assert isinstance(admitted, Ok), admitted

    reported = case_status(work, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(reported, Ok), reported


def test_a_forged_receipt_inside_a_published_prefix_stops_the_replay(
    database: SqlDatabase, migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The other read path, which is the one every *reader* of a decided case uses.

    ``read_working`` is what an advance derives from; ``read_published`` is what
    a status query, a commitment and a disclosure replay from.  They are
    different membership sets and the check has to be on both -- so it lives in
    the function they share rather than in whichever caller was in mind.

    Constructed by pointing the head's transcript prefix at a prefix that names
    the forged entry: the operator-with-SQL door again, and the only way an
    unsigned entry can end up inside a *published* prefix at all now that the
    advance refuses it.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, case)

    from muster.core.case.revision import TranscriptPrefix

    forged = _forged(case)
    _write_past_admission(migrated_dsn, case, forged)

    #  A prefix naming exactly the forged entry, stored and then pinned by the
    #  head. The head stays unanalysed, so no revision claims to be derived
    #  from it -- the point is only that resolving the prefix refuses.
    prefix = TranscriptPrefix(tenant_id, case_id, (entry_digest(forged),))
    octets = encode(prefix.to_node())
    digest = digest_octets(DigestKind.TRANSCRIPT_PREFIX, octets)
    with psycopg.connect(migrated_dsn) as connection:
        connection.execute(
            "INSERT INTO store.content (tenant_id, digest, kind, octets) "
            "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (tenant_id, digest.octets, DigestKind.TRANSCRIPT_PREFIX.value, octets),
        )
        connection.execute(
            "UPDATE casework.case_head SET transcript_prefix_digest = %s, "
            "revision_digest = %s, revision_number = 1, certificate_digest = %s "
            "WHERE tenant_id = %s AND case_id = %s",
            (digest.octets, digest.octets, digest.octets, tenant_id, case_id),
        )

    with database.reading(tenant_id) as scope:
        replayed = read_published(
            scope,
            case_id,
            A.publisher_verifier(),
            A.officer_verifier(),
            A.source_verifier(),
        )
    assert isinstance(replayed, Err), replayed
    assert "is not signed by" in replayed.error.detail


def test_a_statement_needs_no_signature_and_is_still_inert(
    database: SqlDatabase, tenant_id: str, case_id: str
) -> None:
    """The deliberate exception, asserted rather than left to be inferred.

    A ``StatementRecord`` carries no signature -- a party's claim about itself
    is not an attestation and has nothing to verify -- so the new check must
    not refuse one. Its inertness comes from the rule that a self-serving claim
    establishes nothing, not from cryptography, and that rule is unchanged.
    """
    case = ravi.ravi(tenant_id, case_id, attested=True)
    work = ravi.casework(database)
    open_ravi(work, case)

    from muster.core.evidence.transcript import Statement
    from muster.platform.casework.commands import append_transcript_entry

    statements = [entry for entry in case.entries if isinstance(entry, Statement)]
    assert statements, "the fixture must carry a claim for this to test anything"

    outcome = append_transcript_entry(
        work, tenant_id=tenant_id, case_id=case_id, entry=statements[0], now=ravi.NOW
    )
    assert isinstance(outcome, Ok), outcome

    reported = case_status(work, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(reported, Ok), reported
