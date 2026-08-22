"""Building a durable case, and reaching around the repositories on purpose.

Two kinds of helper live here.

The first opens cases and appends entries through the real commands, because a
test that set up its state with raw SQL would be testing a database it wrote
rather than the one the application writes.

The second reaches *past* the repositories with direct SQL -- ``forge_content``
writes octets under a key that is not theirs, ``prune_derived`` deletes the
cache.  Neither is an operation the application has, and that is the point: the
store's collision check and the "derived state is recomputable" claim are only
worth testing if something can actually produce the state they defend against.
"""

from __future__ import annotations

import psycopg

from muster.core.results import Err, Ok
from muster.core.values.times import Instant
from muster.core.wire.digests import Digest
from muster.platform.casework.advance import Advanced, Casework
from muster.platform.casework.commands import Appended, append_transcript_entry, open_case
from muster.platform.casework.ports import CaseHead
from support.ravi import RaviCase, publish_authority


def open_ravi(casework: Casework, case: RaviCase) -> CaseHead:
    """Publish the case's authority state, then open the case.

    Both, in that order, and it is not a convenience.  A case pins the
    authority snapshot it will be judged under, and admission resolves that pin
    before it will store a receipt -- so a suite that opened cases without
    publishing would be a suite in which nothing is ever admitted, and every
    test would fail for the same uninformative reason.

    Publishing here rather than in each test also makes the *absence* of it
    expressible: a test about an unpublished snapshot opens its case by hand
    and gets the fail-closed refusal, which is a thing worth being able to say.
    """
    publish_authority(casework.database, case)
    opened = open_case(
        casework,
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=case.authorization_context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )
    assert isinstance(opened, Ok), opened
    return opened.value


def append(casework: Casework, case: RaviCase, index: int, *, now: Instant) -> Appended:
    """Append one entry. The entry becomes durable; the advance may be refused.

    An intermediate revision of this fixture is legitimately over the engine's
    case-size bound -- the instances are all declared from the start and the
    facts arrive one at a time -- so the advance is returned rather than
    asserted on. The *append* is asserted on, because that is what the command
    promises.
    """
    appended = append_transcript_entry(
        casework,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=case.entries[index],
        now=now,
    )
    assert isinstance(appended, Ok), appended
    return appended.value


def append_all(casework: Casework, case: RaviCase, *, now: Instant) -> Advanced:
    """Append the whole transcript and require that the last advance published."""
    last: Appended | None = None
    for index in range(len(case.entries)):
        last = append(casework, case, index, now=now)
    assert last is not None
    assert isinstance(last.advanced, Ok), last.advanced
    return last.advanced.value


def rejected_append(casework: Casework, case: RaviCase, index: int, *, now: Instant) -> object:
    appended = append_transcript_entry(
        casework,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        entry=case.entries[index],
        now=now,
    )
    assert isinstance(appended, Err), appended
    return appended.error


#  ---- raw access, for states the application cannot create ----------------


def forge_content(dsn: str, tenant_id: str, digest: Digest, kind: str, octets: bytes) -> None:
    """Overwrite stored octets in place. No repository can do this."""
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "UPDATE store.content SET octets = %s, kind = %s WHERE tenant_id = %s AND digest = %s",
            (octets, kind, tenant_id, digest.octets),
        )


def insert_content(dsn: str, tenant_id: str, digest: Digest, kind: str, octets: bytes) -> None:
    """Insert octets under a key that is not their digest."""
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "INSERT INTO store.content (tenant_id, digest, kind, octets) VALUES (%s, %s, %s, %s)",
            (tenant_id, digest.octets, kind, octets),
        )


def prune_derived(dsn: str, tenant_id: str) -> int:
    """Delete every cached revision and certificate this tenant holds.

    The foreign keys decide what this can reach: inputs are referenced and
    refuse to go, derived artifacts are not and do.
    """
    with psycopg.connect(dsn) as connection:
        deleted = connection.execute(
            "DELETE FROM store.content WHERE tenant_id = %s AND kind IN "
            "('CASE_REVISION', 'ANALYSIS_CERTIFICATE')",
            (tenant_id,),
        )
        return deleted.rowcount


def count_content(dsn: str, tenant_id: str, kind: str) -> int:
    with psycopg.connect(dsn) as connection:
        row = connection.execute(
            "SELECT count(*) FROM store.content WHERE tenant_id = %s AND kind = %s",
            (tenant_id, kind),
        ).fetchone()
    assert row is not None
    count = row[0]
    assert isinstance(count, int)
    return count


def reset_tenant(dsn: str, tenant_id: str) -> None:
    """Erase everything one tenant holds, in foreign-key order.

    A teardown, not an application operation.  The acceptance suite needs it
    because the frozen milestone-B digests are digests *of a particular tenant
    and case*, so those tests cannot each invent a fresh tenant the way the
    rest of the suite does -- they have to share one identity and start from
    nothing.

    **The authority and catalog publications are erased too**, and they have to
    be.  Publisher keypairs are generated per session, so a snapshot published
    by an earlier run carries a signature over a key that no longer exists --
    and publication is insert-if-absent, so the stale row would win and every
    admission in the suite would fail on a signature nobody could verify.  That
    is the correct production behaviour meeting a fixture that changes its keys
    between runs; the fixture is the part that gives way.
    """
    with psycopg.connect(dsn) as connection:
        for statement in (
            "DELETE FROM action_gate.execution WHERE tenant_id = %s",
            "DELETE FROM casework.evidence_request WHERE tenant_id = %s",
            "DELETE FROM casework.case_commitment WHERE tenant_id = %s",
            "DELETE FROM casework.transcript_entry WHERE tenant_id = %s",
            "DELETE FROM casework.case_head WHERE tenant_id = %s",
            "DELETE FROM store.content WHERE tenant_id = %s",
            #  Before the registry, because it names a registry row under a
            #  foreign key: "the authority in force" may only ever be a
            #  snapshot that was actually published, which is worth a
            #  constraint and costs one line of ordering here.
            "DELETE FROM authority.publication_state WHERE tenant_id = %s",
            "DELETE FROM authority.registry_snapshot WHERE tenant_id = %s",
            "DELETE FROM authority.revocation_snapshot WHERE tenant_id = %s",
            "DELETE FROM catalog.agent_snapshot WHERE tenant_id = %s",
        ):
            connection.execute(statement, (tenant_id,))


def head_row(dsn: str, tenant_id: str, case_id: str) -> tuple[object, ...]:
    with psycopg.connect(dsn) as connection:
        row = connection.execute(
            "SELECT revision_number, revision_digest, certificate_digest, "
            "transcript_prefix_digest FROM casework.case_head "
            "WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchone()
    assert row is not None
    return row


def repoint_construction(dsn: str, tenant_id: str, case_id: str, digest: Digest) -> None:
    """Point a head at a different construction record. No repository can do this.

    The head's construction digest is a pinned rebuild input, and the only
    operation that sets it is opening the case. Moving it is how a test
    produces the state an operator with SQL could produce and the application
    could not: a case whose stored construction record is real, hashes to its
    own key, and says something the case must not be rebuilt from.
    """
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "UPDATE casework.case_head SET construction_digest = %s "
            "WHERE tenant_id = %s AND case_id = %s",
            (digest.octets, tenant_id, case_id),
        )
