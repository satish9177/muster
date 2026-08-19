"""The schema, as an ordered list of reviewed statements.

There is no migration framework here, and the reason is the one absolute rule
about this schema: **canonical octets are never migrated.**  A migration that
rewrote a stored preimage would invalidate every digest, signature and
commitment that ever referenced it, and no amount of care at review time is
worth as much as a rule a test can check.  So migrations are pure DDL --
``test_migrations`` asserts that no statement in this file is an ``INSERT``,
``UPDATE`` or ``DELETE`` at all, and that only the statement introducing the
column ever names ``octets``.  That guard is three lines because the migrations
are data; against an autogenerating framework it would be a code review.

Each migration is applied inside one transaction, and the whole operation runs
under one advisory lock, so two processes starting at once produce one schema
rather than a race and a failed migration leaves nothing behind. PostgreSQL's
transactional DDL is what makes the second half true, and it is one of the
reasons the design chose PostgreSQL. See ``adapters.sql.schema`` for why the
lock is around the operation rather than around each step.

What the foreign keys say is the authored/derived distinction, enforced:

* ``construction_digest``, ``authorization_context_digest`` and
  ``transcript_prefix_digest`` on the head, and ``entry_digest`` on a member,
  reference ``store.content``.  These are inputs.  The database refuses to lose
  them, and refuses to let a case reference another tenant's octets, because
  the reference carries the tenant in the key.
* ``revision_digest`` and ``certificate_digest`` reference **nothing**.  They
  are a cache addressed by content, and pruning them has to stay possible: a
  revision is a function of the inputs above, so deleting one costs a
  recomputation and no truth. A foreign key here would quietly promote a cache
  to a fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

#  One 64-bit constant, so two processes migrating at once serialise instead of
#  racing. Chosen once and never derived from a name, because a hash that
#  changes with a rename is a lock that stops locking.
#
#  PostgreSQL's advisory namespace is per database and shared by every
#  application in it, so this is distinctive rather than unique -- the octets
#  spell "MUSTER" and a sequence number. A collision would cost an operator a
#  wait, never a schema: the lock guards a critical section, and two unrelated
#  applications taking turns through it is the same outcome as one.
MIGRATION_LOCK_ID = 0x4D55535445520001


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    up: tuple[str, ...]
    down: tuple[str, ...]

    def identity(self) -> str:
        """What the ledger records, and what a later build is compared against.

        **A version number is not an identity.**  Two builds can both carry
        "version 1" and mean two different schemas -- a migration edited in
        place rather than added to -- and a runner that skipped on the number
        alone would let the second build start against tables its repositories
        were not written for.  The name alone is no better: an in-place edit
        usually keeps the name, which makes that the common case rather than
        the edge one.

        So the identity is the name and a digest of the statements. It goes in
        the ``name`` column rather than in a new one, which is the whole reason
        it is a string: adding a column to the ledger would mean migrating the
        table that records migrations, and this runner is deliberately not able
        to do that.

        The fields are length-prefixed rather than joined by a separator, so
        the digest does not rest on no statement ever containing whatever that
        separator happened to be.  And it is not truncated: the column is
        ``text``, so a shortened digest would buy nothing and leave a collision
        argument to make instead of one nobody has to.
        """
        fields = (str(self.version), self.name, *self.up, *self.down)
        body = "".join(f"{len(field)}:{field}" for field in fields)
        return f"{self.name}@{sha256(body.encode('utf-8')).hexdigest()}"


_INITIAL_UP: tuple[str, ...] = (
    "CREATE SCHEMA IF NOT EXISTS store",
    "CREATE SCHEMA IF NOT EXISTS casework",
    #  The content store. Append-only, insert-if-absent, and keyed by tenant as
    #  well as digest: two tenants holding identical octets hold two rows.
    #  Deduplicating across the boundary would make one tenant's retention
    #  decision another tenant's problem and would leak the existence of an
    #  artifact across a boundary that exists to prevent exactly that.
    """
    CREATE TABLE store.content (
        tenant_id  text   NOT NULL,
        digest     bytea  NOT NULL,
        kind       text   NOT NULL,
        octets     bytea  NOT NULL,
        PRIMARY KEY (tenant_id, digest),
        CONSTRAINT content_digest_width CHECK (octet_length(digest) = 32)
    )
    """,
    #  The one mutable row in the system. Everything above the line is a pinned
    #  rebuild input; everything below it is what the last successful
    #  compare-and-swap published.
    """
    CREATE TABLE casework.case_head (
        tenant_id                    text     NOT NULL,
        case_id                      text     NOT NULL,
        construction_digest          bytea    NOT NULL,
        transcript_prefix_digest     bytea    NOT NULL,
        bundle_manifest_digest       bytea    NOT NULL,
        as_of                        bigint   NOT NULL,
        mode                         text     NOT NULL,
        authorization_context_digest bytea    NOT NULL,
        revision_digest              bytea,
        revision_number              integer  NOT NULL,
        certificate_digest           bytea,
        PRIMARY KEY (tenant_id, case_id),
        CONSTRAINT case_head_operational_only CHECK (mode = 'OPERATIONAL'),
        CONSTRAINT case_head_revision_number_non_negative CHECK (revision_number >= 0),
        CONSTRAINT case_head_unanalysed_is_revision_zero
            CHECK ((revision_digest IS NULL) = (revision_number = 0)),
        CONSTRAINT case_head_certificate_accompanies_revision
            CHECK ((revision_digest IS NULL) = (certificate_digest IS NULL)),
        CONSTRAINT case_head_construction_is_stored
            FOREIGN KEY (tenant_id, construction_digest)
            REFERENCES store.content (tenant_id, digest),
        CONSTRAINT case_head_authorization_context_is_stored
            FOREIGN KEY (tenant_id, authorization_context_digest)
            REFERENCES store.content (tenant_id, digest),
        CONSTRAINT case_head_prefix_is_stored
            FOREIGN KEY (tenant_id, transcript_prefix_digest)
            REFERENCES store.content (tenant_id, digest)
    )
    """,
    #  Membership, as a set. The primary key is the deduplication: appending the
    #  same entry twice is one member, which is what makes at-least-once
    #  delivery free. There is no ordinal column, because arrival order is not
    #  part of what a revision commits to and recording it would invite
    #  something to depend on it.
    """
    CREATE TABLE casework.transcript_entry (
        tenant_id    text   NOT NULL,
        case_id      text   NOT NULL,
        entry_digest bytea  NOT NULL,
        PRIMARY KEY (tenant_id, case_id, entry_digest),
        CONSTRAINT transcript_entry_case_exists
            FOREIGN KEY (tenant_id, case_id)
            REFERENCES casework.case_head (tenant_id, case_id),
        CONSTRAINT transcript_entry_octets_are_stored
            FOREIGN KEY (tenant_id, entry_digest)
            REFERENCES store.content (tenant_id, digest)
    )
    """,
    #  Durable intent to ask. Immutable: the identity is the digest of a record
    #  that already contains the revision and the targets, so every column here
    #  except the deadline is a function of the key -- and the deadline is the
    #  reason the row exists, being wall-clock intent rather than a fact about
    #  the case. There is no status column; see ``ports.RecordedRequest``.
    """
    CREATE TABLE casework.evidence_request (
        tenant_id       text    NOT NULL,
        case_id         text    NOT NULL,
        request_id      bytea   NOT NULL,
        revision_digest bytea   NOT NULL,
        deadline        bigint  NOT NULL,
        PRIMARY KEY (tenant_id, case_id, request_id),
        CONSTRAINT evidence_request_case_exists
            FOREIGN KEY (tenant_id, case_id)
            REFERENCES casework.case_head (tenant_id, case_id),
        CONSTRAINT evidence_request_octets_are_stored
            FOREIGN KEY (tenant_id, request_id)
            REFERENCES store.content (tenant_id, digest)
    )
    """,
    #  Answering "which requests are still bound to the head" is a lookup by
    #  case and revision; the primary key leads with the request id, which does
    #  not serve it.
    """
    CREATE INDEX evidence_request_by_revision
        ON casework.evidence_request (tenant_id, case_id, revision_digest)
    """,
)

_INITIAL_DOWN: tuple[str, ...] = (
    "DROP TABLE casework.evidence_request",
    "DROP TABLE casework.transcript_entry",
    "DROP TABLE casework.case_head",
    "DROP TABLE store.content",
    "DROP SCHEMA casework",
    "DROP SCHEMA store",
)


#  The commitment table.  A separate migration rather than an edit to the one
#  above, because version 1 has been applied to databases this build must be
#  able to bring forward -- editing it in place would change its identity and
#  the runner would refuse the database rather than upgrade it.
#
#  Keyed by the revision it commits, so one case accumulates one immutable row
#  per published revision and nothing is ever updated in place.  The foreign key
#  is to the *case*, not to the revision: a revision digest lives in the head
#  row, which moves, and a commitment for a revision that is no longer head is
#  still a true statement about that revision.
_COMMITMENT_UP: tuple[str, ...] = (
    """
    CREATE TABLE casework.case_commitment (
        tenant_id       text   NOT NULL,
        case_id         text   NOT NULL,
        revision_digest bytea  NOT NULL,
        envelope        bytea  NOT NULL,
        PRIMARY KEY (tenant_id, case_id, revision_digest),
        CONSTRAINT case_commitment_revision_digest_width
            CHECK (octet_length(revision_digest) = 32),
        CONSTRAINT case_commitment_envelope_not_empty
            CHECK (octet_length(envelope) > 0),
        CONSTRAINT case_commitment_case_exists
            FOREIGN KEY (tenant_id, case_id)
            REFERENCES casework.case_head (tenant_id, case_id)
    )
    """,
)

_COMMITMENT_DOWN: tuple[str, ...] = ("DROP TABLE casework.case_commitment",)


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "case_custody", _INITIAL_UP, _INITIAL_DOWN),
    Migration(2, "case_commitment", _COMMITMENT_UP, _COMMITMENT_DOWN),
)

#  The ledger. Created by the runner rather than by a migration, because a
#  migration cannot record itself before the table recording it exists. It
#  holds a version and a name and no timestamp: the applied set is the record,
#  and a wall-clock column here would be the only reading of a clock anywhere
#  in this package.
LEDGER_SCHEMA = "CREATE SCHEMA IF NOT EXISTS platform"
LEDGER_TABLE = """
CREATE TABLE IF NOT EXISTS platform.schema_migration (
    version integer PRIMARY KEY,
    name    text NOT NULL
)
"""
