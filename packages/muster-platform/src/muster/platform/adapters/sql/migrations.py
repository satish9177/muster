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


#  Authority and catalog publications.  A third migration rather than an edit,
#  for the reason the second one was.
#
#  Both tables are keyed by the digest of the **unsigned** snapshot, because
#  that is what an authorization context pins and what a discovery result
#  names.  Keying by the signed wrapper's digest would need an index between a
#  pin and the artifact it names, which is one more place for the two to
#  disagree.
#
#  Neither has a foreign key to a case, and neither has one to ``store.content``
#  -- authority is tenant state that exists before any case pins it, and a case
#  that pins a snapshot which was never published fails closed at resolution
#  rather than being prevented at insert time.  There is no ``UPDATE`` and no
#  ``DELETE`` path to either: withdrawing a grant is publishing a successor.
#
#  They are two tables and not one with a ``kind`` column.  Authority answers
#  "who may attest what" and the catalog answers "which agent exists"; one
#  table would put both behind one statement, and the first question about any
#  such statement is which of the two a given row is.
_AUTHORITY_UP: tuple[str, ...] = (
    "CREATE SCHEMA IF NOT EXISTS authority",
    """
    CREATE TABLE authority.registry_snapshot (
        tenant_id       text    NOT NULL,
        snapshot_digest bytea   NOT NULL,
        signed_octets   bytea   NOT NULL,
        published_at    bigint  NOT NULL,
        PRIMARY KEY (tenant_id, snapshot_digest),
        CONSTRAINT registry_snapshot_digest_width
            CHECK (octet_length(snapshot_digest) = 32),
        CONSTRAINT registry_snapshot_not_empty
            CHECK (octet_length(signed_octets) > 0)
    )
    """,
    """
    CREATE TABLE authority.revocation_snapshot (
        tenant_id       text    NOT NULL,
        snapshot_digest bytea   NOT NULL,
        signed_octets   bytea   NOT NULL,
        published_at    bigint  NOT NULL,
        PRIMARY KEY (tenant_id, snapshot_digest),
        CONSTRAINT revocation_snapshot_digest_width
            CHECK (octet_length(snapshot_digest) = 32),
        CONSTRAINT revocation_snapshot_not_empty
            CHECK (octet_length(signed_octets) > 0)
    )
    """,
    "CREATE SCHEMA IF NOT EXISTS catalog",
    """
    CREATE TABLE catalog.agent_snapshot (
        tenant_id       text    NOT NULL,
        snapshot_digest bytea   NOT NULL,
        signed_octets   bytea   NOT NULL,
        published_at    bigint  NOT NULL,
        PRIMARY KEY (tenant_id, snapshot_digest),
        CONSTRAINT agent_snapshot_digest_width
            CHECK (octet_length(snapshot_digest) = 32),
        CONSTRAINT agent_snapshot_not_empty
            CHECK (octet_length(signed_octets) > 0)
    )
    """,
    #  "The newest catalog for this tenant" is the one routing query that is
    #  not a point lookup, and the primary key does not serve it. The digest is
    #  in the index so the ordering is total: two catalogs published at one
    #  instant resolve the same way on every read.
    """
    CREATE INDEX agent_snapshot_by_recency
        ON catalog.agent_snapshot (tenant_id, published_at DESC, snapshot_digest DESC)
    """,
)

_AUTHORITY_DOWN: tuple[str, ...] = (
    "DROP TABLE catalog.agent_snapshot",
    "DROP TABLE authority.revocation_snapshot",
    "DROP TABLE authority.registry_snapshot",
    "DROP SCHEMA catalog",
    "DROP SCHEMA authority",
)


#  The publication state: one row per tenant, and the only mutable row in this
#  schema.  A fourth migration rather than an edit to the third, for the reason
#  every migration here is its own: an applied migration is a fact about a
#  deployed database and rewriting one makes the ledger a description of the
#  file rather than of the database.
#
#  **Why a row and not a query.**  "The authority currently in force" could be
#  derived as the registry snapshot with the greatest published_at, and that
#  would be wrong twice.  It would make the answer depend on a publisher's
#  clock -- two snapshots at one instant have no order, and the tie would be
#  broken by a digest nobody chose.  And it would give the deciding path a
#  *query* to run, where what it needs is a row to lock: the ordering between
#  revocation and admission is a lock conflict on one tuple, and there is no
#  tuple to conflict on in "the maximum of a column".
#
#  **Why it may be updated when nothing else here may.**  It holds no history.
#  Every snapshot it has ever named is still in registry_snapshot under its own
#  digest, immutable, and every case that pinned one still resolves it. What
#  this row records is the present-tense answer to "what may a case opened now
#  pin", which has no past to destroy.
#
#  Three columns because there are three facts, and they move independently.
#  Publishing a registry snapshot moves in_force_digest and the epoch;
#  publishing a revocation snapshot moves in_force_revocation and the epoch. A
#  revocation changes what keys may say without changing which registry is in
#  force, so collapsing the two digests into one would make each publication
#  overwrite the other's answer.
#
#  **Both digests are nullable, and that is not laxness.**  A tenant can have
#  published a registry and not yet a revocation list, or the reverse, and
#  neither order is wrong -- they are two publishers' acts. What is wrong is
#  opening a case while either is missing, and that is refused where cases are
#  opened rather than encoded as NOT NULL here: a NOT NULL column would make
#  the *first* publication of either kind impossible, which is a constraint on
#  the publisher rather than on the case. G7 asks for fail-closed absence, and
#  absence has to be representable before it can be refused.
_PUBLICATION_STATE_UP: tuple[str, ...] = (
    """
    CREATE TABLE authority.publication_state (
        tenant_id            text    NOT NULL,
        in_force_digest      bytea,
        in_force_revocation  bytea,
        epoch                bigint  NOT NULL,
        PRIMARY KEY (tenant_id),
        CONSTRAINT publication_state_digest_width
            CHECK (in_force_digest IS NULL OR octet_length(in_force_digest) = 32),
        CONSTRAINT publication_state_revocation_width
            CHECK (in_force_revocation IS NULL OR octet_length(in_force_revocation) = 32),
        CONSTRAINT publication_state_epoch_positive
            CHECK (epoch >= 1),
        CONSTRAINT publication_state_names_a_published_snapshot
            FOREIGN KEY (tenant_id, in_force_digest)
            REFERENCES authority.registry_snapshot (tenant_id, snapshot_digest),
        CONSTRAINT publication_state_names_a_published_revocation
            FOREIGN KEY (tenant_id, in_force_revocation)
            REFERENCES authority.revocation_snapshot (tenant_id, snapshot_digest)
    )
    """,
)

_PUBLICATION_STATE_DOWN: tuple[str, ...] = ("DROP TABLE authority.publication_state",)


#  The deterministic Action Gate.  One row is one exact authorized proposal's
#  complete execution lifecycle, and every identity column is immutable:
#  only state and its outcome fields are ever updated.  ``intent_octets`` is a
#  canonical operational value, not an entry in the content-addressed semantic
#  store; its execution id is the idempotency hash over those exact octets.
_ACTION_GATE_UP: tuple[str, ...] = (
    "CREATE SCHEMA IF NOT EXISTS action_gate",
    """
    CREATE TABLE action_gate.execution (
        tenant_id                    text    NOT NULL,
        case_id                      text    NOT NULL,
        execution_id                 bytea   NOT NULL,
        intent_octets                bytea   NOT NULL,
        revision_number              integer NOT NULL,
        revision_digest              bytea   NOT NULL,
        certificate_digest           bytea   NOT NULL,
        kernel_result_digest         bytea   NOT NULL,
        bundle_manifest_digest       bytea   NOT NULL,
        authorization_context_digest bytea   NOT NULL,
        action_schema_digest          bytea   NOT NULL,
        action_digest                 bytea   NOT NULL,
        action_kind                   text    NOT NULL,
        gate_id                       text    NOT NULL,
        executor_id                   text    NOT NULL,
        requested_by                  text    NOT NULL,
        state                         text    NOT NULL,
        reserved_at                   bigint  NOT NULL,
        dispatched_at                 bigint,
        finalized_at                  bigint,
        external_reference            text,
        outcome_code                  text,
        detail                        text,
        PRIMARY KEY (tenant_id, execution_id),
        CONSTRAINT action_gate_one_lifecycle_per_authorized_proposal UNIQUE (
            tenant_id, case_id, revision_number, revision_digest,
            certificate_digest, kernel_result_digest, bundle_manifest_digest,
            authorization_context_digest, action_schema_digest, action_digest
        ),
        CONSTRAINT action_gate_external_reference_unique
            UNIQUE (tenant_id, external_reference),
        CONSTRAINT action_gate_case_exists
            FOREIGN KEY (tenant_id, case_id)
            REFERENCES casework.case_head (tenant_id, case_id),
        CONSTRAINT action_gate_execution_id_width
            CHECK (octet_length(execution_id) = 32),
        CONSTRAINT action_gate_revision_digest_width
            CHECK (octet_length(revision_digest) = 32),
        CONSTRAINT action_gate_certificate_digest_width
            CHECK (octet_length(certificate_digest) = 32),
        CONSTRAINT action_gate_kernel_result_digest_width
            CHECK (octet_length(kernel_result_digest) = 32),
        CONSTRAINT action_gate_bundle_digest_width
            CHECK (octet_length(bundle_manifest_digest) = 32),
        CONSTRAINT action_gate_authorization_digest_width
            CHECK (octet_length(authorization_context_digest) = 32),
        CONSTRAINT action_gate_action_schema_digest_width
            CHECK (octet_length(action_schema_digest) = 32),
        CONSTRAINT action_gate_action_digest_width
            CHECK (octet_length(action_digest) = 32),
        CONSTRAINT action_gate_intent_not_empty CHECK (octet_length(intent_octets) > 0),
        CONSTRAINT action_gate_revision_positive CHECK (revision_number >= 1),
        CONSTRAINT action_gate_state_closed
            CHECK (state IN ('RESERVED', 'DISPATCHED', 'CONFIRMED', 'FAILED', 'UNCERTAIN')),
        CONSTRAINT action_gate_timestamps_ordered CHECK (
            (dispatched_at IS NULL OR dispatched_at >= reserved_at)
            AND (finalized_at IS NULL OR (
                dispatched_at IS NOT NULL AND finalized_at >= dispatched_at
            ))
        ),
        CONSTRAINT action_gate_state_shape CHECK (
            (state = 'RESERVED'
                AND dispatched_at IS NULL AND finalized_at IS NULL
                AND external_reference IS NULL AND outcome_code IS NULL AND detail IS NULL)
            OR
            (state = 'DISPATCHED'
                AND dispatched_at IS NOT NULL AND finalized_at IS NULL
                AND external_reference IS NULL AND outcome_code IS NULL AND detail IS NULL)
            OR
            (state = 'CONFIRMED'
                AND dispatched_at IS NOT NULL AND finalized_at IS NOT NULL
                AND external_reference IS NOT NULL AND outcome_code IS NOT NULL)
            OR
            (state IN ('FAILED', 'UNCERTAIN')
                AND dispatched_at IS NOT NULL AND finalized_at IS NOT NULL
                AND external_reference IS NULL AND outcome_code IS NOT NULL)
        )
    )
    """,
)

_ACTION_GATE_DOWN: tuple[str, ...] = (
    "DROP TABLE action_gate.execution",
    "DROP SCHEMA action_gate",
)


#  Reconciliation adds provenance to the existing lifecycle row.  Migration 5's
#  state-shape and timestamp-order constraints remain untouched: the new checks
#  are cumulative, so a reconciled row must satisfy every original lifecycle
#  invariant as well as the narrower observational transition rules below.
_ACTION_GATE_RECONCILIATION_UP: tuple[str, ...] = (
    """
    ALTER TABLE action_gate.execution
        ADD COLUMN reconciled_at bigint,
        ADD COLUMN reconciled_from text
    """,
    """
    ALTER TABLE action_gate.execution
        ADD CONSTRAINT action_gate_reconciliation_metadata_pair CHECK (
            (reconciled_at IS NULL) = (reconciled_from IS NULL)
        ),
        ADD CONSTRAINT action_gate_reconciled_from_closed CHECK (
            reconciled_from IS NULL OR reconciled_from IN ('DISPATCHED', 'UNCERTAIN')
        ),
        ADD CONSTRAINT action_gate_reconciliation_transition CHECK (
            reconciled_from IS NULL
            OR (reconciled_from = 'DISPATCHED'
                AND state IN ('CONFIRMED', 'FAILED', 'UNCERTAIN'))
            OR (reconciled_from = 'UNCERTAIN'
                AND state IN ('CONFIRMED', 'FAILED'))
        ),
        ADD CONSTRAINT action_gate_reconciliation_timestamps CHECK (
            reconciled_at IS NULL OR (
                dispatched_at IS NOT NULL
                AND finalized_at IS NOT NULL
                AND reconciled_at >= finalized_at
            )
        )
    """,
)

_ACTION_GATE_RECONCILIATION_DOWN: tuple[str, ...] = (
    """
    ALTER TABLE action_gate.execution
        DROP CONSTRAINT action_gate_reconciliation_timestamps,
        DROP CONSTRAINT action_gate_reconciliation_transition,
        DROP CONSTRAINT action_gate_reconciled_from_closed,
        DROP CONSTRAINT action_gate_reconciliation_metadata_pair
    """,
    """
    ALTER TABLE action_gate.execution
        DROP COLUMN reconciled_from,
        DROP COLUMN reconciled_at
    """,
)


#  This schema is deliberately outside MUSTER custody.  It is the durable
#  external world of the sandbox simulation: no tenant, case, intent, Gate
#  state, executor identity, or foreign key connects it to action_gate.execution.
#  No real payment rail is represented and no real funds move.
_DURABLE_SANDBOX_RAIL_UP: tuple[str, ...] = (
    "CREATE SCHEMA sandbox_rail",
    """
    CREATE TABLE sandbox_rail.attempt (
        idempotency_key text  PRIMARY KEY,
        outcome         text  NOT NULL,
        failure_code    text,
        failure_detail  text,
        CONSTRAINT sandbox_attempt_outcome CHECK (
            outcome IN ('ATTEMPTED', 'DEFINITIVELY_NOT_EXECUTED')
        ),
        CONSTRAINT sandbox_attempt_evidence_shape CHECK (
            (outcome = 'ATTEMPTED'
                AND failure_code IS NULL AND failure_detail IS NULL)
            OR (outcome = 'DEFINITIVELY_NOT_EXECUTED'
                AND failure_code IS NOT NULL AND failure_detail IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE sandbox_rail.transfer (
        idempotency_key   text    PRIMARY KEY,
        external_reference text  NOT NULL UNIQUE,
        accepted_at       bigint  NOT NULL
    )
    """,
)

_DURABLE_SANDBOX_RAIL_DOWN: tuple[str, ...] = (
    "DROP TABLE sandbox_rail.transfer",
    "DROP TABLE sandbox_rail.attempt",
    "DROP SCHEMA sandbox_rail",
)


MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "case_custody", _INITIAL_UP, _INITIAL_DOWN),
    Migration(2, "case_commitment", _COMMITMENT_UP, _COMMITMENT_DOWN),
    Migration(3, "authority_and_catalog", _AUTHORITY_UP, _AUTHORITY_DOWN),
    Migration(4, "authority_publication_state", _PUBLICATION_STATE_UP, _PUBLICATION_STATE_DOWN),
    Migration(5, "deterministic_action_gate", _ACTION_GATE_UP, _ACTION_GATE_DOWN),
    Migration(
        6,
        "action_gate_reconciliation",
        _ACTION_GATE_RECONCILIATION_UP,
        _ACTION_GATE_RECONCILIATION_DOWN,
    ),
    Migration(
        7,
        "durable_sandbox_external_world",
        _DURABLE_SANDBOX_RAIL_UP,
        _DURABLE_SANDBOX_RAIL_DOWN,
    ),
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
