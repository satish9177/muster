"""The custody protocols over dictionaries, for tests that are about logic.

This is a **peer** of the PostgreSQL adapter, not a substitute for it, and the
difference matters enough to say twice.

*What it is for.*  A test about admission rules, about which decision a
certificate produces, or about what ``open_case`` refuses does not need a
database; it needs an implementation of the four repositories that agrees with
the real one about every answer.  Running those against PostgreSQL costs a
connection and a migration for a claim that has nothing to do with either, and
the cost is paid on every run by everybody.

*What it proves nothing about.*  Concurrency.  A writing transaction here takes
one lock and holds it, so two writers are two writers in sequence -- which means
a compare-and-swap can be *exercised* here but cannot be *contended* here, and a
green concurrency test against this adapter would be a test of a mutex.
Serialisation, snapshot isolation, the visibility of a conflicting insert, the
behaviour of a foreign key under a concurrent delete: none of those exist in a
dictionary, and every one of them is a claim about PostgreSQL that only the
PostgreSQL suite is evidence for.  ``MemoryDatabase`` is deliberately
single-writer so that this reads as an absence rather than as a weaker version
of the same thing.

*What keeps the two honest.*  ``tests/contract`` runs one suite against both.
Where the semantics are genuinely shared -- insert-if-absent, digest collision,
membership as a set, compare-and-swap on the whole parent state, what a
rejection is called -- the suite asserts them of whichever adapter it was handed,
so a divergence fails rather than waits to be noticed.

*Two divergences the contract suite does not assert*, because they are
properties of the substrate rather than of the port:

* ``StoreFailure.CONTENT_NOT_VISIBLE`` is unreachable here.  It reports an
  insert that conflicted with a row the transaction cannot then see, which is a
  statement about MVCC.
* corrupt stored octets are reachable only by going around the port -- raw SQL
  against PostgreSQL, and ``MemoryDatabase.records`` here.  Both adapters
  re-derive the digest on every read; only their own suites can produce the
  state that check defends against.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace

from muster.core.case.revision import RebuildInputs, RebuildMode
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.wire.digests import Digest, DigestKind, digest_octets
from muster.platform.casework.ports import (
    CaseHead,
    CaseHeadRepository,
    CommitmentError,
    CommitmentFailure,
    CommitmentRepository,
    ContentStore,
    EvidenceRequestRepository,
    HeadError,
    HeadFailure,
    PublishedCommitment,
    RecordedRequest,
    RequestError,
    RequestFailure,
    StoreError,
    StoreFailure,
    TenantScope,
    TranscriptError,
    TranscriptFailure,
    TranscriptRepository,
    is_durable_instant,
    same_authored_case,
)

#  ---- the records ---------------------------------------------------------


@dataclass
class MemoryRecords:
    """Everything durable, keyed the way the schema keys it.

    Every key leads with the tenant, exactly as the tables do, so a query that
    forgot to qualify by tenant is the same impossibility here as there -- and
    the tenant-isolation suite is checking one rule rather than two.

    Public, and not a test hook.  The contents of an in-memory database are
    what an in-memory database *is*, and reaching for them is the same act as
    reaching past the repositories with raw SQL: something no application code
    does, and the only way a suite can produce a state the application refuses
    to create.
    """

    content: dict[tuple[str, Digest], tuple[str, bytes]] = field(default_factory=dict)
    heads: dict[tuple[str, str], CaseHead] = field(default_factory=dict)
    members: dict[tuple[str, str], frozenset[Digest]] = field(default_factory=dict)
    requests: dict[tuple[str, str, Digest], RecordedRequest] = field(default_factory=dict)
    commitments: dict[tuple[str, str, Digest], PublishedCommitment] = field(default_factory=dict)

    def copy(self) -> MemoryRecords:
        """A copy a transaction can write to and then abandon.

        Shallow is enough and is not a shortcut: every value stored is
        immutable -- frozen dataclasses, tuples, ``bytes``, ``frozenset`` -- so
        the only thing a transaction can change is which value a key holds.
        """
        return MemoryRecords(
            content=dict(self.content),
            heads=dict(self.heads),
            members=dict(self.members),
            requests=dict(self.requests),
            commitments=dict(self.commitments),
        )


#  ---- content store -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MemoryContentStore:
    """``digest -> octets``, insert-if-absent, and never overwriting."""

    records: MemoryRecords
    tenant_id: str
    writable: bool

    def put(self, kind: DigestKind, octets: bytes) -> Result[Digest, StoreError]:
        _require_writable(self.writable, "store.content")
        digest = digest_octets(kind, octets)
        key = (self.tenant_id, digest)
        existing = self.records.content.get(key)
        if existing is None:
            self.records.content[key] = (kind.value, octets)
            return Ok(digest)

        stored_kind, stored_octets = existing
        if stored_octets != octets or stored_kind != kind.value:
            #  Under SHA-256 this is not a race and not a retry. Same reasoning,
            #  and the same failure name, as the PostgreSQL store.
            return Err(
                StoreError(
                    StoreFailure.DIGEST_COLLISION,
                    digest.hex,
                    f"stored {stored_kind}/{len(stored_octets)} octets, "
                    f"offered {kind.value}/{len(octets)} octets",
                )
            )
        return Ok(digest)

    def get(self, kind: DigestKind, digest: Digest) -> Result[bytes, StoreError]:
        found = self.records.content.get((self.tenant_id, digest))
        if found is None:
            return Err(StoreError(StoreFailure.CONTENT_ABSENT, digest.hex, kind.value))
        stored_kind, octets = found
        if stored_kind != kind.value:
            return Err(
                StoreError(
                    StoreFailure.CONTENT_CORRUPT,
                    digest.hex,
                    f"stored as {stored_kind}, read as {kind.value}",
                )
            )
        if digest_octets(kind, octets) != digest:
            #  The same hash on every read as the SQL store does. Cheap, and the
            #  property every digest in the system rests on.
            return Err(
                StoreError(
                    StoreFailure.CONTENT_CORRUPT, digest.hex, "octets do not hash to their key"
                )
            )
        return Ok(octets)


#  ---- transcript membership -----------------------------------------------


@dataclass(frozen=True, slots=True)
class MemoryTranscriptRepository:
    records: MemoryRecords
    tenant_id: str
    writable: bool

    def add(self, case_id: str, entry_digest: Digest) -> Result[bool, TranscriptError]:
        _require_writable(self.writable, "casework.transcript_entry")
        key = (self.tenant_id, case_id)
        if key not in self.records.heads:
            return Err(TranscriptError(TranscriptFailure.UNKNOWN_CASE, case_id))
        if (self.tenant_id, entry_digest) not in self.records.content:
            #  The schema states this as a foreign key. Membership without a
            #  preimage would make the prefix undecodable, so the octets go in
            #  first and both adapters refuse the other order.
            return Err(
                TranscriptError(
                    TranscriptFailure.CONTENT_NOT_STORED,
                    f"{entry_digest.hex} is not in the store",
                )
            )
        members = self.records.members.get(key, frozenset())
        if entry_digest in members:
            return Ok(False)
        self.records.members[key] = members | {entry_digest}
        return Ok(True)

    def members(self, case_id: str) -> Result[tuple[Digest, ...], TranscriptError]:
        key = (self.tenant_id, case_id)
        if key not in self.records.heads:
            return Err(TranscriptError(TranscriptFailure.UNKNOWN_CASE, case_id))
        #  Ascending by digest octets, which is what ``ORDER BY entry_digest``
        #  means: a set has no order, so the one the caller sees is imposed
        #  identically by both adapters or the prefix digests differ.
        return Ok(tuple(sorted(self.records.members.get(key, frozenset()), key=_by_octets)))


def _by_octets(digest: Digest) -> bytes:
    return digest.octets


#  ---- case head -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MemoryCaseHeadRepository:
    records: MemoryRecords
    tenant_id: str
    writable: bool

    def open(self, inputs: RebuildInputs) -> Result[CaseHead, HeadError]:
        _require_writable(self.writable, "casework.case_head")
        if inputs.tenant_id != self.tenant_id:
            return Err(HeadError(HeadFailure.UNKNOWN_CASE, f"inputs name {inputs.tenant_id!r}"))
        if inputs.mode is not RebuildMode.OPERATIONAL:
            return Err(HeadError(HeadFailure.MODE_NOT_PUBLISHABLE, inputs.mode.value))
        if not is_durable_instant(inputs.as_of):
            #  A dictionary would hold any integer. Refused anyway, because the
            #  contract is what both adapters owe and an adapter that accepted
            #  more than the port allows is a divergence waiting to be relied on.
            return Err(HeadError(HeadFailure.INSTANT_NOT_DURABLE, f"as_of={inputs.as_of}"))

        key = (self.tenant_id, inputs.case_id)
        existing = self.records.heads.get(key)
        if existing is None:
            missing = self._unstored(inputs)
            if missing is not None:
                #  Three foreign keys in the schema, one check here: a case
                #  pinned to an artifact nobody stored would be unreplayable
                #  from the instant it existed.
                return Err(HeadError(HeadFailure.INPUTS_NOT_STORED, missing))
            self.records.heads[key] = CaseHead(
                case_id=inputs.case_id,
                inputs=inputs,
                revision_digest=None,
                revision_number=0,
                certificate_digest=None,
            )
            return self.read(inputs.case_id)

        if not same_authored_case(existing.inputs, inputs):
            return Err(HeadError(HeadFailure.CASE_ALREADY_OPEN, inputs.case_id))
        return Ok(existing)

    def _unstored(self, inputs: RebuildInputs) -> str | None:
        for name, digest in (
            ("case_head_construction_is_stored", inputs.construction_digest),
            ("case_head_prefix_is_stored", inputs.transcript_prefix_digest),
            ("case_head_authorization_context_is_stored", inputs.authorization_context_digest),
        ):
            if (self.tenant_id, digest) not in self.records.content:
                return name
        return None

    def read(self, case_id: str) -> Result[CaseHead, HeadError]:
        found = self.records.heads.get((self.tenant_id, case_id))
        if found is None:
            return Err(HeadError(HeadFailure.UNKNOWN_CASE, case_id))
        return Ok(found)

    def hold(self, case_id: str) -> Result[CaseHead, HeadError]:
        """The same value as ``read``, and here the same guarantee for free.

        A writing transaction in this adapter already excludes every other
        writer, so "hold this case" is implied by having a writing scope at
        all. That is exactly why this adapter is not evidence for the property:
        it satisfies the contract by being coarser than the contract, and a
        green concurrent-admission test against it would prove that one lock
        excludes one lock. The claim is about PostgreSQL row locks, and only
        the PostgreSQL suite is evidence for it.
        """
        _require_writable(self.writable, "casework.case_head")
        return self.read(case_id)

    def advance(
        self,
        *,
        parent: CaseHead,
        prefix_digest: Digest,
        revision_digest: Digest,
        certificate_digest: Digest,
    ) -> Result[CaseHead, HeadError]:
        """Compare-and-swap on the whole parent state, as the ``UPDATE`` does.

        The order of the two refusals is the order PostgreSQL produces them in:
        a statement whose ``WHERE`` matched nothing never reaches its foreign
        key, so a lost swap is reported as a lost swap even when the prefix it
        offered was also absent.
        """
        _require_writable(self.writable, "casework.case_head")
        if parent.inputs.tenant_id != self.tenant_id:
            return Err(HeadError(HeadFailure.UNKNOWN_CASE, parent.inputs.tenant_id))

        key = (self.tenant_id, parent.case_id)
        current = self.records.heads.get(key)
        if current is None or current != parent:
            return Err(
                HeadError(
                    HeadFailure.HEAD_MOVED,
                    f"{parent.case_id} was not at revision {parent.revision_number}",
                )
            )
        if (self.tenant_id, prefix_digest) not in self.records.content:
            return Err(
                HeadError(HeadFailure.PREFIX_NOT_STORED, f"{prefix_digest.hex} is not in the store")
            )

        advanced = CaseHead(
            case_id=parent.case_id,
            inputs=replace(parent.inputs, transcript_prefix_digest=prefix_digest),
            revision_digest=revision_digest,
            revision_number=parent.revision_number + 1,
            certificate_digest=certificate_digest,
        )
        self.records.heads[key] = advanced
        return Ok(advanced)


#  ---- evidence requests ---------------------------------------------------


@dataclass(frozen=True, slots=True)
class MemoryEvidenceRequestRepository:
    records: MemoryRecords
    tenant_id: str
    writable: bool

    def record(self, request: RecordedRequest) -> Result[bool, RequestError]:
        _require_writable(self.writable, "casework.evidence_request")
        if (self.tenant_id, request.case_id) not in self.records.heads:
            return Err(RequestError(RequestFailure.UNKNOWN_CASE, request.case_id))
        if (self.tenant_id, request.request_id) not in self.records.content:
            return Err(
                RequestError(
                    RequestFailure.CONTENT_NOT_STORED,
                    "evidence_request_octets_are_stored",
                )
            )

        key = (self.tenant_id, request.case_id, request.request_id)
        existing = self.records.requests.get(key)
        if existing is None:
            self.records.requests[key] = request
            return Ok(True)
        if existing.revision_digest != request.revision_digest:
            #  The id is the digest of a record that contains the revision, so
            #  this is a digest naming two different things.
            return Err(
                RequestError(
                    RequestFailure.REQUEST_IDENTITY_CONFLICT,
                    f"{request.request_id.hex} already names another revision",
                )
            )
        #  The deadline is the one field the digest does not cover, and a retry
        #  keeps the one already recorded rather than extending it.
        return Ok(False)

    def outstanding(self, case_id: str) -> Result[tuple[RecordedRequest, ...], RequestError]:
        head = self.records.heads.get((self.tenant_id, case_id))
        if head is None:
            return Err(RequestError(RequestFailure.UNKNOWN_CASE, case_id))
        #  Outstanding is the join, not a column: a request stops being
        #  outstanding the instant the head moves, with no second write.
        found = [
            request
            for (tenant, case, _request_id), request in self.records.requests.items()
            if tenant == self.tenant_id
            and case == case_id
            and head.revision_digest is not None
            and request.revision_digest == head.revision_digest
        ]
        return Ok(tuple(sorted(found, key=lambda request: request.request_id.octets)))


#  ---- commitment envelopes ------------------------------------------------


@dataclass(frozen=True, slots=True)
class MemoryCommitmentRepository:
    """One immutable envelope per published revision.  No update, no delete."""

    records: MemoryRecords
    tenant_id: str
    writable: bool

    def publish(self, commitment: PublishedCommitment) -> Result[bool, CommitmentError]:
        _require_writable(self.writable, "casework.case_commitment")
        if (self.tenant_id, commitment.case_id) not in self.records.heads:
            return Err(CommitmentError(CommitmentFailure.UNKNOWN_CASE, commitment.case_id))
        key = (self.tenant_id, commitment.case_id, commitment.revision_digest)
        if key in self.records.commitments:
            #  First writer wins, and the loser is told it created nothing --
            #  which is what makes publishing idempotent rather than merely
            #  repeatable.
            return Ok(False)
        self.records.commitments[key] = commitment
        return Ok(True)

    def read(
        self, case_id: str, revision_digest: Digest
    ) -> Result[PublishedCommitment, CommitmentError]:
        found = self.records.commitments.get((self.tenant_id, case_id, revision_digest))
        if found is None:
            return Err(
                CommitmentError(
                    CommitmentFailure.COMMITMENT_ABSENT,
                    f"{case_id} has no commitment for {revision_digest.hex}",
                )
            )
        return Ok(found)


#  ---- transaction scopes --------------------------------------------------


@dataclass(frozen=True, slots=True)
class MemoryTenantScope:
    """Five repositories over one set of records, one tenant, one transaction."""

    records: MemoryRecords
    _tenant_id: str
    writable: bool

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def content(self) -> ContentStore:
        return MemoryContentStore(self.records, self._tenant_id, self.writable)

    @property
    def transcript(self) -> TranscriptRepository:
        return MemoryTranscriptRepository(self.records, self._tenant_id, self.writable)

    @property
    def heads(self) -> CaseHeadRepository:
        return MemoryCaseHeadRepository(self.records, self._tenant_id, self.writable)

    @property
    def requests(self) -> EvidenceRequestRepository:
        return MemoryEvidenceRequestRepository(self.records, self._tenant_id, self.writable)

    @property
    def commitments(self) -> CommitmentRepository:
        return MemoryCommitmentRepository(self.records, self._tenant_id, self.writable)


def _require_writable(writable: bool, table: str) -> None:
    """A write inside ``reading`` is a defect, not a rejection to hand back.

    PostgreSQL answers this with ``cannot execute ... in a read-only
    transaction``, which is an exception rather than a value, so this is one
    too. A typed rejection would invite a caller to carry on, and the caller
    that reached here asked a read-only scope to change durable state.
    """
    if not writable:
        raise InvariantViolation(f"{table}: written inside a read-only transaction")


class MemoryDatabase:
    """Durable custody in a dictionary, one writer at a time.

    Not a dataclass: it owns a lock and a mutable set of records, and a frozen
    wrapper around mutable state would say something untrue about both.

    **One writer at a time, and no second transaction on the same thread.**  A
    writing transaction takes the lock for its whole extent, which is what
    makes commit-or-discard atomic without an isolation level to reason about.
    Opening *any* other transaction on that thread while it is open would block
    on a lock the thread itself holds, so it is refused by name instead --
    because a deadlock is the least useful failure a suite can produce, and
    because the two things a caller might mean by it are both things only
    PostgreSQL implements: a savepoint, and a second connection that cannot see
    the first one's uncommitted work.
    """

    def __init__(self, records: MemoryRecords | None = None) -> None:
        self.records = MemoryRecords() if records is None else records
        self._lock = threading.Lock()
        self._writing = threading.local()

    @contextmanager
    def writing(self, tenant_id: str) -> Iterator[TenantScope]:
        """Read-write. Installed on a clean exit, discarded on an exception."""
        self._refuse_if_writing("a writing")
        with self._lock:
            self._writing.open = True
            working = self.records.copy()
            try:
                yield MemoryTenantScope(working, tenant_id, writable=True)
            finally:
                self._writing.open = False
            #  Reached only when the body did not raise, so an exception leaves
            #  ``working`` unreferenced and the committed records untouched.
            #  Exactly what a rolled-back transaction costs: the work.
            self.records = working

    @contextmanager
    def reading(self, tenant_id: str) -> Iterator[TenantScope]:
        """Read-only over one consistent snapshot.

        The snapshot is a copy taken under the lock, so a reader sees the
        records as one instant even if a writer commits while it is deriving --
        which is what repeatable-read buys the caller against PostgreSQL.
        """
        self._refuse_if_writing("a reading")
        with self._lock:
            snapshot = self.records.copy()
        yield MemoryTenantScope(snapshot, tenant_id, writable=False)

    def _refuse_if_writing(self, opening: str) -> None:
        if getattr(self._writing, "open", False):
            raise InvariantViolation(
                f"{opening} transaction cannot be opened while this thread already holds "
                "a writing one: the in-memory adapter models neither savepoints nor a "
                "second connection"
            )
