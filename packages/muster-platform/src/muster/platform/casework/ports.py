"""The custody boundary, stated as protocols that name no database.

Five repositories, two transaction scopes, and one structural decision that the
tenant-isolation tests lean on entirely:

**A repository does not exist until a tenant has been named.**  ``TenantScope``
is the only way to reach one, no repository method takes a tenant argument, and
a transaction is opened for exactly one tenant.  A query that forgot to qualify
by tenant is therefore not a mistake a reviewer has to catch -- it is a call
that cannot be spelled.

The second decision is about what is *authored* and what is *derived*.  The
content store, the transcript membership set and the pinned inputs on the head
are inputs: losing one loses truth.  A revision and a certificate are functions
of those inputs, so they are stored as immutable cache artifacts under their own
digests, and deleting them costs a recomputation and nothing else.  That
distinction is enforced in the schema by which foreign keys exist -- see
``adapters.sql.migrations`` -- and it is the reason ``ContentStore`` has no
delete: pruning a cache is an operator's deliberate act against the table, not
an operation the application is given.

The commitment repository is the one artifact that sits on neither side of that
line cleanly, and it says so: its *content* is derived and reproducible, its
*signature* is not, so it is stored as an immutable authored artifact and never
recomputed in place.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from muster.core.case.revision import RebuildInputs
from muster.core.results import InvariantViolation, Result
from muster.core.values.times import Instant
from muster.core.wire.digests import Digest, DigestKind

#  ---- durable instants ---------------------------------------------------

#  A durable instant is a signed 64-bit integer, because that is what every
#  store either has or has to emulate.  ``Instant`` is an alias for ``int`` and
#  Python integers are unbounded, so the bound is not in the type and has to be
#  in the contract: without it, an instant past this range is accepted happily
#  by an in-memory adapter and raises ``NumericValueOutOfRange`` from a
#  PostgreSQL ``bigint`` column -- two adapters disagreeing about a port-level
#  value, which is the exact divergence the shared contract exists to prevent.
#
#  Only the instants that reach an integer *column* are bounded here: the head's
#  ``as_of`` and a request's ``deadline``.  Every other instant in the system --
#  observed, issued, statement and validity times -- lives inside canonical
#  octets in a ``bytea``, where the wire format is the only contract there is.
DURABLE_INSTANT_BOUND = 9_223_372_036_854_775_808  # 2**63


def is_durable_instant(value: Instant) -> bool:
    """Does this instant fit in the column that would have to hold it?"""
    return -DURABLE_INSTANT_BOUND <= value < DURABLE_INSTANT_BOUND


#  ---- content store ------------------------------------------------------


class StoreFailure(Enum):
    """Why a content-addressed read or write did not happen."""

    #  Two different octet strings under one digest.  Under SHA-256 this is not
    #  a race and not a retry -- it is corruption or a forged row, and the only
    #  safe response is to refuse and say so.
    DIGEST_COLLISION = "DIGEST_COLLISION"
    CONTENT_ABSENT = "CONTENT_ABSENT"
    #  Stored octets that do not hash to the key they are stored under. Checked
    #  on every read, because a store that silently returns the wrong preimage
    #  makes every digest in the system a lie.
    CONTENT_CORRUPT = "CONTENT_CORRUPT"
    #  The insert conflicted with a row that is then not visible to this
    #  transaction.  Retryable, and distinguished from a collision so that a
    #  concurrency artefact is never reported as corruption.
    CONTENT_NOT_VISIBLE = "CONTENT_NOT_VISIBLE"


@dataclass(frozen=True, slots=True)
class StoreError:
    failure: StoreFailure
    digest: str
    detail: str = ""


class ContentStore(Protocol):
    """``digest -> canonical octets``, append-only, insert-if-absent.

    There is no ``put(digest, octets)``: the store derives the key from the
    octets and the domain it is being stored under, so writing a preimage under
    a key that is not its own is unrepresentable rather than rejected.
    """

    def put(self, kind: DigestKind, octets: bytes) -> Result[Digest, StoreError]:
        """Store these octets under their own digest. Idempotent, never overwriting."""
        ...

    def get(self, kind: DigestKind, digest: Digest) -> Result[bytes, StoreError]:
        """Exactly the octets that were stored, or a typed absence."""
        ...


#  ---- transcript membership ----------------------------------------------


class TranscriptFailure(Enum):
    UNKNOWN_CASE = "UNKNOWN_CASE"
    #  Membership without a preimage would make the prefix undecodable, so the
    #  octets go in first and the database refuses the ordering the other way.
    CONTENT_NOT_STORED = "CONTENT_NOT_STORED"


@dataclass(frozen=True, slots=True)
class TranscriptError:
    failure: TranscriptFailure
    detail: str


class TranscriptRepository(Protocol):
    """An append-only *set* of entry digests per case.

    A set, not a log.  Nothing here removes a member, arrival order is not
    recorded because it is not observable, and adding the same entry twice is
    one member -- which is what makes at-least-once delivery free.
    """

    def add(self, case_id: str, entry_digest: Digest) -> Result[bool, TranscriptError]:
        """Insert if absent. ``True`` when this call created the membership."""
        ...

    def members(self, case_id: str) -> Result[tuple[Digest, ...], TranscriptError]:
        """Every member, ascending by digest octets."""
        ...


#  ---- case head ----------------------------------------------------------


class HeadFailure(Enum):
    UNKNOWN_CASE = "UNKNOWN_CASE"
    #  ``open`` is idempotent by inputs. A second open of the same case naming
    #  different inputs is a caller error, not a duplicate.
    CASE_ALREADY_OPEN = "CASE_ALREADY_OPEN"
    #  The compare-and-swap matched no row: someone else advanced the head, or
    #  the pinned inputs are not the ones this computation analysed.
    HEAD_MOVED = "HEAD_MOVED"
    #  The head would name a transcript prefix whose octets are not in the
    #  store, leaving the revision unreplayable. The publication path stores the
    #  prefix first, so reaching this is a defect rather than a race -- and it
    #  is refused rather than allowed to abort the caller's transaction.
    PREFIX_NOT_STORED = "PREFIX_NOT_STORED"
    #  Opening a case whose construction record, authorization context or empty
    #  prefix is not in the store. Distinguished from ``UNKNOWN_CASE`` because
    #  it says the opposite thing: the case is being created, and one of the
    #  artifacts it is pinned to is missing.
    INPUTS_NOT_STORED = "INPUTS_NOT_STORED"
    #  Only ``OPERATIONAL`` revisions are published. A counterfactual rebuild
    #  answers a question; it is not a state a case can be in.
    MODE_NOT_PUBLISHABLE = "MODE_NOT_PUBLISHABLE"
    #  The head's ``as_of`` does not fit in the column that would hold it. The
    #  kernel's ``as_of`` is unbounded and correctly so -- a counterfactual
    #  rebuild has no column -- so the bound belongs to the head, which does.
    INSTANT_NOT_DURABLE = "INSTANT_NOT_DURABLE"


@dataclass(frozen=True, slots=True)
class HeadError:
    failure: HeadFailure
    detail: str


@dataclass(frozen=True, slots=True)
class CaseHead:
    """The one mutable row in the system, as a value.

    ``inputs`` carries all eight ``RebuildInputs`` fields rather than their
    digest: the digest is a function of them, and storing both would be two
    sources of one truth.  ``revision_digest`` is ``None`` for a case that has
    been opened and never analysed -- which is a real state, not a placeholder,
    and the compare-and-swap treats it as the parent it is.
    """

    case_id: str
    inputs: RebuildInputs
    revision_digest: Digest | None
    revision_number: int
    certificate_digest: Digest | None


def same_authored_case(stored: RebuildInputs, offered: RebuildInputs) -> bool:
    """Are these the same authored case?

    Every rebuild input except one, and the exception is the reason this is a
    function rather than ``==``.  The transcript prefix is *derived*: it is the
    empty prefix at the moment a case is opened and it moves with every
    publication, so comparing it would make re-opening a case succeed exactly
    once and then start failing -- which is not idempotence, it is a race with
    the case's own progress.  What identifies the case is what the officer
    signed and pinned.

    It lives here rather than in an adapter because it is the *contract* every
    ``open`` implementation has to satisfy.  Two adapters each carrying their
    own copy would be two definitions of case identity, and the one that drifted
    would be found by whichever suite happened to cover it.
    """
    return (
        stored.tenant_id == offered.tenant_id
        and stored.case_id == offered.case_id
        and stored.construction_digest == offered.construction_digest
        and stored.bundle_manifest_digest == offered.bundle_manifest_digest
        and stored.as_of == offered.as_of
        and stored.mode == offered.mode
        and stored.authorization_context_digest == offered.authorization_context_digest
    )


class CaseHeadRepository(Protocol):
    def open(self, inputs: RebuildInputs) -> Result[CaseHead, HeadError]:
        """Create the case if absent; return the existing head if the inputs match.

        Idempotent by ``same_authored_case`` rather than by the case identifier:
        two officers opening "the same case" under different pins are opening two
        different cases that happen to share a name.
        """
        ...

    def read(self, case_id: str) -> Result[CaseHead, HeadError]: ...

    def hold(self, case_id: str) -> Result[CaseHead, HeadError]:
        """Read the head, and hold this case against other writers until commit.

        The same value ``read`` returns, and a different guarantee: no other
        transaction may add to this case, or publish it, until the transaction
        that called this one ends.

        It exists because **an admission has to be checked against the
        transcript it will actually produce.**  Membership rows for two
        different entries have two different keys, so nothing about inserting
        them conflicts -- and under read-committed neither transaction can see
        the other's uncommitted row.  Two appenders, each admitting an entry
        that is individually fine and jointly refused, would therefore both
        rebuild successfully, both commit, and leave a transcript that rebuilds
        for nobody.  Membership is append-only, so that state is permanent.

        The contract is an *upper* bound on what may wait, not a lower one: no
        implementation may let a status query take it, and none may let it
        outlive the transaction that took it.  An adapter is free to be coarser
        -- the in-memory one makes every writing transaction exclusive and so
        satisfies this by excluding more than it has to -- which is exactly why
        an adapter that is coarser is not evidence for the property.  Only the
        PostgreSQL suite is: there the hold is one row lock on one case, and
        appends to other cases do not wait for it.

        Taking it is the caller's decision and not the repository's.  Nothing
        stops ``TranscriptRepository.add`` being called without it; what stops
        it happening is that one function in this package inserts membership,
        and an architecture test says so.
        """
        ...

    def advance(
        self,
        *,
        parent: CaseHead,
        prefix_digest: Digest,
        revision_digest: Digest,
        certificate_digest: Digest,
    ) -> Result[CaseHead, HeadError]:
        """Compare-and-swap the head from ``parent`` to the revision named here.

        The swap is conditional on the *whole* parent state -- revision digest,
        revision number, and every pinned rebuild input -- not on the revision
        digest alone.  A computation that analysed one parent therefore cannot
        publish over a head that is any other parent, including one that
        happens to carry the same revision digest under a different pin.

        The transcript prefix is the only rebuild input this operation may
        change, and it changes it from the argument rather than from the
        caller's copy of the inputs, so no other field can travel with it.
        """
        ...


#  ---- evidence requests --------------------------------------------------


class RequestFailure(Enum):
    UNKNOWN_CASE = "UNKNOWN_CASE"
    CONTENT_NOT_STORED = "CONTENT_NOT_STORED"
    #  One request id naming two different revisions. The id is the digest of a
    #  record that contains the revision, so this is corruption rather than a
    #  legitimate re-registration.
    REQUEST_IDENTITY_CONFLICT = "REQUEST_IDENTITY_CONFLICT"


@dataclass(frozen=True, slots=True)
class RequestError:
    failure: RequestFailure
    detail: str


@dataclass(frozen=True, slots=True)
class RecordedRequest:
    """Durable intent to ask for evidence.

    Everything here except the deadline is recomputable from the revision, and
    the deadline is precisely why the row exists: "answer by this instant" is
    wall-clock intent taken once, not a function of the record.

    There is no status column.  The only transition Milestone C could make --
    outstanding to superseded -- is exactly ``revision_digest`` no longer being
    the head's, so it is read off the head instead of written down twice.
    """

    case_id: str
    request_id: Digest
    revision_digest: Digest
    deadline: Instant

    def __post_init__(self) -> None:
        #  The backstop, not the rejection path. A misconfigured TTL produces an
        #  undurable deadline, and the command layer refuses that *before* it
        #  opens a transaction, as a typed rejection -- see ``advance._compute``.
        #  This is what makes both adapters refuse identically even when
        #  something reaches a repository directly.
        if not is_durable_instant(self.deadline):
            raise InvariantViolation(f"a deadline is not a durable instant: {self.deadline}")


class EvidenceRequestRepository(Protocol):
    def record(self, request: RecordedRequest) -> Result[bool, RequestError]:
        """Insert if absent. ``True`` when this call created the row."""
        ...

    def outstanding(self, case_id: str) -> Result[tuple[RecordedRequest, ...], RequestError]:
        """Requests bound to the revision the head currently names."""
        ...


#  ---- commitment envelopes -----------------------------------------------


class CommitmentFailure(Enum):
    UNKNOWN_CASE = "UNKNOWN_CASE"
    #: No envelope has been published for this revision.  A normal state, not a
    #: fault: a revision becomes head first and is committed immediately after,
    #: and a reader that arrives between the two is early rather than wrong.
    COMMITMENT_ABSENT = "COMMITMENT_ABSENT"


@dataclass(frozen=True, slots=True)
class CommitmentError:
    failure: CommitmentFailure
    detail: str


@dataclass(frozen=True, slots=True)
class PublishedCommitment:
    """A signed envelope, as the octets it was signed as.

    Octets rather than a decoded value, for the same reason the content store
    holds octets: the signature covers a canonical encoding, and a store that
    decoded and re-encoded would be asserting its own codec agrees with the one
    that signed.  It either returns what was written or it is broken.
    """

    case_id: str
    revision_digest: Digest
    envelope_octets: bytes


class CommitmentRepository(Protocol):
    """One immutable envelope per published revision.

    Append-only and insert-if-absent, like everything else that is authored
    rather than derived -- and an envelope is *both*, which is why it is stored
    at all.  Its content is a function of the record and the case salt, so it
    is reproducible; its signature is not, because the signing primitive is
    randomised and a managed key will not re-issue the same octets.  Storing it
    is therefore the only way a participant can be handed the same authenticated
    envelope twice.

    There is no update and no delete.  A second publication of one revision
    keeps the first envelope: two valid signatures over identical content are
    equally true, and choosing the later one would mean a participant who
    checked yesterday cannot check the same artifact today.
    """

    def publish(self, commitment: PublishedCommitment) -> Result[bool, CommitmentError]:
        """Insert if absent. ``True`` when this call created the row."""
        ...

    def read(
        self, case_id: str, revision_digest: Digest
    ) -> Result[PublishedCommitment, CommitmentError]:
        """The envelope published for this revision, or a typed absence."""
        ...


#  ---- transaction scopes -------------------------------------------------


class TenantScope(Protocol):
    """Every repository, already bound to one tenant."""

    @property
    def tenant_id(self) -> str: ...
    @property
    def content(self) -> ContentStore: ...
    @property
    def transcript(self) -> TranscriptRepository: ...
    @property
    def heads(self) -> CaseHeadRepository: ...
    @property
    def requests(self) -> EvidenceRequestRepository: ...
    @property
    def commitments(self) -> CommitmentRepository: ...


class CaseworkDatabase(Protocol):
    """Durable custody, entered one tenant and one transaction at a time.

    A transaction cannot span two tenants, because the tenant is named when the
    transaction is opened and the scope it yields has no way to change it.
    """

    def writing(self, tenant_id: str) -> AbstractContextManager[TenantScope]:
        """A read-write transaction. Committed on exit, rolled back on exception."""
        ...

    def reading(self, tenant_id: str) -> AbstractContextManager[TenantScope]:
        """A read-only transaction over one consistent snapshot.

        Read-only and repeatable-read, because the caller is about to derive a
        revision from what it reads and needs the head and the membership it
        saw to be the same instant.
        """
        ...
