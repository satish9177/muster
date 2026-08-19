"""A historical disclosure does not need today's solver, and does not trust a row.

Five regressions for one invariant and its fail-closed edges.

The invariant: **a view committed yesterday stays readable after the engine is
reconfigured today.**  A certificate records what a particular solver, at a
particular version, under a particular budget, answered -- so re-deriving one
asks a *different* engine to reproduce it, and an operator raising a bound would
otherwise make every case committed before the change permanently undisclosable.
The revision is still replayed, byte for byte; only the certificate is read.

The edges: reading a stored artifact instead of deriving it is safe only if
every way the row could be wrong is refused.  Four of these tests are that
refusal -- tampered octets, octets that are not their own digest, a certificate
belonging to another case, and one belonging to another revision or another
rulebook.

The same invariant, one layer up: a stored *envelope* names the key that signed
it, so rotating the control plane's signing key must not orphan every
commitment taken before the rotation either.  Three more tests hold that line
and the two refusals that keep it safe -- a key this control plane never held,
and a signature that does not verify under the key the row names.

They are one file because they are one argument.  A reader who accepts the
first test has to see the other seven next to it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from muster.core.analysis.certificate import AnalysisCertificate
from muster.core.evidence.transcript import Signature
from muster.core.results import Err, Ok, Result
from muster.core.wire.codec import decode, encode
from muster.core.wire.digests import Digest, DigestKind
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.casework.commands import case_status
from muster.platform.casework.ports import (
    CaseHead,
    CaseHeadRepository,
    CommitmentRepository,
    ContentStore,
    EvidenceRequestRepository,
    StoreError,
    TranscriptRepository,
)
from muster.platform.casework.snapshot import SnapshotFailure, read_certificate
from muster.platform.commit.envelope import read_signed_envelope
from muster.platform.commit.publish import Commitment, CommitmentFailureReason, read_commitment
from muster.platform.disclose.audience import AudienceClass
from muster.platform.disclose.queries import (
    DisclosureFailure,
    DisclosureRejection,
    DisclosureService,
    get_my_view,
)
from muster.platform.disclose.verify import accepted, verify_view
from muster.platform.disclose.views import View
from muster.solve.reference.bounded import BoundedEnumerationBackend
from support import ravi
from support.commitment import (
    MUSTER_KEY,
    NOTIFICATION,
    NOW,
    OTHER_KEY,
    WORKER,
    CommittedFixture,
    committed_case,
    directory_for,
    reader,
    salts,
    signing_pair,
    workforce_policy,
)

TENANT = "T-HISTORY"
CASE = "CASE-HISTORY-1"

#  Configuration B: the same backend under a different enumeration budget.  The
#  budget sits inside the solver fingerprint and the fingerprint inside the
#  certificate, so this is the smallest honest way to make *this* engine unable
#  to reproduce what the stored certificate says -- while touching not one input
#  the revision is a function of.
OTHER_BUDGET = ravi.configuration().enumeration_budget + 1


def _fixture() -> CommittedFixture:
    return committed_case(tenant_id=TENANT, case_id=CASE)


def _reopened(
    fixture: CommittedFixture,
    *,
    budget: int,
    key_ref: str = MUSTER_KEY,
    retired: frozenset[str] = frozenset(),
) -> DisclosureService:
    """The same durable records, under a freshly composed control plane.

    A new ``MemoryDatabase`` over the records the first one left behind, a new
    solver factory and a freshly composed signer: everything a restart
    replaces, and nothing that was written down.  ``key_ref`` and ``retired``
    are how a test spells a *rotation* rather than a restart -- the process
    comes back holding a different signing key and still honouring the old one.
    """
    database = MemoryDatabase(fixture.database.records)
    signer, verifier = signing_pair(key_ref)
    return DisclosureService(
        commitment=Commitment(
            casework=ravi.casework(database, solver=lambda: BoundedEnumerationBackend(budget)),
            salts=salts(),
            signer=signer,
            verifier=verifier,
            retired_key_refs=retired,
        ),
        directory=directory_for(TENANT),
    )


def _worker_view(service: DisclosureService) -> Result[View, DisclosureRejection]:
    return get_my_view(
        service,
        tenant_id=TENANT,
        principal=WORKER,
        case_id=CASE,
        context=NOTIFICATION,
        acting_as=None,
    )


def _verifies(fixture: CommittedFixture, view: View) -> bool:
    return accepted(
        verify_view(
            view,
            reader(
                policy=workforce_policy(),
                pins=fixture.pins,
                audience=AudienceClass("WORKER"),
                context=NOTIFICATION,
            ),
        )
    )


#  ---- A and E: the invariant ------------------------------------------------


def test_A_a_view_survives_an_engine_reconfiguration() -> None:
    """Publish under configuration A, close, reopen under B, read the same view.

    Nothing about the case changes: the same records, the same transcript, the
    same head.  What changes is the engine's enumeration budget, which is inside
    the solver fingerprint and therefore inside the certificate -- exactly the
    kind of operational change that used to make an already-committed case
    unreadable.

    The view that comes back is compared octet for octet, not merely accepted.
    A disclosure that *verified* while differing would mean the recipient who
    checked it yesterday and the one who checks it today are checking two
    different artifacts.
    """
    fixture = _fixture()
    before = _worker_view(fixture.service)
    assert isinstance(before, Ok), before

    after = _worker_view(_reopened(fixture, budget=OTHER_BUDGET))
    assert isinstance(after, Ok), after

    assert encode(after.value.to_node()) == encode(before.value.to_node())
    assert _verifies(fixture, after.value)


def test_E_an_engine_that_cannot_reproduce_the_certificate_still_discloses() -> None:
    """The same reconfiguration, with the non-reproduction asserted rather than assumed.

    ``test_A`` would pass vacuously if the budget change happened not to move
    the certificate.  So this one asks the status query -- which does re-derive
    the certificate, and reports honestly whether *this* process's engine
    reproduces the one the head names -- and requires the answer to be no.
    Under that condition, and with the revision still replaying exactly, the
    disclosure has to remain readable.  That is the whole claim.
    """
    fixture = _fixture()
    reopened = _reopened(fixture, budget=OTHER_BUDGET)

    report = case_status(reopened.commitment.casework, tenant_id=TENANT, case_id=CASE, now=NOW)
    assert isinstance(report, Ok), report
    #  The revision still reproduces. Asserted from the *replayed* value rather
    #  than from the head's own column, which is durable and would agree with
    #  itself: ``case_status`` derives this by rebuilding, and returns
    #  ``REVISION_DIVERGED`` instead when the two disagree.
    analysis = report.value.analysis
    assert analysis is not None
    assert analysis.revision.digest() == report.value.head.revision_digest
    #  The certificate does not, and that alone must cost nothing.
    assert report.value.certificate_reproduced is False

    served = _worker_view(reopened)
    assert isinstance(served, Ok), served
    assert _verifies(fixture, served.value)

    #  And the commitment reads back as the same envelope, signature included.
    read = read_commitment(reopened.commitment, tenant_id=TENANT, case_id=CASE)
    assert isinstance(read, Ok), read
    assert read.value.commitment.signed_envelope == fixture.committed.commitment.signed_envelope


#  ---- B, C, D: the edges ----------------------------------------------------


def _certificate_of(fixture: CommittedFixture) -> AnalysisCertificate:
    return fixture.committed.record.certificate


def _head_of(fixture: CommittedFixture) -> CaseHead:
    return fixture.database.records.heads[(TENANT, CASE)]


def _repoint(fixture: CommittedFixture, certificate: AnalysisCertificate) -> None:
    """Store this certificate under its own digest and have the head name it.

    Going around the repositories on purpose.  The application cannot produce
    this state -- a head names the certificate the analysis that advanced it
    produced -- so the only way to test the refusal is to write the row the way
    an operator with SQL could.
    """
    octets = encode(certificate.to_node())
    records = fixture.database.records
    records.content[(TENANT, certificate.digest())] = (
        DigestKind.ANALYSIS_CERTIFICATE.value,
        octets,
    )
    records.heads[(TENANT, CASE)] = replace(
        _head_of(fixture), certificate_digest=certificate.digest()
    )


def test_B_tampered_certificate_octets_fail_closed() -> None:
    """One flipped bit in the stored row, and nothing is served.

    The store re-derives the digest on every read, so the refusal arrives
    before the typed reader sees anything -- and it arrives as a refusal, not
    as a decode exception on the disclosure path.
    """
    fixture = _fixture()
    digest = _certificate_of(fixture).digest()
    records = fixture.database.records
    kind, octets = records.content[(TENANT, digest)]
    records.content[(TENANT, digest)] = (kind, octets[:-1] + bytes([octets[-1] ^ 0x01]))

    refused = read_commitment(fixture.service.commitment, tenant_id=TENANT, case_id=CASE)
    assert isinstance(refused, Err)
    assert refused.error.failure is CommitmentFailureReason.CERTIFICATE_UNREADABLE

    served = _worker_view(fixture.service)
    assert isinstance(served, Err)
    assert served.error.failure is DisclosureFailure.COMMITMENT_REFUSED


def test_C_a_certificate_that_is_not_its_own_digest_fails_closed() -> None:
    """The check that does not delegate to the store.

    ``read_certificate`` re-encodes what it read and compares the digest against
    the key it came from.  That is not a second opinion about the store -- it is
    the claim that *this reader is lossless for these octets*, which is what the
    whole commitment rests on: every leaf is re-encoded from the value the
    reader returns, so a reader that silently dropped a field would publish a
    smaller record that still verified against itself.

    Proving it needs a store that does not check, because a store that does
    checks first.  So this one hands back octets that are not their key's
    preimage, and the reader refuses on its own.
    """
    fixture = _fixture()
    certificate = _certificate_of(fixture)
    someone_else = replace(certificate, tenant_id="T-ELSEWHERE")

    refused = read_certificate(
        _ContentOnlyScope(TENANT, _UncheckedStore(encode(someone_else.to_node()))),
        _head_of(fixture),
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is SnapshotFailure.CONTENT_UNREADABLE
    assert "re-encoding" in refused.error.detail

    #  And the honest octets pass the same check, so the test is about the
    #  substitution rather than about the reader being broken.
    accepted_read = read_certificate(
        _ContentOnlyScope(TENANT, _UncheckedStore(encode(certificate.to_node()))),
        _head_of(fixture),
    )
    assert isinstance(accepted_read, Ok), accepted_read
    #  Compared as octets, not as values. Losslessness is a claim about the
    #  encoding: a set-valued field comes back in canonical order whatever order
    #  its producer used, so value equality is a stronger claim than the design
    #  makes and would fail on a bundle that happened to list source classes
    #  unsorted -- while nothing was wrong.
    assert encode(accepted_read.value.to_node()) == encode(certificate.to_node())


def test_D_a_certificate_bound_elsewhere_fails_closed() -> None:
    """Three ways to be a perfectly good certificate for a different question.

    Each one is well-formed, canonically encoded and stored under its own true
    digest, so nothing about the octets is wrong.  What is wrong is which case,
    which revision, or which rulebook they are about -- and all three are
    reported as *not bound*, which is the operator-facing distinction that
    matters: the artifact is fine and it is not this case's, as opposed to a
    row that is corrupt or a row that is gone.
    """
    certificate = _certificate_of(_fixture())

    elsewhere = (
        (
            replace(certificate, case_id="CASE-SOMEWHERE-ELSE"),
            CommitmentFailureReason.CERTIFICATE_NOT_BOUND,
        ),
        (
            replace(certificate, revision_semantic_digest=Digest(bytes(32))),
            CommitmentFailureReason.CERTIFICATE_NOT_BOUND,
        ),
        (
            replace(certificate, bundle_manifest_digest=Digest(bytes(range(32)))),
            CommitmentFailureReason.CERTIFICATE_NOT_BOUND,
        ),
    )

    for substitute, expected in elsewhere:
        fixture = _fixture()
        _repoint(fixture, substitute)

        refused = read_commitment(fixture.service.commitment, tenant_id=TENANT, case_id=CASE)
        assert isinstance(refused, Err), substitute
        assert refused.error.failure is expected, refused

        served = _worker_view(fixture.service)
        assert isinstance(served, Err)
        assert served.error.failure is DisclosureFailure.COMMITMENT_REFUSED


#  ---- F, G, H: the same invariant, one layer up -----------------------------


def test_F_a_view_survives_a_signing_key_rotation() -> None:
    """Rotate the control plane's signing key; yesterday's view still reads.

    A stored envelope names the key that signed it, inside the signed body.  A
    read path that re-derived that field from the key it holds *today* would
    demand that last year's envelope name this year's key, and would therefore
    refuse every commitment taken before a rotation -- permanently, with nothing
    wrong anywhere.  That is the engine-configuration failure again, in the
    custody dimension, and it fails the same test.

    The rotated process signs under the new key and still honours the old one.
    What it must not do is *re-sign*: the artifact a participant checks has to
    be the one they were handed before.
    """
    fixture = _fixture()
    before = _worker_view(fixture.service)
    assert isinstance(before, Ok), before

    rotated = _reopened(
        fixture, budget=OTHER_BUDGET, key_ref=OTHER_KEY, retired=frozenset({MUSTER_KEY})
    )
    after = _worker_view(rotated)
    assert isinstance(after, Ok), after

    assert encode(after.value.to_node()) == encode(before.value.to_node())
    #  Still signed by the retired key, and still verifiable by a recipient who
    #  holds its public half -- which is why the recipient's trusted set is
    #  about keys and not about which one is current.
    assert after.value.envelope.envelope.signer_key_ref == MUSTER_KEY
    assert _verifies(fixture, after.value)


def test_G_an_envelope_naming_an_unaccepted_key_is_refused() -> None:
    """The check that keeps the rotation fix from being a hole.

    Deriving the signer reference from the row is what makes rotation work, and
    on its own it would make the field comparison tautological on exactly the
    field an attacker with database access would move.  What closes it is that
    the reference must be one this control plane holds or has retired -- so a
    process that rotated *without* retaining the old key refuses rather than
    serving an envelope it cannot account for.
    """
    fixture = _fixture()
    orphaned = _reopened(fixture, budget=OTHER_BUDGET, key_ref=OTHER_KEY)

    refused = read_commitment(orphaned.commitment, tenant_id=TENANT, case_id=CASE)
    assert isinstance(refused, Err)
    assert refused.error.failure is CommitmentFailureReason.SIGNER_NOT_ACCEPTED

    served = _worker_view(orphaned)
    assert isinstance(served, Err)
    assert served.error.failure is DisclosureFailure.COMMITMENT_REFUSED


def test_H_a_stored_signature_that_does_not_verify_is_refused() -> None:
    """And the other half: an accepted key reference is not an accepted envelope.

    The control plane checks the signature on what it is about to serve.  That
    does not make the recipient's own check redundant -- refusing to *serve* an
    artifact you cannot authenticate is a different act from refusing to
    *believe* one -- but it is what stops a row written by something that could
    not sign from reaching a participant at all.
    """
    fixture = _fixture()
    records = fixture.database.records
    key = (TENANT, CASE, fixture.committed.record.revision.digest())
    stored = records.commitments[key]

    node = decode(stored.envelope_octets)
    assert isinstance(node, Ok), node
    signed = read_signed_envelope(node.value)
    forged = replace(
        signed,
        signature=Signature(
            signed.signature.algorithm,
            bytes(octet ^ 0xFF for octet in signed.signature.octets),
        ),
    )
    records.commitments[key] = replace(stored, envelope_octets=forged.octets())

    refused = read_commitment(fixture.service.commitment, tenant_id=TENANT, case_id=CASE)
    assert isinstance(refused, Err)
    assert refused.error.failure is CommitmentFailureReason.ENVELOPE_NOT_AUTHENTIC

    served = _worker_view(fixture.service)
    assert isinstance(served, Err)
    assert served.error.failure is DisclosureFailure.COMMITMENT_REFUSED


#  ---- the store that does not check -----------------------------------------


@dataclass(frozen=True, slots=True)
class _UncheckedStore:
    """A content store that hands back whatever it was given.

    Exists to isolate one guard.  Both real adapters verify that stored octets
    hash to the key they are stored under, which is right and which also means
    no test against them can show what the commit layer does on its own.
    """

    octets: bytes

    def put(self, kind: DigestKind, octets: bytes) -> Result[Digest, StoreError]:
        raise NotImplementedError(f"{kind.value}: {len(octets)} octets")

    def get(self, kind: DigestKind, digest: Digest) -> Result[bytes, StoreError]:
        assert kind is DigestKind.ANALYSIS_CERTIFICATE
        assert digest.octets
        return Ok(self.octets)


@dataclass(frozen=True, slots=True)
class _ContentOnlyScope:
    """A tenant scope with a content store and nothing else.

    ``read_certificate`` reads octets and re-binds them, so those are the only
    two members it may touch; the rest raise rather than return an empty
    stand-in, which is what makes that a fact this test establishes rather than
    a claim it makes.
    """

    tenant_id: str
    content: ContentStore

    @property
    def transcript(self) -> TranscriptRepository:
        raise NotImplementedError

    @property
    def heads(self) -> CaseHeadRepository:
        raise NotImplementedError

    @property
    def requests(self) -> EvidenceRequestRepository:
        raise NotImplementedError

    @property
    def commitments(self) -> CommitmentRepository:
        raise NotImplementedError
