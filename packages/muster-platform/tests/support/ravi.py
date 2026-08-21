"""The Ravi case, rebound to a fresh tenant and case, ready to be made durable.

The fixture is the kernel's, deliberately.  The whole claim of this milestone is
that surrounding the kernel with a database changes no answer, and the only way
to check that is to run the *same* case through both paths and compare the
digests -- so the case data has one home and the platform suite reads it rather
than restating it.

Rebinding is needed because the fixture carries one tenant and one case
identifier, and every test wants its own.  Rebinding is mechanical: the tenant
and case appear inside the signed payloads, so they are rewritten there too,
which changes every digest in the case.  That is correct and it is the point --
a receipt bound to a different tenant is a different receipt.

**The authority state is rebound too, and the same argument applies twice
over.**  A grant names the tenant it is scoped to, and a snapshot names the
tenant it was published for, so rebinding a case to a new tenant produces a new
authority snapshot with a new digest -- and the case's authorization context
has to be recomputed to pin it.  A test that rebound the case and kept the old
pin would be a test in which nothing is admissible, which is a confusing way to
discover that Q-12(c) works.

**Construction records and attestations are both signed for real.**
Milestones A to D carried an explicitly unsigned signature and said so; from E
the admission path verifies both, so an unsigned receipt is refused before
authority is consulted and an unsigned construction record is refused before a
head exists.  ``signed``
here mints a real ECDSA signature under the key the payload already names, so
every authority test starts from a receipt that is genuinely authentic and
fails, when it fails, on authority alone.  That is the separation the milestone
is about, and a suite that could not produce a valid signature could not
demonstrate it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from functools import cache
from pathlib import Path

from muster.application.case_file import (
    CaseFile,
    EngineConfiguration,
    load_case_file,
    load_engine_limits,
)
from muster.core.authority.check import AuthorityView
from muster.core.authority.grants import AuthorityRegistrySnapshot, canonical_grants
from muster.core.authority.revocation import RevocationSnapshot
from muster.core.authority.signing import SourceVerifier
from muster.core.case.revision import AuthorizationContext, RebuildMode
from muster.core.evidence.requests import EvidenceRequest
from muster.core.evidence.transcript import (
    Attestation,
    CaseConstructionRecord,
    Statement,
    TranscriptEntry,
)
from muster.core.results import Ok
from muster.core.values.times import Duration, Instant
from muster.domains.workforce.bundle import workforce_bundle
from muster.platform.authority.publish import (
    AuthorityPublisher,
    publish_authority_snapshot,
    publish_revocation_snapshot,
)
from muster.platform.casework.advance import Casework, CaseworkPolicy
from muster.platform.casework.ports import CaseworkDatabase
from muster.platform.ingest.admission import AdmissionAuthority
from muster.policy.registry import BundleRegistry
from muster.solve.backend import SolverBackend
from muster.solve.reference.bounded import BoundedEnumerationBackend
from support.authority import (
    AUTHORITY_PUBLISHER_KEY,
    WORKER,
    officer_verifier,
    publisher_signer,
    publisher_verifier,
    sign_construction,
    signed,
    source_verifier,
)
from support.paths import KERNEL_FIXTURES

CASE_FILE = KERNEL_FIXTURES / "ravi-saturday.json"
ATTESTED_CASE_FILE = KERNEL_FIXTURES / "ravi-saturday-attested.json"
LIMITS_FILE = KERNEL_FIXTURES / "engine-limits.json"

#  One hour, as a length rather than as a moment. A number the operator sets;
#  there is no default anywhere in the production code.
ONE_HOUR = Duration(3_600 * 1_000_000)

#  A clock reading, fixed. Every test that needs "now" passes this or an offset
#  from it, so a decision is reproducible by supplying the reading it was made
#  under rather than by controlling the machine's clock.
NOW: Instant = 1_760_000_000_000_000


@dataclass(frozen=True, slots=True)
class RaviCase:
    """A rebound copy of the fixture, plus the pieces the commands take."""

    tenant_id: str
    case_id: str
    policy_id: str
    construction: CaseConstructionRecord
    authorization_context: AuthorizationContext
    authority_snapshot: AuthorityRegistrySnapshot
    revocation_snapshot: RevocationSnapshot
    as_of: Instant
    mode: RebuildMode
    entries: tuple[TranscriptEntry, ...]
    #: What the case solicited.  Empty for the worked fixtures, which describe
    #: cases in which every receipt was volunteered -- see the case-file reader.
    #: Carried as a field rather than defaulted at each call site so a test that
    #: builds a solicited case has somewhere to put it.
    solicitations: tuple[EvidenceRequest, ...] = ()


@cache
def configuration() -> EngineConfiguration:
    loaded = load_engine_limits(LIMITS_FILE)
    assert isinstance(loaded, Ok), loaded
    return loaded.value


@cache
def _case_file(path: Path) -> CaseFile:
    loaded = load_case_file(path)
    assert isinstance(loaded, Ok), loaded
    return loaded.value


def backend() -> SolverBackend:
    return BoundedEnumerationBackend(configuration().enumeration_budget)


def registry() -> BundleRegistry:
    return BundleRegistry((workforce_bundle(),))


def casework(
    database: CaseworkDatabase,
    *,
    max_publication_attempts: int = 3,
    evidence_request_ttl: Duration = ONE_HOUR,
    solver: Callable[[], SolverBackend] | None = None,
    sources: SourceVerifier | None = None,
) -> Casework:
    """Compose the control plane over a database. No mocks anywhere in it.

    ``sources`` overrides the keyring the admission path verifies attestations
    against.  It is a parameter because a *deployed* source signs under a key
    this process never generated: the fixture keyring holds the seeded record's
    public halves, and a run that talks to real agents has to hold theirs as
    well.  Defaulting it to the fixture's keeps every existing caller reading
    the way it did.
    """
    return Casework(
        database=database,
        registry=registry(),
        backend=backend if solver is None else solver,
        limits=configuration().limits,
        policy=CaseworkPolicy(
            max_publication_attempts=max_publication_attempts,
            evidence_request_ttl=evidence_request_ttl,
        ),
        source_verifier=source_verifier() if sources is None else sources,
        publisher_verifier=publisher_verifier(),
        officer_verifier=officer_verifier(),
    )


def publish_authority(database: CaseworkDatabase, case: RaviCase) -> None:
    """Make this case's pinned authority state resolvable.

    Publishes exactly the two snapshots the case's context pins -- not
    equivalents, not a superset -- so a test that later substitutes one is
    substituting for something that was genuinely there.  Idempotent, because
    publication is insert-if-absent and several tests open the same case twice.
    """
    publisher = AuthorityPublisher(
        database=database,
        signer=publisher_signer(AUTHORITY_PUBLISHER_KEY),
        verifier=publisher_verifier(),
    )
    published = publish_authority_snapshot(
        publisher, tenant_id=case.tenant_id, snapshot=case.authority_snapshot, now=NOW
    )
    assert isinstance(published, Ok), published
    revoked = publish_revocation_snapshot(
        publisher, tenant_id=case.tenant_id, snapshot=case.revocation_snapshot, now=NOW
    )
    assert isinstance(revoked, Ok), revoked


def publish_authority_snapshot_for(
    database: CaseworkDatabase, tenant_id: str, snapshot: AuthorityRegistrySnapshot
) -> None:
    """Publish one more authority snapshot, making it the one in force.

    The successor half of the G7 story, as a helper: a test that needs "and
    then the publisher replaced it" should not have to assemble a publisher to
    say so.  Goes through the production publisher, so the publication state
    moves exactly as it does in production -- a test that wrote the row itself
    would be testing its own SQL.
    """
    publisher = AuthorityPublisher(
        database=database,
        signer=publisher_signer(AUTHORITY_PUBLISHER_KEY),
        verifier=publisher_verifier(),
    )
    published = publish_authority_snapshot(
        publisher, tenant_id=tenant_id, snapshot=snapshot, now=NOW
    )
    assert isinstance(published, Ok), published


#  The fixture's own identity. The acceptance path uses it unchanged, because
#  the frozen milestone-B digests are digests *of this tenant and this case* --
#  rebinding to a fresh tenant would change every one of them, and the whole
#  point of that test is that the database moves none of them.
FIXTURE_TENANT = "ALPHA"
FIXTURE_CASE = "CASE-RAVI-SAT-001"


def unbound(*, attested: bool = False) -> RaviCase:
    """The fixture case exactly as authored, with nothing rebound."""
    source = _case_file(ATTESTED_CASE_FILE if attested else CASE_FILE)
    return RaviCase(
        tenant_id=source.construction.tenant_id,
        case_id=source.construction.case_id,
        policy_id=source.policy_id,
        construction=sign_construction(source.construction),
        authorization_context=source.authorization_context,
        authority_snapshot=source.authority_snapshot,
        revocation_snapshot=source.revocation_snapshot,
        as_of=source.as_of,
        mode=source.mode,
        entries=signed(source.entries),
        solicitations=source.solicitations,
    )


def ravi(tenant_id: str, case_id: str, *, attested: bool = False) -> RaviCase:
    """The fixture case, rebound to this tenant and case identifier."""
    source = _case_file(ATTESTED_CASE_FILE if attested else CASE_FILE)
    authority = _rebind_authority(source.authority_snapshot, tenant_id)
    revoked = replace(source.revocation_snapshot, tenant_id=tenant_id)
    return RaviCase(
        tenant_id=tenant_id,
        case_id=case_id,
        policy_id=source.policy_id,
        construction=_rebind_construction(source.construction, tenant_id, case_id),
        #  Recomputed rather than carried across.  The pins are digests of the
        #  rebound snapshots, and a rebound case pinning the original tenant's
        #  authority would resolve nothing -- which is Q-12(c) working, but not
        #  the thing most tests are asking about.
        authorization_context=replace(
            source.authorization_context,
            authority_registry_snapshot_digest=authority.digest(),
            revocation_snapshot_digest=revoked.digest(),
        ),
        authority_snapshot=authority,
        revocation_snapshot=revoked,
        as_of=source.as_of,
        mode=source.mode,
        entries=signed(tuple(_rebind_entry(entry, tenant_id, case_id) for entry in source.entries)),
        solicitations=tuple(
            replace(request, tenant_id=tenant_id, case_id=case_id)
            for request in source.solicitations
        ),
    )


def _rebind_authority(
    snapshot: AuthorityRegistrySnapshot, tenant_id: str
) -> AuthorityRegistrySnapshot:
    """The same grants, scoped to another tenant.

    Every grant's ``tenant_scope`` moves with the snapshot's ``tenant_id``,
    because Q-12(c) requires all four of grant, snapshot, revision and payload
    to agree -- and a rebinding that moved only the outer one would produce a
    snapshot that grants nothing to anybody.
    """
    return replace(
        snapshot,
        tenant_id=tenant_id,
        grants=canonical_grants(
            replace(grant, tenant_scope=tenant_id) for grant in snapshot.grants
        ),
    )


def _rebind_construction(
    record: CaseConstructionRecord, tenant_id: str, case_id: str
) -> CaseConstructionRecord:
    #  Re-signed, not merely rebound.  The officer signature covers the tenant,
    #  the case and the coordinates, so a record whose tenant moved and whose
    #  signature did not is a record admission refuses -- correctly, and for a
    #  reason no test in this suite is about.
    return sign_construction(
        replace(
            record,
            tenant_id=tenant_id,
            case_id=case_id,
            parties=tuple(replace(party, tenant_id=tenant_id) for party in record.parties),
        )
    )


def _rebind_entry(entry: TranscriptEntry, tenant_id: str, case_id: str) -> TranscriptEntry:
    match entry:
        case Attestation(receipt):
            return Attestation(
                replace(
                    receipt,
                    payload=replace(receipt.payload, tenant_id=tenant_id, case_id=case_id),
                )
            )
        case Statement(record):
            return Statement(replace(record, tenant_id=tenant_id, case_id=case_id))


#  ---- shaping the worked transcript --------------------------------------
#
#  Here rather than beside the fleet fixture, because shaping a case is a
#  statement about the *case* and nothing in it knows an agent exists.  The
#  fleet fixture and the cloud composition root both read it, which is what
#  keeps "what the fleet is asked for" one list rather than two.

#: The Saturday under dispute, as the worked case names it.
SATURDAY = "SAT"

#: What the fleet is asked to supply in the worked run: the employer's roster
#: entry for the Saturday, and the site's two observations of it.  Removing the
#: worker's own statement as well is what lets a *worker agent* produce it from
#: his own words rather than the fixture producing it from JSON -- so a run
#: driving that agent removes all three, and a run replaying the claim removes
#: only what a source could attest.
ACQUIRED_BY_THE_FLEET: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("scheduled", (WORKER, SATURDAY)),
    ("present_on_site", (WORKER, SATURDAY)),
    ("on_site_duration", (WORKER, SATURDAY)),
)


def without(case: RaviCase, *propositions: tuple[str, tuple[str, ...]]) -> RaviCase:
    """The same case with named propositions removed from its transcript.

    The worked fixture carries a complete week.  An agent-driven run has to
    *acquire* the disputed Saturday rather than start with it, so the entries
    that would have answered it are removed and the fleet is asked instead.
    Everything else -- the authority snapshots, the construction record, the
    pins -- is untouched, so what the run exercises is acquisition and not a
    differently-configured case.
    """
    removed = set(propositions)
    return replace(
        case,
        entries=tuple(entry for entry in case.entries if _proposition(entry) not in removed),
    )


def without_attestations(case: RaviCase, *propositions: tuple[str, tuple[str, ...]]) -> RaviCase:
    """The same case with named propositions removed from its *attested* record.

    Statements stay.  A claim is not something a source can be asked for -- the
    fleet has no agent that could attest one and no target could name it -- so a
    run that acquires the attested half still replays what the claimant said,
    and the claim is inert on arrival exactly as it was when it was made.

    Separate from :func:`without` rather than a flag on it: the two express
    different intentions about the same case, and a boolean at the call site
    would say neither.
    """
    removed = set(propositions)
    return replace(
        case,
        entries=tuple(
            entry
            for entry in case.entries
            if not (isinstance(entry, Attestation) and _proposition(entry) in removed)
        ),
    )


def _proposition(entry: TranscriptEntry) -> tuple[str, tuple[str, ...]]:
    match entry:
        case Attestation(receipt):
            reference = receipt.payload.proposition
        case Statement(record):
            reference = record.proposition
        case _:
            raise AssertionError(f"an entry is an attestation or a statement: {entry}")
    return (reference.predicate_id, reference.args)


def admission_authority(case: RaviCase) -> AdmissionAuthority:
    """The authority input the admission path takes, built from a case.

    A required argument in production and therefore a required argument here.
    There is no test-only ``admit_entry`` that skips Q-12, because a bypass
    that exists for tests is a bypass -- so a suite about membership or about
    idempotence builds a real view and admits a genuinely authorized receipt,
    and the authority machinery is exercised on every one of those runs rather
    than only in the tests named after it.
    """
    bundle = workforce_bundle()
    return AdmissionAuthority(
        source_verifier=source_verifier(),
        schema=bundle.predicate_schema,
        pinned_schema_digest=bundle.predicate_schema.digest(),
        view=AuthorityView(
            snapshot=case.authority_snapshot,
            revocation=case.revocation_snapshot,
            tenant_id=case.tenant_id,
            authorization_policy_version=(case.authorization_context.authorization_policy_version),
            case_scope_coordinates=case.construction.case_scope_coordinates,
            as_of=case.as_of,
        ),
        #  Empty by default: a suite fixture describes a tenant that has
        #  withdrawn nothing.  A test about withdrawal publishes a revocation
        #  and goes through ``append_transcript_entry``, which resolves the
        #  real set -- there is no way to reach the gate by handing this
        #  helper a value.
        withdrawn_keys=frozenset(),
    )
