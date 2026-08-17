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
from muster.core.case.revision import AuthorizationContext, RebuildMode
from muster.core.evidence.transcript import (
    Attestation,
    CaseConstructionRecord,
    Statement,
    TranscriptEntry,
)
from muster.core.results import Ok
from muster.core.values.times import Duration, Instant
from muster.domains.workforce.bundle import workforce_bundle
from muster.platform.casework.advance import Casework, CaseworkPolicy
from muster.platform.casework.ports import CaseworkDatabase
from muster.policy.registry import BundleRegistry
from muster.solve.backend import SolverBackend
from muster.solve.reference.bounded import BoundedEnumerationBackend
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
    as_of: Instant
    mode: RebuildMode
    entries: tuple[TranscriptEntry, ...]


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
) -> Casework:
    """Compose the control plane over a database. No mocks anywhere in it."""
    return Casework(
        database=database,
        registry=registry(),
        backend=backend if solver is None else solver,
        limits=configuration().limits,
        policy=CaseworkPolicy(
            max_publication_attempts=max_publication_attempts,
            evidence_request_ttl=evidence_request_ttl,
        ),
    )


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
        construction=source.construction,
        authorization_context=source.authorization_context,
        as_of=source.as_of,
        mode=source.mode,
        entries=source.entries,
    )


def ravi(tenant_id: str, case_id: str, *, attested: bool = False) -> RaviCase:
    """The fixture case, rebound to this tenant and case identifier."""
    source = _case_file(ATTESTED_CASE_FILE if attested else CASE_FILE)
    return RaviCase(
        tenant_id=tenant_id,
        case_id=case_id,
        policy_id=source.policy_id,
        construction=_rebind_construction(source.construction, tenant_id, case_id),
        authorization_context=source.authorization_context,
        as_of=source.as_of,
        mode=source.mode,
        entries=tuple(_rebind_entry(entry, tenant_id, case_id) for entry in source.entries),
    )


def _rebind_construction(
    record: CaseConstructionRecord, tenant_id: str, case_id: str
) -> CaseConstructionRecord:
    return replace(
        record,
        tenant_id=tenant_id,
        case_id=case_id,
        parties=tuple(replace(party, tenant_id=tenant_id) for party in record.parties),
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
