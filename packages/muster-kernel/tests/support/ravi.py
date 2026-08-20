"""Running the Ravi case, once, for whatever a test needs to look at."""

from __future__ import annotations

from functools import cache

from muster.application.case_file import (
    CaseFile,
    EngineConfiguration,
    load_case_file,
    load_engine_limits,
)
from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.case.revision import CaseRevision
from muster.core.results import Ok
from muster.domains.workforce.bundle import workforce_bundle
from muster.hinge.prepare import EngineLimits
from muster.policy.manifest import LoadedBundle
from muster.solve.reference.bounded import BoundedEnumerationBackend
from tests.conftest import FIXTURES

CASE_FILE = FIXTURES / "ravi-saturday.json"
ATTESTED_CASE_FILE = FIXTURES / "ravi-saturday-attested.json"
LIMITS_FILE = FIXTURES / "engine-limits.json"

RAVI = "RAVI"
SATURDAY = "SAT"


@cache
def configuration() -> EngineConfiguration:
    loaded = load_engine_limits(LIMITS_FILE)
    assert isinstance(loaded, Ok), loaded
    return loaded.value


def limits() -> EngineLimits:
    return configuration().limits


@cache
def case_file() -> CaseFile:
    loaded = load_case_file(CASE_FILE)
    assert isinstance(loaded, Ok), loaded
    return loaded.value


@cache
def attested_case_file() -> CaseFile:
    """The variant whose transcript carries the site and duration attestations."""
    loaded = load_case_file(ATTESTED_CASE_FILE)
    assert isinstance(loaded, Ok), loaded
    return loaded.value


@cache
def bundle() -> LoadedBundle:
    return workforce_bundle()


@cache
def revision() -> CaseRevision:
    case = case_file()
    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    inputs = case.rebuild_inputs(bundle().digest(), prefix.digest())
    built = rebuild(
        inputs,
        case.construction,
        case.entries,
        bundle(),
        case.authorization_context,
        case.authority_snapshot,
        case.revocation_snapshot,
        case.solicitations,
    )
    assert isinstance(built, Ok), built
    return built.value


def backend() -> BoundedEnumerationBackend:
    return BoundedEnumerationBackend(configuration().enumeration_budget)


@cache
def analysis() -> CaseAnalysis:
    produced = analyse_revision(revision(), bundle(), backend(), limits())
    assert isinstance(produced, Ok), produced
    return produced.value
