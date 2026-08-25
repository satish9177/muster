"""The worked run, driven from inside the project against deployed agents.

    replay Ravi               -> an opened case, an inert claim, a divergence
    analyse                   -> an EvidenceRequest naming three propositions
    the fleet catalog         -> two agents, one per source class
    the control plane's own   -> the site's raw object          DENIED
      identity
    HttpAcquisitionTransport  -> authenticated Cloud Run agents -> configured Gemini
    signed receipts           -> append_transcript_entry        -> Q-12
    rebuild and analyse       -> Invariant

Run it as a Cloud Run job under ``muster-control-plane``:

    infra/scripts/90-hero-job.sh

**This is the control plane, and it is the whole of it.** Every step uses the
production-oriented application path -- ``open_case``, ``append_transcript_entry``,
``acquire_outstanding``, ``case_status`` -- carried to the fleet by
``HttpAcquisitionTransport`` over authenticated HTTPS.  There is no in-process
agent here and there cannot be one: this module imports nothing from
``muster.agents``, the image it runs in installs no agent distribution, and the
paths it puts on ``sys.path`` do not include one.  What answers is whatever is
deployed at the endpoints the catalog names.

**It runs a model nowhere.**  A model is called inside each *source*, over that
source's own material, behind that source's own identity.  The process that
holds the case record has no model client, no storage client and no source key,
and the run demonstrates the last of those by trying: it asks Cloud Storage for
the site's raw object under its own identity, before it acquires anything, and
expects to be refused.

**The claim is replayed rather than re-elicited.**  ``demo/hero.py`` drives the
worker agent so that Ravi's message becomes a claim in front of you; here the
claim is already in the case, exactly as the fixture authored it, because a
claim is not something a source can be asked for and the worker agent is not
deployed.  What the fleet is asked for is the attested half, and that is the
half that crosses a network.

**Nothing this prints is evidence.**  The narration carries predicate names,
identifiers, digests, enum values and counts.  It never prints a ``detail``
field, a model's words, a prompt, an object body, a token or a key -- the
control plane's own output is the last place source material could leak from,
and the discipline is a closed vocabulary rather than a filter.

**Where it stops.**  At the analysis.  There is no gate here, nothing is
authorized, and nothing is settled -- those belong to a later milestone, and a
demo that acted would be claiming a capability this system does not have.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
#  The kernel, the control plane, and the fixture that holds the worked case.
#  **Deliberately not the fleet.**  An agent package on this path would make
#  "no model runs here" a thing to check rather than a thing that is true.
for _entry in (
    REPOSITORY,
    REPOSITORY / "packages" / "muster-kernel" / "src",
    REPOSITORY / "packages" / "muster-platform" / "src",
    REPOSITORY / "packages" / "muster-platform" / "tests",
):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from muster.core.analysis.outcomes import Invariant, outcome_class  # noqa: E402
from muster.core.authority.grants import canonical_grants  # noqa: E402
from muster.core.evidence.delivery import AcquisitionTransport  # noqa: E402
from muster.core.evidence.requests import EvidenceRequest  # noqa: E402
from muster.core.evidence.transcript import Statement, StatementRecord  # noqa: E402
from muster.core.results import Err, Ok  # noqa: E402
from muster.core.values.scalars import render  # noqa: E402
from muster.core.values.times import Instant  # noqa: E402
from muster.platform.adapters.http import (  # noqa: E402
    HttpAcquisitionTransport,
    MetadataServerTokens,
    direct_opener,
)
from muster.platform.adapters.sql.config import (  # noqa: E402
    DatabaseConfigurationError,
    DatabaseDeployment,
    configuration_from_environment,
)
from muster.platform.adapters.sql.schema import (  # noqa: E402
    SchemaNotCurrent,
    require_current_schema,
)
from muster.platform.casework.advance import Casework  # noqa: E402
from muster.platform.casework.commands import (  # noqa: E402
    CaseReport,
    append_transcript_entry,
    case_status,
)
from muster.platform.casework.ports import CaseworkDatabase  # noqa: E402
from muster.platform.dispatch.acquire import (  # noqa: E402
    Abstained,
    AcquisitionReport,
    Answered,
    EnvelopeRefused,
    Unreachable,
    acquire_outstanding,
)
from muster.platform.orchestration.decisions import Dispatch  # noqa: E402
from support import ravi  # noqa: E402
from support.authority import (  # noqa: E402
    payroll_grant,
    payroll_profile,
    publish_fleet,
    site_grant,
    site_profile,
    source_keyring,
)
from support.fixtures import open_ravi  # noqa: E402
from support.ravi import RaviCase  # noqa: E402

#  ---- configuration -------------------------------------------------------
#
#  Read once, from the environment, at start-up -- the same discipline a
#  deployed agent's configuration is read under, and for the same reason: a
#  value read per step is a value that can differ between two steps.

TENANT = "MUSTER_HERO_TENANT"
CASE = "MUSTER_HERO_CASE"
SITE_ENDPOINT = "MUSTER_HERO_SITE_ENDPOINT"
EMPLOYER_ENDPOINT = "MUSTER_HERO_EMPLOYER_ENDPOINT"
SITE_KEY_REF = "MUSTER_HERO_SITE_KEY_REF"
EMPLOYER_KEY_REF = "MUSTER_HERO_EMPLOYER_KEY_REF"
SITE_PUBLIC_KEY = "MUSTER_HERO_SITE_PUBLIC_KEY"
EMPLOYER_PUBLIC_KEY = "MUSTER_HERO_EMPLOYER_PUBLIC_KEY"
TIMEOUT = "MUSTER_HERO_TIMEOUT_SECONDS"
RAW_OBJECT = "MUSTER_HERO_RAW_OBJECT"
#  The database is not read from a ``MUSTER_HERO_`` variable of its own.  Both
#  the custody label and the connection string belong to the SQL adapter's
#  configuration, which validates them, and a second name for the same value is
#  the beginning of two deployments disagreeing about which one is authoritative.

#: Where a workload on Google Cloud asks for an OAuth token naming itself.  A
#: sibling of the identity endpoint the transport uses, and reached the same
#: way: no client library, no credential to hold, and an answer that depends on
#: where the request came from rather than on anything this process knows.
METADATA_TOKEN_URL = (
    #  The address of an endpoint, not a credential.
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"  # noqa: S105
)
METADATA_HEADER = ("Metadata-Flavor", "Google")

#: The object-metadata read the control plane must be refused.  ``fields=name``
#: is not a courtesy: the JSON API would otherwise answer with the object's
#: full metadata, and the *media* form of this URL would answer with its
#: octets.  What is being tested is whether the identity may reach the object
#: at all -- ``storage.objects.get`` gates both -- so the request is shaped to
#: bring back nothing that could be evidence even if it succeeded.
STORAGE_OBJECT_URL = "https://storage.googleapis.com/storage/v1/b/{bucket}/o/{object}?fields=name"

#: What the probe reads of an answer it should never get.  A few octets: enough
#: for a JSON error body's status, and far too few to carry a gate log.
MAX_PROBE_OCTETS = 512


@dataclass(frozen=True, slots=True)
class CloudFleet:
    """Everything the run needs that is not in the case."""

    tenant_id: str
    case_id: str
    site_endpoint: str
    employer_endpoint: str
    site_key_ref: str
    employer_key_ref: str
    #: The public halves of the deployed signing keys, as PEM.  Public
    #: material: it is what a verifier holds, and holding it grants nothing.
    site_public_key: bytes
    employer_public_key: bytes
    #: How long to wait for a source.  ``None`` leaves the transport's own
    #: default in place rather than restating it here, so the arithmetic behind
    #: the number lives in one place and a deployment overrides it or does not.
    timeout_seconds: float | None
    #: ``gs://bucket/object`` -- the raw object this identity must not reach.
    raw_object: str | None
    postgres: str | None
    #: Which custody this deployment *chose*.  Defaulted, because the suite's
    #: fleet is an in-memory one and says so by carrying no DSN; a deployed run
    #: never inherits this default, because ``from_environment`` refuses to
    #: assemble a fleet without an explicit label.
    deployment: DatabaseDeployment = DatabaseDeployment.EPHEMERAL

    def __post_init__(self) -> None:
        """Custody and connection string agree, however the fleet was built.

        ``from_environment`` already establishes this.  Stating it here closes
        the other door: a fleet constructed directly -- in a test, in a future
        composition root -- cannot claim Cloud SQL custody with no DSN, nor
        carry a DSN it has decided not to use.
        """
        durable = self.deployment is not DatabaseDeployment.EPHEMERAL
        if durable and not self.postgres:
            raise ValueError(f"{self.deployment.value} custody names no database")
        if not durable and self.postgres:
            raise ValueError("EPHEMERAL custody carries no database")

    @property
    def hosts(self) -> frozenset[str]:
        """The hosts this deployment will send an authenticated request to.

        Taken from the *configuration* rather than from the catalog it also
        publishes.  A catalog is a signed publication and this run happens to
        write it, but the transport's allowlist exists precisely for the case
        where a catalog says something the deployment never authorised -- so it
        is read from the one place a compromised catalog cannot reach.
        """
        found = {
            urllib.parse.urlsplit(endpoint).hostname
            for endpoint in (self.site_endpoint, self.employer_endpoint)
        }
        return frozenset(host for host in found if host)


def from_environment(environ: dict[str, str] | None = None) -> CloudFleet:
    """Read the deployment's configuration, or say which variable is wrong."""
    source = dict(os.environ) if environ is None else environ

    try:
        database = configuration_from_environment(source, require_deployed=True)
    except DatabaseConfigurationError as error:
        raise SystemExit(f"muster-cloud-hero: DATABASE CONFIGURATION REFUSED: {error}") from error

    def required(name: str) -> str:
        value = (source.get(name) or "").strip()
        if not value:
            raise SystemExit(f"muster-cloud-hero: MISSING: {name}")
        return value

    def pem(name: str) -> bytes:
        #  Base64 rather than the PEM itself, because a PEM is multi-line and
        #  an environment variable that has to survive a deployment script,
        #  a container spec and a shell is better off with no newlines in it.
        try:
            return base64.b64decode(required(name), validate=True)
        except ValueError as malformed:
            raise SystemExit(f"muster-cloud-hero: MALFORMED: {name} is not base64") from malformed

    def seconds(name: str) -> float | None:
        raw = (source.get(name) or "").strip()
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError as malformed:
            raise SystemExit(f"muster-cloud-hero: MALFORMED: {name}") from malformed

    fleet = CloudFleet(
        tenant_id=required(TENANT),
        case_id=required(CASE),
        site_endpoint=required(SITE_ENDPOINT),
        employer_endpoint=required(EMPLOYER_ENDPOINT),
        site_key_ref=required(SITE_KEY_REF),
        employer_key_ref=required(EMPLOYER_KEY_REF),
        site_public_key=pem(SITE_PUBLIC_KEY),
        employer_public_key=pem(EMPLOYER_PUBLIC_KEY),
        timeout_seconds=seconds(TIMEOUT),
        raw_object=(source.get(RAW_OBJECT) or "").strip() or None,
        postgres=database.dsn,
        deployment=database.deployment,
    )
    for endpoint in (fleet.site_endpoint, fleet.employer_endpoint):
        if not endpoint.startswith("https://"):
            raise SystemExit(f"muster-cloud-hero: MALFORMED: {endpoint!r} is not an https endpoint")
    if fleet.site_key_ref == fleet.employer_key_ref:
        #  One reference resolves to one public key.  Two agents sharing one
        #  would mean the registry could hold one agent's key or the other's,
        #  and Q-12(b) would refuse whichever lost.
        raise SystemExit("muster-cloud-hero: MALFORMED: the two agents name one key reference")
    return fleet


#  ---- the case, and the authority the deployed keys hold ------------------


def cloud_case(fleet: CloudFleet) -> RaviCase:
    """The worked case, with the deployed keys granted what the seeded ones have.

    Two changes to the fixture and no others.

    The attested half of the disputed Saturday is **removed**, so the case has
    to acquire it rather than start with it.  Ravi's statement stays: a claim is
    inert, no source can be asked for one, and replaying it is what makes the
    analysis divergent in the first place.

    Two grants are **added**, one per deployed agent, naming the key reference
    that agent actually signs under.  Same principal, same source class, same
    predicates, same resource scope, same validity as the seeded grant beside
    them -- a deployed agent is the same institution holding a newer key, and a
    grant that widened anything would be answering a different question than
    the one this run is about.  The case's authorization context is repinned to
    the snapshot that results, because a case pins the authority it is judged
    under by digest and a snapshot with another grant in it is another snapshot.
    """
    case = ravi.without_attestations(
        ravi.ravi(fleet.tenant_id, fleet.case_id), *ravi.ACQUIRED_BY_THE_FLEET
    )
    authority = replace(
        case.authority_snapshot,
        grants=canonical_grants(
            (
                *case.authority_snapshot.grants,
                site_grant(fleet.tenant_id, key_ref=fleet.site_key_ref),
                payroll_grant(fleet.tenant_id, key_ref=fleet.employer_key_ref),
            )
        ),
    )
    return replace(
        case,
        authority_snapshot=authority,
        authorization_context=replace(
            case.authorization_context,
            authority_registry_snapshot_digest=authority.digest(),
        ),
    )


def build_casework(fleet: CloudFleet, database: CaseworkDatabase) -> Casework:
    """The control plane, holding the deployed agents' public keys and no more.

    The keyring is the only place the deployment's own key material appears,
    and it is public material: verifying a signature establishes authenticity
    and nothing else.  What the key may *say* is check Q-12, decided against
    the published snapshot, which has never heard of a keyring.
    """
    return ravi.casework(
        database,
        sources=source_keyring(
            **{
                fleet.site_key_ref: fleet.site_public_key,
                fleet.employer_key_ref: fleet.employer_public_key,
            }
        ),
    )


def build_transport(fleet: CloudFleet) -> HttpAcquisitionTransport:
    """The one outbound edge: authenticated HTTPS to a named list of hosts."""
    transport = HttpAcquisitionTransport(tokens=MetadataServerTokens(), hosts=fleet.hosts)
    if fleet.timeout_seconds is None:
        return transport
    return replace(transport, timeout_seconds=fleet.timeout_seconds)


#  ---- the boundary, as a thing this process tried ------------------------


class RawAccess(Enum):
    """What happened when the control plane reached for the site's material."""

    #: Refused by Cloud Storage.  The expected result, and the whole point.
    DENIED = "DENIED"
    #: Reached it.  The deployment is not the one the architecture describes,
    #: and the run stops rather than continuing on top of a broken boundary.
    ALLOWED = "ALLOWED"
    #: No such object.  Proves nothing: a denial and an absence look alike from
    #: here, and reporting an absence as a denial is how this check would come
    #: to mean nothing at all.
    ABSENT = "ABSENT"
    #: No metadata server, or Cloud Storage was unreachable.  Also proves
    #: nothing, and says so.
    UNAVAILABLE = "UNAVAILABLE"
    #: Not configured.  Nothing was attempted.
    SKIPPED = "SKIPPED"


@dataclass(frozen=True, slots=True)
class RawAttempt:
    """One attempted read, recorded as an outcome and a status code."""

    outcome: RawAccess
    reference: str
    status: int


def raw_object_access(reference: str | None, *, timeout_seconds: float = 10.0) -> RawAttempt:
    """Ask Cloud Storage for one object, under this process's own identity.

    A metadata read shaped to bring back a name, so a *successful* call would
    still carry no evidence -- which matters, because the one outcome this
    function must handle safely is the one where the boundary does not hold.
    The body is never read into anything the run reports.

    Written against the standard library rather than a storage client, and the
    absence is the same decision the transport made: a cloud SDK in the control
    plane's image would be one dependency away from a model client, and "this
    process cannot read source material" is worth more as a fact about IAM than
    as a fact about which library was installed.
    """
    if reference is None:
        return RawAttempt(RawAccess.SKIPPED, "", 0)
    bucket, _, name = reference.removeprefix("gs://").partition("/")
    if not bucket or not name:
        return RawAttempt(RawAccess.UNAVAILABLE, reference, 0)

    token = _access_token(timeout_seconds)
    if token is None:
        return RawAttempt(RawAccess.UNAVAILABLE, reference, 0)

    request = urllib.request.Request(  # noqa: S310 - a fixed https host
        STORAGE_OBJECT_URL.format(
            bucket=urllib.parse.quote(bucket, safe=""),
            object=urllib.parse.quote(name, safe=""),
        ),
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    try:
        with direct_opener().open(request, timeout=timeout_seconds) as answer:
            answer.read(MAX_PROBE_OCTETS)
            return RawAttempt(RawAccess.ALLOWED, reference, int(answer.status))
    except urllib.error.HTTPError as refused:
        if refused.code in (401, 403):
            return RawAttempt(RawAccess.DENIED, reference, refused.code)
        if refused.code == 404:
            #  Cloud Storage answers 404 for an object a caller may not even
            #  learn the existence of, so this is "denied or absent" and is
            #  reported as absent: the weaker reading, because claiming the
            #  stronger one would be claiming evidence this call cannot supply.
            return RawAttempt(RawAccess.ABSENT, reference, refused.code)
        return RawAttempt(RawAccess.UNAVAILABLE, reference, refused.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return RawAttempt(RawAccess.UNAVAILABLE, reference, 0)


def _access_token(timeout_seconds: float) -> str | None:
    """This workload's own OAuth token, or nothing.  Never logged, never stored."""
    request = urllib.request.Request(
        METADATA_TOKEN_URL, headers=dict((METADATA_HEADER,)), method="GET"
    )
    try:
        with direct_opener().open(request, timeout=timeout_seconds) as answer:
            minted = json.loads(answer.read(8192).decode("ascii"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    token = minted.get("access_token")
    return token if isinstance(token, str) and token else None


#  ---- the run -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CloudHeroRun:
    """Everything the run produced, so a caller can assert on it or print it."""

    claims: tuple[StatementRecord, ...]
    #: The plan the case arrived at before anything was acquired.
    solicited: EvidenceRequest
    raw_access: RawAttempt
    reports: tuple[AcquisitionReport, ...]
    report: CaseReport | None

    def reached_invariant(self) -> bool:
        if self.report is None or self.report.analysis is None:
            return False
        return isinstance(self.report.analysis.kernel.outcome, Invariant)


def run_cloud_hero(
    casework: Casework,
    transport: AcquisitionTransport,
    *,
    case: RaviCase,
    site_endpoint: str,
    employer_endpoint: str,
    raw_object: str | None = None,
    now: Instant = ravi.NOW,
) -> CloudHeroRun:
    """Drive the whole case against deployed agents and return what happened.

    Returns rather than prints, so the assertions a test makes and the lines a
    demo shows are made from one value.

    ``transport`` is the *port*, not the HTTPS implementation, for the reason
    every other seam here is a port: what this function does must not depend on
    how the octets travel.  The deployment's choice is made once, in
    :func:`build_transport`, and it is authenticated HTTPS -- there is no branch
    below that could reach an in-process agent even if one were importable.
    """
    open_ravi(casework, case)
    #  The catalog names the deployed services.  Published by the control plane
    #  and signed: an agent cannot enter itself into one, which is why the
    #  endpoints arrive here as configuration rather than as registration.
    publish_fleet(
        casework.database,
        case.tenant_id,
        case.authority_snapshot,
        profiles=(
            replace(site_profile(case.tenant_id), endpoint_ref=site_endpoint),
            replace(payroll_profile(case.tenant_id), endpoint_ref=employer_endpoint),
        ),
    )

    #  1. The record as it stands: the undisputed week, and Ravi's own claim
    #     about the Saturday.  The claim is a statement, so appending it moves
    #     nothing -- and the analysis that follows is what asks for evidence.
    #
    #     **The decision is read from the last advance, and only the last one is
    #     required to have published.**  Intermediate revisions of this case are
    #     legitimately over the engine's bound -- every instance is declared from
    #     the start and the facts arrive one at a time -- so an advance partway
    #     through may be refused and the append still stands.  What must succeed
    #     is the analysis of the whole record, because that is the one a plan is
    #     read from; taking a decision from whichever advance last happened to
    #     work would let a stale plan describe a case that had moved on.
    advanced: object = None
    for entry in case.entries:
        appended = append_transcript_entry(
            casework, tenant_id=case.tenant_id, case_id=case.case_id, entry=entry, now=now
        )
        _require(appended, "appending the worked record")
        assert isinstance(appended, Ok)
        advanced = appended.value.advanced
    _require(advanced, "analysing the worked record")
    assert isinstance(advanced, Ok), "the case has no entries to analyse"
    decision = advanced.value.decision
    if not isinstance(decision, Dispatch):
        raise SystemExit(f"the case did not ask for evidence: {type(decision).__name__}")

    claims = tuple(entry.record for entry in case.entries if isinstance(entry, Statement))

    #  2. Before asking anybody: can this process read the site's material
    #     itself?  It must not, and finding that it can stops the run -- there
    #     is nothing worth demonstrating on top of a boundary that is open.
    attempt = raw_object_access(raw_object)
    if attempt.outcome is RawAccess.ALLOWED:
        return CloudHeroRun(claims, decision.request, attempt, (), None)

    #  3. Ask the fleet.  Routing, an identity token per audience, HTTPS,
    #     interpretation inside each source, signing, Q-12, rebuild.
    acquired = acquire_outstanding(
        casework, transport, tenant_id=case.tenant_id, case_id=case.case_id, now=now
    )
    _require(acquired, "acquiring evidence")
    assert isinstance(acquired, Ok)

    read = case_status(casework, tenant_id=case.tenant_id, case_id=case.case_id, now=now)
    _require(read, "reading the case")
    assert isinstance(read, Ok)
    return CloudHeroRun(claims, decision.request, attempt, acquired.value, read.value)


def _require(outcome: object, what: str) -> None:
    """Stop, naming the failure and never quoting what it refused.

    Every rejection in the control plane carries a closed enumeration beside a
    free-text detail, and the detail can quote a case artifact -- a receipt, an
    entry, a value.  The enumeration is what an operator reading a failed job
    needs, and it is the only half that travels.
    """
    if not isinstance(outcome, Err):
        return
    failure = getattr(outcome.error, "failure", None)
    named = getattr(failure, "value", None)
    raise SystemExit(f"{what} failed: {named or type(outcome.error).__name__}")


#  ---- narration -----------------------------------------------------------
#
#  A closed vocabulary.  Every line below is built from a predicate name, an
#  identifier, a digest, an enum value or a count -- and from nothing else.  No
#  ``detail`` field is read anywhere in this section, because a detail is the
#  one string on these paths that something outside the control plane may have
#  authored.


def narrate(run: CloudHeroRun, write: Callable[[str], None] = print) -> None:
    """What happened, in the order it happened, with no adjectives."""
    write("")
    write("CLAIM")
    for statement in run.claims:
        write(f"  claim      {_reference(statement.proposition)}")
        write(f"  by         {statement.claimant} as {statement.role_in_case}")
        write("  effect     none: a claim is not a justification variant")

    write("")
    write("PLAN")
    write(f"  request    {run.solicited.digest().hex[:16]}")
    for target in run.solicited.targets:
        write(
            f"  needs      {_reference(target.proposition)}"
            f"  from {', '.join(target.permitted_source_classes)}"
        )

    write("")
    write("CONTROL PLANE, REACHING FOR RAW EVIDENCE")
    write(f"  object     {run.raw_access.reference or 'not configured'}")
    write(f"  outcome    {run.raw_access.outcome.value}  http {run.raw_access.status}")
    write(f"  meaning    {_MEANINGS[run.raw_access.outcome]}")
    if run.raw_access.outcome is RawAccess.ALLOWED:
        write("")
        write("  The run stopped here.  Nothing was acquired and nothing was decided.")
        write("")
        return

    write("")
    write("FLEET")
    for report in run.reports:
        for exchange in report.exchanges:
            host = urllib.parse.urlsplit(exchange.endpoint_ref).hostname or "?"
            write(
                f"  agent      {exchange.assignment.agent_id}"
                f"  at {host}  targets {len(exchange.assignment.targets)}"
            )
            _narrate_exchange(exchange.result, write)
        for unroutable in report.unroutable:
            write(
                f"  unrouted   {_reference(unroutable.target.proposition)}"
                f"  {unroutable.error.failure.value}"
            )

    write("")
    write("RESULT")
    _narrate_result(run.report, write)


def _narrate_exchange(result: object, write: Callable[[str], None]) -> None:
    match result:
        case Answered(admitted, refused):
            for entry in admitted:
                write(
                    f"  admitted   {_reference(entry.proposition)}"
                    f"  q-12 passed  entry {entry.entry_digest.hex[:12]}"
                    f"  {'new' if entry.created else 'already a member'}"
                )
                write(f"  rebuilt    {'yes' if isinstance(entry.advanced, Ok) else 'deferred'}")
            for rejected in refused:
                write(
                    f"  refused    {_reference(rejected.proposition)}"
                    f"  {rejected.error.failure.value}"
                )
        case Abstained(abstention):
            write(f"  abstained  {abstention.reason.value}")
        case Unreachable(error):
            write(f"  unreached  {error.failure.value}")
        case EnvelopeRefused(error):
            write(f"  envelope   {error.failure.value}")
        case _:
            write(f"  outcome    {type(result).__name__}")


def _narrate_result(report: CaseReport | None, write: Callable[[str], None]) -> None:
    if report is None:
        write("  status     the case was not read")
        return
    write(f"  status     {report.status.value}")
    analysis = report.analysis
    if analysis is None:
        write("  outcome    the case has never been analysed")
        return
    write(f"  outcome    {outcome_class(analysis.kernel.outcome)}")
    action = getattr(analysis.kernel.outcome, "action", None)
    if action is not None:
        fields = "  ".join(
            f"{field.name}={render(field.value)}" for field in action.consequential_fields
        )
        write(f"  action     {action.kind}  {fields}")
    unresolved = sorted(str(reference) for reference in analysis.projected.unresolved())
    write(f"  unresolved {', '.join(unresolved) if unresolved else 'nothing'}")
    write("  gate       not reached: this run stops at the analysis")
    write("")
    #  **Only when the case actually reached it.**  A run that ended divergent
    #  has established nothing, and printing the product claim under it would
    #  be the demo saying the one thing this system is careful never to say.
    if isinstance(analysis.kernel.outcome, Invariant):
        write("  MUSTER has not decided that Ravi worked.  It has decided that his")
        write("  Saturday shift is payable under the pinned policy, on attested grounds.")
    else:
        write("  Nothing was established.  The case is exactly as it was, its request is")
        write("  still outstanding, and no answer follows from what it holds.")
    write("")


_MEANINGS: dict[RawAccess, str] = {
    RawAccess.DENIED: "the process holding the case record cannot read the material",
    RawAccess.ALLOWED: "THE BOUNDARY DOES NOT HOLD; this deployment is not the architecture",
    RawAccess.ABSENT: "denied or absent, indistinguishable from here; this proves nothing",
    RawAccess.UNAVAILABLE: "the attempt could not be made; this proves nothing",
    RawAccess.SKIPPED: "no object was named; nothing was attempted",
}


def _reference(proposition: object) -> str:
    """``predicate(arg, arg)`` -- a name and its arguments, never a value."""
    predicate = getattr(proposition, "predicate_id", "?")
    args = getattr(proposition, "args", ())
    return f"{predicate}({', '.join(args)})"


#  ---- custody -------------------------------------------------------------


def open_database(fleet: CloudFleet) -> CaseworkDatabase:
    """Exactly the custody the deployment named, or no run at all.

    Two kinds, and the deployment chose which before this function was called.
    ``EPHEMERAL`` is in-memory custody that lasts one execution -- the shape the
    verified Stage-90 run had, kept deliberately runnable and deliberately
    labelled, so a run that keeps nothing says so rather than looking like a
    durable one that lost its rows.

    ``CLOUD_SQL`` is durable custody, and every way it can fail ends the run.
    There is no ``except`` here that reaches the branch above: a missing secret,
    an unmigrated database, a stale ledger and an unreachable instance are four
    different refusals and none of them is "carry on in memory".  That is the
    whole point of the label being explicit -- falling back would silently
    downgrade the one property the deployment was provisioned for.
    """
    if fleet.deployment is DatabaseDeployment.EPHEMERAL:
        from muster.platform.adapters.memory import MemoryDatabase

        return MemoryDatabase()

    from muster.platform.adapters.sql.database import SqlDatabase

    if fleet.postgres is None:
        #  ``CloudFleet`` already refuses this, in ``__post_init__`` and again
        #  in ``from_environment``.  Stated a third time because the cost of
        #  being wrong here is a cloud run that quietly kept nothing.
        raise SystemExit("muster-cloud-hero: DATABASE CONFIGURATION REFUSED")
    try:
        require_current_schema(fleet.postgres)
    except SchemaNotCurrent as error:
        raise SystemExit(f"muster-cloud-hero: DATABASE SCHEMA REFUSED: {error}") from error
    except Exception as error:
        #  A driver exception can quote connection fields.  Keep credentials out
        #  of Cloud Run logs while retaining the actionable failure class.
        raise SystemExit(
            f"muster-cloud-hero: DATABASE CONNECTION REFUSED: {type(error).__name__}"
        ) from error
    return SqlDatabase(fleet.postgres)


#  ---- reading a case a previous execution left behind ---------------------


@dataclass(frozen=True, slots=True)
class DurableCase:
    """What a case looks like from a process that did not create it.

    Identifiers, digests and counts.  No predicate values, no receipt bodies,
    no source material -- the same closed vocabulary the narration keeps, and
    for the same reason: this is printed into a job log.

    **This is a persistence claim and only that.**  Two executions printing the
    same nine lines establishes that the head, the transcript membership and
    the certificate identity survived the first process ending.  It is *not* a
    restart, not a resume, and not a re-validation: nothing here re-admits a
    record, re-runs Q-12 or re-analyses anything.  Stable cross-process
    re-verification needs trust material that does not live inside one process,
    which the worked fixture's per-process officer key is not -- and that
    belongs to the durable-async milestone rather than to this one.
    """

    tenant_id: str
    case_id: str
    revision_number: int
    revision_digest: str
    certificate_digest: str
    construction_digest: str
    authorization_context_digest: str
    transcript_entries: int
    transcript_digest: str

    def lines(self) -> tuple[str, ...]:
        return (
            f"tenant                 {self.tenant_id}",
            f"case                   {self.case_id}",
            f"revision number        {self.revision_number}",
            f"revision digest        {self.revision_digest}",
            f"certificate digest     {self.certificate_digest}",
            f"construction digest    {self.construction_digest}",
            f"authorization context  {self.authorization_context_digest}",
            f"transcript entries     {self.transcript_entries}",
            f"transcript digest      {self.transcript_digest}",
        )


def read_durable_case(
    database: CaseworkDatabase, *, tenant_id: str, case_id: str
) -> DurableCase:
    """Read a case this process did not open, and say what is durably there.

    **Nothing here writes**, and nothing here re-verifies.  It takes a read
    scope, reads the head and the transcript membership, and reports digests.
    That is the whole of it, and each half of that is deliberate.

    *No write*, because a verification step that created what it went looking
    for would establish nothing at all.

    *No re-verification*, because re-verification is a different claim from
    persistence and this function is only making the second one.  Asking
    ``case_status`` here would re-admit the stored construction record against
    **this** process's officer verifier, and the worked fixture signs with a
    key generated per process -- so a second execution is told
    ``CaseConstructionRecord ... is not signed by a trusted officer`` about a
    record that is durably present and was perfectly valid when it was written.
    That refusal is the fixture's key discipline showing through, not a custody
    failure, and reporting it as one would be exactly backwards.  What the
    execution that *wrote* the case established -- admission, Q-12, the
    analysis, the certificate -- it established then, and the certificate
    digest below is the durable record of it.
    """
    with database.reading(tenant_id) as scope:
        head = scope.heads.read(case_id)
        if isinstance(head, Err):
            raise SystemExit(
                f"muster-cloud-hero: DURABLE CASE ABSENT: {head.error.failure.value}"
            )
        stored = head.value
        if stored.revision_digest is None or stored.certificate_digest is None:
            raise SystemExit("muster-cloud-hero: DURABLE CASE NOT ANALYSED")
        members = scope.transcript.members(case_id)
        if isinstance(members, Err):
            raise SystemExit(
                f"muster-cloud-hero: DURABLE TRANSCRIPT UNREADABLE: "
                f"{members.error.failure.value}"
            )

    #  One digest over the membership, in the order the repository returns it,
    #  so two executions can be compared on a single line without either of
    #  them printing what any entry says.
    rolling = hashlib.sha256()
    for member in members.value:
        rolling.update(member.octets)

    return DurableCase(
        tenant_id=tenant_id,
        case_id=case_id,
        revision_number=stored.revision_number,
        revision_digest=stored.revision_digest.octets.hex(),
        certificate_digest=stored.certificate_digest.octets.hex(),
        construction_digest=stored.inputs.construction_digest.octets.hex(),
        authorization_context_digest=stored.inputs.authorization_context_digest.octets.hex(),
        transcript_entries=len(members.value),
        transcript_digest=rolling.hexdigest(),
    )


def _print_durable_case(durable: DurableCase, *, heading: str) -> None:
    print(heading)
    print("")
    for line in durable.lines():
        print(f"  {line}")
    print("")


#  ---- entry point ---------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="the worked run, against deployed agents")
    parser.add_argument(
        "--print-configuration",
        action="store_true",
        help="report what this job would do, contact nobody, and exit",
    )
    parser.add_argument(
        "--verify-durable-case",
        action="store_true",
        help=(
            "read the case a previous execution left in durable custody, print "
            "its identity, and exit.  A persistence check only -- it opens "
            "nothing, appends nothing, acquires nothing, re-verifies nothing, "
            "and requires CLOUD_SQL"
        ),
    )
    arguments = parser.parse_args(argv)

    fleet = from_environment()
    transport = build_transport(fleet)
    if arguments.print_configuration:
        for line in _configuration_lines(fleet, transport):
            print(line)
        return 0

    database = open_database(fleet)

    if arguments.verify_durable_case:
        #  A durability proof read out of memory would be a proof about this
        #  process.  EPHEMERAL custody has nothing a previous execution could
        #  have left, so asking is a configuration error rather than an empty
        #  answer.
        if fleet.deployment is DatabaseDeployment.EPHEMERAL:
            raise SystemExit(
                "muster-cloud-hero: DURABLE VERIFICATION REFUSED: "
                "EPHEMERAL custody keeps nothing between executions"
            )
        _print_durable_case(
            read_durable_case(database, tenant_id=fleet.tenant_id, case_id=fleet.case_id),
            heading=(
                "durable case, read by a process that did not create it\n"
                "  (persistence only: nothing below was re-verified in this process)"
            ),
        )
        return 0

    case = cloud_case(fleet)
    run = run_cloud_hero(
        build_casework(fleet, database),
        transport,
        case=case,
        site_endpoint=fleet.site_endpoint,
        employer_endpoint=fleet.employer_endpoint,
        raw_object=fleet.raw_object,
    )
    narrate(run)
    if run.reached_invariant() and run.raw_access == RawAttempt(
        RawAccess.DENIED, run.raw_access.reference, 403
    ):
        from demo.case_trace_artifact import (
            build_case_trace_artifact,
            cloud_artifact_context_from_environment,
        )

        try:
            artifact = build_case_trace_artifact(
                run, case, cloud_artifact_context_from_environment()
            )
        except ValueError as error:
            raise SystemExit(f"muster-cloud-hero: ARTIFACT REFUSED: {error}") from error
        print(artifact.machine_record())
    #  Under durable custody, print what the case now *is* in the database, in
    #  exactly the form ``--verify-durable-case`` prints it.  A later execution
    #  reading the same rows produces the same nine lines, and two job logs that
    #  can be compared line for line is what makes "it persisted" checkable
    #  rather than asserted.
    if fleet.deployment is not DatabaseDeployment.EPHEMERAL and run.reached_invariant():
        _print_durable_case(
            read_durable_case(database, tenant_id=fleet.tenant_id, case_id=fleet.case_id),
            heading="durable case, as this execution left it",
        )

    #  The exit status is the claim.  A run that did not reach the invariant
    #  answer is a run that did not demonstrate anything, and an operator
    #  reading a job execution should not have to read the log to find out.
    return 0 if run.reached_invariant() else 1


def _configuration_lines(fleet: CloudFleet, transport: HttpAcquisitionTransport) -> tuple[str, ...]:
    """What this job is pointed at.  Names and hosts; no key material."""
    return (
        f"tenant     {fleet.tenant_id}",
        f"case       {fleet.case_id}",
        f"site       {urllib.parse.urlsplit(fleet.site_endpoint).hostname}"
        f"  key {fleet.site_key_ref}",
        f"employer   {urllib.parse.urlsplit(fleet.employer_endpoint).hostname}"
        f"  key {fleet.employer_key_ref}",
        f"hosts      {', '.join(sorted(fleet.hosts))}",
        f"timeout    {transport.timeout_seconds:g}s",
        f"raw object {fleet.raw_object or 'not configured'}",
        f"store      {_custody(fleet.deployment)}",
    )


#: What each custody is, in the words an operator needs to read it by.  The
#: ephemeral line says what is *lost*, because a configuration report that made
#: in-memory custody sound like a store is how a run that kept nothing gets
#: described afterwards as a durable one.
_CUSTODY: dict[DatabaseDeployment, str] = {
    DatabaseDeployment.EPHEMERAL: (
        "EPHEMERAL MEMORY -- custody lasts one execution and is not durable"
    ),
    DatabaseDeployment.CLOUD_SQL: (
        "CLOUD SQL POSTGRESQL -- durable, and refuses to run before bootstrap"
    ),
    DatabaseDeployment.LOCAL: "LOCAL POSTGRESQL",
}


def _custody(deployment: DatabaseDeployment) -> str:
    return _CUSTODY[deployment]


if __name__ == "__main__":
    raise SystemExit(main())
