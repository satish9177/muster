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

**Where it stops, and where it deliberately does not.**  ``ANALYSIS_ONLY`` is
the default and is the verified U1 shape: the run ends at the analysis, nothing
is authorized and nothing is settled.  ``CLOUD_SQL_ACTION_GATE_SANDBOX`` is a
mode an operator has to *name*, and it continues past the analysis into the
deterministic Action Gate over the same durable Cloud SQL custody.  There is no
path that reaches the Gate without that label, and none that reaches it under
ephemeral custody: an operator asking for an analysis gets an analysis.

**Nothing it executes moves money.**  The executor it composes is the synthetic
sandbox one -- no payment rail, no provider credential, no account -- and it
says so in every line it prints and every field it emits.  What the Gate
demonstrates is the *lifecycle*: one durable reservation, one dispatch, one
confirmation, and a retry that reads the confirmation instead of paying twice.
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
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Never

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

from demo.stable_keys import (  # noqa: E402
    _OfficerSigner,
    _public_key,
    _PublisherSigner,
    _SourceSigner,
)

from muster.core.analysis.outcomes import Invariant, outcome_class  # noqa: E402
from muster.core.authority.grants import canonical_grants  # noqa: E402
from muster.core.authority.signing import PublisherRole  # noqa: E402
from muster.core.evidence.delivery import AcquisitionTransport  # noqa: E402
from muster.core.evidence.requests import EvidenceRequest  # noqa: E402
from muster.core.evidence.signing import (  # noqa: E402
    attestation_preimage,
    case_construction_preimage,
)
from muster.core.evidence.transcript import (  # noqa: E402
    Attestation,
    Statement,
    StatementRecord,
    TranscriptEntry,
)
from muster.core.results import Err, InvariantViolation, Ok, Result  # noqa: E402
from muster.core.values.scalars import render  # noqa: E402
from muster.core.values.times import Instant  # noqa: E402
from muster.platform.adapters.crypto import (  # noqa: E402
    LocalEcdsaOfficerVerifier,
    LocalEcdsaPublisherVerifier,
    LocalEcdsaSourceVerifier,
)
from muster.platform.adapters.http import (  # noqa: E402
    HttpAcquisitionTransport,
    MetadataServerPrincipal,
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
from muster.platform.authority.publish import (  # noqa: E402
    AuthorityPublisher,
    publish_authority_snapshot,
    publish_revocation_snapshot,
)
from muster.platform.casework.advance import Casework  # noqa: E402
from muster.platform.casework.commands import (  # noqa: E402
    CaseReport,
    OpenRejection,
    append_transcript_entry,
    case_status,
    open_case,
)
from muster.platform.casework.ports import (  # noqa: E402
    CaseHead,
    CaseworkDatabase,
    TenantScope,
)
from muster.platform.casework.snapshot import read_published  # noqa: E402
from muster.platform.catalog.publish import (  # noqa: E402
    CatalogPublisher,
    publish_catalog_snapshot,
)
from muster.platform.dispatch.acquire import (  # noqa: E402
    Abstained,
    AcquisitionReport,
    Answered,
    EnvelopeRefused,
    Unreachable,
    acquire_outstanding,
)
from muster.platform.gate.authority import GateCaller  # noqa: E402
from muster.platform.gate.cloud import (  # noqa: E402
    CloudExecutionAuthorityConfiguration,
    resolve_cloud_gate_authority,
)
from muster.platform.gate.executor import SandboxPaymentExecutor  # noqa: E402
from muster.platform.gate.model import (  # noqa: E402
    ExecuteProposal,
    ExecutionKey,
    ExecutionLookup,
    ExecutionRecord,
    ExecutionState,
)
from muster.platform.gate.service import ActionGate  # noqa: E402
from muster.platform.orchestration.decisions import Dispatch  # noqa: E402
from muster.platform.orchestration.status import CaseStatus  # noqa: E402
from support import ravi  # noqa: E402
from support.authority import (  # noqa: E402
    AUTHORITY_PUBLISHER_KEY,
    CATALOG_PUBLISHER_KEY,
    OFFICER_KEY,
    SOURCE_KEYS,
    catalog,
    payroll_grant,
    payroll_profile,
    site_grant,
    site_profile,
)
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

#  ---- the deliberate Action Gate mode -------------------------------------
#
#  Three variables, and the first one is the only thing that turns the Gate on.
#  A deployment that says nothing gets the analysis-only run that U1 verified;
#  a deployment that wants the Gate has to name it, name the principal it
#  provisioned, and be on durable custody.  None of that is inferred.
GATE_MODE = "MUSTER_HERO_GATE_MODE"
GATE_PRINCIPAL = "MUSTER_HERO_GATE_PRINCIPAL"
#: Required only by ``--verify-gate-idempotency``.  See ``ExecutionLookup``: a
#: retry names the *execution* it is asking about, by the identity the first
#: run printed.  That identity is the hash of the exact authorized intent and
#: the durable primary key of its row, so it keeps naming the same historical
#: execution however far the case has advanced since -- which is why nothing on
#: the retry path reads the case head.
#:
#: ``_EXECUTION_ID`` rather than ``_EXECUTION_KEY``, matching the durable
#: column.  The value is public, but the deployment writes it *by value* into a
#: Cloud Run environment file, and the rule that file lives under is that
#: anything key-ish in it is a reference or a public half.  A non-secret named
#: ``..._KEY`` there would spend that rule to save a word.
GATE_EXECUTION_ID = "MUSTER_HERO_GATE_EXECUTION_ID"

#: The width of that identity, checked before ``ExecutionKey`` sees it so a
#: mistyped variable is a named configuration refusal rather than an
#: ``InvariantViolation`` from two layers down.
EXECUTION_KEY_OCTETS = 32

#: The deployed Gate's own identity, and the executor's.  Deliberately *not*
#: the local demo's ``local-action-gate/v1``: a stored lifecycle names the gate
#: that authorized it, and two compositions sharing one identity would be two
#: different trust boundaries answering to one name.
CLOUD_GATE_ID = "cloud-action-gate/v1"
CLOUD_EXECUTOR_ID = "sandbox-payment-cloud/v1"
#: The one action kind this deployment grants.  Not a wildcard, and not read
#: from the case: a grant is what the *deployment* decided, and the case's own
#: action is checked against it inside the Gate.
CLOUD_ACTION_KIND = "PAY"

#: What the executor is, in the words that have to survive a screenshot.
SANDBOX_LABEL = "SANDBOX: NO REAL FUNDS TRANSFERRED"

#: Where the *observed* principal came from, as a closed token rather than a
#: sentence.  There is one value because there is one source: the instance
#: metadata server.  No environment variable, request field or argument can
#: produce a caller here, so this line can never read anything else -- which is
#: what makes it worth printing into a machine trace at all.
PRINCIPAL_SOURCE = "METADATA_SERVER"

#: And what happened when the observed identity met the configured one.  Only
#: ``MATCHED`` is ever printed: every other outcome is a refusal that ends the
#: run before a Gate exists, so a trace carrying this line is a trace whose
#: principal check passed.  Content-free by construction -- neither this nor
#: PRINCIPAL_SOURCE carries an address, a token or a credential.
PRINCIPAL_STATUS_MATCHED = "MATCHED"

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


class HeroMode(Enum):
    """What this execution was asked to do, as something it was *told*.

    A mode rather than a flag, and an enumeration rather than a boolean,
    because the failure this closes is a deployment reaching the Gate by
    accident.  ``from_environment`` refuses any other spelling, so an
    operator who mistypes the mode gets a refusal rather than an analysis
    they will later describe as an execution -- or, far worse, the reverse.
    """

    #: The verified U1 shape.  Replay, plan, boundary probe, fleet, rebuild,
    #: stop.  Nothing is authorized and nothing is executed.
    ANALYSIS_ONLY = "ANALYSIS_ONLY"
    #: The U2 shape.  Everything above, and then the deterministic Action Gate
    #: over the same Cloud SQL custody, dispatching to the synthetic sandbox
    #: executor.  Requires CLOUD_SQL custody and a provisioned principal.
    CLOUD_SQL_ACTION_GATE_SANDBOX = "CLOUD_SQL_ACTION_GATE_SANDBOX"


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
    #: What this execution was asked to do.  Defaulted to the analysis-only
    #: shape for the same reason ``deployment`` defaults to EPHEMERAL: a fleet
    #: assembled in a test is not a deployment, and a deployed run never
    #: inherits either default because ``from_environment`` reads both.
    gate_mode: HeroMode = HeroMode.ANALYSIS_ONLY
    #: The service-account identity this deployment provisioned the Gate for.
    #: Compared against the identity the *runtime* reports; never trusted as a
    #: substitute for it.
    gate_principal: str | None = None
    #: The durable execution a retry is asking about.  Present only for the
    #: idempotency read, which is the one mode with no analysis of its own --
    #: and, deliberately, no case head to derive an identity from either.
    gate_execution_key: ExecutionKey | None = None

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

        #  The Gate's two preconditions, closed here as well as in
        #  ``from_environment`` and for the same reason the custody rule is:
        #  a fleet constructed directly -- in a test, in a later composition
        #  root -- must not be able to claim a durable execution proof over
        #  custody that keeps nothing, or under an authority nobody named.
        if self.gate_mode is HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX:
            if self.deployment is not DatabaseDeployment.CLOUD_SQL:
                raise ValueError(
                    "the Action Gate mode requires CLOUD_SQL custody; a durable "
                    "execution lifecycle in memory is a proof about one process"
                )
            if not self.gate_principal:
                raise ValueError("the Action Gate mode names the principal it grants")

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

    def mode() -> HeroMode:
        raw = (source.get(GATE_MODE) or "").strip()
        if not raw:
            return HeroMode.ANALYSIS_ONLY
        try:
            return HeroMode(raw)
        except ValueError:
            choices = ", ".join(member.value for member in HeroMode)
            raise SystemExit(
                f"muster-cloud-hero: MALFORMED: {GATE_MODE}; expected {choices}"
            ) from None

    def execution_key(name: str) -> ExecutionKey | None:
        """A 32-octet execution key from lowercase hex, or nothing at all.

        Parsed here rather than where it is used, so a malformed value is a
        configuration refusal before the job connects to anything.
        ``ExecutionKey`` itself refuses the wrong width; what this adds is
        refusing the wrong *alphabet*, because ``bytes.fromhex`` accepts
        whitespace and uppercase and the value has to be the exact key the
        first execution printed.
        """
        raw = (source.get(name) or "").strip()
        if not raw:
            return None
        if len(raw) != EXECUTION_KEY_OCTETS * 2 or raw != raw.lower():
            raise SystemExit(f"muster-cloud-hero: MALFORMED: {name}")
        try:
            return ExecutionKey(bytes.fromhex(raw))
        except (ValueError, InvariantViolation):
            raise SystemExit(f"muster-cloud-hero: MALFORMED: {name}") from None

    gate_mode = mode()
    if gate_mode is HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX:
        #  Named before the fleet is built, so the operator is told which
        #  decision is missing rather than which constructor complained.
        if database.deployment is not DatabaseDeployment.CLOUD_SQL:
            raise SystemExit(
                f"muster-cloud-hero: GATE REFUSED: {GATE_MODE}={gate_mode.value} "
                "requires CLOUD_SQL custody"
            )
        if not (source.get(GATE_PRINCIPAL) or "").strip():
            raise SystemExit(f"muster-cloud-hero: MISSING: {GATE_PRINCIPAL}")

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
        gate_mode=gate_mode,
        gate_principal=(source.get(GATE_PRINCIPAL) or "").strip() or None,
        gate_execution_key=execution_key(GATE_EXECUTION_ID),
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
    case = _stable_hero_construction(case)
    case = _stable_hero_sources(case)
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


def _stable_hero_construction(case: RaviCase) -> RaviCase:
    construction = case.construction
    return replace(
        case,
        construction=replace(
            construction,
            signature=_OfficerSigner(construction.signer_key_ref).sign(
                case_construction_preimage(construction.body())
            ),
        ),
    )


def _stable_hero_sources(case: RaviCase) -> RaviCase:
    """Give the synthetic fixture attestations stable source signatures.

    Only attestations whose ``signer_key_ref`` belongs to ``SOURCE_KEYS`` are
    re-signed.  Statements are inert on the admission path and are not
    signature-verified there, so they are preserved byte-for-byte; a source
    reference outside that fixture population belongs to a deployed agent and
    is likewise left exactly as it arrived.  Stable signatures matter because
    an attestation's signature contributes to its entry digest, and a fresh
    process must reconstruct the same transcript prefix in order to reopen and
    replay the durable hero case.
    """
    entries: list[TranscriptEntry] = []
    for entry in case.entries:
        if not isinstance(entry, Attestation):
            entries.append(entry)
            continue
        receipt = entry.receipt
        key_ref = receipt.payload.signer_key_ref
        if key_ref not in SOURCE_KEYS:
            entries.append(entry)
            continue
        entries.append(
            Attestation(
                replace(
                    receipt,
                    signature=_SourceSigner(key_ref).sign(attestation_preimage(receipt.payload)),
                )
            )
        )
    return replace(case, entries=tuple(entries))


def build_casework(fleet: CloudFleet, database: CaseworkDatabase) -> Casework:
    """The control plane, holding the deployed agents' public keys and no more.

    The keyring is the only place the deployment's own key material appears,
    and it is public material: verifying a signature establishes authenticity
    and nothing else.  What the key may *say* is check Q-12, decided against
    the published snapshot, which has never heard of a keyring.
    """
    fixture_sources = {key_ref: _public_key("source", key_ref) for key_ref in SOURCE_KEYS}
    deployed_sources = {
        fleet.site_key_ref: fleet.site_public_key,
        fleet.employer_key_ref: fleet.employer_public_key,
    }
    configured = ravi.casework(
        database,
        sources=LocalEcdsaSourceVerifier(fixture_sources | deployed_sources),
    )
    return _stable_hero_trust(configured)


def _stable_hero_trust(casework: Casework) -> Casework:
    """Install stable synthetic officer and publisher trust."""
    authority_key = _public_key("publisher", AUTHORITY_PUBLISHER_KEY)
    return replace(
        casework,
        officer_verifier=LocalEcdsaOfficerVerifier(
            {OFFICER_KEY: _public_key("officer", OFFICER_KEY)}
        ),
        publisher_verifier=LocalEcdsaPublisherVerifier(
            {
                PublisherRole.AUTHORITY: {AUTHORITY_PUBLISHER_KEY: authority_key},
                PublisherRole.REVOCATION: {AUTHORITY_PUBLISHER_KEY: authority_key},
                PublisherRole.CATALOG: {
                    CATALOG_PUBLISHER_KEY: _public_key(
                        "publisher", CATALOG_PUBLISHER_KEY
                    )
                },
            }
        ),
    )


def _publish_hero_authority(casework: Casework, case: RaviCase) -> None:
    publisher = AuthorityPublisher(
        database=casework.database,
        signer=_PublisherSigner(AUTHORITY_PUBLISHER_KEY),
        verifier=casework.publisher_verifier,
    )
    published = publish_authority_snapshot(
        publisher,
        tenant_id=case.tenant_id,
        snapshot=case.authority_snapshot,
        now=ravi.NOW,
    )
    _require(published, "publishing hero authority")
    revoked = publish_revocation_snapshot(
        publisher,
        tenant_id=case.tenant_id,
        snapshot=case.revocation_snapshot,
        now=ravi.NOW,
    )
    _require(revoked, "publishing hero revocation")


def _open_hero_case(
    casework: Casework, case: RaviCase
) -> Result[CaseHead, OpenRejection]:
    """Publish stable trust material and idempotently open this authored case."""
    _publish_hero_authority(casework, case)
    return open_case(
        casework,
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=case.authorization_context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )


def _publish_hero_fleet(
    casework: Casework,
    case: RaviCase,
    *,
    site_endpoint: str,
    employer_endpoint: str,
) -> None:
    snapshot = catalog(
        case.tenant_id,
        (
            replace(site_profile(case.tenant_id), endpoint_ref=site_endpoint),
            replace(payroll_profile(case.tenant_id), endpoint_ref=employer_endpoint),
        ),
        case.authority_snapshot,
    )
    published = publish_catalog_snapshot(
        CatalogPublisher(
            database=casework.database,
            signer=_PublisherSigner(CATALOG_PUBLISHER_KEY),
            verifier=casework.publisher_verifier,
        ),
        tenant_id=case.tenant_id,
        snapshot=snapshot,
    )
    _require(published, "publishing hero fleet")


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

    **The composition installs derived deterministic keys for the synthetic
    fixture population as well as for the officer and publishers.**  The first
    statements below re-sign the construction and replace ``officer_verifier``
    and ``publisher_verifier`` with :func:`_stable_hero_trust`'s matching demo
    keys; :func:`build_casework` also installs the matching derived public halves
    for fixture source references.  Deployed agents are the deliberate boundary:
    their configured key references keep their configured real public halves and
    are never derived.  Stated in the signature's own documentation because a
    function that quietly rebinds part of its argument's trust material is a
    function whose caller has to read it to know what it composed.

    Why it happens here rather than only at the composition roots: this is what
    makes the hero re-entrant.  A per-process officer key gives a different
    construction digest in every execution, so ``open_case`` would refuse the
    second one as ``CASE_ALREADY_OPEN``.  A per-process source key gives a
    different entry digest and therefore a different transcript prefix,
    revision, certificate and ``ExecutionKey`` in every execution.  Applying
    the stable fixture trust on the way in means any caller gets the re-entrant
    behaviour, including one that assembled its own control plane.

    It **narrows** what this run trusts and never widens it: the key references
    and the publisher role topology are exactly ``support.authority``'s own, so
    the same officer reference and the same three publisher roles are trusted,
    and the key nobody trusts stays untrusted.  Only the key material changes,
    from process-random to derived -- which is the whole point, and which is why
    it is confined to the synthetic hero tenant and its sandbox executor.
    """
    case = _stable_hero_construction(case)
    casework = _stable_hero_trust(casework)
    opened = _open_hero_case(casework, case)
    _require(opened, "opening the hero case")
    #  The catalog names the deployed services.  Published by the control plane
    #  and signed: an agent cannot enter itself into one, which is why the
    #  endpoints arrive here as configuration rather than as registration.
    _publish_hero_fleet(
        casework,
        case,
        site_endpoint=site_endpoint,
        employer_endpoint=employer_endpoint,
    )

    existing = case_status(
        casework,
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        now=now,
    )
    _require(existing, "reading the existing hero case")
    assert isinstance(existing, Ok)
    prior_solicitation: EvidenceRequest | None = None
    if existing.value.status is CaseStatus.PROPOSED:
        with casework.database.reading(case.tenant_id) as scope:
            published = read_published(
                scope,
                case.case_id,
                casework.publisher_verifier,
                casework.officer_verifier,
                casework.source_verifier,
            )
        _require(published, "reading the proposed hero evidence")
        assert isinstance(published, Ok)
        if len(published.value.solicitations) != 1:
            raise SystemExit("the proposed hero case does not carry its one solicitation")
        prior_solicitation = published.value.solicitations[0]

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
    if isinstance(decision, Dispatch):
        solicited = decision.request
    elif prior_solicitation is not None:
        solicited = prior_solicitation
    else:
        raise SystemExit(f"the case did not ask for evidence: {type(decision).__name__}")

    claims = tuple(entry.record for entry in case.entries if isinstance(entry, Statement))

    #  2. Before asking anybody: can this process read the site's material
    #     itself?  It must not, and finding that it can stops the run -- there
    #     is nothing worth demonstrating on top of a boundary that is open.
    attempt = raw_object_access(raw_object)
    if attempt.outcome is RawAccess.ALLOWED:
        return CloudHeroRun(claims, solicited, attempt, (), None)

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
    return CloudHeroRun(claims, solicited, attempt, acquired.value, read.value)


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


#  ---- the deliberate Action Gate ------------------------------------------
#
#  Everything below runs only under ``CLOUD_SQL_ACTION_GATE_SANDBOX``.  There is
#  no call to any of it on the analysis-only path, and the architecture suite
#  reads this file to say so.


@dataclass(frozen=True, slots=True)
class CloudGateExecution:
    """What the deployed Gate did, in the same closed vocabulary as the run.

    Every field is a value the Gate or its executor actually produced: a state
    from the durable row, the idempotency key that *is* the hash of the exact
    authorized intent, the three timestamps the row carries, the synthetic
    reference the sandbox minted, the outcome code it returned, and the two
    counters the executor kept.  Nothing here is a label this module chose to
    believe -- ``real_funds`` in particular is read off the composed executor
    rather than asserted, so a composition that ever named a real one could not
    print ``false``.

    **The timestamps are read, never reconstructed.**  ``reserved_at`` is
    always present because a row cannot exist without it; ``dispatched_at`` and
    ``finalized_at`` are ``None`` for exactly the states in which the durable
    record has not reached them.  Nothing here fills a missing one in from the
    state machine: a CONFIRMED row does imply that RESERVED and DISPATCHED
    happened, but *when* they happened is a stored fact, and inventing it would
    make the one part of this artifact that is a measurement into a drawing.
    """

    state: str
    execution_key: str
    external_reference: str | None
    outcome_code: str | None
    real_funds: bool
    gate_id: str
    executor_id: str
    principal_id: str
    #: The durable lifecycle instants, exactly as the execution row carries
    #: them.  ``None`` means the row has not reached that transition, and is
    #: printed as ``none`` rather than guessed at.
    reserved_at: int
    dispatched_at: int | None
    finalized_at: int | None
    #: The digest of the exact action the Gate authorized, read back off the
    #: stored intent.  Printed for the operator's benefit; it is no longer what
    #: the retry is configured with, because the retry names the *execution*.
    action_digest: str
    #: How many times *this process* crossed the executor boundary.  The whole
    #: point of the idempotency read is that this is zero on a retry.
    dispatch_count: int
    execution_count: int

    def lines(self) -> tuple[str, ...]:
        return (
            f"gate                   {self.gate_id}",
            f"executor               {self.executor_id}",
            f"principal              {self.principal_id}",
            f"principal source       {PRINCIPAL_SOURCE}",
            f"state                  {self.state}",
            f"execution id           {self.execution_key}",
            f"action digest          {self.action_digest}",
            f"reserved at            {self.reserved_at}",
            f"dispatched at          {_instant(self.dispatched_at)}",
            f"finalized at           {_instant(self.finalized_at)}",
            f"external reference     {self.external_reference or 'none'}",
            f"outcome code           {self.outcome_code or 'none'}",
            f"real funds             {'true' if self.real_funds else 'false'}",
            f"dispatches this run    {self.dispatch_count}",
            f"executions this run    {self.execution_count}",
        )


def _instant(value: int | None) -> str:
    """A durable instant, or the honest absence of one."""
    return "none" if value is None else str(value)


def cloud_executor() -> SandboxPaymentExecutor:
    """The one executor a deployed Gate composes: synthetic, and labelled.

    No provider, no account, no credential and no network call.  It mints a
    deterministic reference from the execution key and keeps two counters, and
    those counters are what the duplicate-prevention proof is read from.
    """
    return SandboxPaymentExecutor(
        executor_id=CLOUD_EXECUTOR_ID, trusted_gate_id=CLOUD_GATE_ID
    )


def cloud_gate(
    casework: Casework, fleet: CloudFleet, executor: SandboxPaymentExecutor
) -> tuple[ActionGate, GateCaller]:
    """Compose the deployed Gate, or end the run saying which decision failed.

    The caller is the identity the *metadata server* reports for this workload,
    checked against the one the deployment provisioned.  Nothing on this path
    reads a request field, an argument or a model's output, so there is no
    value an untrusted party can supply that changes who the Gate thinks is
    asking -- which is the property the whole grant rests on.

    Only the failure enumeration travels into the log.
    """
    resolved = resolve_cloud_gate_authority(
        MetadataServerPrincipal(),
        CloudExecutionAuthorityConfiguration(
            expected_principal_id=fleet.gate_principal or "",
            tenant_id=fleet.tenant_id,
            action_kind=CLOUD_ACTION_KIND,
            gate_id=CLOUD_GATE_ID,
            executor_id=executor.executor_id,
        ),
    )
    if isinstance(resolved, Err):
        raise SystemExit(
            f"muster-cloud-hero: GATE AUTHORITY REFUSED: {resolved.error.failure.value}"
        )
    authority = resolved.value
    #  Two machine-readable lines, and both are closed tokens.  They say where
    #  the identity that got past the comparison came from and that it matched
    #  -- which is exactly the claim a proof needs and the whole of what it may
    #  safely carry.  No address, no token, no header.
    print(f"  gate.principal.source = {PRINCIPAL_SOURCE}")
    print(f"  gate.principal.status = {PRINCIPAL_STATUS_MATCHED}")
    return (
        ActionGate(
            casework=casework,
            authority=authority.authority,
            executor=executor,
            gate_id=CLOUD_GATE_ID,
        ),
        authority.caller,
    )


def _executed(
    record: ExecutionRecord,
    executor: SandboxPaymentExecutor,
    caller: GateCaller,
) -> CloudGateExecution:
    """Project the durable row, field for field, with nothing added.

    Every value below is either read off ``ExecutionRecord`` -- which is itself
    read back from the stored canonical octets -- or off the composed executor.
    There is no default, no ``or`` fallback and no derived timestamp here, so a
    field this prints is a field the database holds.
    """
    return CloudGateExecution(
        state=record.state.value,
        execution_key=record.execution_key.hex,
        external_reference=record.external_reference,
        outcome_code=record.outcome_code,
        real_funds=executor.transfers_real_funds,
        gate_id=record.intent.gate_id,
        executor_id=record.intent.executor_id,
        principal_id=caller.principal_id,
        reserved_at=record.reserved_at,
        dispatched_at=record.dispatched_at,
        finalized_at=record.finalized_at,
        action_digest=record.intent.action_digest.hex,
        dispatch_count=executor.dispatch_count,
        execution_count=executor.execution_count,
    )


def execute_cloud_gate(
    casework: Casework,
    fleet: CloudFleet,
    report: CaseReport,
    *,
    now: Instant = ravi.NOW,
) -> CloudGateExecution:
    """Run the Gate over the proposal this execution's own analysis produced.

    **The proposal is built from the case, never from configuration.**  The
    revision and certificate come off the head the analysis returned, and the
    action digest is the digest of the invariant action the kernel derived.
    There is no recipient, amount, currency or action kind on this path at all:
    the Gate re-derives every one of them server-side from the current head,
    and the executor receives the exact ``ActionIntent`` and nothing else.

    Executed in the *same process* that authored the case, deliberately.  The
    Gate's first-execution path revalidates the case, and the worked fixture's
    officer key lives for one process -- so this is where a full semantic
    validation is honest.  What a later process may do with the result is the
    idempotency read below, which asks a different and much narrower question.
    """
    head = report.head
    analysis = report.analysis
    if analysis is None or head.revision_digest is None or head.certificate_digest is None:
        raise SystemExit("muster-cloud-hero: GATE REFUSED: the case carries no analysis")
    outcome = analysis.kernel.outcome
    if not isinstance(outcome, Invariant):
        raise SystemExit(
            "muster-cloud-hero: GATE REFUSED: only an invariant action is executable"
        )

    executor = cloud_executor()
    gate, caller = cloud_gate(casework, fleet, executor)
    performed = gate.execute(
        caller=caller,
        tenant_id=fleet.tenant_id,
        request=ExecuteProposal(
            case_id=head.case_id,
            revision_digest=head.revision_digest,
            certificate_digest=head.certificate_digest,
            action_digest=outcome.action.digest(),
        ),
        now=now,
    )
    if isinstance(performed, Err):
        raise SystemExit(f"muster-cloud-hero: GATE REFUSED: {performed.error.failure.value}")
    return _executed(performed.value, executor, caller)


def repeat_gate_execution(
    database: CaseworkDatabase,
    fleet: CloudFleet,
    transport: AcquisitionTransport,
    *,
    now: Instant = ravi.NOW,
) -> CloudGateExecution:
    """Re-run the complete hero path and execute its re-derived proposal.

    This is not the idempotency read below. It reopens and replays the durable
    case, re-drives acquisition, reproduces the certificate, and calls the same
    ``execute_cloud_gate`` entry point as the first execution. The existing
    reservation is what makes the fresh executor's dispatch counter stay zero;
    no execution identity is accepted as configuration on this path.
    """
    if fleet.gate_mode is not HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX:
        raise SystemExit(
            "muster-cloud-hero: GATE REPEAT REFUSED: "
            f"{GATE_MODE}={HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX.value} is required"
        )
    if fleet.deployment is not DatabaseDeployment.CLOUD_SQL:
        raise SystemExit(
            "muster-cloud-hero: GATE REPEAT REFUSED: CLOUD_SQL custody is required"
        )

    casework = build_casework(fleet, database)
    run = run_cloud_hero(
        casework,
        transport,
        case=cloud_case(fleet),
        site_endpoint=fleet.site_endpoint,
        employer_endpoint=fleet.employer_endpoint,
        raw_object=fleet.raw_object,
        now=now,
    )
    boundary_held = run.raw_access == RawAttempt(
        RawAccess.DENIED, run.raw_access.reference, 403
    )
    if not run.reached_invariant() or not boundary_held or run.report is None:
        raise SystemExit(
            "muster-cloud-hero: GATE REPEAT REFUSED: the full hero proof did not reproduce"
        )
    return execute_cloud_gate(casework, fleet, run.report, now=now)


def verify_gate_idempotency(
    database: CaseworkDatabase, fleet: CloudFleet
) -> CloudGateExecution:
    """Read the lifecycle an earlier authorization already produced. Nothing else.

    **This is an idempotency read and it is not a restart.**  It opens no case,
    appends nothing, acquires nothing, asks no source, runs no check, calls no
    model, calls no solver, reads no case head, and never reaches the
    executor's dispatch -- the executor it composes exists only so the Gate has
    an identity to compare against, and its dispatch counter is printed
    precisely because it stays at zero.

    **What it identifies is an execution, not a proposal.**  The tenant and the
    case are configuration; the identity is the ``ExecutionKey`` the first Gate
    execution printed, which is the hash of the exact canonical ``ActionIntent``
    that was authorized and the primary key of the row holding those octets.
    So this asks "what did *that* execution do", and the answer does not move
    when the case does.  A retry derived from the current head would have gone
    absent the moment one more transcript entry was appended -- which is a
    duplicate-prevention story with an expiry date, and not one worth telling.

    The case identifier is still passed, as ``expected_case_id``: a caller that
    knows which case it is retrying says so, and a key belonging to a different
    case is refused rather than confidently answered.  It narrows; it does not
    identify.

    Nothing here re-admits a record, re-runs Q-12 or re-derives a certificate,
    which is why it works from a process that does not hold the officer key the
    case was authored under -- and why it makes no claim that it does.
    """
    if fleet.gate_execution_key is None:
        raise SystemExit(f"muster-cloud-hero: MISSING: {GATE_EXECUTION_ID}")

    executor = cloud_executor()
    gate, caller = cloud_gate(build_casework(fleet, database), fleet, executor)
    read = gate.read_authorized_execution(
        caller=caller,
        tenant_id=fleet.tenant_id,
        lookup=ExecutionLookup(
            execution_key=fleet.gate_execution_key,
            expected_case_id=fleet.case_id,
        ),
    )
    if isinstance(read, Err):
        raise SystemExit(
            f"muster-cloud-hero: GATE IDEMPOTENCY REFUSED: {read.error.failure.value}"
        )
    record = read.value
    if record.state is not ExecutionState.CONFIRMED:
        #  A retry that reported an unconfirmed lifecycle as a proof would be
        #  claiming an execution the durable record does not carry.  The state
        #  is named, and the exit status says the proof was not established.
        raise SystemExit(
            f"muster-cloud-hero: GATE IDEMPOTENCY NOT CONFIRMED: {record.state.value}"
        )
    return _executed(record, executor, caller)


def _print_execution(execution: CloudGateExecution, *, heading: str) -> None:
    print(heading)
    print("")
    print(f"  {SANDBOX_LABEL}")
    print("")
    for line in execution.lines():
        print(f"  {line}")
    print("")


#  ---- reading a case a previous execution left behind ---------------------


@dataclass(frozen=True, slots=True)
class DurableCase:
    """What a case looks like from a process that did not create it.

    Identifiers, digests and counts.  No predicate values, no receipt bodies,
    no source material -- the same closed vocabulary the narration keeps, and
    for the same reason: this is printed into a job log.

    **This is a persistence claim and only that.**  Two executions printing the
    same nine lines establishes that the head, the transcript membership and
    the certificate identity survived the first process ending.  It does not
    itself re-admit a record, re-run Q-12 or re-analyse anything.  The separate
    :func:`revalidate_durable_case` path makes that semantic claim using the
    process-stable synthetic officer, publisher and fixture-source trust.
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
    persistence and this function is only making the second one.  The cloud
    hero now composes process-stable synthetic officer, publisher and fixture
    source trust, so :func:`revalidate_durable_case` can ask ``case_status`` in
    a fresh process.  Keeping this narrower read separate preserves the useful
    distinction between "the rows survived" and "the stored case reproduced."
    """
    with database.reading(tenant_id) as scope:
        return _read_durable_case(scope, tenant_id=tenant_id, case_id=case_id)


def _read_durable_case(
    scope: TenantScope, *, tenant_id: str, case_id: str
) -> DurableCase:
    """Project durable identities from an already-open coherent read scope."""
    head = scope.heads.read(case_id)
    if isinstance(head, Err):
        raise SystemExit(f"muster-cloud-hero: DURABLE CASE ABSENT: {head.error.failure.value}")
    stored = head.value
    if stored.revision_digest is None or stored.certificate_digest is None:
        raise SystemExit("muster-cloud-hero: DURABLE CASE NOT ANALYSED")
    members = scope.transcript.members(case_id)
    if isinstance(members, Err):
        raise SystemExit(
            f"muster-cloud-hero: DURABLE TRANSCRIPT UNREADABLE: {members.error.failure.value}"
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


class _RevalidationDatabase:
    """Capture every reported observation inside ``case_status``'s read scope."""

    def __init__(
        self,
        database: CaseworkDatabase,
        casework: Casework,
        *,
        tenant_id: str,
        case_id: str,
    ) -> None:
        self._database = database
        self._casework = casework
        self._tenant_id = tenant_id
        self._case_id = case_id
        self._durable: DurableCase | None = None
        self._entries_reverified: int | None = None

    def writing(self, tenant_id: str) -> Never:
        raise InvariantViolation(f"revalidation cannot write tenant {tenant_id!r}")

    @contextmanager
    def reading(self, tenant_id: str) -> Iterator[TenantScope]:
        if tenant_id != self._tenant_id:
            raise InvariantViolation(
                f"revalidation for {self._tenant_id!r} cannot read tenant {tenant_id!r}"
            )
        with self._database.reading(tenant_id) as scope:
            durable = _read_durable_case(
                scope,
                tenant_id=tenant_id,
                case_id=self._case_id,
            )
            authenticated = read_published(
                scope,
                self._case_id,
                self._casework.publisher_verifier,
                self._casework.officer_verifier,
                self._casework.source_verifier,
            )
            self._durable = durable
            if isinstance(authenticated, Ok):
                self._entries_reverified = len(authenticated.value.entries)
            yield scope

    def observation(self) -> tuple[DurableCase, int]:
        if self._durable is None or self._entries_reverified is None:
            raise InvariantViolation("revalidation completed without a durable observation")
        return self._durable, self._entries_reverified


def _print_durable_case(durable: DurableCase, *, heading: str) -> None:
    print(heading)
    print("")
    for line in durable.lines():
        print(f"  {line}")
    print("")


@dataclass(frozen=True, slots=True)
class RevalidatedCase:
    """What a durable case looks like after an independent semantic replay.

    This record carries the durable identities alongside what the replaying
    process established: the resulting status, whether its engine reproduced
    the head's certificate, and how many entries from the head's own transcript
    prefix were authenticated again.

    **The zeros are structural, not observations.**  ``writes`` and
    ``dispatches`` do not count operations that happened to remain at zero.
    This path opens no write scope and constructs no executor, so it has no
    mechanism by which it could mutate custody or dispatch an action.
    """

    tenant_id: str
    case_id: str
    revision_number: int
    revision_digest: str
    certificate_digest: str
    construction_digest: str
    authorization_context_digest: str
    transcript_entries: int
    transcript_membership_digest: str
    status: str
    certificate_reproduced: bool
    entries_reverified: int
    writes: int = 0
    dispatches: int = 0

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
            f"transcript membership  {self.transcript_membership_digest}",
            f"status                 {self.status}",
            f"certificate reproduced {'true' if self.certificate_reproduced else 'false'}",
            f"entries reverified     {self.entries_reverified}",
            f"writes                 {self.writes}",
            f"dispatches             {self.dispatches}",
        )


def revalidate_durable_case(
    database: CaseworkDatabase,
    fleet: CloudFleet,
    *,
    now: Instant = ravi.NOW,
) -> RevalidatedCase:
    """Re-admit and replay a durable case in a process that did not write it.

    **This is semantic revalidation.**  The path re-admits the stored
    construction record, re-verifies every stored attestation's source
    signature, re-reads the pinned authority and catalog publications, re-runs
    Q-12, replays the head's own transcript prefix, re-analyses the case, and
    compares the replayed certificate with the digest held on the head.

    **It gathers and authorizes nothing.**  There is no
    ``acquire_outstanding`` because this is a re-check of what is stored, not a
    new gathering.  There is no model and no agent transport.  It constructs no
    ``ActionGate`` or ``GateCaller``, derives no execution identity, and asks no
    metadata server for a principal: a read must not be able to become an
    authorization, and there is nothing here to authorize.  It opens no
    ``database.writing()`` scope because a verification that created what it
    went looking for would establish nothing.  Publication, case, and gate
    state are therefore never mutated.

    **This is stronger than the persistence read.**  :func:`read_durable_case`
    establishes only that rows and their identities survived another process;
    this entry point establishes that the stored case can be authenticated and
    derived again.  That claim became possible only when the synthetic officer,
    publisher, and fixture-source populations all became process-stable, so a
    fresh process holds the same public trust material as the writer.

    **Certificate reproduction describes this process's engine.**
    ``certificate_reproduced`` is reported by :func:`case_status` and, as
    :class:`CaseReport` documents, is a property of the replaying process's
    engine configuration.  A different solver build can legitimately move it.
    This entry point nevertheless treats non-reproduction as a refusal because
    reproduction is precisely the question it was asked to answer.
    """
    if fleet.deployment is DatabaseDeployment.EPHEMERAL:
        raise SystemExit(
            "muster-cloud-hero: REVALIDATION REFUSED: "
            "EPHEMERAL custody keeps nothing between executions"
        )

    casework = build_casework(fleet, database)
    observation = _RevalidationDatabase(
        database,
        casework,
        tenant_id=fleet.tenant_id,
        case_id=fleet.case_id,
    )
    casework = replace(casework, database=observation)
    replayed = case_status(
        casework,
        tenant_id=fleet.tenant_id,
        case_id=fleet.case_id,
        now=now,
    )
    if isinstance(replayed, Err):
        raise SystemExit(f"muster-cloud-hero: REVALIDATION REFUSED: {replayed.error.failure.value}")
    report = replayed.value
    if report.analysis is None:
        raise SystemExit("muster-cloud-hero: DURABLE CASE NOT ANALYSED")
    if not report.certificate_reproduced:
        raise SystemExit("muster-cloud-hero: CERTIFICATE NOT REPRODUCED")
    durable, entries_reverified = observation.observation()

    return RevalidatedCase(
        tenant_id=durable.tenant_id,
        case_id=durable.case_id,
        revision_number=durable.revision_number,
        revision_digest=durable.revision_digest,
        certificate_digest=durable.certificate_digest,
        construction_digest=durable.construction_digest,
        authorization_context_digest=durable.authorization_context_digest,
        transcript_entries=durable.transcript_entries,
        transcript_membership_digest=durable.transcript_digest,
        status=report.status.value,
        certificate_reproduced=report.certificate_reproduced,
        entries_reverified=entries_reverified,
    )


def _print_revalidated_case(revalidated: RevalidatedCase, *, heading: str) -> None:
    print(heading)
    print("")
    for line in revalidated.lines():
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
    parser.add_argument(
        "--revalidate-durable-case",
        action="store_true",
        help=(
            "read and semantically revalidate the case a previous execution "
            "left in durable custody, reproduce its certificate, write and "
            "dispatch nothing, and exit; requires non-EPHEMERAL custody"
        ),
    )
    parser.add_argument(
        "--verify-gate-idempotency",
        action="store_true",
        help=(
            "read the execution lifecycle an earlier authorization already "
            "produced for the configured proposal, confirm it is CONFIRMED, "
            "and exit.  An idempotency read only -- it authorizes nothing, "
            "dispatches nothing, asks no source, runs no check and creates no "
            "row; it requires the Action Gate mode and CLOUD_SQL"
        ),
    )
    parser.add_argument(
        "--repeat-gate-execution",
        action="store_true",
        help=(
            "run the complete durable hero path again, re-derive the exact "
            "proposal, execute it through the existing Action Gate, and exit; "
            "requires the Action Gate mode and CLOUD_SQL"
        ),
    )
    arguments = parser.parse_args(argv)

    fleet = from_environment()
    if arguments.print_configuration:
        transport = build_transport(fleet)
        for line in _configuration_lines(fleet, transport):
            print(line)
        return 0

    database = open_database(fleet)

    if arguments.revalidate_durable_case:
        _print_revalidated_case(
            revalidate_durable_case(database, fleet),
            heading=(
                "durable case, semantically revalidated by a process that did not create it\n"
                "  (stored inputs reverified and certificate reproduced; no writes or dispatches)"
            ),
        )
        return 0

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

    if arguments.verify_gate_idempotency:
        #  Gated on the mode rather than on the flag alone.  The idempotency
        #  read needs the deployment's execution authority and its durable
        #  custody, and a job that carried the flag without the mode would be
        #  asking about a Gate this deployment never provisioned.
        if fleet.gate_mode is not HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX:
            raise SystemExit(
                "muster-cloud-hero: GATE IDEMPOTENCY REFUSED: "
                f"{GATE_MODE}={HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX.value} is required"
            )
        _print_execution(
            verify_gate_idempotency(database, fleet),
            heading=(
                "durable execution, read by a process that did not create it\n"
                "  (idempotency only: no case was validated and nothing was dispatched)"
            ),
        )
        return 0

    if arguments.repeat_gate_execution:
        if fleet.gate_mode is not HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX:
            raise SystemExit(
                "muster-cloud-hero: GATE REPEAT REFUSED: "
                f"{GATE_MODE}={HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX.value} is required"
            )
        if fleet.deployment is not DatabaseDeployment.CLOUD_SQL:
            raise SystemExit(
                "muster-cloud-hero: GATE REPEAT REFUSED: CLOUD_SQL custody is required"
            )
        repeated = repeat_gate_execution(database, fleet, build_transport(fleet))
        _print_execution(
            repeated,
            heading=(
                "cloud action gate, after the complete hero path was repeated\n"
                "  (the execution identity was re-derived, not configured)"
            ),
        )
        return 0 if repeated.state == "CONFIRMED" else 1

    transport = build_transport(fleet)
    case = cloud_case(fleet)
    #  One control plane for the whole run.  The Gate below revalidates the
    #  case, and it must do so against the same verifiers the acquisition ran
    #  under -- a second composition would be a second answer to "who is a
    #  trusted officer" inside one execution.
    casework = build_casework(fleet, database)
    run = run_cloud_hero(
        casework,
        transport,
        case=case,
        site_endpoint=fleet.site_endpoint,
        employer_endpoint=fleet.employer_endpoint,
        raw_object=fleet.raw_object,
    )
    narrate(run)

    #  The Gate, and only when the deployment named it.  Reached after the
    #  analysis has already been narrated, so a Gate refusal ends a run whose
    #  reasoning is already on the log rather than one that printed nothing.
    #
    #  The 403 is a precondition here as much as it is for the artifact: a
    #  deployment whose control plane can read the source's raw material has
    #  not demonstrated the architecture, and executing a payment on top of
    #  that would be the demo asserting the one thing it just disproved.
    boundary_held = run.raw_access == RawAttempt(RawAccess.DENIED, run.raw_access.reference, 403)
    execution: CloudGateExecution | None = None
    if (
        fleet.gate_mode is HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX
        and run.reached_invariant()
        and boundary_held
        and run.report is not None
    ):
        execution = execute_cloud_gate(casework, fleet, run.report)
        _print_execution(execution, heading="cloud action gate, as this execution ran it")

    if run.reached_invariant() and boundary_held:
        from demo.case_trace_artifact import (
            build_case_trace_artifact,
            cloud_artifact_context_from_environment,
        )

        try:
            artifact = build_case_trace_artifact(
                run, case, cloud_artifact_context_from_environment(), execution=execution
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
    #  Under the Gate mode the claim is larger, so the bar is: the lifecycle
    #  reached CONFIRMED.  A DISPATCHED or UNCERTAIN row is a legitimate durable
    #  state and an honest one to leave behind -- it is simply not the proof
    #  this mode was asked for, and saying so is what the exit status is for.
    if not run.reached_invariant():
        return 1
    if fleet.gate_mode is HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX:
        return 0 if execution is not None and execution.state == "CONFIRMED" else 1
    return 0


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
        f"mode       {_mode(fleet.gate_mode)}",
        f"gate       {CLOUD_GATE_ID}  executor {CLOUD_EXECUTOR_ID}",
        f"principal  {fleet.gate_principal or 'not configured'}",
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


#: What each mode is, in the words that decide whether an operator reading a
#: configuration report expects a payment to happen.  The analysis line says
#: what is *not* reached, for the same reason the ephemeral custody line says
#: what is lost.
_MODES: dict[HeroMode, str] = {
    HeroMode.ANALYSIS_ONLY: (
        "ANALYSIS ONLY -- the run stops at the analysis; no gate, nothing authorized"
    ),
    HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX: (
        f"CLOUD_SQL + ACTION_GATE_SANDBOX -- {SANDBOX_LABEL}"
    ),
}


def _mode(gate_mode: HeroMode) -> str:
    return _MODES[gate_mode]


if __name__ == "__main__":
    raise SystemExit(main())
