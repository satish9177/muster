"""One place an agent's deployment settings are read, and one time they are read.

Every value a deployed agent needs that is not in the assignment: which model
to call, where it runs, how long it may take, where its material lives, what it
is called, and which key it signs under.  All of it arrives from the process
environment at start-up and is frozen into a value, so nothing further down
reads the environment and nothing can differ between two requests.

**The model identifier is configuration and never a literal.**  A model is
upgraded by changing a deployment variable, not by editing a file, and the
identifier is recorded as telemetry rather than pinned as a semantic input --
because replay never replays a model call.  A different model changes *which
evidence gets acquired*; it cannot change what follows from evidence.

**Nothing here holds a secret.**  The signing key arrives as a path or, in a
real deployment, as a managed key the process never sees; the identity is a
service account attached to the revision.  There is no credential literal, no
API key default and no place for one: an agent whose configuration could carry
a static key is an agent whose configuration ends up in a repository.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from muster.core.authority.scope import ResourceScope
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.times import Duration

#: The default runtime model.  A current Gemini Flash: multimodal, fast enough
#: for a live demo, and strong enough on structured tool calls that abstention
#: stays a decision rather than an accident.  Overridden per deployment with
#: ``MUSTER_AGENT_MODEL`` -- and the override is the expected case, because a
#: default that outlives its model family is a default that stops working
#: silently.
#:
#: **It is chosen with :data:`DEFAULT_MODEL_LOCATION`, never separately.**  A
#: model is served in some locations and not others, and the pairing is the
#: decision rather than either half of it.  This one is served from the
#: ``global`` Vertex endpoint, which was confirmed against the live API in the
#: deployment project by ``:countTokens``; the deployment re-checks the pair
#: before it deploys anything -- see the preflight in
#: ``infra/scripts/50-deploy.sh`` -- because availability moves and a stale
#: default here fails silently otherwise.
DEFAULT_MODEL = "gemini-3.7-flash"

#: Where the model is called, and **only** that.  Read from
#: ``GOOGLE_CLOUD_LOCATION``, which is the variable the Vertex client itself
#: reads, so what this names is the inference endpoint and nothing else.
#:
#: ``global`` rather than a region, and stated rather than inherited.  The model
#: above is served from the global endpoint, and pretending otherwise would give
#: a fleet that comes up, raises inside the model client on every assignment and
#: abstains honestly forever -- the one misconfiguration that produces no error
#: anywhere.  So the consequence is named instead: **the interpretation happens
#: outside the region the material sits in.**  What crosses is a prompt built
#: from the material, never the material -- the objects are read only by the
#: source agent's own identity, from a bucket in
#: :data:`DEFAULT_MATERIAL_REGION`, and nothing in this distribution copies them
#: anywhere.  That is a smaller thing than moving the evidence and it is not a
#: nothing, which is why it is a value an operator sets rather than a default
#: that follows the region.
DEFAULT_MODEL_LOCATION = "global"

#: Where the service runs and where its material lives -- the Cloud Run region
#: and the evidence bucket's location.  A *different* value from
#: :data:`DEFAULT_MODEL_LOCATION` and deliberately a separate one: collapsing
#: the two is what made "where the model is called" follow "where the data is"
#: silently, so that changing either moved both.
#:
#: Nothing in the agent runtime reads it -- a deployed process learns its region
#: from the platform and the storage client resolves a bucket's location for
#: itself.  It is named here so that the two halves of the shipped deployment
#: are stated in one place and can be checked against ``infra/scripts/env.sh``,
#: which is the file that actually sets them.
DEFAULT_MATERIAL_REGION = "asia-south1"

DEFAULT_MODEL_CALLS = 12
DEFAULT_TIMEOUT_SECONDS = 45.0
#: A day.  How long a source stands behind what it observed.
DEFAULT_VALIDITY_TTL = Duration(24 * 3_600 * 1_000_000)

#: Thirty days.  How far back a source will attest to having observed
#: anything -- a different length from the one above, because how long an
#: answer stands and how old the material may be are different questions.
#: It bounds the one field a model authors freely, so it is deliberately a
#: *bound* rather than a limit anybody expects to reach.
DEFAULT_OBSERVATION_HORIZON = Duration(30 * 24 * 3_600 * 1_000_000)


class Backend(Enum):
    """Which Google surface the model is called through.

    Vertex AI is what a deployed agent uses: the call is authenticated by the
    service identity attached to the revision, so there is no key to hold and
    none to leak.  The Gemini API with a key exists for a laptop, and it is
    named ``DEVELOPER`` rather than ``API_KEY`` so that reading the
    configuration of a production service makes the wrong choice obvious.
    """

    VERTEX = "VERTEX"
    DEVELOPER = "DEVELOPER"


class ConfigurationFailure(Enum):
    MISSING = "MISSING"
    MALFORMED = "MALFORMED"


@dataclass(frozen=True, slots=True)
class ConfigurationError:
    failure: ConfigurationFailure
    detail: str


@dataclass(frozen=True, slots=True)
class ModelConfiguration:
    """Which model, on which surface, at which Vertex location, under what bounds.

    ``location`` is the **inference** endpoint and not the deployment region.
    The two are separate values in this system and ship as different ones -- the
    service and its material are regional, the model call is global -- so a
    reader of this record cannot conclude anything about where the evidence
    lives from where the model is called.
    """

    backend: Backend
    model: str
    project: str | None
    location: str
    max_model_calls: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        if not self.model:
            raise InvariantViolation("an agent names the model it calls")
        if self.backend is Backend.VERTEX and not self.project:
            raise InvariantViolation("a Vertex-backed agent names its project")


@dataclass(frozen=True, slots=True)
class MaterialConfiguration:
    """Where this source's own material lives.

    Exactly one of the two is set.  A directory is what a site runs in
    development; a bucket is what it runs deployed, read by the source's own
    identity and by no other.  Both being set would leave which one wins to
    whichever branch was written first.
    """

    directory: str | None
    bucket: str | None
    prefix: str

    def __post_init__(self) -> None:
        if (self.directory is None) == (self.bucket is None):
            raise InvariantViolation(
                "a source reads a local directory or a bucket, and names exactly one"
            )


@dataclass(frozen=True, slots=True)
class AgentConfiguration:
    """Everything a deployed agent is, before an assignment arrives."""

    agent_id: str
    principal_id: str
    tenant_id: str
    source_class: str
    key_ref: str
    signing_key_path: str
    acquirable_predicates: tuple[str, ...]
    resource_scope: tuple[ResourceScope, ...]
    material: MaterialConfiguration
    model: ModelConfiguration
    validity_ttl: Duration
    observation_horizon: Duration
    #: The audience an inbound identity token must name.  The service's own URL
    #: in a deployment; unset only where the transport is in-process and there
    #: is no network identity to check.
    expected_audience: str | None


def from_environment(
    environ: dict[str, str] | None = None,
) -> Result[AgentConfiguration, ConfigurationError]:
    """Read one agent's configuration, or say exactly which variable is wrong.

    ``environ`` is an argument so that this is testable without touching the
    process, and defaults to the process environment so that a deployment does
    not have to arrange one.  It is read **once**, at start-up: a value read per
    request is a value that can differ between two requests, and an agent whose
    source class could change halfway through a case is not one thing.
    """
    source = dict(os.environ) if environ is None else environ

    def required(name: str) -> Result[str, ConfigurationError]:
        value = source.get(name, "").strip()
        if not value:
            return Err(ConfigurationError(ConfigurationFailure.MISSING, name))
        return Ok(value)

    fields: dict[str, str] = {}
    for name in (
        "MUSTER_AGENT_ID",
        "MUSTER_AGENT_PRINCIPAL",
        "MUSTER_AGENT_TENANT",
        "MUSTER_AGENT_SOURCE_CLASS",
        "MUSTER_AGENT_KEY_REF",
        "MUSTER_AGENT_SIGNING_KEY_PATH",
        "MUSTER_AGENT_PREDICATES",
        "MUSTER_AGENT_RESOURCE_SCOPE",
    ):
        found = required(name)
        if isinstance(found, Err):
            return found
        fields[name] = found.value

    scope = _scope_of(fields["MUSTER_AGENT_RESOURCE_SCOPE"])
    if isinstance(scope, Err):
        return scope

    material = _material_of(source)
    if isinstance(material, Err):
        return material

    model = _model_of(source)
    if isinstance(model, Err):
        return model

    ttl = _duration_of(source.get("MUSTER_AGENT_VALIDITY_SECONDS"), DEFAULT_VALIDITY_TTL)
    if isinstance(ttl, Err):
        return ttl

    horizon = _duration_of(source.get("MUSTER_AGENT_HORIZON_SECONDS"), DEFAULT_OBSERVATION_HORIZON)
    if isinstance(horizon, Err):
        return horizon

    try:
        return Ok(
            AgentConfiguration(
                agent_id=fields["MUSTER_AGENT_ID"],
                principal_id=fields["MUSTER_AGENT_PRINCIPAL"],
                tenant_id=fields["MUSTER_AGENT_TENANT"],
                source_class=fields["MUSTER_AGENT_SOURCE_CLASS"],
                key_ref=fields["MUSTER_AGENT_KEY_REF"],
                signing_key_path=fields["MUSTER_AGENT_SIGNING_KEY_PATH"],
                acquirable_predicates=tuple(
                    sorted(
                        part.strip()
                        for part in fields["MUSTER_AGENT_PREDICATES"].split(",")
                        if part.strip()
                    )
                ),
                resource_scope=scope.value,
                material=material.value,
                model=model.value,
                validity_ttl=ttl.value,
                observation_horizon=horizon.value,
                expected_audience=(source.get("MUSTER_AGENT_AUDIENCE") or "").strip() or None,
            )
        )
    except InvariantViolation as violation:
        return Err(ConfigurationError(ConfigurationFailure.MALFORMED, str(violation)))


def _scope_of(text: str) -> Result[tuple[ResourceScope, ...], ConfigurationError]:
    """``SITE:SITE-A,COST_CENTRE:CC-114`` -- enumerated, never a wildcard."""
    coordinates: list[ResourceScope] = []
    for part in text.split(","):
        stripped = part.strip()
        if not stripped:
            continue
        kind, separator, value = stripped.partition(":")
        if not separator:
            return Err(
                ConfigurationError(
                    ConfigurationFailure.MALFORMED,
                    f"MUSTER_AGENT_RESOURCE_SCOPE: {stripped!r} is not KIND:VALUE",
                )
            )
        try:
            coordinates.append(ResourceScope(kind.strip(), value.strip()))
        except InvariantViolation as violation:
            return Err(
                ConfigurationError(
                    ConfigurationFailure.MALFORMED,
                    f"MUSTER_AGENT_RESOURCE_SCOPE: {violation}",
                )
            )
    if not coordinates:
        return Err(
            ConfigurationError(
                ConfigurationFailure.MALFORMED, "MUSTER_AGENT_RESOURCE_SCOPE is empty"
            )
        )
    return Ok(tuple(coordinates))


def _material_of(source: dict[str, str]) -> Result[MaterialConfiguration, ConfigurationError]:
    directory = (source.get("MUSTER_AGENT_MATERIAL_DIR") or "").strip() or None
    bucket = (source.get("MUSTER_AGENT_MATERIAL_BUCKET") or "").strip() or None
    try:
        return Ok(
            MaterialConfiguration(
                directory=directory,
                bucket=bucket,
                prefix=(source.get("MUSTER_AGENT_MATERIAL_PREFIX") or "").strip(),
            )
        )
    except InvariantViolation as violation:
        return Err(ConfigurationError(ConfigurationFailure.MALFORMED, str(violation)))


def _model_of(source: dict[str, str]) -> Result[ModelConfiguration, ConfigurationError]:
    backend_name = (source.get("MUSTER_AGENT_MODEL_BACKEND") or Backend.VERTEX.value).strip()
    try:
        backend = Backend(backend_name)
    except ValueError:
        return Err(
            ConfigurationError(
                ConfigurationFailure.MALFORMED,
                f"MUSTER_AGENT_MODEL_BACKEND: {backend_name!r} is not "
                f"{' or '.join(member.value for member in Backend)}",
            )
        )
    calls = _int_of(source.get("MUSTER_AGENT_MAX_MODEL_CALLS"), DEFAULT_MODEL_CALLS)
    if isinstance(calls, Err):
        return calls
    seconds = _float_of(source.get("MUSTER_AGENT_TIMEOUT_SECONDS"), DEFAULT_TIMEOUT_SECONDS)
    if isinstance(seconds, Err):
        return seconds
    try:
        return Ok(
            ModelConfiguration(
                backend=backend,
                model=(source.get("MUSTER_AGENT_MODEL") or DEFAULT_MODEL).strip(),
                project=(source.get("GOOGLE_CLOUD_PROJECT") or "").strip() or None,
                location=(source.get("GOOGLE_CLOUD_LOCATION") or DEFAULT_MODEL_LOCATION).strip(),
                max_model_calls=calls.value,
                timeout_seconds=seconds.value,
            )
        )
    except InvariantViolation as violation:
        return Err(ConfigurationError(ConfigurationFailure.MALFORMED, str(violation)))


def _int_of(text: str | None, fallback: int) -> Result[int, ConfigurationError]:
    if text is None or not text.strip():
        return Ok(fallback)
    stripped = text.strip()
    if not stripped.isdigit():
        return Err(ConfigurationError(ConfigurationFailure.MALFORMED, stripped))
    return Ok(int(stripped))


def _float_of(text: str | None, fallback: float) -> Result[float, ConfigurationError]:
    if text is None or not text.strip():
        return Ok(fallback)
    try:
        return Ok(float(text.strip()))
    except ValueError:
        return Err(ConfigurationError(ConfigurationFailure.MALFORMED, text.strip()))


def _duration_of(text: str | None, fallback: Duration) -> Result[Duration, ConfigurationError]:
    seconds = _int_of(text, 0)
    if isinstance(seconds, Err):
        return seconds
    if seconds.value == 0:
        return Ok(fallback)
    return Ok(Duration(seconds.value * 1_000_000))
