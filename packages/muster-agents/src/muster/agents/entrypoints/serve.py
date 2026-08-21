"""Bring one source agent up: read configuration, build it, serve one route.

The composition root of a deployed agent, and the only module in this
distribution that decides *which* store, *which* model and *which* identity
checker are in play.  Everything below it is written against ports, which is
why the same runtime serves a directory on a laptop and a private bucket behind
a service identity without a branch anywhere but here.

**It fails to start rather than starting wrong.**  A missing variable, an
unloadable key, a Vertex-backed agent with no project, a service that cannot
name its own audience -- each one stops the process with a message naming the
variable.  A source agent that came up and abstained on every request would be
indistinguishable, from the control plane, from a source with nothing to say,
and a fleet-wide misconfiguration would present as a quiet epidemic of honest
abstentions.

**Which profile it is comes from the source class, and is checked.**  The
profile factories refuse an identity presenting the wrong class, so a
deployment that pointed the site agent's configuration at the payroll agent's
key stops at start-up rather than producing receipts Q-12(b) refuses.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from muster.agents.common.environment import SystemClock, SystemNonce
from muster.agents.common.identity import SourceIdentity
from muster.agents.config import (
    AgentConfiguration,
    Backend,
    ConfigurationError,
    MaterialConfiguration,
    from_environment,
)
from muster.agents.google.models import build_model
from muster.agents.keys import LocalSourceSigner
from muster.agents.profiles import (
    HR_PAYROLL_SYSTEM,
    SITE_ACCESS_CONTROL,
    employer_agent,
    site_agent,
)
from muster.agents.runtime.agent import AcquisitionAgent
from muster.agents.runtime.interpret import InterpreterLimits
from muster.agents.runtime.receipts import AttestationPolicy
from muster.agents.sources.local import LocalDirectoryEvidenceStore
from muster.agents.sources.ports import SourceEvidenceStore
from muster.agents.transport.identity import CallerIdentity, GoogleIdentityToken, UncheckedCaller
from muster.agents.transport.service import AcquisitionService
from muster.core.results import Err

#: Cloud Run supplies the port to listen on.  Defaulted so the same command
#: runs on a laptop, and read here rather than deeper so that nothing below a
#: composition root reads the environment at all.
PORT_VARIABLE = "PORT"
DEFAULT_PORT = 8080

#: Which service accounts may send this agent assignments.  Ordinarily one --
#: the control plane's -- and required: an agent that served everybody would
#: make the identity check a formality.
CALLERS_VARIABLE = "MUSTER_AGENT_PERMITTED_CALLERS"

#: Set by Cloud Run, and by nothing a developer runs on a laptop.  Read for one
#: purpose: to refuse to start a *deployed* service that has no identity check,
#: which is the one configuration mistake that would come up and look fine.
SERVICE_VARIABLE = "K_SERVICE"


def build_agent(configuration: AgentConfiguration) -> AcquisitionAgent:
    """One agent, from one configuration record.  Raises if it cannot be built."""
    identity = SourceIdentity(
        agent_id=configuration.agent_id,
        principal_id=configuration.principal_id,
        tenant_id=configuration.tenant_id,
        source_class=configuration.source_class,
        key_ref=configuration.key_ref,
        acquirable_predicates=configuration.acquirable_predicates,
        resource_scope=configuration.resource_scope,
    )
    if configuration.source_class not in (SITE_ACCESS_CONTROL, HR_PAYROLL_SYSTEM):
        raise SystemExit(
            f"MUSTER_AGENT_SOURCE_CLASS: {configuration.source_class!r} has no profile"
        )
    _refuse_developer_backend_in_a_deployment(configuration)
    build = site_agent if configuration.source_class == SITE_ACCESS_CONTROL else employer_agent
    return build(
        identity=identity,
        store=_store(configuration.material),
        model=build_model(configuration.model),
        signer=LocalSourceSigner(
            configuration.key_ref, Path(configuration.signing_key_path).read_bytes()
        ),
        clock=SystemClock(),
        nonces=SystemNonce(),
        limits=InterpreterLimits(
            max_model_calls=configuration.model.max_model_calls,
            timeout_seconds=configuration.model.timeout_seconds,
        ),
        policy=AttestationPolicy(
            validity_ttl=configuration.validity_ttl,
            observation_horizon=configuration.observation_horizon,
        ),
    )


def build_service(
    configuration: AgentConfiguration, environ: dict[str, str] | None = None
) -> AcquisitionService:
    source = dict(os.environ) if environ is None else environ
    return AcquisitionService(
        agent=build_agent(configuration), identity=_identity(configuration, source)
    )


def _refuse_developer_backend_in_a_deployment(configuration: AgentConfiguration) -> None:
    """A deployed source calls Vertex, in a region somebody chose.

    The developer surface exists for a laptop and authenticates with an API key
    the client reads from the environment.  A deployed revision using it would
    send one site's private material to a key-authenticated public endpoint
    instead of to Vertex in the configured region -- undoing the data-residency
    decision the deployment took deliberately, and attributing the call to
    whoever's key it is rather than to a service.

    Nothing in the configuration record forbids it, because a laptop
    legitimately wants it.  What forbids it is being on Cloud Run.
    """
    if configuration.model.backend is Backend.VERTEX:
        return
    if os.environ.get(SERVICE_VARIABLE):
        raise SystemExit(
            f"MUSTER_AGENT_MODEL_BACKEND={configuration.model.backend.value} on a deployed "
            "service: a deployed agent calls Vertex under its own identity"
        )


def _store(material: MaterialConfiguration) -> SourceEvidenceStore:
    if material.directory is not None:
        return LocalDirectoryEvidenceStore(Path(material.directory))
    #  Imported here rather than at module scope: the cloud store pulls a
    #  storage client, and an agent reading a directory should not have to have
    #  one installed.  The extra is declared in the distribution metadata, and
    #  a deployment that names a bucket without it fails here, loudly, at
    #  start-up.
    from muster.agents.google.storage import GcsEvidenceStore  # noqa: PLC0415

    assert material.bucket is not None
    return GcsEvidenceStore(bucket=material.bucket, prefix=material.prefix)


def _identity(configuration: AgentConfiguration, source: dict[str, str]) -> CallerIdentity:
    """Who this service will do work for -- or a refusal to start.

    Three outcomes and no fourth.  The audience and the caller list go together
    because an agent that checks tokens has to know its own name, and an agent
    that knows its name and serves everybody is worse than one that will not
    start: the first looks like a working deployment.
    """
    callers = frozenset(
        part.strip() for part in source.get(CALLERS_VARIABLE, "").split(",") if part.strip()
    )
    if configuration.expected_audience is None and not callers:
        if source.get(SERVICE_VARIABLE):
            #  **A deployed service may not fall back to the unchecked caller.**
            #  Cloud Run sets ``K_SERVICE``, so a revision that reached here has
            #  a public-facing port and no identity check at all -- and would
            #  accept an assignment from anybody who can reach it, including one
            #  with no bearer token.  It is refused at start-up rather than
            #  served, because a fleet-wide misconfiguration that comes up and
            #  works is the one nobody finds.
            raise SystemExit(
                f"{source['K_SERVICE']} is a deployed service and names no audience; "
                f"set MUSTER_AGENT_AUDIENCE and {CALLERS_VARIABLE}"
            )
        #  A laptop: nothing to verify a token against and nobody but the
        #  developer able to reach the port.  Named for what it is, so that
        #  finding it in a deployed service's logs is finding a defect.
        return UncheckedCaller()
    if configuration.expected_audience is None or not callers:
        raise SystemExit(
            "an agent that checks callers needs both MUSTER_AGENT_AUDIENCE and "
            f"{CALLERS_VARIABLE}; set both or neither"
        )
    return GoogleIdentityToken(audience=configuration.expected_audience, permitted_callers=callers)


def main() -> int:
    """Read configuration, build the agent, and serve until stopped."""
    configuration = from_environment()
    if isinstance(configuration, Err):
        _refuse(configuration.error)
        return 2
    service = build_service(configuration.value)
    #  Imported here so that the distribution's own tests, which exercise the
    #  ASGI application directly, never load a server.
    import uvicorn  # noqa: PLC0415

    uvicorn.run(
        service,
        host="0.0.0.0",  # noqa: S104 - Cloud Run routes to the container's own interface
        port=int(os.environ.get(PORT_VARIABLE, DEFAULT_PORT)),
        log_level="info",
        access_log=False,
    )
    return 0


def _refuse(error: ConfigurationError) -> None:
    print(f"muster-agent: {error.failure.value}: {error.detail}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
