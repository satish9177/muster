"""Constructing the model an agent calls, from configuration and nothing else.

One function, and it exists so that every other module in this distribution
takes a ``BaseLlm`` it was handed rather than naming a model.  That is what
makes the deterministic suite run the real runtime against a scripted model and
the deployment run the same runtime against Gemini, with no branch anywhere in
between that knows which.

**Vertex AI is the deployed surface, and it holds no key.**  The call is
authenticated by the service identity attached to the Cloud Run revision, so
there is nothing to rotate, nothing to leak and nothing to check into a
repository.  The developer surface exists for a laptop and takes a key from the
environment the client reads for itself; a deployment that used it would be one
whose model calls are attributed to a person rather than to a service, which is
exactly the sort of thing an audit should be able to see in a configuration
file.

**The project and the Vertex location are stated, not inherited.**  The client
would happily resolve both from ambient environment variables, and an agent that
resolved its own endpoint from whatever the container inherited would be an
agent whose data flow is a deployment accident.  They come from the same
configuration record everything else does, and a Vertex-backed agent that names
no project does not start.

**The location here is where the model is called, not where the agent runs.**
The two are configured separately and ship as different values: the service and
the source's material are regional, and the model is called at the ``global``
endpoint because that is where the shipped model is served.  So what leaves the
region is a prompt built from the material, and never the material -- the
objects are read by the source's own identity, in its own region, by the
storage adapter beside this one.

**The identifier is not pinned here and must not be.**  A model version is
telemetry: it records which model produced a candidate and it decides nothing,
because a candidate has to survive deterministic validation whatever produced
it.  Replay never replays a model call.
"""

from __future__ import annotations

from typing import Any

from google.adk.models.google_llm import Gemini

from muster.agents.config import Backend, ModelConfiguration
from muster.core.results import InvariantViolation


def build_model(configuration: ModelConfiguration) -> Gemini:
    """The ADK model this agent calls, on the surface its configuration names.

    Raises rather than returning a refusal, and deliberately: this runs once at
    start-up, from configuration an operator wrote, and a process that cannot
    build its own interpreter should fail to start rather than accept traffic
    and abstain on every request.  An agent that answered "the interpreter is
    unavailable" to every assignment would look, from the control plane,
    exactly like a source with nothing to say -- and a fleet-wide
    misconfiguration would present as a quiet epidemic of honest abstentions.
    """
    return Gemini(model=configuration.model, client_kwargs=_client_kwargs(configuration))


def _client_kwargs(configuration: ModelConfiguration) -> dict[str, Any]:
    match configuration.backend:
        case Backend.VERTEX:
            if not configuration.project:
                #  Also refused when the configuration record is built.  Stated
                #  twice because this is the branch that would otherwise fall
                #  back to an ambient project, and an agent reading somebody
                #  else's project out of the environment is worse than one that
                #  will not start.
                raise InvariantViolation("a Vertex-backed agent names its project")
            return {
                "vertexai": True,
                "project": configuration.project,
                "location": configuration.location,
            }
        case Backend.DEVELOPER:
            #  No API key here, on purpose.  The client reads one from the
            #  environment; passing it through this record would put a secret
            #  in a value that gets logged, compared and repr'd.
            return {"vertexai": False}
