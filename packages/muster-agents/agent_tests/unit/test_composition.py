"""What a deployment must not be able to come up as.

The composition root is the one place that decides which store, which model and
which identity check are in play, so it is the one place a deployment can be
wrong in a way that looks like a working service. Each case here is a
configuration that must stop the process instead.
"""

from __future__ import annotations

import pytest

from muster.agents.config import from_environment
from muster.agents.entrypoints.serve import (
    CALLERS_VARIABLE,
    SERVICE_VARIABLE,
    _identity,
    build_agent,
)
from muster.agents.transport.identity import GoogleIdentityToken, UncheckedCaller
from muster.core.results import Ok

AUDIENCE = "https://muster-site-agent-abc.a.run.app"
CALLER = "muster-control-plane@a-project.iam.gserviceaccount.com"

BASE = {
    "MUSTER_AGENT_ID": "agent-site-a",
    "MUSTER_AGENT_PRINCIPAL": "SITE-A",
    "MUSTER_AGENT_TENANT": "ALPHA",
    "MUSTER_AGENT_SOURCE_CLASS": "SITE_ACCESS_CONTROL",
    "MUSTER_AGENT_KEY_REF": "key-site-a-1",
    "MUSTER_AGENT_SIGNING_KEY_PATH": "/var/run/muster/signing-key.pem",
    "MUSTER_AGENT_PREDICATES": "present_on_site,on_site_duration",
    "MUSTER_AGENT_RESOURCE_SCOPE": "SITE:SITE-A",
    "MUSTER_AGENT_MATERIAL_BUCKET": "muster-site-evidence",
    "GOOGLE_CLOUD_PROJECT": "a-project",
}


def _identity_for(**changes: str) -> object:
    environ = dict(BASE) | changes
    configuration = from_environment(environ)
    assert isinstance(configuration, Ok), configuration
    return _identity(configuration.value, environ)


def test_a_laptop_with_no_identity_infrastructure_gets_the_unchecked_caller() -> None:
    """Named for what it does, so finding it in a deployed log is finding a bug."""
    assert isinstance(_identity_for(), UncheckedCaller)


def test_a_deployed_service_with_no_audience_refuses_to_start() -> None:
    """The configuration that would otherwise come up and serve everybody.

    Cloud Run sets ``K_SERVICE``. A revision that reached the unchecked caller
    would have a port, a signing key and no identity check -- and would answer
    an assignment from anybody who could reach it, with no bearer token at all.
    """
    with pytest.raises(SystemExit) as refusal:
        _identity_for(**{SERVICE_VARIABLE: "muster-site-agent"})
    assert "MUSTER_AGENT_AUDIENCE" in str(refusal.value)


@pytest.mark.parametrize(
    "half",
    [
        pytest.param({"MUSTER_AGENT_AUDIENCE": AUDIENCE}, id="audience-without-callers"),
        pytest.param({CALLERS_VARIABLE: CALLER}, id="callers-without-audience"),
    ],
)
def test_half_an_identity_check_refuses_to_start(half: dict[str, str]) -> None:
    """Both, or neither.

    On a laptop "neither" is a laptop. On Cloud Run it is not available at
    all -- the test above refuses it -- so a deployment script cannot reach
    its first URL by carrying neither, and the one below says what it carries
    instead.
    """
    with pytest.raises(SystemExit) as refusal:
        _identity_for(**half)
    assert "both or neither" in str(refusal.value)


def test_a_complete_deployment_checks_its_callers() -> None:
    identity = _identity_for(**{"MUSTER_AGENT_AUDIENCE": AUDIENCE, CALLERS_VARIABLE: CALLER})
    assert isinstance(identity, GoogleIdentityToken)
    assert identity.audience == AUDIENCE
    assert identity.permitted_callers == frozenset({CALLER})


def test_a_deployed_service_cannot_use_the_developer_model_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other configuration that would come up and look fine.

    The developer surface authenticates with an API key from the environment
    and talks to the public endpoint -- so a deployed revision using it would
    send one site's private material out of the region the deployment chose,
    attributed to whoever's key it is rather than to a service.
    """
    monkeypatch.setenv(SERVICE_VARIABLE, "muster-site-agent")
    environ = dict(BASE) | {"MUSTER_AGENT_MODEL_BACKEND": "DEVELOPER"}
    configuration = from_environment(environ)
    assert isinstance(configuration, Ok), configuration
    with pytest.raises(SystemExit) as refusal:
        build_agent(configuration.value)
    assert "Vertex" in str(refusal.value)


@pytest.mark.parametrize("spelling", ["", "  ", ",", " , "])
def test_a_caller_list_of_separators_is_not_a_caller_list(spelling: str) -> None:
    """An empty allowlist reads as "anybody", which is how one stops being one."""
    with pytest.raises(SystemExit):
        _identity_for(**{"MUSTER_AGENT_AUDIENCE": AUDIENCE, CALLERS_VARIABLE: spelling})


#  ---- the first deploy pass ----------------------------------------------
#
#  A service's identity-token audience is its own URL, and a service has no URL
#  until it has been deployed once. The deployment script therefore deploys
#  twice, and the *first* pass has to name an audience it does not yet know --
#  because a Cloud Run revision that names none refuses to start, which is the
#  test two above this one.
#
#  The review found the script reasoning the other way: that the first pass
#  could carry neither variable, as a laptop does. It cannot. Read together,
#  the tests here now say what a first pass must do, and the architecture suite
#  checks the script actually does it.

PLACEHOLDER_AUDIENCE = "https://audience-not-yet-resolved.invalid"


def test_the_first_deploy_pass_starts_and_serves_nobody() -> None:
    """A placeholder audience is not a weakening; it is a closed door.

    The revision comes up, checks every inbound token against an audience
    nothing was ever minted for, and refuses all of them. That is the same
    posture as refusing to start, and it is strictly more useful: it produces
    the URL the second pass needs.
    """
    identity = _identity_for(
        **{
            SERVICE_VARIABLE: "muster-site-agent",
            "MUSTER_AGENT_AUDIENCE": PLACEHOLDER_AUDIENCE,
            CALLERS_VARIABLE: CALLER,
        }
    )
    assert isinstance(identity, GoogleIdentityToken)
    assert identity.audience == PLACEHOLDER_AUDIENCE
    assert identity.permitted_callers == frozenset({CALLER})


def test_the_placeholder_audience_is_one_no_token_can_carry() -> None:
    """``.invalid`` is reserved and resolves nowhere.

    A placeholder that happened to be a reachable host would be an audience
    somebody could mint a token for, which is the one property it must not
    have.
    """
    assert PLACEHOLDER_AUDIENCE.endswith(".invalid")
