"""The local hero's offline default and explicit live model split."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from demo import hero
from google.adk.models.google_llm import Gemini

from agent_tests.support import fleet
from agent_tests.support.interpreters import RuleBasedClaimant
from muster.agents.config import (
    DEFAULT_CLAIM_MODEL,
    DEFAULT_MODEL,
    DEFAULT_MODEL_CALLS,
    DEFAULT_MODEL_LOCATION,
    DEFAULT_TIMEOUT_SECONDS,
)
from muster.agents.runtime.interpret import InterpreterLimits

CONFIGURED_ENVIRONMENT = {
    "MUSTER_AGENT_ID": "agent-site-a",
    "MUSTER_AGENT_PRINCIPAL": "SITE-A",
    "MUSTER_AGENT_TENANT": "ALPHA",
    "MUSTER_AGENT_SOURCE_CLASS": "SITE_ACCESS_CONTROL",
    "MUSTER_AGENT_KEY_REF": "key-site-a-1",
    "MUSTER_AGENT_SIGNING_KEY_PATH": "/unused/by/model-construction.pem",
    "MUSTER_AGENT_PREDICATES": "present_on_site,on_site_duration",
    "MUSTER_AGENT_RESOURCE_SCOPE": "SITE:SITE-A",
    "MUSTER_AGENT_MATERIAL_BUCKET": "synthetic-site-evidence",
    "GOOGLE_CLOUD_PROJECT": "synthetic-project",
}


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """An agent configured the way a deployment configures one, and no network."""
    monkeypatch.delenv("MUSTER_AGENT_MATERIAL_DIR", raising=False)
    monkeypatch.delenv("MUSTER_AGENT_MODEL_BACKEND", raising=False)
    monkeypatch.delenv("MUSTER_AGENT_MAX_MODEL_CALLS", raising=False)
    monkeypatch.delenv("MUSTER_AGENT_TIMEOUT_SECONDS", raising=False)
    for name, value in CONFIGURED_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)


@pytest.mark.usefixtures("configured")
def test_live_hero_uses_developer_gemma_only_for_the_worker() -> None:
    live = hero._live_models()

    institutional = live.institutional
    assert isinstance(institutional, Gemini)
    assert institutional.model == DEFAULT_MODEL == "gemini-3.7-flash"
    assert institutional.client_kwargs == {
        "vertexai": True,
        "project": "synthetic-project",
        "location": DEFAULT_MODEL_LOCATION,
    }
    assert isinstance(live.worker_claim, Gemini)
    assert live.worker_claim.model == DEFAULT_CLAIM_MODEL == "gemma-4-26b-a4b-it"
    assert live.worker_claim.client_kwargs == {"vertexai": False}


#  ---- the bounds a --live run runs under ----------------------------------


@pytest.mark.usefixtures("configured")
def test_live_hero_reads_its_bounds_from_the_configuration_it_already_reads() -> None:
    """The configured bounds, not the deterministic fixture's.

    ``--live`` read the model out of ``from_environment`` and left the bounds
    behind, so a run against the deployment's model was bounded by the suite's
    fixture -- two different agents, described as one.
    """
    live = hero._live_models()

    assert live.limits == InterpreterLimits(
        max_model_calls=DEFAULT_MODEL_CALLS,
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
    )
    assert live.limits.timeout_seconds == 45.0
    assert live.limits != fleet.LIMITS


@pytest.mark.usefixtures("configured")
def test_live_hero_honours_an_operator_override_of_either_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MUSTER_AGENT_TIMEOUT_SECONDS", "70.5")
    monkeypatch.setenv("MUSTER_AGENT_MAX_MODEL_CALLS", "5")

    live = hero._live_models()

    assert live.limits == InterpreterLimits(max_model_calls=5, timeout_seconds=70.5)


def test_every_live_agent_is_given_the_configured_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wiring, at the place the bounds were being dropped.

    Driven through ``main`` rather than around it, because the defect was not in
    what ``_live_models`` returned -- it was in what ``main`` did with it.
    """
    configured_limits = InterpreterLimits(max_model_calls=7, timeout_seconds=45.0)
    monkeypatch.setattr(
        hero,
        "_live_models",
        lambda: hero.LiveFleet(
            institutional=fleet.site_reader(),
            worker_claim=RuleBasedClaimant(
                model="rule-based-claim-intake", claims={"present_on_site": "true"}
            ),
            limits=configured_limits,
        ),
    )
    seen: dict[str, InterpreterLimits] = {}
    for name in ("site", "employer", "worker"):
        monkeypatch.setattr(fleet, name, _recording(name, getattr(fleet, name), seen))

    assert hero.main(["--live"]) == 0
    assert seen == {
        "site": configured_limits,
        "employer": configured_limits,
        "worker": configured_limits,
    }


def _recording(
    name: str,
    factory: Callable[..., object],
    seen: dict[str, InterpreterLimits],
) -> Callable[..., object]:
    """One fleet factory, wrapped to note the bounds the agent it built holds."""

    def build(*arguments: object, **keywords: object) -> object:
        agent = factory(*arguments, **keywords)
        seen[name] = agent.limits  # type: ignore[attr-defined]
        return agent

    return build


def test_the_deterministic_fleet_still_runs_under_its_own_fixture_bounds(
    tenant_id: str,
) -> None:
    """The optional argument is optional, and omitting it changes nothing."""
    assert fleet.site(tenant_id).limits is fleet.LIMITS
    assert fleet.employer(tenant_id).limits is fleet.LIMITS
    assert fleet.worker().limits is fleet.LIMITS
    assert fleet.LIMITS == InterpreterLimits(max_model_calls=12, timeout_seconds=30.0)  # noqa: SIM300


def test_default_hero_never_constructs_a_live_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def live_model_forbidden() -> object:
        raise AssertionError("the offline hero tried to construct a hosted model")

    monkeypatch.setattr(hero, "_live_models", live_model_forbidden)

    assert hero.main([]) == 0
