"""The local hero's offline default and explicit live model split."""

from __future__ import annotations

import pytest
from demo import hero
from google.adk.models.google_llm import Gemini

from muster.agents.config import DEFAULT_CLAIM_MODEL, DEFAULT_MODEL, DEFAULT_MODEL_LOCATION


def test_live_hero_uses_developer_gemma_only_for_the_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = {
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
    monkeypatch.delenv("MUSTER_AGENT_MATERIAL_DIR", raising=False)
    monkeypatch.delenv("MUSTER_AGENT_MODEL_BACKEND", raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    site, employer, worker = hero._live_models()

    for institutional in (site, employer):
        assert isinstance(institutional, Gemini)
        assert institutional.model == DEFAULT_MODEL == "gemini-3.7-flash"
        assert institutional.client_kwargs == {
            "vertexai": True,
            "project": "synthetic-project",
            "location": DEFAULT_MODEL_LOCATION,
        }
    assert isinstance(worker, Gemini)
    assert worker.model == DEFAULT_CLAIM_MODEL == "gemma-4-26b-a4b-it"
    assert worker.client_kwargs == {"vertexai": False}


def test_default_hero_never_constructs_a_live_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def live_model_forbidden() -> tuple[object, object, object]:
        raise AssertionError("the offline hero tried to construct a hosted model")

    monkeypatch.setattr(hero, "_live_models", live_model_forbidden)

    assert hero.main([]) == 0
