"""Reading a deployment, and refusing one that is wrong before it serves traffic.

A source agent that came up misconfigured would abstain on every assignment,
and from the control plane that is indistinguishable from a source with nothing
to say -- so a fleet-wide mistake would present as a quiet epidemic of honest
abstentions.  Every case here is a deployment that must fail to start instead.
"""

from __future__ import annotations

import pytest

from muster.agents.config import (
    DEFAULT_MATERIAL_REGION,
    DEFAULT_MODEL,
    DEFAULT_MODEL_LOCATION,
    Backend,
    ConfigurationFailure,
    from_environment,
)
from muster.agents.sources.local import parse_manifest
from muster.agents.sources.ports import EvidenceStoreFailure
from muster.core.authority.scope import ResourceScope
from muster.core.results import Err, Ok

MINIMUM = {
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


def read(**changes: str) -> object:
    environ = dict(MINIMUM)
    for name, value in changes.items():
        if value == "":
            environ.pop(name, None)
        else:
            environ[name] = value
    return from_environment(environ)


def refusal(**changes: str) -> tuple[ConfigurationFailure, str]:
    outcome = read(**changes)
    assert isinstance(outcome, Err), outcome
    return outcome.error.failure, outcome.error.detail


def test_a_complete_deployment_reads() -> None:
    outcome = read()
    assert isinstance(outcome, Ok), outcome
    configuration = outcome.value
    assert configuration.agent_id == "agent-site-a"
    assert configuration.resource_scope == (ResourceScope("SITE", "SITE-A"),)
    assert configuration.acquirable_predicates == ("on_site_duration", "present_on_site")
    assert configuration.material.bucket == "muster-site-evidence"
    assert configuration.model.backend is Backend.VERTEX
    assert configuration.model.model == DEFAULT_MODEL
    assert configuration.model.location == DEFAULT_MODEL_LOCATION


def test_the_model_location_is_where_the_model_is_called_and_nothing_else() -> None:
    """``GOOGLE_CLOUD_LOCATION`` names the Vertex endpoint, not the deployment.

    The two used to be one value: the model was called wherever the service ran.
    They ship as different ones now -- the services and the material are in
    ``asia-south1``, the model is called at ``global`` -- so the record has to
    keep them apart, and an operator has to be able to move either without
    touching the other.

    Both remain overridable.  Setting ``GOOGLE_CLOUD_LOCATION`` to the
    deployment region is the co-located choice, correct for any model served
    regionally there, and this is what makes it a one-variable decision.
    """
    assert DEFAULT_MODEL_LOCATION != DEFAULT_MATERIAL_REGION

    outcome = read(GOOGLE_CLOUD_LOCATION=DEFAULT_MATERIAL_REGION)
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.model.location == DEFAULT_MATERIAL_REGION

    #  And nothing about the material moved with it: where a source reads from
    #  is the bucket it names, which the model location has no say in.
    assert outcome.value.material.bucket == "muster-site-evidence"


def test_the_model_and_the_location_are_overridden_independently() -> None:
    """Neither default is reachable only through the other.

    A deployment upgrading its model must not have to accept a location it did
    not choose, and one moving its location must not silently change model --
    which is what a single paired variable, or a location derived from a model
    name, would do.
    """
    outcome = read(MUSTER_AGENT_MODEL="gemini-4.0-flash")
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.model.model == "gemini-4.0-flash"
    assert outcome.value.model.location == DEFAULT_MODEL_LOCATION

    outcome = read(GOOGLE_CLOUD_LOCATION="europe-west4")
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.model.model == DEFAULT_MODEL
    assert outcome.value.model.location == "europe-west4"


@pytest.mark.parametrize("variable", sorted(MINIMUM.keys() - {"GOOGLE_CLOUD_PROJECT"}))
def test_every_required_variable_is_required_by_name(variable: str) -> None:
    """The message names the variable, because that is what fixes it."""
    if variable == "MUSTER_AGENT_MATERIAL_BUCKET":
        failure, detail = refusal(**{variable: ""})
        assert failure is ConfigurationFailure.MALFORMED
        assert "directory or a bucket" in detail
        return
    failure, detail = refusal(**{variable: ""})
    assert failure is ConfigurationFailure.MISSING
    assert detail == variable


def test_a_vertex_agent_without_a_project_does_not_start() -> None:
    """Rather than resolving one from whatever the container inherited.

    An agent reading somebody else's project out of the environment is worse
    than one that refuses to come up.
    """
    failure, detail = refusal(GOOGLE_CLOUD_PROJECT="")
    assert failure is ConfigurationFailure.MALFORMED
    assert "project" in detail


def test_a_source_reads_a_directory_or_a_bucket_and_names_exactly_one() -> None:
    failure, _ = refusal(MUSTER_AGENT_MATERIAL_DIR="/srv/site-a")
    assert failure is ConfigurationFailure.MALFORMED

    outcome = read(MUSTER_AGENT_MATERIAL_BUCKET="", MUSTER_AGENT_MATERIAL_DIR="/srv/site-a")
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.material.directory == "/srv/site-a"


@pytest.mark.parametrize("spelling", ["SITE-A", "SITE:", ":SITE-A", "SITE:*", "ANY:ANY"])
def test_a_resource_scope_is_enumerated_and_never_a_wildcard(spelling: str) -> None:
    """The registry refuses a wildcard grant; so does the configuration that
    would ask for one."""
    failure, _ = refusal(MUSTER_AGENT_RESOURCE_SCOPE=spelling)
    assert failure is ConfigurationFailure.MALFORMED


def test_an_unknown_model_backend_is_refused_by_name() -> None:
    failure, detail = refusal(MUSTER_AGENT_MODEL_BACKEND="OLLAMA")
    assert failure is ConfigurationFailure.MALFORMED
    assert "VERTEX" in detail


def test_the_audience_and_the_caller_list_go_together() -> None:
    """A service that checks tokens needs to know its own name.

    ``build_service`` refuses one without the other; here the *record* keeps
    the audience optional, because a laptop legitimately has neither.
    """
    outcome = read(MUSTER_AGENT_AUDIENCE="https://agent-site-a.example.run.app")
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.expected_audience == "https://agent-site-a.example.run.app"

    laptop = read()
    assert isinstance(laptop, Ok), laptop
    assert laptop.value.expected_audience is None


#  ---- the manifest, which is operator-written and therefore input ---------


def test_a_manifest_that_names_a_file_outside_the_store_is_refused() -> None:
    """A store whose lookup is a path join is a store where ``../`` is a
    capability, and the material on the other side of it is the private
    evidence this boundary exists for."""
    outcome = parse_manifest(
        '{"items": [{"ref": "x", "media_type": "text/plain", "label": "l", '
        '"file": "../../etc/passwd", "subject": "RAVI", '
        '"scope": [{"kind": "SITE", "value": "SITE-A"}]}]}'
    )
    assert isinstance(outcome, Err), outcome
    assert outcome.error.failure is EvidenceStoreFailure.UNREADABLE
    assert "outside the store" in outcome.error.detail


@pytest.mark.parametrize(
    "document",
    [
        "not json at all",
        "[]",
        '{"items": "everything"}',
        '{"items": [{"ref": "x"}]}',
        '{"items": [{"ref": "x", "media_type": "text/plain", "label": "l", "file": "f", '
        '"subject": "RAVI", "scope": []}]}',
        '{"items": [{"ref": "x", "media_type": "text/plain", "label": "l", "file": "f", '
        '"subject": "RAVI", "scope": [{"kind": "SITE", "value": "*"}]}]}',
    ],
)
def test_a_malformed_manifest_is_a_value_and_not_an_exception(document: str) -> None:
    """A site with a typo reports a typo, rather than raising out of a handler."""
    assert isinstance(parse_manifest(document), Err)


def test_a_manifest_with_an_extra_field_still_reads() -> None:
    """Forward compatibility for the operator, and only in that direction.

    An unknown key is ignored; a missing or wrongly typed one is refused.
    """
    outcome = parse_manifest(
        '{"items": [{"ref": "x", "media_type": "text/plain", "label": "l", "file": "f", '
        '"subject": "RAVI", "scope": [{"kind": "SITE", "value": "SITE-A"}], '
        '"retention_days": 30}]}'
    )
    assert isinstance(outcome, Ok), outcome
    assert outcome.value[0].handle.ref == "x"
