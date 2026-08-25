"""The deployment script and the composition root, checked against each other.

Everything else in this suite tests the agent. This tests the *agreement*
between the agent and the thing that deploys it -- which is where the review
found the milestone's worst defect, and which nothing here was looking at.

``serve.py`` refuses to start a deployed service that names no audience: such a
revision would have a port, a signing key and no identity check, so it fails
closed at start-up. ``50-deploy.sh`` deploys twice, because a service's
identity-token audience is its own URL and a service has no URL until it exists
-- and its first pass carried *neither* the audience nor the caller list, on
the reasoning that "both or neither" made "neither" safe.

It is safe on a laptop and unreachable on Cloud Run, which sets ``K_SERVICE`` on
every revision. So the first pass could never have started, ``gcloud run
deploy`` would have failed, the URL the second pass reads would never have
existed, and the whole deployment stops at its first command. The repair
somebody reaches for at that point is the dangerous one: delete the guard, and
the fleet comes up serving anybody who can reach the port.

Neither side was wrong on its own. The script was checkable and the runtime was
checkable and the sentence spanning them was not, so this file makes it one.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
import yaml

from muster.agents.config import (
    DEFAULT_MATERIAL_REGION,
    DEFAULT_MODEL,
    DEFAULT_MODEL_LOCATION,
)
from muster.agents.entrypoints.serve import CALLERS_VARIABLE

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
SCRIPTS = REPOSITORY / "infra" / "scripts"
DEPLOY = SCRIPTS / "50-deploy.sh"
ENVIRONMENT = SCRIPTS / "env.sh"
TEARDOWN = SCRIPTS / "99-teardown.sh"
HERO = SCRIPTS / "90-hero-job.sh"

AUDIENCE_VARIABLE = "MUSTER_AGENT_AUDIENCE"

#: A line that writes one entry into the environment file a resource is given.
_ASSIGNED = re.compile(r"muster::env_entry (MUSTER_AGENT_[A-Z_]+) ")

#: The same line, read for what it writes as well as for what it names.
_ASSIGNED_VALUE = re.compile(r'muster::env_entry ([A-Z_]+) "([^"]*)"')


def _executable(path: Path) -> str:
    """One script, with its commentary removed.

    Every assertion in this file is about what a script *does*.  Its comments
    say the same things in prose, and a test satisfiable by prose is one that
    passes for a script that deleted the thing and explained why it mattered.
    """
    return "\n".join(
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )


def _default_of(name: str) -> str:
    """What ``env.sh`` falls back to for one overridable name."""
    declared = re.search(
        rf'^: "\$\{{{name}:?=(.*)\}}"', ENVIRONMENT.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert declared is not None, f"env.sh declares no default for {name}"
    return declared.group(1).strip()


def _unconditional_variables(script: str) -> set[str]:
    """Which agent variables every deploy sets, whatever branch it took.

    Nesting is tracked by ``if``/``fi`` rather than parsed, because the
    question is not what the script computes -- it is whether a variable can be
    *skipped*, and a line inside any conditional can be.
    """
    names: set[str] = set()
    depth = 0
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("if "):
            depth += 1
        elif stripped == "fi":
            depth = max(0, depth - 1)
        found = _ASSIGNED.search(line)
        if found is not None and depth == 0:
            names.add(found.group(1))
    return names


def test_every_deploy_names_an_audience_and_the_callers_it_serves() -> None:
    """The pairing, checked where it is spelled rather than where it is read.

    Both, and unconditionally. A pass that could omit either one is a pass that
    either never starts (no audience, on a deployed service) or refuses to
    start (one of the pair) -- and both stop the deployment at the point where
    the pressure to remove the check is highest.
    """
    unconditional = _unconditional_variables(DEPLOY.read_text(encoding="utf-8"))
    assert AUDIENCE_VARIABLE in unconditional, (
        f"{DEPLOY.name} can deploy a revision that names no audience; "
        "such a revision refuses to start on Cloud Run"
    )
    assert CALLERS_VARIABLE in unconditional, (
        f"{DEPLOY.name} can deploy a revision that names no permitted callers"
    )


def test_the_first_pass_placeholder_is_a_host_nothing_can_be_minted_for() -> None:
    """The audience the first pass names before the real URL exists.

    ``.invalid`` is reserved by RFC 2606 and resolves nowhere, so no token can
    carry it as an audience and the placeholder revision serves nobody. A
    placeholder that named a reachable host would be one somebody could mint a
    token for, which is the single property it must not have.
    """
    declared = re.search(r'UNRESOLVED_AUDIENCE:=([^}"]+)', ENVIRONMENT.read_text(encoding="utf-8"))
    assert declared is not None, "env.sh declares no placeholder audience"
    placeholder = declared.group(1).strip()
    assert placeholder.startswith("https://")
    assert placeholder.endswith(".invalid")


def test_the_deployed_backend_is_vertex_and_is_stated() -> None:
    """The other configuration that comes up and looks fine.

    ``serve.py`` refuses the developer surface on a deployed service, and the
    script has to be asking for the one it will accept -- otherwise the same
    shape repeats: a deployment that stops at its first command, and a guard
    somebody deletes to get past it.
    """
    script = DEPLOY.read_text(encoding="utf-8")
    assigned = dict(_ASSIGNED_VALUE.findall(script))
    assert assigned.get("MUSTER_AGENT_MODEL_BACKEND") == "VERTEX"


def test_every_identity_the_deployment_creates_is_used_by_something() -> None:
    """An identity nothing runs as is a role grant with no principal behind it.

    ``10-identities.sh`` creates four accounts and grants the build one
    ``artifactregistry.writer`` and ``logging.logWriter``. The build then ran
    without naming it -- as the project's default build or compute account,
    which in most projects carries ``roles/editor`` and with it project-wide
    object reads. So the identity whose entire purpose is that a build *cannot*
    read the evidence bucket existed, was granted, was documented in bold, and
    was not used; and the containment it describes was never in force.

    Checked against *executable* lines that make an account a runtime identity
    or bind one to a runnable thing -- ``--service-account``, ``--member``, or
    an argument to ``muster::deploy``. Comments are excluded on purpose: a
    comment naming an account is the exact artifact this defect already had,
    and a test satisfied by one would pass on the code it exists to fail.
    """
    scripts = REPOSITORY / "infra" / "scripts"
    created = set(
        re.findall(
            r'muster::create_sa "\$\{([A-Z_]+)\}"',
            (scripts / "10-identities.sh").read_text(encoding="utf-8"),
        )
    )
    assert created, "no service accounts are created; this test is looking in the wrong place"

    #: The scripts that create or bind workloads. 10-identities creates every
    #: account, 99-teardown deletes them and 70-verify-iam asserts about them,
    #: so an identity can appear in all three and be one nothing runs as.
    binding = ("--service-account", "--member", "muster::deploy")
    used = [
        line
        for name in (
            "40-build.sh",
            "50-deploy.sh",
            "55-probe-job.sh",
            "60-invoker.sh",
            "85-database-bootstrap.sh",
        )
        for line in (scripts / name).read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#") and any(mark in line for mark in binding)
    ]
    unused = {
        name
        for name in created
        if not any(f"${{{name.removesuffix('_ID')}}}" in line for line in used)
    }
    assert not unused, (
        f"{', '.join(sorted(unused))} is created and granted roles and nothing runs as it; "
        "the containment its grants describe is not in force"
    )


#  ---- the model and the location are one decision -------------------------
#
#  Two locations ship, and they are different: the services and the material are
#  regional, and the model is called at the ``global`` Vertex endpoint because
#  that is where the shipped model is served.  Everything below is about keeping
#  those two facts *separate and both true* -- a deployment that collapsed them
#  would either call a model that is not served where it looked, or move the
#  Cloud Run services and the evidence bucket for a reason that has nothing to
#  do with either.


def test_the_shipped_model_and_locations_are_the_same_in_both_places() -> None:
    """The composition root and the deployment script agree on what ships.

    They are two files and they are read by two different things -- the script
    by an operator, the module by a laptop run with nothing configured -- so a
    drift between them is a deployment whose preflight checked one pair and
    whose revisions call another.  There is no failure mode in that: the agent
    comes up, raises inside the model client on every assignment, and abstains
    honestly forever.

    All three values, because there are now three: the model, the region the
    services and the material are in, and the location the model is called at.
    """
    assert _default_of("AGENT_MODEL") == DEFAULT_MODEL
    assert _default_of("REGION") == DEFAULT_MATERIAL_REGION
    assert _default_of("VERTEX_LOCATION") == DEFAULT_MODEL_LOCATION


def test_the_deployment_region_and_the_model_location_are_two_values() -> None:
    """Where the services run and where the model is called are separate decisions.

    ``VERTEX_LOCATION`` used to default to ``${REGION}``, which made them one
    value wearing two names: changing the model to one served only globally
    moved the *interpretation*, and changing the region to follow the model
    would have moved the Cloud Run services and the evidence bucket with it.
    Neither move is one a deployment should be able to make by editing the other
    half.

    So they are declared independently, and this asserts the independence rather
    than the values: ``VERTEX_LOCATION`` must not be derived from ``REGION``, and
    ``REGION`` must not be derived from ``VERTEX_LOCATION``.  Both remain
    overridable -- ``:=`` is the shell's "unless the environment already said
    so" -- which is what makes co-locating them again a one-variable decision an
    operator can still take.
    """
    region = _default_of("REGION")
    location = _default_of("VERTEX_LOCATION")
    assert "VERTEX_LOCATION" not in region, (
        f"REGION is derived from VERTEX_LOCATION ({region}); "
        "moving the model would move the services and the evidence bucket"
    )
    assert "REGION" not in location, (
        f"VERTEX_LOCATION is derived from REGION ({location}); "
        "the two locations are one value again, and changing either moves both"
    )
    assert DEFAULT_MATERIAL_REGION != DEFAULT_MODEL_LOCATION


def test_the_shipped_deployment_region_is_a_region() -> None:
    """Cloud Run and the evidence bucket are somewhere specific.

    ``asia-south1`` rather than a multi-region or ``global``: the site's raw
    material and the process that reads it should not be in two jurisdictions
    because nobody chose, and a bucket location is the one thing here that is
    genuinely about where bytes at rest are.
    """
    assert DEFAULT_MATERIAL_REGION != "global"
    assert "-" in DEFAULT_MATERIAL_REGION, f"{DEFAULT_MATERIAL_REGION} does not look like a region"


def test_the_shipped_model_location_is_a_shape_the_preflight_can_probe() -> None:
    """Whether the model is served there is a live question, asked at deploy time.

    What is checkable in a file is narrower and is exactly the part that broke
    silently before: the location the revision is handed must be one the
    preflight knows how to build a hostname for.  ``global`` is the bare host
    and a region is a prefix; a third shape would be one nobody has checked
    against the live API.

    What this deliberately does not do is assert that ``gemini-3.7-flash`` is
    served at ``global``.  Google's availability table moves, and a copy of it
    here would be a second source of truth going stale silently -- which is the
    failure the ``:countTokens`` preflight exists to prevent.
    """
    assert DEFAULT_MODEL_LOCATION == "global" or "-" in DEFAULT_MODEL_LOCATION


def test_the_pair_the_preflight_checks_is_the_pair_the_revision_is_given() -> None:
    """A preflight that checked one pair and deployed another would pass and lie.

    The check builds its URL from ``AGENT_MODEL`` and ``VERTEX_LOCATION``; the
    revision has to be handed those same two values, under the names the agent's
    configuration reads, and unconditionally.
    """
    script = DEPLOY.read_text(encoding="utf-8")
    assert "${VERTEX_LOCATION}-aiplatform.googleapis.com" in script
    assert "/publishers/google/models/${AGENT_MODEL}" in script

    assigned = dict(_ASSIGNED_VALUE.findall(script))
    assert assigned.get("MUSTER_AGENT_MODEL") == "${AGENT_MODEL}"
    assert assigned.get("GOOGLE_CLOUD_LOCATION") == "${VERTEX_LOCATION}"
    assert "MUSTER_AGENT_MODEL" in _unconditional_variables(script)


#: The flags that decide where a resource is *created*.  Every other appearance
#: of a location in these scripts is a lookup, a printed message, or the model
#: probe -- and the model probe is the one this must never be confused with.
_PLACEMENT = re.compile(r'--(?:region|locations?)="([^"]+)"')


def _placements(path: Path) -> set[str]:
    """Every value one script places a resource at.

    Collected across the whole script rather than per command, because a
    ``gcloud run deploy`` here is written over a dozen continuation lines and
    the flag never shares a line with the verb.  Comments are stripped first:
    a comment naming a location is prose, and prose is not a placement.
    """
    return set(_PLACEMENT.findall(_executable(path)))


def test_the_revision_is_told_the_model_location_and_placed_in_the_region() -> None:
    """The two locations reach the deployment through two different channels.

    This is the whole of the split, and it is what has to keep being true after
    somebody tidies away "the duplicate region variable":

    * every placement flag in ``50-deploy.sh`` is ``${REGION}``.  That is where
      the service is *put*, and it is the same region ``20-site-evidence.sh``
      creates the evidence bucket in;
    * ``GOOGLE_CLOUD_LOCATION`` in the environment file is
      ``${VERTEX_LOCATION}``.  That is the variable the Vertex client reads, so
      it is where the model is *called* -- ``global``, as shipped.

    Crossing them fails in two directions and neither is loud.  Placing the
    service at ``${VERTEX_LOCATION}`` would try to deploy Cloud Run to
    ``global``, away from the bucket its identity is scoped to.  Handing the
    agent ``${REGION}`` as its Vertex location would point the model client at a
    regional endpoint the shipped model is not served from -- and the fleet
    would come up, raise inside the model client on every assignment and abstain
    honestly forever, with a preflight that had confirmed a location nothing
    calls.
    """
    assigned = dict(_ASSIGNED_VALUE.findall(DEPLOY.read_text(encoding="utf-8")))
    assert assigned.get("GOOGLE_CLOUD_LOCATION") == "${VERTEX_LOCATION}", (
        "the agent is not handed VERTEX_LOCATION as the location it calls the model at"
    )

    placed = _placements(DEPLOY)
    assert placed, "50-deploy.sh places nothing; this test is looking in the wrong place"
    assert placed == {"${REGION}"}, (
        f"50-deploy.sh places a resource somewhere other than REGION: {sorted(placed)}"
    )


def test_no_deployment_script_places_a_resource_at_the_model_location() -> None:
    """Checked across every script, because the split has to hold everywhere.

    ``50-deploy.sh`` is not the only file that names a location: the bucket, the
    registry, the secret replicas, the two jobs and the invoker bindings all do.
    One of them switched to ``VERTEX_LOCATION`` would put a single resource
    somewhere nobody chose while the rest stayed put -- and the symptom is a 404
    on something that "was definitely created", not a residency finding.

    The model location has exactly two legitimate appearances in the whole
    deployment, both in ``50-deploy.sh``: the preflight's probe, and the
    environment entry the agent reads.  Neither is a placement.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        assert "${VERTEX_LOCATION}" not in _placements(path), (
            f"{path.name} places a resource at the model location"
        )


def test_the_evidence_bucket_is_created_in_the_deployment_region() -> None:
    """The material stays where the services are, whatever the model location is.

    The one claim a ``global`` Vertex endpoint must not be allowed to weaken
    quietly.  What crosses a region boundary is a prompt the source agent built
    inside its own container; the objects themselves are created in
    ``${REGION}`` and read by the source's own identity, and this is where that
    stops being prose.
    """
    site = SCRIPTS / "20-site-evidence.sh"
    assert _placements(site) == {"${REGION}"}, (
        "the evidence bucket is no longer created in the deployment region"
    )
    assert "VERTEX_LOCATION" not in _executable(site)


def test_the_preflight_still_runs_and_runs_before_anything_is_deployed() -> None:
    """Removing it is the repair somebody reaches for under demo pressure.

    It is the one misconfiguration that produces no error anywhere -- a fleet
    that comes up and abstains -- so it is checked that the call is still there,
    that it is not inside a conditional, and that it happens before the first
    thing that creates a resource.
    """
    lines = [
        line
        for line in DEPLOY.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]
    called = next(
        (index for index, line in enumerate(lines) if line.strip() == "muster::check_model"), None
    )
    assert called is not None, "50-deploy.sh no longer runs the model preflight"
    deployed = next(
        (index for index, line in enumerate(lines) if "gcloud run deploy" in line), None
    )
    assert deployed is not None, "50-deploy.sh deploys nothing; this test is looking wrongly"
    assert called < deployed, "the preflight runs after something has been deployed"


#  ---- what the preflight actually asks ------------------------------------
#
#  The check that was here read the publisher model as a resource -- a plain GET
#  of ``.../publishers/google/models/${AGENT_MODEL}`` -- and that read is not a
#  test of publisher Gemini availability.  Confirmed by hand, in this project:
#  ``gemini-3.5-flash`` in ``asia-south1`` answers 404 to the metadata read and
#  200 to ``:countTokens``.  The pair that ships now -- ``gemini-3.7-flash`` at
#  ``global`` -- was verified the same way and answers 200.
#
#  So the preflight refused a deployment that would have worked, and that is the
#  worse direction for this particular check to fail in.  A preflight that misses
#  a bad pair costs a fleet that abstains until somebody notices.  A preflight
#  that refuses a good one costs a decision: the operator changes the model, or
#  moves VERTEX_LOCATION -- and moving VERTEX_LOCATION moves where the
#  interpretation happens, out of the region the material sits in, for a reason
#  that was not true.
#
#  These pin the probe to the API the agent will itself use, and to the two
#  hostname shapes that API has.

#: The publisher model, as the deployment names it.  Never reached by a method
#: of its own -- see ``test_the_preflight_does_not_read_the_model_as_metadata``.
MODEL_PATH = "/publishers/google/models/${AGENT_MODEL}"

#: A regional location is a hostname prefix; ``global`` is the bare host.
REGIONAL_HOST = "${VERTEX_LOCATION}-aiplatform.googleapis.com"
GLOBAL_HOST = "aiplatform.googleapis.com"

#: Commands that bring something into existence.  None of them belongs in a
#: check whose entire promise is that a refusal has left the project untouched.
CREATING = (
    "gcloud run deploy",
    "gcloud run jobs",
    "gcloud iam",
    "gcloud storage",
    "gcloud secrets",
    "gcloud builds",
    "gcloud services enable",
    "gcloud artifacts",
)


def _preflight() -> str:
    """The body of ``muster::check_model``, with its commentary removed.

    The comments say why the probe is the one it is, at some length.  They are
    not the probe: a test satisfiable by prose passes for a script that deleted
    the request and explained what it used to do.
    """
    lines = DEPLOY.read_text(encoding="utf-8").splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.startswith("muster::check_model()")),
        None,
    )
    assert start is not None, "50-deploy.sh no longer defines a model preflight"
    end = next(index for index, line in enumerate(lines) if index > start and line == "}")
    return "\n".join(line for line in lines[start : end + 1] if not line.lstrip().startswith("#"))


def _preflight_hosts() -> set[str]:
    """Every hostname the preflight can build."""
    return set(re.findall(r'^\s*host="([^"]+)"', _preflight(), re.MULTILINE))


def test_the_preflight_probes_the_regional_endpoint_for_a_regional_location() -> None:
    """A regional location is a prefix on the host, not a path segment alone.

    Resolved rather than merely matched, and resolved against the *deployment
    region* -- which is what ``VERTEX_LOCATION=${REGION}`` names, the co-located
    override an operator takes when the model they want is served regionally.
    With ``asia-south1`` the probe goes to
    ``asia-south1-aiplatform.googleapis.com``, which is the host that answered by
    hand.  The location also stays in the path, where the API expects it -- a
    probe that named the region in one place and not the other would ask about a
    location nobody deployed to.

    The shipped default takes the other branch; see the test below.
    """
    assert REGIONAL_HOST in _preflight_hosts()
    assert (
        REGIONAL_HOST.replace("${VERTEX_LOCATION}", DEFAULT_MATERIAL_REGION)
        == f"{DEFAULT_MATERIAL_REGION}-aiplatform.googleapis.com"
    )
    assert "https://${host}/v1/projects/${PROJECT_ID}/locations/${VERTEX_LOCATION}" in _preflight()


def test_the_preflight_probes_the_bare_host_for_the_global_location() -> None:
    """``global-aiplatform.googleapis.com`` resolves to nothing.

    A probe that built the regional prefix unconditionally would report "not
    served" for the one location several current Gemini models are served in --
    and the operator, believing it, would change a model or a region that was
    right.  Two hosts, and exactly two: a third would be a shape nobody has
    checked against the live API.
    """
    assert _preflight_hosts() == {REGIONAL_HOST, GLOBAL_HOST}
    assert '"${VERTEX_LOCATION}" == "global"' in _preflight()
    #  And the shipped default takes that branch, so the path this
    #  deployment actually walks is the one this test covers rather than a
    #  spare kept for somebody else.
    assert DEFAULT_MODEL_LOCATION == "global"


def test_the_preflight_asks_the_model_to_count_tokens() -> None:
    """The probe is a real request to the real model, and produces nothing.

    ``:countTokens`` is served by the same publisher model at the same location
    over the same path, so it answers the availability question the way the
    agent's own calls will -- and it returns a count rather than a completion.
    The payload is a literal, because a preflight has no evidence in scope and
    writing it into the file is what keeps a later "more realistic" probe from
    quietly acquiring one.
    """
    probe = _preflight()
    assert f"{MODEL_PATH}:countTokens" in probe
    assert "-X POST" in probe
    assert '"text":"hello"' in probe


def test_the_preflight_does_not_read_the_model_as_metadata() -> None:
    """The check this replaced, kept out rather than merely removed.

    A plain GET of the publisher model is the obvious thing to write and it
    answers 404 for models that serve requests perfectly well at that location.
    So the model is never named without a method: every line that reaches for it
    reaches for the one endpoint whose answer was verified against this project.
    """
    probe = _preflight()
    for number, line in enumerate(probe.splitlines(), 1):
        if MODEL_PATH in line:
            assert f"{MODEL_PATH}:countTokens" in line, (
                f"preflight line {number} names the model with no method: {line.strip()}"
            )
    assert "-X GET" not in probe
    assert "--request GET" not in probe


def test_no_deployment_script_generates_to_find_out_whether_it_can_deploy() -> None:
    """Readiness is a question about configuration, and it is asked for free.

    ``:generateContent`` would answer the same question by consuming a real
    inference request -- charging a check that runs before every deployment, and
    again on every retry, to the quota and the budget of the work.  Checked
    across every script rather than in the preflight alone, because the next
    place somebody would put it is the smoke test.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            assert "generateContent" not in line, (
                f"{path.name}:{number} generates during deployment"
            )


def test_the_preflight_accepts_only_a_count() -> None:
    """200 is necessary and not sufficient, and every other answer is a refusal.

    A proxy, a captive portal or a misrouted host all answer 200; none of them
    answers with the field the response type is defined by, so the body is
    checked and not just the status.  And the statuses that mean different
    things are named separately -- 401 is credentials, 403 is an API that is off
    or a principal that may not call it, 404 is a model not served here -- so an
    operator is told which of three repairs this is instead of being told to
    change the model whatever happened.
    """
    probe = _preflight()
    assert '"${status}" == "200"' in probe
    assert '"totalTokens"' in probe
    for status in ("401", "403", "404"):
        assert f"{status}) diagnosis=" in probe, (
            f"the preflight does not distinguish {status} from any other refusal"
        )


def test_a_failed_preflight_creates_nothing() -> None:
    """The promise the refusal makes, checked where it could stop being true.

    Two halves.  The probe itself brings nothing into existence -- it reads a
    token and makes one HTTP request, and a check that provisioned so much as a
    bucket to test readiness would make "nothing has been deployed" a lie the
    operator has no way to catch.  And the function ends in ``exit 1``, so a
    path added later that decides nothing leaves the script rather than falling
    through into the deploy: the ordering test above only guarantees the check
    runs first, not that it stops anything.
    """
    probe = _preflight()
    for verb in CREATING:
        assert verb not in probe, f"the preflight runs '{verb}'"
    assert probe.rstrip().endswith("exit 1\n}"), (
        "the preflight can reach its end without deciding, and the deploy follows"
    )


#  ---- what a Cloud Run resource is told, and how it is told ---------------
#
#  Two deploys have failed here, the same way both times and both at the moment
#  of creation.  ``--set-env-vars`` packs every name and every value into one
#  string split on a delimiter, and a delimiter has to be a character that
#  appears in no value.  The comma broke first: MUSTER_AGENT_PREDICATES is a
#  comma-separated list, so its second predicate parsed as an entry with no
#  ``=``.  Its repair, gcloud's ``^@^``, broke second:
#
#      ERROR: (gcloud.run.deploy) argument --set-env-vars:
#      Bad syntax for dict arg: [muster-agentic-2026-9177.iam.gserviceaccount.com]
#
#  -- which is the tail of MUSTER_AGENT_PERMITTED_CALLERS, a service-account
#  address, after the '@' it was split at.
#
#  What makes this worth pinning is the repair available under pressure.  The
#  error names a value, so the thing to do is shorten it: drop a predicate, or
#  drop a caller.  Dropping a predicate leaves an agent that silently refuses to
#  acquire it, and the fault then reads as an authority problem.  Dropping a
#  caller leaves an agent serving nobody, or -- one edit further -- serving
#  anybody.  Both look like configuration and both are the removal of a control.
#
#  So the values are written to a file, where there is no delimiter to collide
#  with.  These hold three things: that nothing packs an environment into an
#  argument any more, that one emitter does the writing, and that what the
#  emitter writes reads back as exactly what it was given.

#: Values the deployment sends today, and values it does not send yet.  The
#: second group is the point: a serialisation checked only against what it
#: currently carries is how both of the previous two survived review.
SERIALISATION_CASES = {
    #  The two that actually broke a deploy.
    "MUSTER_AGENT_PREDICATES": "present_on_site,on_site_duration",
    "MUSTER_AGENT_PERMITTED_CALLERS": (
        "muster-control-plane@muster-agentic-2026-9177.iam.gserviceaccount.com"
    ),
    #  The rest of what the two scripts send.
    "MUSTER_AGENT_RESOURCE_SCOPE": "SITE:SITE-A",
    "MUSTER_AGENT_AUDIENCE": "https://audience-not-yet-resolved.invalid",
    "MUSTER_AGENT_SIGNING_KEY_PATH": "/var/run/muster/signing-key.pem",
    "MUSTER_HERO_RAW_OBJECT": "gs://muster-site-evidence-p/site-a/gate-log-sat.txt",
    #  A public key, whose base64 alphabet already holds '+', '/' and '='.
    "MUSTER_HERO_SITE_PUBLIC_KEY": "MFkwEwYHKoZIzj0CAQYIKo+ZIzj0DAQcDQgAE/abc+def==",
    #  And the ones nobody sends, which is what the previous two delimiters were
    #  never checked against.
    "BOTH_DELIMITERS_AT_ONCE": "a,b@c,d@e",
    "AN_APOSTROPHE": "it's, and it's again",
    "LOOKS_LIKE_A_MAPPING": "key: value, other: thing",
    "LOOKS_LIKE_A_COMMENT": "value  # not a comment",
    "LOOKS_LIKE_A_SEQUENCE": "[one, two]",
    "LOOKS_LIKE_A_BOOLEAN": "true",
    "LOOKS_LIKE_A_NUMBER": "0123",
    "LOOKS_LIKE_ABSENCE": "null",
    "PADDED": "  spaces either side  ",
    "EVERY_PUNCTUATION": '!"#$%&()*+,-./:;<=>?@[]^_`{|}~',
    "EMPTY": "",
}

#: The arguments each agent is deployed with, in the order muster::deploy takes
#: them.  Every one of them decides something different about what that agent
#: may do, so the two agents must differ in all of them.
DEPLOY_ARGUMENTS = (
    "service",
    "identity",
    "agent id",
    "principal",
    "source class",
    "key reference",
    "predicates",
    "resource scope",
    "material prefix",
    "signing-key secret",
)


def _serialise(values: Mapping[str, str], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Run the deployment's own emitter over these values.

    Executed rather than imitated.  A test that reimplemented the quoting would
    be a second implementation of the thing under test, and would agree with the
    first one right up until the moment either was wrong.
    """
    bash = shutil.which("bash")
    assert bash is not None
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        #  Set, so sourcing env.sh does not go asking gcloud for a project.
        'PROJECT_ID="serialisation-test"',
        f'source "{ENVIRONMENT.as_posix()}"',
    ]
    #  Names and values travel in the environment rather than in the script, so
    #  nothing here is quoted twice and the shell is handed exactly these bytes.
    environment = dict(os.environ)
    for index, (name, value) in enumerate(values.items()):
        environment[f"NAME_{index}"] = name
        environment[f"VALUE_{index}"] = value
        lines.append(f'muster::env_entry "${{NAME_{index}}}" "${{VALUE_{index}}}"')
    driver = tmp_path / "emit.sh"
    driver.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    #  check=False: the refusal path is a thing this file tests, so a non-zero
    #  exit is a result here rather than an error.
    return subprocess.run(  # noqa: S603
        [bash, driver.as_posix()],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )


def _deploy_calls() -> list[list[str]]:
    """The arguments of each ``muster::deploy`` invocation, continuations joined."""
    joined = _executable(DEPLOY).replace("\\\n", " ")
    return [
        shlex.split(line)[1:] for line in joined.splitlines() if line.startswith("muster::deploy ")
    ]


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_every_value_survives_serialisation_exactly(tmp_path: Path) -> None:
    """Written by the script, read back by a YAML parser, compared byte for byte.

    A real parser and not a hand-written one, because the reader that matters is
    gcloud's: the claim being made is that what this writes is what the
    container is given, and only a parser can say so.  Commas and '@' are in
    here because they are what broke; the rest are in here because the next
    value nobody thought about is the one that breaks next.
    """
    done = _serialise(SERIALISATION_CASES, tmp_path)
    assert done.returncode == 0, done.stderr
    parsed = yaml.safe_load(done.stdout)
    assert parsed == SERIALISATION_CASES
    for name in SERIALISATION_CASES:
        assert isinstance(parsed[name], str), (
            f"{name} came back as {type(parsed[name]).__name__}; Cloud Run takes strings"
        )


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_a_value_that_cannot_be_written_stops_the_deployment(tmp_path: Path) -> None:
    """The one thing an entry-per-line file cannot carry, refused rather than folded.

    A newline would be a second line that is not an entry, and a single-quoted
    YAML scalar folds it to a space rather than failing -- so the container would
    come up holding a value that is nearly the one it was given, which is the
    kind of wrong nobody looks for.  Nothing sends one today; this is what makes
    that a property instead of an observation.
    """
    done = _serialise({"MULTILINE": "one\ntwo"}, tmp_path)
    assert done.returncode != 0, "a newline was serialised into something"
    assert "MULTILINE" in done.stderr


def test_no_deployment_script_packs_the_environment_into_one_argument() -> None:
    """The flag both failures came through, kept out rather than merely replaced.

    ``--set-env-vars`` and ``--update-env-vars`` both take the delimited form.
    Checked across every script because the next place somebody would add a
    variable is whichever script needs one, not the two that have been fixed.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for flag in ("--set-env-vars", "--update-env-vars"):
                assert flag not in line, (
                    f"{path.name}:{number} packs the environment into one delimited argument"
                )


def test_both_deployments_serialise_through_the_same_emitter() -> None:
    """One implementation, so a fix here cannot fix only half of the deployment.

    The hero job had the same defect latent: its values are URLs, a ``gs://``
    path and two base64 blobs, none of which contains an '@' *today*.  It would
    have deployed successfully and broken on the first value that did -- eleven
    steps later, in the script whose failure looks like the fleet being down.
    """
    for path in (DEPLOY, HERO):
        executable = _executable(path)
        assert "muster::env_entry " in executable, f"{path.name} does not use the emitter"
        assert "muster::env_file " in executable, f"{path.name} names its own file"
        assert '--env-vars-file="${env_file}"' in executable
        assert "${variables}" not in executable, f"{path.name} still builds a delimited string"

    defined = [
        path.name
        for path in sorted(SCRIPTS.glob("*.sh"))
        if "muster::env_entry() {" in path.read_text(encoding="utf-8")
    ]
    assert defined == ["env.sh"], f"the emitter is defined in {defined}"


def test_the_environment_file_is_made_safely_and_removed_however_the_script_ends() -> None:
    """It is a temporary file in the deployment's hand, so it is the deployment's to remove.

    Made by ``mktemp -d`` -- 0700, outside the repository, under a name nobody
    can guess -- and removed on the ordinary exit, on the refusals that exit
    early, and on the interrupt somebody types when a deploy hangs.  A file left
    behind holds no secret and is still a description of the fleet's
    configuration sitting in a world-listable directory.
    """
    text = ENVIRONMENT.read_text(encoding="utf-8")
    assert 'mktemp -d "${TMPDIR:-/tmp}/muster-env.XXXXXX"' in text
    assert 'rm -rf "${MUSTER_ENV_DIR}"' in text
    for signal in ("EXIT", "INT", "TERM"):
        assert re.search(rf"^\s*trap .*\b{signal}$", text, re.MULTILINE), (
            f"nothing removes the environment directory on {signal}"
        )


def test_the_environment_file_is_not_named_through_a_subshell() -> None:
    """``$(muster::env_file ...)`` would create the directory in a shell that ends.

    And ending it fires the cleanup trap installed a line earlier, so the path
    handed back names a directory that has already been removed: the deploy then
    fails on a redirect, quoting a path that was real at the moment it was
    printed.  It cost a dry run to find and would have cost a deployment.

    This is why the function answers in a variable, which reads worse -- and this
    is the test that fails when somebody improves it back.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for form in ("$(muster::env_file", "`muster::env_file"):
                assert form not in line, (
                    f"{path.name}:{number} reads the path from a subshell that removes it"
                )


def test_the_environment_file_holds_no_key_material() -> None:
    """A signing key reaches a container as a reference, and this file is not one.

    ``--set-secrets`` mounts a Secret Manager version at a path, so what appears
    on the command line is a name and a number.  The hero job is the other half:
    it sends key material by value, and what it sends is the public half --
    every key-ish name it writes is either a reference or a public key.
    """
    deploy = _executable(DEPLOY)
    assert '--set-secrets="${SIGNING_KEY_MOUNT}=${secret}:${SIGNING_KEY_VERSION}"' in deploy
    for name, value in _ASSIGNED_VALUE.findall(deploy):
        assert "${secret}" not in value, f"{name} carries the secret itself"

    for name, _ in _ASSIGNED_VALUE.findall(_executable(HERO)):
        if "KEY" not in name:
            continue
        assert name.endswith("_KEY_REF") or name.endswith("_PUBLIC_KEY"), (
            f"{name} is neither a key reference nor a public half"
        )


def test_the_two_agents_are_configured_differently_and_both_passes_agree() -> None:
    """Four deploys, two configurations, one serialisation.

    The two agents must differ in every argument, because every one of them
    decides something the other must not be able to do -- a shared key
    reference, source class or resource scope would be one agent able to answer
    for the other, and the deployment would look entirely normal.

    And the second pass must differ from the first in the audience alone.  It
    exists only to tell each service the URL it turned out to have; a pass that
    also changed something else would be a second configuration nobody wrote
    down, applied to a running service.
    """
    calls = _deploy_calls()
    assert len(calls) == 4, f"expected two passes over two agents, found {len(calls)} deploys"
    site_first, employer_first, site_second, employer_second = calls

    for index, what in enumerate(DEPLOY_ARGUMENTS):
        assert site_first[index] != employer_first[index], f"both agents share a {what}"

    assert len(site_first) == len(DEPLOY_ARGUMENTS)
    assert site_second[: len(DEPLOY_ARGUMENTS)] == site_first
    assert employer_second[: len(DEPLOY_ARGUMENTS)] == employer_first
    assert len(site_second) == len(DEPLOY_ARGUMENTS) + 1, "the second pass names no audience"
    assert len(employer_second) == len(DEPLOY_ARGUMENTS) + 1

    assert _executable(DEPLOY).count("gcloud run deploy") == 1, (
        "a second deploy command is a second serialisation, and only one of them is tested"
    )


#  ---- the deployment and the catalog name the same fleet ------------------


def test_the_deployment_names_the_agents_the_catalog_names() -> None:
    """An agent refuses an assignment addressed to a name that is not its own.

    So a deployment that renamed an agent would produce a fleet that comes up,
    passes its smoke test, and abstains on every assignment with
    ``ASSIGNMENT_REFUSED`` -- which reads as a routing fault and is a typo in a
    variable.  The catalog and the deployment are two files; this is the
    sentence spanning them.
    """
    from agent_tests.support import fleet

    assert _default_of("SITE_AGENT_ID") == fleet.SITE_AGENT_ID
    assert _default_of("EMPLOYER_AGENT_ID") == fleet.EMPLOYER_AGENT_ID
    assert _default_of("SITE_PRINCIPAL") == fleet.SITE
    assert _default_of("EMPLOYER_PRINCIPAL") == fleet.EMPLOYER


def test_the_deployment_signs_under_the_references_the_cloud_run_grants() -> None:
    """Two keys, two references, and both sides have to spell them the same.

    The agents mount keys an operator minted and sign under the references
    ``env.sh`` configures; the control plane grants those references and holds
    the matching public halves.  A drift between the two is receipts that are
    authentic, unauthorized, and refused by Q-12(b) one layer past where the
    mistake was made.
    """
    from agent_tests.support import cloud

    assert _default_of("SITE_KEY_REF") == cloud.SITE_KEY_REF
    assert _default_of("EMPLOYER_KEY_REF") == cloud.EMPLOYER_KEY_REF


def test_the_deployed_key_references_are_not_the_ones_the_case_is_seeded_under() -> None:
    """One reference resolves to one public key, so a new key needs a new name.

    The worked case's historical record is signed by keys generated in the
    process that seeds it.  A deployment reusing those references would put two
    different public keys under one name, and the registry can hold one -- so
    half the case would stop verifying, on whichever half lost.
    """
    from support.authority import PAYROLL_KEY, SITE_A_KEY

    assert _default_of("SITE_KEY_REF") != SITE_A_KEY
    assert _default_of("EMPLOYER_KEY_REF") != PAYROLL_KEY


#  ---- the control plane is a job, and the teardown is true ----------------


def test_no_script_deploys_a_control_plane_service() -> None:
    """The control plane calls outbound and is never called.

    A service would be an ingress nothing needs and one more thing to hold
    closed.  Checked per script: a file that runs something under the control
    plane's identity has to be deploying a *job*.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        text = path.read_text(encoding="utf-8")
        executable = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        if '--service-account="${CONTROL_PLANE_SA}"' not in executable:
            continue
        assert "gcloud run jobs deploy" in executable, path.name
        assert "gcloud run deploy" not in executable, (
            f"{path.name} deploys a service under the control plane's identity"
        )


def test_the_hero_job_runs_under_the_control_plane_identity() -> None:
    """Not the operator's, and not an agent's.

    The whole point of running it in the project is that the identity doing the
    acquiring is the one the IAM policy describes -- an operator running it from
    a laptop is outside that boundary and would prove nothing about it.
    """
    executable = "\n".join(
        line
        for line in HERO.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    assert '--service-account="${CONTROL_PLANE_SA}"' in executable
    assert "gcloud run jobs deploy" in executable
    assert '--image="${CONTROL_PLANE_IMAGE}"' in executable
    for agent_identity in ("${SITE_SA}", "${EMPLOYER_SA}"):
        assert f'--service-account="{agent_identity}"' not in executable


#: How a resource gets created in these scripts.  Each pattern captures the
#: environment variable naming the thing that comes into existence.
_CREATED = (
    re.compile(r'muster::create_sa "\$\{([A-Z_]+)\}"'),
    re.compile(r'muster::store "\$\{([A-Z_]+)\}"'),
    re.compile(r'muster::deploy "\$\{([A-Z_]+)\}"'),
    re.compile(r'gcloud run jobs deploy "\$\{([A-Z_]+)\}"'),
    re.compile(r'gcloud artifacts repositories create "\$\{([A-Z_]+)\}"'),
    re.compile(r'gcloud storage buckets create "gs://\$\{([A-Z_]+)\}"'),
)


def test_the_teardown_removes_every_resource_the_other_scripts_create() -> None:
    """The claim in its header, checked rather than believed.

    A teardown that names fewer resources than the deployment creates is worse
    than one that made no claim: it leaves billable resources and source
    material behind while reporting success, and the operator has no reason to
    look.  The list is *derived* from the creating scripts, so a script that
    creates something new fails this until the teardown removes it.

    Names are compared with any ``_ID`` suffix stripped, because an account is
    created by identifier and deleted by address and those are two variables
    holding one name.
    """
    created: set[str] = set()
    for path in sorted(SCRIPTS.glob("*.sh")):
        if path.name.startswith("99-"):
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):
                continue
            for pattern in _CREATED:
                created.update(pattern.findall(line))
    assert created, "no resource creation was found; this test is looking in the wrong place"

    teardown = "\n".join(
        line
        for line in TEARDOWN.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    missing = {
        name
        for name in created
        if f"${{{name}}}" not in teardown and f"${{{name.removesuffix('_ID')}}}" not in teardown
    }
    assert not missing, (
        f"{', '.join(sorted(missing))} is created by a deployment script and the teardown "
        "does not remove it"
    )


def test_the_teardown_reports_what_it_did_rather_than_what_it_attempted() -> None:
    """A survivor has to be distinguishable from something never created.

    Both look like a failed delete.  Reporting the second as a failure trains an
    operator to ignore the exit code, and reporting the first as a success is
    the defect the exit code exists to catch -- so the script describes the
    resource first and only counts a genuine failure.
    """
    text = TEARDOWN.read_text(encoding="utf-8")
    assert "muster::remove_if_present" in text
    assert "absent" in text
    assert "FAILURES" in text


#  ---- the route the hero job takes to an internal agent -------------------
#
#  A Cloud Run resource is recognised as internal traffic by a service deployed
#  ``--ingress=internal`` only when its request leaves through a VPC network in
#  the project.  Default job networking is not that route.  So the hero job's
#  network attachment is not a tuning parameter: without it the deployment comes
#  up complete, correct in every other respect, and the fleet is unreachable --
#  reported as ``unreached ENDPOINT_REFUSED``, which is also what a source
#  declining to answer looks like from a distance.
#
#  These check the three flags together, because any one of them alone is a
#  configuration that reads as right and does nothing.


def _hero_flags() -> str:
    """The hero script, read for what it does."""
    return _executable(HERO)


def test_the_hero_job_attaches_a_vpc_network() -> None:
    """And one the deployment names, rather than one gcloud infers."""
    assert '--network="${HERO_VPC_NETWORK}"' in _hero_flags()
    assert _default_of("HERO_VPC_NETWORK") == "default"


def test_the_hero_job_attaches_a_subnet() -> None:
    """Direct VPC egress attaches to a subnet, and the region has to hold one.

    A network without a subnet is not a route, and ``gcloud run jobs deploy``
    refuses the pair half-given -- so that failure lands at deploy rather than
    in the run, which is the better place for it and still not a reason to
    leave the default unset.
    """
    assert '--subnet="${HERO_VPC_SUBNET}"' in _hero_flags()
    assert _default_of("HERO_VPC_SUBNET") == "default"


def test_the_hero_job_sends_all_traffic_through_the_vpc() -> None:
    """``private-ranges-only`` would be the silent version of not doing it.

    The agent is reached at its ordinary ``run.app`` URL -- a public hostname at
    a public address -- so a job restricting VPC egress to private ranges sends
    that request out by the default path, where it arrives from outside any VPC
    and is judged at the perimeter exactly as if no network were attached.
    """
    assert '--vpc-egress="${HERO_VPC_EGRESS}"' in _hero_flags()
    assert _default_of("HERO_VPC_EGRESS") == "all-traffic"


def test_the_vpc_route_is_the_default_path_and_not_a_remedy() -> None:
    """Nothing has to be exported for the job to be reachable.

    The three flags are conditional on the network and subnet being non-empty,
    which is how the diagnostic path is reached -- so what makes the route the
    default is the defaults, and this is the test that fails if somebody
    "tidies" env.sh by unsetting them again.
    """
    for name in ("HERO_VPC_NETWORK", "HERO_VPC_SUBNET", "HERO_VPC_EGRESS"):
        assert _default_of(name), f"env.sh leaves {name} empty; the hero job then has no route"


def test_the_deployment_enables_the_api_the_vpc_route_needs() -> None:
    """Networks and subnets are Compute Engine resources.

    A project without ``compute.googleapis.com`` has no ``default`` network for
    the job to name, and ``90-hero-job.sh`` fails at its deploy command --
    eleven steps after the one that could have prevented it.
    """
    enabled = "\n".join(
        line
        for line in (SCRIPTS / "00-enable-apis.sh").read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "compute.googleapis.com" in enabled


#  ---- and the perimeter the route exists to satisfy stays closed ----------


def test_the_agent_services_are_deployed_with_internal_ingress() -> None:
    """The control the VPC route exists to satisfy, still there to be satisfied.

    Checked at both ends: the deploy passes an ingress flag at all, and the
    value it falls back to is the closed one.  A deployment that stopped passing
    the flag would inherit Cloud Run's default, which is not this.
    """
    assert '--ingress="${RUN_INGRESS}"' in DEPLOY.read_text(encoding="utf-8")
    assert _default_of("RUN_INGRESS") == "internal"


def test_no_deployment_script_broadens_the_agents_ingress() -> None:
    """``RUN_INGRESS=all`` is a diagnostic somebody types, never a script's doing.

    It removes the outermost of the three controls in front of an agent.  A
    script that set it -- to make its own path work, which is the only reason it
    would ever happen -- would broaden the perimeter for every later run in that
    shell, and the deployment would still look exactly like the README describes.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            assert "RUN_INGRESS=all" not in stripped, f"{path.name}:{number} broadens the ingress"
            assert "--ingress=all" not in stripped, f"{path.name}:{number} broadens the ingress"


def test_every_deployment_script_is_line_ended_for_the_shell_that_runs_it() -> None:
    """These run on Linux and macOS, where a carriage return is not whitespace.

    Written on Windows they are one editor away from CRLF -- and then ``set -euo
    pipefail`` carries a trailing return that makes it an invalid option name,
    the interpreter line names a program called ``bash`` plus a return, and the
    deployment stops at its first command with an error about something that is
    plainly installed.  Git Bash tolerates it, so this is invisible from the
    machine the scripts are written on, which is why it is asserted here rather
    than left to be noticed.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        assert b"\r" not in path.read_bytes(), f"{path.name} has CRLF line endings"


#  ---- the output of a run belongs to that run -----------------------------
#
#  A Cloud Run job outlives its executions, and so do their logs.  What
#  90-hero-job.sh read under the heading "what it printed" was
#
#      resource.type=cloud_run_job AND resource.labels.job_name=${HERO_JOB}
#      --limit=200 --order=asc
#
#  -- a filter over the *job*, oldest first, capped at 200.  So a successful run
#  whose predecessor had timed out printed the predecessor's
#
#      Terminating task because it has reached the maximum timeout of 900 seconds.
#
#  as its own output.  Every word of that line is true and it is evidence of a
#  different execution, which is the worst thing an evidence path can produce:
#  authentic, legible, and about something else.  It also degrades with age
#  rather than announcing itself -- once a job has 200 entries behind it, the
#  current execution's lines can never be reached at all, under an unchanged
#  heading.
#
#  The repair is that an execution is named by the call that created it and
#  every read is scoped to that name.  These hold that in the file, and then
#  hold it by *running* the two helpers against a gcloud that would hand back
#  the older execution's lines if the scope were ever dropped.

#: The label Cloud Run stamps on every entry one job execution produces -- the
#: container's own output and the platform's messages about that execution
#: alike, which is why scoping to it excludes the timeout line by the same
#: clause that selects the output.  This is the runtime spelling, as it appears
#: in a filter that has actually been built.
EXECUTION_LABEL = 'labels."run.googleapis.com/execution_name"'

#: The same label as it appears in a *script*, where the quotes around it are
#: sometimes the shell's to escape.  Reading source is what needs this; a filter
#: that has been built has the quotes as quotes.
EXECUTION_LABEL_IN_SOURCE = "run.googleapis.com/execution_name"

#: How an execution must never be chosen.  "The most recent one" is a guess
#: that is usually right, and a retry or a second operator is all it takes for
#: it to be quietly wrong -- which is the same defect with a smaller window.
#: ``--limit=1`` is matched with its digits bounded, so the bound on how much of
#: one execution's output is read does not read as a selection.
BY_RECENCY = (
    re.compile(r"--sort-by"),
    re.compile(r"--limit=1(?!\d)"),
    re.compile(r"run jobs executions list"),
    re.compile(r"--last\b"),
)


def _non_comment_lines(path: Path) -> list[str]:
    """One script's lines with whole-line comments dropped, order preserved.

    Heredoc bodies are kept.  A ``gcloud logging read`` a script *prints* for an
    operator to run is evidence collection too -- it is just deferred by one
    copy and paste -- so it is held to the same rule as one the script runs.
    """
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]


def _function_body(path: Path, name: str) -> str:
    """The body of one ``muster::`` function, with its commentary removed.

    Same reason as ``_preflight`` above: the comments here say at length why the
    scope is the scope, and a test satisfiable by prose passes for a file that
    deleted the clause and explained what it used to do.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.startswith(f"{name}() {{")), None
    )
    assert start is not None, f"{path.name} no longer defines {name}"
    end = next(index for index, line in enumerate(lines) if index > start and line == "}")
    return "\n".join(line for line in lines[start : end + 1] if not line.lstrip().startswith("#"))


def _calls_unconditionally(path: Path, call: str) -> bool:
    """Whether one script makes a call on every path it can take.

    Nesting is counted rather than parsed, exactly as ``_unconditional_variables``
    does: the question is not what the script computes, it is whether the call
    can be *skipped*, and a line inside any conditional can be.
    """
    depth = 0
    for line in _non_comment_lines(path):
        stripped = line.strip()
        if stripped.startswith("if "):
            depth += 1
        elif stripped == "fi":
            depth = max(0, depth - 1)
        elif stripped == call and depth == 0:
            return True
    return False


def test_the_hero_job_reads_back_through_the_execution_scoped_helper() -> None:
    """It runs one execution and prints that execution, by name, and nothing else.

    Both halves matter.  A script that started the job through the shared runner
    and then read the logs itself would have the name and not use it, which is
    the version of this bug that survives a review because the fix is visibly
    present.
    """
    executable = _executable(HERO)
    assert 'muster::execute_job "${HERO_JOB}"' in executable
    assert 'muster::execution_output "${HERO_JOB}" "${execution}"' in executable
    assert "gcloud logging read" not in executable, (
        "90-hero-job.sh reads logs itself again, around the execution-scoped helper"
    )
    assert "gcloud run jobs execute" not in executable, (
        "90-hero-job.sh starts an execution it does not learn the name of"
    )


def test_no_deployment_script_reads_job_logs_without_naming_an_execution() -> None:
    """Across every script, and including the reads a script only prints.

    Checked in a window around each ``logging read`` rather than on the line
    itself, because a filter is built over several lines in one place and spelled
    over several lines in the other.  The property is the same in both: a read of
    a Cloud Run job's logs that does not name an execution is a read of every
    execution that job has ever had.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        lines = _non_comment_lines(path)
        for index, line in enumerate(lines):
            if "logging read" not in line:
                continue
            window = "\n".join(lines[max(0, index - 12) : index + 12])
            assert EXECUTION_LABEL_IN_SOURCE in window, (
                f"{path.name} reads cloud_run_job logs without naming an execution; "
                "the answer spans every execution of that job"
            )


def test_the_execution_is_named_by_the_call_that_created_it() -> None:
    """``--async`` answers with the execution it just made, whatever happens next.

    ``--wait`` does not: it reports an outcome and, on a failed run, exits with
    an error instead of a name -- and the failed run is precisely the one whose
    output somebody needs.  So the create is asynchronous, the name is taken from
    its own answer, and the waiting is done against that name.
    """
    body = _function_body(ENVIRONMENT, "muster::execute_job")
    assert "--async" in body
    assert '--format="value(metadata.name,name)"' in body, (
        "the runner asks for one representation of the execution name and not both"
    )
    assert "--wait" not in body, (
        "the runner waits through gcloud, which does not answer with a name"
    )


def test_no_script_selects_an_execution_by_recency() -> None:
    """ "The latest one" is the same defect with a shorter window.

    It is right until a retry, a second operator, or a run started from another
    terminal -- and when it is wrong it is wrong silently, in the direction of
    attributing one run's output to another.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        executable = _executable(path)
        for form in BY_RECENCY:
            assert form.search(executable) is None, (
                f"{path.name} picks an execution by recency ({form.pattern}) rather than by name"
            )


def test_reading_back_refuses_before_it_widens() -> None:
    """With no execution to scope to, the helper prints nothing at all.

    The tempting fallback is to read the job instead, so that *something*
    appears under the heading.  That is the original defect offered as an error
    path: the heading would still say "what it printed" and the lines would
    still belong to another run.
    """
    body = _function_body(ENVIRONMENT, "muster::execution_output")
    guard = body.index('if [[ -z "${execution}" ]]; then')
    assert guard < body.index("gcloud logging read"), (
        "the helper reaches gcloud before it has established which execution it is reading"
    )
    assert body.count("gcloud logging read") == 1, "there is a second read, and only one is scoped"
    assert EXECUTION_LABEL_IN_SOURCE in body
    assert 'gcloud logging read "${filter}"' in body, (
        "the read does not use the filter the helper built"
    )


def test_the_runner_and_the_reader_are_defined_once() -> None:
    """One implementation, so a scope added here cannot be missing over there.

    The same reasoning as the environment emitter: two copies agree until one of
    them is wrong, and this is a defect whose whole nature is being invisible in
    the output.
    """
    for name in ("muster::execute_job", "muster::execution_output"):
        defined = [
            path.name
            for path in sorted(SCRIPTS.glob("*.sh"))
            if f"{name}() {{" in path.read_text(encoding="utf-8")
        ]
        assert defined == ["env.sh"], f"{name} is defined in {defined}"


def test_an_unread_outcome_is_not_reported_as_a_failed_one() -> None:
    """ "The run said no" and "we do not know what the run said" are two facts.

    The runner separates them -- 1 and 2 -- and the hero job carries the
    separation out to its own exit status rather than collapsing it back.  A
    script that reported an unreadable outcome as a refusal would be stating a
    verdict it does not hold, about a case.
    """
    body = _function_body(ENVIRONMENT, "muster::execute_job")
    assert "return 2" in body, "the runner cannot say that it does not know"
    assert "return 1" in body
    assert "return 0" in body

    executable = _executable(HERO)
    assert "if [[ ${status} -eq 2 ]]; then" in executable
    assert "exit 4" in executable, "the hero job reports an unread outcome as a verdict"


#  ---- the same thing, by running it ---------------------------------------
#
#  Everything above reads the scripts.  What follows runs the two helpers
#  against a ``gcloud`` that behaves like the real one in the single respect
#  this defect turns on: asked for a job's logs with no execution named, it
#  answers with **every** execution's lines, oldest first.  So the older
#  execution's timeout line is there to be picked up, and the only thing
#  keeping it out of the output is the scope.

#: The two executions in the fixture: the one that timed out, and the one that
#: worked.  Named as Cloud Run names them, because the filter that selects
#: between them is matched as a string.
OLDER_EXECUTION = "muster-control-plane-hero-p4t9x"
NEWER_EXECUTION = "muster-control-plane-hero-nrrgr"

#: What the failed execution left behind.  The last line is the one that was
#: printed under a successful run's heading.
OLDER_OUTPUT = "\n".join(
    (
        "== the worked case ==",
        "unreached  ENDPOINT_REFUSED",
        "Terminating task because it has reached the maximum timeout of 900 seconds.",
    )
)

#: What the successful execution printed, in the shape the run actually
#: produced: a denial, three admitted facts, a rebuild and an outcome.
NEWER_OUTPUT = "\n".join(
    (
        "raw-object DENIED HTTP 403",
        "admitted   employer scheduled          Q-12 passed",
        "admitted   site present_on_site        Q-12 passed",
        "admitted   site duration lower bound   Q-12 passed",
        "rebuild    deterministic",
        "outcome    INVARIANT",
    )
)

STALE_LINE = "maximum timeout of 900 seconds"

#: A gcloud that is a shell *function* rather than a program on PATH.  env.sh's
#: helpers call ``gcloud``, and a function of that name intercepts every one of
#: those calls -- including the ones inside command substitutions -- with no
#: dependence on how this platform spells a search path or an executable bit.
#: ``sleep`` is stubbed for the same reason: the retry this file exercises is a
#: real one and its waiting is not the thing under test.
FAKE_GCLOUD = r"""
sleep() { : ; }

_fake_execute() {
  printf '%s\n' "${FAKE_EXECUTE_OUTPUT}"
  return "${FAKE_EXECUTE_STATUS:-0}"
}

_fake_executions() {
  local joined="$*"
  case "${joined}" in
    *status.completionTime*) printf '%s\n' "${FAKE_COMPLETION_TIME:-}" ;;
    *status.succeededCount*) printf '%s\n' "${FAKE_SUCCEEDED:-}" ;;
    *) echo "fake gcloud: unexpected executions call: $*" >&2; return 99 ;;
  esac
  return 0
}

#  The whole point of the fixture.  With no execution named, this answers the
#  way Cloud Logging does: every execution of the job, oldest first -- which is
#  what --order=asc then hands back as "what it printed".
#  Matched on the execution names themselves rather than on the shape of the
#  clause carrying them: the label is quoted, the value is quoted, and a fixture
#  that insisted on one spelling of that would answer "no entries" for a filter
#  that was perfectly correct -- which is a fixture that passes this file for
#  the wrong reason.  Neither name is a substring of the job's own name.
_fake_logging() {
  local filter="${1:-}"
  printf '%s\n' "${filter}" >> "${FAKE_FILTERS}"
  case "${filter}" in
    *"${NEWER_EXECUTION}"*) printf '%s\n' "${NEWER_OUTPUT}" ;;
    *"${OLDER_EXECUTION}"*) printf '%s\n' "${OLDER_OUTPUT}" ;;
    *execution_name*) : ;;
    *) printf '%s\n' "${OLDER_OUTPUT}"; printf '%s\n' "${NEWER_OUTPUT}" ;;
  esac
  return 0
}

_fake_subnets() {
  local joined="$*"
  case "${joined}" in
    *"subnets describe"*)
      printf 'describe\n' >> "${FAKE_CALLS}"
      cat "${FAKE_PGA_STATE}"
      ;;
    *"subnets update"*)
      printf 'update\n' >> "${FAKE_CALLS}"
      if [[ "${FAKE_PGA_UPDATE:-allow}" == "allow" ]]; then
        printf 'True\n' > "${FAKE_PGA_STATE}"
        return 0
      fi
      echo "PERMISSION_DENIED: compute.subnetworks.setPrivateIpGoogleAccess" >&2
      return 1
      ;;
    *) echo "fake gcloud: unexpected compute call: $*" >&2; return 99 ;;
  esac
  return 0
}

gcloud() {
  case "${1:-} ${2:-}" in
    "run jobs")
      case "${3:-}" in
        execute) _fake_execute "$@" ;;
        executions) _fake_executions "$@" ;;
        *) echo "fake gcloud: unexpected: $*" >&2; return 99 ;;
      esac
      ;;
    "logging read") _fake_logging "${3:-}" ;;
    "compute networks") _fake_subnets "$@" ;;
    *) echo "fake gcloud: unexpected: $*" >&2; return 99 ;;
  esac
}
"""


def _fake_environment(tmp_path: Path, **overrides: str) -> dict[str, str]:
    """The environment the fake reads its answers out of."""
    state = tmp_path / "pga-state"
    if not state.exists():
        state.write_text("True\n", encoding="utf-8")
    environment = dict(os.environ)
    environment.update(
        {
            "PROJECT_ID": "execution-scoping-test",
            "FAKE_EXECUTE_OUTPUT": f"{NEWER_EXECUTION}\t",
            "FAKE_COMPLETION_TIME": "2026-08-21T18:41:07.512Z",
            "FAKE_SUCCEEDED": "1",
            "FAKE_FILTERS": (tmp_path / "filters").as_posix(),
            "FAKE_CALLS": (tmp_path / "calls").as_posix(),
            "FAKE_PGA_STATE": state.as_posix(),
            "OLDER_EXECUTION": OLDER_EXECUTION,
            "NEWER_EXECUTION": NEWER_EXECUTION,
            "OLDER_OUTPUT": OLDER_OUTPUT,
            "NEWER_OUTPUT": NEWER_OUTPUT,
        }
    )
    environment.update(overrides)
    return environment


def _drive(body: str, tmp_path: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    """Source env.sh over the fake gcloud and run one fragment against it."""
    bash = shutil.which("bash")
    assert bash is not None
    script = "\n".join(
        (
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            FAKE_GCLOUD,
            f'source "{ENVIRONMENT.as_posix()}"',
            body,
        )
    )
    driver = tmp_path / "drive.sh"
    driver.write_bytes((script + "\n").encode("utf-8"))
    #  check=False: a refusal is a result this file asserts about.
    return subprocess.run(  # noqa: S603
        [bash, driver.as_posix()],
        capture_output=True,
        text=True,
        env=_fake_environment(tmp_path, **overrides),
        check=False,
    )


RUN_AND_READ = """
set +e
muster::execute_job "${HERO_JOB}"
outcome=$?
set -e
echo "OUTCOME ${outcome}"
echo "EXECUTION ${MUSTER_EXECUTION}"
echo "--- what it printed ---"
muster::execution_output "${HERO_JOB}" "${MUSTER_EXECUTION}" || echo "NOTHING PRINTED"
"""


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_the_fixture_would_hand_back_the_older_executions_lines(tmp_path: Path) -> None:
    """The regression test's own premise, asserted before it is relied on.

    If the fake answered a job-wide filter with only the newest execution, every
    test below would pass for a helper that had dropped the scope entirely --
    which is the exact defect being regressed.  So this asks it the unscoped
    question first and confirms the stale line comes back.
    """
    done = _drive(
        '_fake_logging \'resource.type="cloud_run_job" '
        'AND resource.labels.job_name="muster-control-plane-hero"\'',
        tmp_path,
    )
    assert done.returncode == 0, done.stderr
    assert STALE_LINE in done.stdout, (
        "the fixture cannot contaminate, so it cannot regress anything"
    )
    assert "outcome    INVARIANT" in done.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_only_the_lines_of_the_execution_this_run_created_are_printed(tmp_path: Path) -> None:
    """The defect, run rather than read.

    One execution is created, its name comes back from the call that created it,
    and the read is scoped to that name -- so the older execution's timeout line
    is in the fixture, reachable by the unscoped filter the previous version
    sent, and absent from the output.
    """
    done = _drive(RUN_AND_READ, tmp_path)
    assert done.returncode == 0, done.stderr
    assert f"EXECUTION {NEWER_EXECUTION}" in done.stdout
    assert "OUTCOME 0" in done.stdout
    assert "outcome    INVARIANT" in done.stdout
    assert "raw-object DENIED HTTP 403" in done.stdout
    assert STALE_LINE not in done.stdout, "a previous execution's output was printed as this run's"
    assert OLDER_EXECUTION not in done.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_every_read_names_the_execution_that_was_created(tmp_path: Path) -> None:
    """Checked on the filters themselves, not only on what came back.

    A read that happened to return the right lines while asking a wider question
    is the same defect waiting for a busier job, so what the helper *asked* is
    recorded and asserted about.
    """
    done = _drive(RUN_AND_READ, tmp_path)
    assert done.returncode == 0, done.stderr
    filters = (tmp_path / "filters").read_text(encoding="utf-8").splitlines()
    assert filters, "no read was made at all"
    for filter_text in filters:
        assert f'{EXECUTION_LABEL}="{NEWER_EXECUTION}"' in filter_text
        assert 'resource.labels.job_name="muster-control-plane-hero"' in filter_text


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_the_execution_name_is_read_from_either_representation(tmp_path: Path) -> None:
    """gcloud spells it ``metadata.name`` or ``name``, depending on its version.

    Both are asked for in one projection, and whichever answered is used -- a
    full resource path reduced to its last segment, which is what the log label
    carries.  Getting this wrong would fail closed rather than contaminate, and
    it would fail closed on every real run.
    """
    path_form = f"\tprojects/p/locations/asia-south1/jobs/j/executions/{NEWER_EXECUTION}"
    done = _drive(RUN_AND_READ, tmp_path, FAKE_EXECUTE_OUTPUT=path_form)
    assert done.returncode == 0, done.stderr
    assert f"EXECUTION {NEWER_EXECUTION}" in done.stdout
    assert "outcome    INVARIANT" in done.stdout
    assert STALE_LINE not in done.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_an_unnamed_execution_prints_nothing_rather_than_something(tmp_path: Path) -> None:
    """The fallback that would restore the defect, refused.

    With no name to scope to there is a job-wide read available that would fill
    the heading with lines.  Every one of them would belong to some other run.
    """
    done = _drive(RUN_AND_READ, tmp_path, FAKE_EXECUTE_OUTPUT="")
    assert "OUTCOME 2" in done.stdout, "an unstarted run was reported as a verdict"
    assert "EXECUTION " in done.stdout
    assert "NOTHING PRINTED" in done.stdout
    assert STALE_LINE not in done.stdout
    assert "outcome    INVARIANT" not in done.stdout
    filters = tmp_path / "filters"
    assert not filters.exists(), "a read was attempted with no execution to scope it to"


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_a_failed_execution_still_names_itself_so_its_output_can_be_read(tmp_path: Path) -> None:
    """The run worth reading is the one that failed, so the name has to survive it.

    ``--wait`` is what this replaced, and on a failed execution it exits with an
    error rather than a name -- which is why the create is asynchronous and the
    waiting is done here.
    """
    done = _drive(RUN_AND_READ, tmp_path, FAKE_SUCCEEDED="0")
    assert "OUTCOME 1" in done.stdout, "a failed execution was not reported as failed"
    assert f"EXECUTION {NEWER_EXECUTION}" in done.stdout
    assert "outcome    INVARIANT" in done.stdout
    assert STALE_LINE not in done.stdout


#  ---- the prerequisite that was a manual step ------------------------------
#
#  ``--vpc-egress=all-traffic`` sends every packet the job emits through the
#  subnet, and a Cloud Run instance on Direct VPC egress has no external
#  address.  The agents answer at ``run.app`` hostnames on Google front-end
#  addresses, so without **Private Google Access** on that subnet the job's
#  outbound calls have no path -- and they do not fail.  They hang, until the
#  task timeout kills the execution with a message about 900 seconds and nothing
#  about a network.
#
#  This deployment already paid for that: it was made to work by turning the
#  setting on by hand, on a subnet, once.  A cloud prerequisite that lives
#  outside these scripts is one that will be missing in the next project, where
#  it will present as the fleet being down.


def test_the_hero_job_establishes_private_google_access_before_it_deploys() -> None:
    """Unconditionally, and ahead of the first thing that creates anything.

    The check declines for itself on the routes that do not need it, which is a
    decision that belongs next to the reason rather than in a caller's branch --
    and putting the call inside the VPC conditional would be the version of this
    that quietly stops running when somebody restructures that branch.
    """
    assert _calls_unconditionally(HERO, "muster::require_private_google_access"), (
        "90-hero-job.sh can deploy the job without establishing the route's other half"
    )
    lines = _non_comment_lines(HERO)
    checked = next(
        index
        for index, line in enumerate(lines)
        if line.strip() == "muster::require_private_google_access"
    )
    deployed = next(index for index, line in enumerate(lines) if "gcloud run jobs deploy" in line)
    assert checked < deployed, "the check runs after the job has been deployed"


def test_the_prerequisite_is_established_or_refused_and_never_assumed() -> None:
    """Both halves, because either alone is the manual step in a costume.

    Establishing it without checking afterwards would report success for an
    update that did not take.  Refusing without trying to establish it would
    leave the operator with the same manual step, merely better described.
    """
    body = _function_body(ENVIRONMENT, "muster::require_private_google_access")
    assert "--enable-private-ip-google-access" in body, "nothing establishes it"
    assert body.count("privateIpGoogleAccess") >= 2, (
        "the state is read once, so an update that did not take reads as success"
    )
    assert body.rstrip().endswith("exit 2\n}"), (
        "the check can reach its end without deciding, and the deploy follows"
    )


def test_the_prerequisite_is_required_only_where_the_route_needs_it() -> None:
    """``private-ranges-only`` does not need it, and the diagnostic path has no subnet.

    A ``run.app`` address is not a private range, so under
    ``private-ranges-only`` that request leaves by Cloud Run's default path and
    Private Google Access has no bearing on it.  Demanding it there would refuse
    a configuration that is merely differently broken, which teaches an operator
    that the check is noise.
    """
    body = _function_body(ENVIRONMENT, "muster::require_private_google_access")
    assert '[[ "${HERO_VPC_EGRESS}" != "all-traffic" ]]' in body
    assert '[[ -z "${HERO_VPC_NETWORK}" || -z "${HERO_VPC_SUBNET}" ]]' in body


def test_establishing_the_prerequisite_broadens_nothing() -> None:
    """It is a network setting about egress, and it must not become a way in.

    Private Google Access decides whether an instance with no external address
    may reach Google APIs outbound.  It grants no principal anything and it makes
    nothing reachable from outside the project -- and the one place that could
    change is here, where a check that "could not connect" would be tempted to
    open the perimeter it exists to let the job arrive at.
    """
    #  What it *runs*, so the lines it merely says are dropped first.  The
    #  refusal quotes the ingress the agents keep and the command an operator
    #  runs, and a check that could not name either would be a worse refusal.
    body = "\n".join(
        line
        for line in _function_body(
            ENVIRONMENT, "muster::require_private_google_access"
        ).splitlines()
        if not line.strip().startswith("echo")
    )
    for verb in (*CREATING, "add-iam-policy-binding", "--ingress", "--member"):
        assert verb not in body, f"the prerequisite check runs '{verb}'"


PRIVATE_ACCESS = """
muster::require_private_google_access
echo "PROCEEDED"
"""


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_a_subnet_that_already_has_it_is_left_alone(tmp_path: Path) -> None:
    """Idempotent, and visibly so: the deployment is re-run far more often than not."""
    done = _drive(PRIVATE_ACCESS, tmp_path)
    assert done.returncode == 0, done.stderr
    assert "PROCEEDED" in done.stdout
    calls = (tmp_path / "calls").read_text(encoding="utf-8").split()
    assert "update" not in calls, "a subnet that already had it was written to anyway"


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_a_subnet_without_it_has_it_established(tmp_path: Path) -> None:
    """The hidden manual step, taken by the script that needs it.

    And confirmed by reading the subnet back: an update that reported success
    and did not take would otherwise be indistinguishable from one that did.
    """
    (tmp_path / "pga-state").write_text("False\n", encoding="utf-8")
    done = _drive(PRIVATE_ACCESS, tmp_path)
    assert done.returncode == 0, done.stderr
    assert "PROCEEDED" in done.stdout
    calls = (tmp_path / "calls").read_text(encoding="utf-8").split()
    assert calls.count("update") == 1
    assert calls.count("describe") == 2, "the subnet was not read back after being updated"


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_a_prerequisite_that_cannot_be_established_stops_the_deployment(tmp_path: Path) -> None:
    """Fail closed, before anything exists, naming the exact command.

    The alternative is the run this repair came from: a job that comes up
    looking entirely correct, reaches nothing, and is killed by its own task
    timeout with a message that mentions no network at all.
    """
    (tmp_path / "pga-state").write_text("False\n", encoding="utf-8")
    done = _drive(PRIVATE_ACCESS, tmp_path, FAKE_PGA_UPDATE="deny")
    assert done.returncode == 2
    assert "PROCEEDED" not in done.stdout, "the deployment continued without the route"
    assert "Nothing has been deployed" in done.stderr
    assert "--enable-private-ip-google-access" in done.stderr, (
        "the refusal does not say what to run"
    )
    assert "compute.subnetworks.setPrivateIpGoogleAccess" in done.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_a_subnet_that_is_not_there_stops_the_deployment(tmp_path: Path) -> None:
    """A named network that does not exist fails at the deploy, eleven steps in.

    Here it fails at the check, with the command that lists what the project
    actually has -- and with the two variables to set, which is the whole repair
    for a project that keeps its workloads somewhere other than ``default``.
    """
    (tmp_path / "pga-state").write_text("", encoding="utf-8")
    done = _drive(PRIVATE_ACCESS, tmp_path)
    assert done.returncode == 2
    assert "PROCEEDED" not in done.stdout
    assert "HERO_VPC_SUBNET" in done.stderr
    assert "subnets list" in done.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_the_diagnostic_path_and_private_ranges_are_left_to_fail_their_own_way(
    tmp_path: Path,
) -> None:
    """Neither needs Private Google Access, so neither is refused for lacking it.

    Both are already broken in a way this deployment documents at length, and a
    check that refused them here would report the wrong reason for a failure
    somebody chose deliberately.
    """
    (tmp_path / "pga-state").write_text("False\n", encoding="utf-8")
    for overrides in (
        {"HERO_VPC_EGRESS": "private-ranges-only"},
        {"HERO_VPC_NETWORK": "", "HERO_VPC_SUBNET": ""},
    ):
        done = _drive(PRIVATE_ACCESS, tmp_path, **overrides)
        assert done.returncode == 0, done.stderr
        assert "PROCEEDED" in done.stdout, overrides
    assert not (tmp_path / "calls").exists(), "a route that does not need the subnet read it"


#  ---- what Cloud Run is actually asked for --------------------------------
#
#  Driven through bash and the real env.sh rather than read as text, because the
#  thing that has to be right is the *expansion*.  A layout that reads correctly
#  and expands to two secrets in one directory is refused by gcloud, client-side,
#  after review and in front of a cloud:
#
#      Cannot update secret at [...] because a different secret is already
#      mounted in the same directory.
#
#  A Cloud Run secret volume maps to exactly one secret and supports no
#  subpaths, so "one directory, one secret" is the rule, and these expand each
#  deployment's own line to check it holds.


def _expanded_mappings(script: Path, tmp_path: Path, **overrides: str) -> list[tuple[str, str]]:
    """Pull the script's own ``--set-secrets`` line and let bash expand it."""
    body = "\n".join(
        (
            f"""line="$(grep -o -- '--set-secrets="[^"]*"' "{script.as_posix()}" | head -1)\"""",
            'eval "printf %s ${line#--set-secrets=}"',
            "",
        )
    )
    done = _drive(body, tmp_path, **overrides)
    assert done.returncode == 0, done.stderr
    mappings: list[tuple[str, str]] = []
    for entry in done.stdout.strip().split(","):
        key, _, value = entry.partition("=")
        mappings.append((key, value))
    return mappings


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
@pytest.mark.parametrize("script", ("90-hero-job.sh", "85-database-bootstrap.sh"))
def test_no_deployment_mounts_two_secrets_in_one_directory(script: str, tmp_path: Path) -> None:
    """The expansion, grouped exactly the way gcloud groups it."""
    mappings = _expanded_mappings(SCRIPTS / script, tmp_path)
    assert mappings, f"{script} asks for no secrets"

    directories: dict[str, set[str]] = {}
    for key, value in mappings:
        if key.startswith("/"):
            directories.setdefault(key.rsplit("/", 1)[0], set()).add(value)
    assert directories, f"{script} mounts no secret file"
    for directory, secrets in directories.items():
        assert len(secrets) == 1, f"{directory} would be handed {sorted(secrets)}"


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
@pytest.mark.parametrize("script", ("90-hero-job.sh", "85-database-bootstrap.sh"))
def test_a_deployment_mounts_only_a_certificate_and_never_a_private_key(
    script: str, tmp_path: Path
) -> None:
    """The DSN carries the password and is resolved into the environment.

    What is mounted is a public certificate, which is why 0444 is the right mode
    for it and why nothing has to copy it anywhere before libpq will read it.
    """
    for key, _ in _expanded_mappings(SCRIPTS / script, tmp_path):
        if key.startswith("/"):
            assert key.endswith("server-ca.pem"), key
        else:
            assert key.endswith("DATABASE_URL"), key


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_stage_ninety_demands_pinned_versions_only_for_the_custody_it_runs(
    tmp_path: Path,
) -> None:
    """EPHEMERAL needs no database secret, and CLOUD_SQL needs a reviewed one.

    Both halves matter.  Demanding the secrets unconditionally is what made the
    in-memory run -- the one already verified in the cloud -- undeployable; not
    demanding them under CLOUD_SQL would let 'latest' re-resolve a credential at
    every cold start.
    """
    body = 'muster::require_database_secret_version\necho PROCEEDED\n'

    ephemeral = _drive(body, tmp_path, HERO_DATABASE_DEPLOYMENT="EPHEMERAL")
    assert ephemeral.returncode == 0, ephemeral.stderr
    assert "PROCEEDED" in ephemeral.stdout

    unpinned = _drive(body, tmp_path, HERO_DATABASE_DEPLOYMENT="CLOUD_SQL")
    assert unpinned.returncode == 2
    assert "PROCEEDED" not in unpinned.stdout
    assert "DATABASE_DSN_SECRET_VERSION" in unpinned.stderr

    latest = _drive(
        body,
        tmp_path,
        HERO_DATABASE_DEPLOYMENT="CLOUD_SQL",
        DATABASE_DSN_SECRET_VERSION="latest",  # noqa: S106 - a version, not a credential
        DATABASE_SERVER_CA_SECRET_VERSION="1",  # noqa: S106 - a version, not a credential
    )
    assert latest.returncode == 2
    assert "PROCEEDED" not in latest.stdout

    pinned = _drive(
        body,
        tmp_path,
        HERO_DATABASE_DEPLOYMENT="CLOUD_SQL",
        DATABASE_DSN_SECRET_VERSION="3",  # noqa: S106 - a version, not a credential
        DATABASE_SERVER_CA_SECRET_VERSION="1",  # noqa: S106 - a version, not a credential
    )
    assert pinned.returncode == 0, pinned.stderr
    assert "PROCEEDED" in pinned.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_a_custody_that_is_neither_stops_the_deployment(tmp_path: Path) -> None:
    """Two kinds, and a typo is not silently one of them."""
    done = _drive("echo PROCEEDED", tmp_path, HERO_DATABASE_DEPLOYMENT="FIRESTORE")

    assert done.returncode == 2
    assert "PROCEEDED" not in done.stdout
    assert "EPHEMERAL or CLOUD_SQL" in done.stderr


#  ---- container paths on a shell that rewrites them ------------------------
#
#  Git Bash and MSYS2 rewrite arguments that look like POSIX paths before the
#  program sees them.  For a local file that is right; for a *container* path it
#  is a defect that deploys cleanly and dies at runtime:
#
#      --args=/app/demo/database_bootstrap.py
#          arrives as  C:/Program Files/Git/app/demo/database_bootstrap.py
#          and the job fails on
#          can't open file '/app/C:/Program Files/Git/app/demo/...'
#
#  Driven through bash rather than read as text, because the thing that has to
#  be right is what the argument *becomes*.


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_a_container_path_survives_argument_conversion(tmp_path: Path) -> None:
    """The exact ``C:/Program Files/Git/app/...`` class, asserted as absent.

    Handed to a **native** executable rather than a shell builtin.  MSYS
    rewrites arguments on the boundary between the POSIX shell and a native
    program, so a builtin like ``printf`` never sees a converted path -- and a
    version of this test written against one passed against the broken code,
    which is how it came to be pointed at ``sys.executable`` instead.
    """
    echoer = tmp_path / "echo_argv.py"
    echoer.write_text("import sys\nprint(sys.argv[1])\n", encoding="utf-8")
    body = (
        f'muster::gcloud_container_args "{Path(sys.executable).as_posix()}" '
        f'"{echoer.as_posix()}" "--args=/app/demo/database_bootstrap.py,--cloud-sql"'
    )
    done = _drive(body, tmp_path)
    assert done.returncode == 0, done.stderr

    printed = done.stdout.strip()
    assert printed == "--args=/app/demo/database_bootstrap.py,--cloud-sql", printed
    #  The failure this exists for, named rather than merely implied.
    assert "Program Files" not in printed
    assert ":/" not in printed.split("=", 1)[1]


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_the_container_arg_helper_does_not_change_the_operators_shell(tmp_path: Path) -> None:
    """Scoped to one invocation.  A deployment script is not a place to export."""
    body = 'muster::gcloud_container_args true\necho "AFTER=[${MSYS2_ARG_CONV_EXCL:-unset}]"'
    done = _drive(body, tmp_path)

    assert done.returncode == 0, done.stderr
    assert "AFTER=[unset]" in done.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_an_existing_conversion_exclusion_is_preserved(tmp_path: Path) -> None:
    """An operator who set one meant it, so it is appended to and then restored."""
    body = "\n".join(
        (
            'muster::gcloud_container_args env | grep MSYS2_ARG_CONV_EXCL | sed "s/^/INSIDE /"',
            'echo "AFTER=[${MSYS2_ARG_CONV_EXCL}]"',
        )
    )
    done = _drive(body, tmp_path, MSYS2_ARG_CONV_EXCL="--other=")

    assert done.returncode == 0, done.stderr
    assert "INSIDE MSYS2_ARG_CONV_EXCL=--other=;--args=" in done.stdout, done.stdout
    assert "AFTER=[--other=]" in done.stdout


def test_the_exclusion_is_never_widened_to_everything() -> None:
    """``'*'`` is the obvious fix and it breaks gcloud's own launcher.

    gcloud on Windows is a shell script whose own interpreter path *must* be
    converted, so excluding everything makes gcloud itself fail with
    ``can't open file 'C:\\c\\Program Files (x86)\\...\\gcloud.py'``.  Both
    blanket forms are ruled out where they would be written rather than merely
    avoided by whoever wrote the last script.
    """
    for path in sorted(SCRIPTS.glob("*.sh")):
        executable = "\n".join(
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        assert "MSYS2_ARG_CONV_EXCL='*'" not in executable, path.name
        assert 'MSYS2_ARG_CONV_EXCL="*"' not in executable, path.name
        assert "MSYS_NO_PATHCONV" not in executable, path.name


def test_every_container_path_argument_goes_through_the_helper() -> None:
    """A second script passing a container path must not rediscover this."""
    for path in sorted(SCRIPTS.glob("*.sh")):
        executable = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        ]
        carries = [line for line in executable if "--args=" in line and "/app/" in line]
        if not carries:
            continue
        assert any("muster::gcloud_container_args" in line for line in executable), (
            f"{path.name} passes a container path to --args without the helper"
        )


#  ---- the local interpreter ------------------------------------------------


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_an_interpreter_is_established_by_running_one(tmp_path: Path) -> None:
    """Found by execution, not by ``command -v``: on Windows they differ."""
    done = _drive('muster::require_python\necho "CHOSE=[${MUSTER_PYTHON}]"', tmp_path)

    assert done.returncode == 0, done.stderr
    assert "CHOSE=[" in done.stdout
    assert "CHOSE=[]" not in done.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_a_present_but_unrunnable_interpreter_is_refused(tmp_path: Path) -> None:
    """The Windows App Execution Alias, reproduced.

    A file that exists, is on PATH, is executable, and does not run a program --
    which is what ``python3`` is on a Windows box without Python, and what made
    Stage 90 fail *after* the model calls were spent and the case was durable.
    ``command -v`` finds it; only running it tells the truth.
    """
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    stub = stub_dir / "python3"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "echo 'Python was not found; run without arguments to install from the"
        " Microsoft Store' >&2\n"
        "exit 9009\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)

    body = "\n".join(
        (
            f'export PATH="{stub_dir.as_posix()}:$PATH"',
            'command -v python3 >/dev/null && echo "ON_PATH yes"',
            'if muster::usable_python python3; then echo USABLE; else echo REFUSED; fi',
        )
    )
    done = _drive(body, tmp_path)

    assert done.returncode == 0, done.stderr
    assert "ON_PATH yes" in done.stdout, "the stub must be findable, or this proves nothing"
    assert "REFUSED" in done.stdout, done.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="the deployment scripts are bash")
def test_an_explicit_interpreter_that_does_not_run_stops_the_deployment(
    tmp_path: Path,
) -> None:
    """An override that is wrong says so here, not three stages later."""
    done = _drive(
        "muster::require_python\necho PROCEEDED",
        tmp_path,
        MUSTER_PYTHON="/definitely/not/here",
    )

    assert done.returncode == 2
    assert "PROCEEDED" not in done.stdout
    assert "does not run" in done.stderr


def test_the_interpreter_is_established_before_anything_is_deployed() -> None:
    """Ordering is the whole point: the cheapest check runs before the run.

    Discovering a missing local interpreter *after* the hero job has executed
    costs a real execution, real model calls and a durable case, and a second
    attempt cannot undo any of the three.
    """
    executable = [
        line
        for line in (SCRIPTS / "90-hero-job.sh").read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]
    guard = next(i for i, line in enumerate(executable) if "muster::require_python" in line)
    deploy = next(i for i, line in enumerate(executable) if "gcloud run jobs deploy" in line)
    execute = next(i for i, line in enumerate(executable) if "muster::execute_job" in line)
    capture = next(i for i, line in enumerate(executable) if "capture_case_trace.py" in line)

    assert guard < deploy, "the interpreter is checked after the job is deployed"
    assert guard < execute, "the interpreter is checked after the job has run"
    assert execute < capture, "the capture would not be the step that needs it"
