"""What the cloud composition root is, and what it must not be able to become.

``demo/cloud_hero.py`` is the process that runs in the project holding the case
record.  Three properties make it that rather than something else, and all
three are the kind that survive a review and die in a refactor, so they are
read out of the file itself rather than trusted:

* it reaches **no agent runtime** -- not by import, not by path, not by name;
* the transport it builds is the **authenticated HTTPS** one, and there is no
  branch anywhere in it that could select another;
* it prints **no ``detail``** -- the one class of string on these paths that
  something outside the control plane may have authored.

The image is checked here too.  "The control plane has no model dependency" is
a claim about what is installed, and the Dockerfile is where that is decided.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
CLOUD_HERO = REPOSITORY / "demo" / "cloud_hero.py"
CONTROL_PLANE_IMAGE = REPOSITORY / "infra" / "docker" / "control-plane.Dockerfile"
AGENT_IMAGE = REPOSITORY / "infra" / "docker" / "agent.Dockerfile"
CLOUDBUILD = REPOSITORY / "infra" / "cloudbuild.yaml"
HERO_DEPLOYMENT = REPOSITORY / "infra" / "scripts" / "90-hero-job.sh"
BOOTSTRAP_DEPLOYMENT = REPOSITORY / "infra" / "scripts" / "85-database-bootstrap.sh"
ENVIRONMENT = REPOSITORY / "infra" / "scripts" / "env.sh"

#: Vocabulary belonging to a milestone this run stops before.  A demo that
#: authorized or settled anything would be claiming a capability the system
#: does not have, and the cheapest way to be sure it does not is that the words
#: are absent.
BEYOND_THIS_MILESTONE = (
    "actiongate",
    "action_gate",
    "authorizedaction",
    "authorized_action",
    "gatedecision",
    "gate_decision",
    "settle",
    "settlement",
    "disburse",
    "disbursement",
    "payout",
    "spendinglimit",
    "spending_limit",
)


def _tree() -> ast.Module:
    return ast.parse(CLOUD_HERO.read_text(encoding="utf-8"), filename=str(CLOUD_HERO))


def _imports() -> set[str]:
    found: set[str] = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


#  ---- no agent runtime, by any route --------------------------------------


def test_the_cloud_hero_imports_no_agent_module() -> None:
    """The strongest form: not an import, anywhere, at any depth.

    Including inside a function. A deferred import is still an import; the SQL
    database import in ``main`` remains a control-plane adapter reached only
    after production configuration and schema readiness have been validated.
    """
    reached = {module for module in _imports() if module.split(".")[:2] == ["muster", "agents"]}
    assert not reached, sorted(reached)
    assert not {module for module in _imports() if module.startswith("agent_tests")}


def test_the_cloud_hero_puts_no_agent_package_on_its_path() -> None:
    """An import contract is worth nothing if the path makes one importable.

    The composition root extends ``sys.path`` so that it can be run from a
    checkout as well as from an image.  What it extends it with is checked,
    because "muster-agents" appearing in that tuple would make every rule above
    a matter of nobody having written the import yet.
    """
    text = CLOUD_HERO.read_text(encoding="utf-8")
    bootstrap = text.split("from muster.core", maxsplit=1)[0]
    assert "muster-agents" not in bootstrap
    assert "muster-kernel" in bootstrap
    assert "muster-platform" in bootstrap


def test_no_in_process_transport_is_named_anywhere_in_the_cloud_hero() -> None:
    """Cloud mode cannot fall back to talking to itself.

    ``InProcessAcquisitionTransport`` is an agent-package class and the local
    worked run uses it deliberately.  A cloud driver that could reach one would
    be a driver that could produce a green demo without a network, an identity
    token, or a deployed source.
    """
    text = CLOUD_HERO.read_text(encoding="utf-8").lower()
    for name in ("inprocess", "in_process", "inprocessacquisitiontransport"):
        assert name not in text, name


def test_the_transport_the_cloud_hero_builds_is_the_authenticated_https_one() -> None:
    """Read from the function rather than from a docstring: it is built here."""
    import sys

    sys.path.insert(0, str(REPOSITORY))
    from demo.cloud_hero import CloudFleet, build_transport

    from muster.platform.adapters.http import HttpAcquisitionTransport, MetadataServerTokens

    transport = build_transport(
        CloudFleet(
            tenant_id="ALPHA",
            case_id="CASE-1",
            site_endpoint="https://site.example.com",
            employer_endpoint="https://employer.example.com",
            site_key_ref="key-site-a-cloud-1",
            employer_key_ref="key-hr-payroll-cloud-1",
            site_public_key=b"",
            employer_public_key=b"",
            timeout_seconds=None,
            raw_object=None,
            postgres=None,
        )
    )
    assert isinstance(transport, HttpAcquisitionTransport)
    assert isinstance(transport.tokens, MetadataServerTokens)
    #  The allowlist is exactly the two configured hosts.  Not a wildcard, not
    #  the catalog's word for it, and not empty.
    assert transport.hosts == frozenset({"site.example.com", "employer.example.com"})


#  ---- what it may print ---------------------------------------------------


def test_the_cloud_hero_reads_no_detail_field() -> None:
    """A ``detail`` is the one string on these paths written outside this process.

    A transport failure carries the responder's own reason phrase; an
    abstention detail is authored inside a source; a submission error quotes
    what it refused.  None of them is needed to say what happened -- every
    failure here also carries a closed enumeration -- so the rule is that the
    field is never read, which is checkable and does not depend on judgement
    about which details happen to be safe today.
    """
    reading = [
        node.attr
        for node in ast.walk(_tree())
        if isinstance(node, ast.Attribute) and node.attr == "detail"
    ]
    assert not reading, "the cloud hero reads a detail field"


def test_the_cloud_hero_never_asks_cloud_storage_for_object_content() -> None:
    """The one request it makes of the evidence bucket brings back a name.

    ``alt=media`` is how the JSON API returns an object's octets.  A probe that
    used it would, on the day the boundary did not hold, pull the site's gate
    log into the process that publishes the demo's output.
    """
    text = CLOUD_HERO.read_text(encoding="utf-8")
    assert "alt=media" not in text
    assert "fields=name" in text


def test_the_cloud_hero_stops_before_the_action_gate() -> None:
    """No gate, no authorization, no settlement.

    Checked over *identifiers* -- what the module names, calls, imports and
    reads -- rather than over its text.  The docstring says out loud that
    nothing here is settled, and a test that failed on the sentence describing
    the property would be a test nobody could satisfy while documenting it.
    """
    named: set[str] = set()
    for node in ast.walk(_tree()):
        match node:
            case ast.Name(id=identifier):
                named.add(identifier.lower())
            case ast.Attribute(attr=attribute):
                named.add(attribute.lower())
            case (
                ast.FunctionDef(name=name)
                | ast.AsyncFunctionDef(name=name)
                | ast.ClassDef(name=name)
            ):
                named.add(name.lower())
            case ast.arg(arg=argument):
                named.add(argument.lower())
            case _:
                continue
    named |= {module.lower() for module in _imports()}
    for fragment in BEYOND_THIS_MILESTONE:
        offending = {identifier for identifier in named if fragment in identifier}
        assert not offending, sorted(offending)


def test_the_last_thing_the_cloud_hero_does_is_read_the_case() -> None:
    """The run ends at a status read, and nothing follows it.

    Stated over the calls the module actually makes: the four control-plane
    commands it uses are the four a case advances through, and there is no
    fifth that acts on the answer.
    """
    called = {
        node.func.id
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert {"append_transcript_entry", "acquire_outstanding", "case_status"} <= called
    assert not {name for name in called if "gate" in name or "settle" in name}


def test_no_database_failure_can_reach_the_in_memory_database() -> None:
    """In-memory custody is a branch, never a rescue.

    ``MemoryDatabase`` is present on purpose: an EPHEMERAL deployment is a thing
    Stage 90 may be asked for, and the verified run that kept nothing has to stay
    runnable.  What must not exist is an ``except`` -- or a ``finally``, or an
    ``or`` -- that arrives at it from the durable branch, because that would turn
    "the database is unreachable" into "the run kept nothing" without saying so.

    Checked on the tree rather than on the text: a construction inside a handler
    is what is being ruled out, and reading for the word would rule out the
    legitimate branch too.  ``test_cloud_hero_custody.py`` proves the behaviour;
    this proves no *later* edit can reintroduce the shape.
    """
    tree = _tree()
    memory_calls = {
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "MemoryDatabase"
    }
    assert memory_calls, "the EPHEMERAL branch is gone"

    rescued = {
        call
        for handler in ast.walk(tree)
        if isinstance(handler, ast.ExceptHandler)
        for call in ast.walk(handler)
        if call in memory_calls
    }
    assert not rescued, "an exception handler opens in-memory custody"

    #  And the durable branch reads the ledger rather than trusting the secret.
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "require_current_schema" in called


def test_the_cloud_hero_never_migrates_schema_during_a_run() -> None:
    """DDL belongs to the explicit bootstrap command, not normal execution."""
    called = {
        node.func.id
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "migrate" not in called


#  ---- the image -----------------------------------------------------------


def test_the_control_plane_image_installs_no_agent_distribution() -> None:
    """``pip list`` is the check, and this is where the answer is decided."""
    text = CONTROL_PLANE_IMAGE.read_text(encoding="utf-8")
    executable = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "muster-platform" in executable
    assert "muster-kernel" in executable
    assert "muster-agents" not in executable, "the control-plane image installs an agent runtime"
    for model in ("google-adk", "google-genai", "google-cloud-storage", "[cloud]"):
        assert model not in executable, model


def test_the_control_plane_image_carries_the_case_it_replays() -> None:
    """The seed is the suite's fixture, shipped on purpose.

    A demo with its own seed would be a second definition of the case and the
    first thing to drift.  Both directories have to be present and at the depth
    the fixture's own path arithmetic expects.
    """
    executable = CONTROL_PLANE_IMAGE.read_text(encoding="utf-8")
    assert "/app/packages/muster-platform/tests/support" in executable
    assert "/app/packages/muster-kernel/fixtures" in executable
    assert "/app/demo/cloud_hero.py" in executable


def test_the_control_plane_image_carries_the_explicit_migration_command() -> None:
    executable = CONTROL_PLANE_IMAGE.read_text(encoding="utf-8")
    assert "/app/demo/database_bootstrap.py" in executable


#  ---- the secrets a deployment asks Cloud Run for -------------------------


def _uncommented(path: Path) -> str:
    return "\n".join(
        line for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )


def _defaults() -> dict[str, str]:
    """The literal values ``env.sh`` gives its own variables.

    Both forms it uses: ``: "${NAME:=value}"`` for an overridable default and
    ``NAME="value"`` for one derived from another.  Read rather than duplicated,
    so a rename that broke the composition cannot leave this file agreeing with
    itself about a mount path nothing uses any more.
    """
    text = _uncommented(ENVIRONMENT)
    found: dict[str, str] = {}
    for name, value in re.findall(r'^: "\$\{([A-Z_]+):=([^}"]*)\}"', text, re.MULTILINE):
        found[name] = value
    for name, value in re.findall(r'^([A-Z_]+)="([^"]*)"$', text, re.MULTILINE):
        found[name] = value
    return found


def _expand(value: str, defaults: dict[str, str]) -> str:
    for _ in range(4):
        expanded = re.sub(r"\$\{([A-Z_]+)\}", lambda m: defaults.get(m.group(1), m.group(0)), value)
        if expanded == value:
            break
        value = expanded
    return value


def _secret_mappings(path: Path) -> tuple[tuple[str, str], ...]:
    """Every ``KEY=SECRET:VERSION`` this script hands ``--set-secrets``.

    Keys are expanded against ``env.sh``, because what Cloud Run is asked for is
    the expansion and not the reference.  ``${DATABASE_CA_FILE}`` is a mount path
    or it is nothing, and a test that read it as an environment-variable name
    would have declared the mount layout safe without looking at it.
    """
    defaults = _defaults()
    mappings: list[tuple[str, str]] = []
    for match in re.finditer(r'--set-secrets="([^"]+)"', _uncommented(path)):
        for entry in match.group(1).split(","):
            key, _, value = entry.partition("=")
            mappings.append((_expand(key, defaults), value))
    return tuple(mappings)


@pytest.mark.parametrize("deployment", (HERO_DEPLOYMENT, BOOTSTRAP_DEPLOYMENT))
def test_no_two_secrets_are_mounted_in_one_directory(deployment: Path) -> None:
    """The shape Cloud Run refuses, ruled out where it is written.

    A Cloud Run secret volume maps to exactly one secret and supports no
    subpaths, so two secret *files* under one directory is not a tighter layout:
    ``gcloud`` rejects it client-side, before anything is created, with

        Cannot update secret at [...] because a different secret is already
        mounted in the same directory.

    A deployment script that cannot deploy fails at the worst possible moment --
    after review, in front of a cloud -- and a test that asserted the string
    would have called it green.  So the assertion is on the composition: group
    the file mappings by mount directory and require each directory to name one
    secret.  Environment mappings are exempt because they are not volumes.
    """
    directories: dict[str, set[str]] = {}
    for key, value in _secret_mappings(deployment):
        if not key.startswith("/") and "/" not in key:
            continue
        directories.setdefault(key.rsplit("/", 1)[0], set()).add(value)

    for directory, secrets in directories.items():
        assert len(secrets) == 1, f"{directory} mounts {len(secrets)} different secrets"


@pytest.mark.parametrize("deployment", (HERO_DEPLOYMENT, BOOTSTRAP_DEPLOYMENT))
def test_a_connection_string_is_an_environment_secret_and_never_a_file(
    deployment: Path,
) -> None:
    """The DSN carries the password, so it is resolved rather than written.

    Cloud Run resolves a pinned version straight into the container's
    environment.  A file would mean the same secret, mounted in the directory
    the certificate already occupies -- which is the layout above -- for no gain.
    """
    mappings = _secret_mappings(deployment)
    assert mappings, f"{deployment.name} asks for no secrets at all"

    environment = {key for key, _ in mappings if not key.startswith("/")}
    files = {key for key, _ in mappings if key.startswith("/")}
    assert environment <= {"MUSTER_DATABASE_URL", "MUSTER_MIGRATION_DATABASE_URL"}
    assert environment, "the connection string is not an environment secret"
    assert all(name.endswith("server-ca.pem") for name in files), sorted(files)


@pytest.mark.parametrize("deployment", (HERO_DEPLOYMENT, BOOTSTRAP_DEPLOYMENT))
def test_every_secret_is_pinned_to_a_reviewed_version(deployment: Path) -> None:
    """``latest`` re-resolves at every cold start, which is a rotation nobody read."""
    for key, value in _secret_mappings(deployment):
        assert not value.endswith(":latest"), key
        assert "_VERSION}" in value, f"{key} does not name a pinned version"


def test_a_client_certificate_is_nowhere_in_the_deployment() -> None:
    """Cloud SQL is reached with a password and a verified server, and no more."""
    for path in (HERO_DEPLOYMENT, BOOTSTRAP_DEPLOYMENT, ENVIRONMENT, CONTROL_PLANE_IMAGE):
        text = path.read_text(encoding="utf-8")
        for absent in ("client-cert", "client-key", "CLIENT_KEY", "CLIENT_CERT", "sslkey"):
            assert absent not in text, f"{path.name} still carries {absent}"


def test_the_hero_names_the_custody_it_was_configured_for() -> None:
    """One label, written from one variable, and never a literal.

    Hard-coding ``CLOUD_SQL`` here is what made the previously verified,
    in-memory Stage-90 run undeployable.  The deployment carries whichever
    custody it was asked for, and ``env.sh`` refuses anything that is neither.
    """
    executable = _uncommented(HERO_DEPLOYMENT)
    assert 'muster::env_entry MUSTER_DATABASE_DEPLOYMENT "${HERO_DATABASE_DEPLOYMENT}"' in (
        executable
    )
    #  The DSN is never written into an env-vars file, under either custody.
    assert "muster::env_entry MUSTER_DATABASE_URL" not in executable
    #  An EPHEMERAL redeploy takes the old mount off rather than leaving a
    #  credential attached to a job whose custody no longer names one.
    assert "--clear-secrets" in executable


def test_the_environment_refuses_a_custody_that_is_neither() -> None:
    environment = ENVIRONMENT.read_text(encoding="utf-8")
    assert "HERO_DATABASE_DEPLOYMENT:=EPHEMERAL" in environment
    assert "EPHEMERAL|CLOUD_SQL)" in environment


def test_the_bootstrap_job_runs_as_the_migrator_and_retries_nothing() -> None:
    """DDL under an identity the control plane does not hold, exactly once."""
    executable = _uncommented(BOOTSTRAP_DEPLOYMENT)
    assert '--service-account="${MIGRATOR_SA}"' in executable
    assert '--args="/app/demo/database_bootstrap.py,--cloud-sql"' in executable
    assert "--max-retries=0" in executable
    assert '--service-account="${CONTROL_PLANE_SA}"' not in executable


def test_the_control_plane_image_carries_no_source_material() -> None:
    """A source's material belongs to the source, and it reads it from a bucket."""
    executable = CONTROL_PLANE_IMAGE.read_text(encoding="utf-8")
    assert "muster-agents/fixtures" not in executable


def test_both_images_are_built_from_one_submission() -> None:
    """A control plane and a fleet from two commits disagree about the wire.

    They would disagree quietly: the symptom is receipts refused on an envelope
    check nobody changed.  One build config naming both is what makes the pair
    a pair.
    """
    build = CLOUDBUILD.read_text(encoding="utf-8")
    assert "infra/docker/agent.Dockerfile" in build
    assert "infra/docker/control-plane.Dockerfile" in build
    assert build.count("${_IMAGE}") >= 2
    assert build.count("${_CONTROL_PLANE_IMAGE}") >= 2


def test_neither_image_resolves_the_kernel_from_an_index() -> None:
    """The kernel is a local wheel, and both images have to say so.

    ``pip install --prefix`` puts a distribution somewhere pip does not look
    when it resolves the next install, so an image that installed the kernel
    that way and then installed a distribution depending on it would go to PyPI
    for ``muster-kernel==0.1.0``, find nothing, and stop -- at build time, with
    the whole deployment behind it.
    """
    for image in (AGENT_IMAGE, CONTROL_PLANE_IMAGE):
        text = image.read_text(encoding="utf-8")
        executable = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        assert "pip wheel --no-deps --wheel-dir=/wheels ./packages/muster-kernel" in executable, (
            image.name
        )
        assert "--find-links=/wheels" in executable, image.name
