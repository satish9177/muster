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

U2 added a fourth, and it replaced a rule rather than joining it.  Before this
milestone the composition root could not reach the Action Gate *at all*, and
that was the honest statement of a system that had no deployed Gate.  It has
one now, so the checkable property changed shape: the Gate is reachable only
from the mode an operator names, ``run_cloud_hero`` itself cannot reach it, and
the idempotency read cannot reach a case command.  What did **not** change is
the vocabulary of settlement -- nothing here settles, disburses or pays out,
and those words are still absent.

The image is checked here too.  "The control plane has no model dependency" is
a claim about what is installed, and the Dockerfile is where that is decided.
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
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

#: Vocabulary for a capability this system still does not have.  The Gate
#: reserves, dispatches and records an outcome against a *synthetic* executor;
#: it does not settle, disburse or pay out anything, and it holds no spending
#: authority of its own.  The cheapest way to be sure of that is that the words
#: are absent.
#:
#: ``action_gate`` and ``gate_decision`` deliberately left this tuple at U2.
#: They named the milestone boundary rather than a dangerous capability, and a
#: composition root that composes a Gate has to be able to say so.
BEYOND_THIS_MILESTONE = (
    "settle",
    "settlement",
    "disburse",
    "disbursement",
    "payout",
    "spendinglimit",
    "spending_limit",
    "realfunds",
    "payment_provider",
    "paymentprovider",
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


def test_the_cloud_hero_settles_nothing_and_holds_no_spending_authority() -> None:
    """The Gate acts; it does not settle.

    Checked over *identifiers* -- what the module names, calls, imports and
    reads -- rather than over its text.  The docstring says out loud that no
    funds move, and a test that failed on the sentence describing the property
    would be a test nobody could satisfy while documenting it.
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


def _called_in(name: str) -> set[str]:
    """Every function ``name`` calls, by the identifier at the call site.

    Attribute calls are included as their attribute, so ``gate.execute(...)``
    contributes ``execute`` -- which is what makes the rules below able to say
    that a function never reaches a method as well as never reaching a helper.
    """
    for node in ast.walk(_tree()):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            called: set[str] = set()
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                match inner.func:
                    case ast.Name(id=identifier):
                        called.add(identifier)
                    case ast.Attribute(attr=attribute):
                        called.add(attribute)
                    case _:
                        continue
            return called
    raise AssertionError(f"{name} is gone from the cloud hero")


def test_the_acquisition_run_still_ends_at_the_case_read() -> None:
    """``run_cloud_hero`` is the analysis, and it is *only* the analysis.

    The Gate lives one level up, in ``main``, behind a mode.  This is what
    keeps that true rather than incidental: the function that drives the fleet
    ends at ``case_status``, and there is no call inside it -- not to a helper,
    not to a method -- that could reserve, dispatch or execute anything.
    """
    called = _called_in("run_cloud_hero")
    assert {"append_transcript_entry", "acquire_outstanding", "case_status"} <= called
    assert not {
        name
        for name in called
        if name in {"execute", "reserve", "begin_dispatch", "dispatch", "finalize"}
        or "gate" in name.lower()
    }


def test_the_action_gate_is_reached_only_from_the_named_mode() -> None:
    """Every call into the Gate sits under a test of ``gate_mode``.

    The property the whole U2 composition rests on: an operator who asked for
    an analysis cannot get an execution.  Read from the tree rather than from
    the configuration, because the configuration is the thing being trusted --
    what is checked here is that no *branch* reaches the Gate without first
    comparing the mode.

    Stated as "the enclosing statements include a comparison against
    ``HeroMode``", which is deliberately shape-independent: an ``if``, a match,
    a guard clause and an early return all satisfy it, and none of them can be
    satisfied by a call that is simply unconditional.
    """
    tree = _tree()
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def guarded_by_mode(node: ast.AST) -> bool:
        current: ast.AST | None = node
        while current is not None:
            for inner in ast.walk(current):
                if (
                    isinstance(inner, ast.Attribute)
                    and isinstance(inner.value, ast.Name)
                    and inner.value.id == "HeroMode"
                ):
                    return True
            current = parents.get(current)
        return False

    entries = {
        "execute_cloud_gate",
        "repeat_gate_execution",
        "verify_gate_idempotency",
    }
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in entries
    ]
    #  All three are called, and each call is under a mode comparison.
    assert {call.func.id for call in calls if isinstance(call.func, ast.Name)} == entries
    for call in calls:
        assert guarded_by_mode(call), ast.unparse(call)


def test_the_idempotency_read_reaches_no_case_command_and_no_dispatch() -> None:
    """The retry proof is a read, and this is what makes that checkable.

    Named function by function rather than by comment: the five control-plane
    commands, the case head's own reader and the executor boundary are all
    absent from the call graph of ``verify_gate_idempotency``.  A retry that
    could reach any of them would be a retry that could re-derive, re-admit,
    consult mutable case state, or pay -- and the claim the mode makes is
    precisely that it does none of those.

    ``read`` and ``reading`` are on this list now, and they were not before.
    That is the identity redesign: the retry used to open the database to read
    the durable head, and it no longer has any reason to, because the execution
    key names the row on its own.
    """
    called = _called_in("verify_gate_idempotency")
    forbidden = {
        "case_status",
        "append_transcript_entry",
        "acquire_outstanding",
        "open_case",
        "open_ravi",
        "publish_fleet",
        "run_cloud_hero",
        "cloud_case",
        "execute",
        "reserve",
        "begin_dispatch",
        "finalize",
        "dispatch",
        "hold",
        "read",
        "reading",
        "writing",
    }
    assert not (called & forbidden), sorted(called & forbidden)
    #  And what it *does* reach: the Gate's idempotency read, and nothing else
    #  that touches durable state.
    assert "read_authorized_execution" in called


def test_the_deployed_gate_never_takes_its_caller_from_configuration_alone() -> None:
    """The principal is observed.  Configuration only says which one is expected.

    ``MetadataServerPrincipal`` is constructed at the one place a Gate caller
    is resolved, and ``GateCaller`` is never constructed anywhere in this file:
    a composition root that built one from a string would be a composition root
    where a deployment variable, not the runtime, decided who was asking.
    """
    constructed = {
        node.func.id
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "MetadataServerPrincipal" in constructed
    assert "GateCaller" not in constructed


def test_the_principal_trace_is_two_closed_tokens_and_not_a_formatted_value() -> None:
    """The trace line says *where* the identity came from, and nothing else.

    Read as constants rather than as behaviour, because the risk is a later
    edit that made either half interpolated -- ``f"...source = {something}"``
    would be a line whose content depends on a runtime value, and the whole
    point of a content-free trace is that it cannot.

    ``METADATA_SERVER`` is the only source there is, and ``MATCHED`` is the only
    status ever printed, because every other outcome ends the run before a Gate
    exists.
    """
    literals = {
        node.value
        for node in ast.walk(_tree())
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "METADATA_SERVER" in literals
    assert "MATCHED" in literals

    text = CLOUD_HERO.read_text(encoding="utf-8")
    assert "gate.principal.source = {PRINCIPAL_SOURCE}" in text
    assert "gate.principal.status = {PRINCIPAL_STATUS_MATCHED}" in text


def test_the_cloud_executor_is_the_sandbox_one_and_is_named_as_such() -> None:
    """No payment provider is composable here, and the label is not decorative."""
    text = CLOUD_HERO.read_text(encoding="utf-8")
    assert "SANDBOX: NO REAL FUNDS TRANSFERRED" in text
    constructed = {
        node.func.id
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "SandboxPaymentExecutor" in constructed
    #  Both synthetic simulations are composable and neither is a payment rail;
    #  durable custody changes whether a later process can inspect the effect,
    #  never what kind of external system the Gate is allowed to reach.
    assert "DurableSandboxPaymentExecutor" in constructed
    #  The gate and executor identities are this composition's own, and not the
    #  local demo's.  A stored lifecycle names the gate that authorized it, so
    #  two compositions sharing one identity would be two trust boundaries
    #  answering to one name.
    assert 'CLOUD_GATE_ID = "cloud-action-gate/v1"' in text
    assert 'CLOUD_EXECUTOR_ID = "sandbox-payment-cloud/v1"' in text
    #  Over string *constants* rather than over the text, so the comment that
    #  explains why the local identity is not reused does not fail the rule it
    #  is explaining.
    literals = {
        node.value
        for node in ast.walk(_tree())
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "local-action-gate/v1" not in literals
    assert "sandbox-payment/v1" not in literals


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


def _sourcing(script: str, **environment: str) -> subprocess.CompletedProcess[str]:
    """Source ``env.sh`` in a real shell and run one snippet against it.

    A real shell rather than a regular expression, because the property under
    test is *what sourcing does* -- and "no ``exit`` at file scope" is a claim
    about execution that a text search can only approximate.

    ``bash`` is resolved rather than named, so this runs the interpreter on the
    PATH instead of trusting a partial executable path; the deployment scripts
    are checked for their ``bash`` shebang elsewhere.
    """
    shell = shutil.which("bash")
    if shell is None:
        pytest.skip("this asserts what sourcing env.sh does, which needs a shell")
    return subprocess.run(  # noqa: S603 - a resolved interpreter and a fixed argv
        [shell, "-c", script, "bash", str(ENVIRONMENT)],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            #  Set so env.sh does not ask gcloud for a project it has no
            #  business asking about from a unit test.
            "PROJECT_ID": "muster-architecture-test",
            **environment,
        },
    )


def _shell_function(text: str, name: str) -> str:
    """The body of one shell function, from its header to its closing brace.

    Deliberately literal: the closing brace of a top-level function in these
    scripts is a ``}`` in column zero, and nothing else in them is.  A test that
    searched the whole file instead would be unable to say *where* a refusal
    lives, which is the only thing the callers of this helper are asking.
    """
    opening = f"{name}() {{"
    start = text.index(opening)
    end = text.index("\n}", start)
    return text[start:end]


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


def test_the_gate_mode_defaults_to_the_analysis_and_is_a_closed_set() -> None:
    """An operator who names nothing gets the run U1 verified."""
    environment = _uncommented(ENVIRONMENT)
    assert "HERO_GATE_MODE:=ANALYSIS_ONLY" in environment
    assert "ANALYSIS_ONLY|CLOUD_SQL_ACTION_GATE_SANDBOX)" in environment


def test_the_gate_mode_cannot_run_against_the_analysis_only_case() -> None:
    """U1's case is published evidence, and the deployment refuses to touch it.

    Two halves, and both are needed.  The Gate's configuration check refuses a
    configuration where the two case names are equal, and the deployment writes
    the *derived* name into the container -- so there is no way to ask for the
    Gate and have it act on the case whose rows a previous milestone already
    published.
    """
    environment = _uncommented(ENVIRONMENT)
    assert "HERO_GATE_CASE_ID:=CASE-RAVI-SAT-CLOUD-GATE" in environment
    assert '[[ "${HERO_GATE_CASE_ID}" == "${HERO_CASE_ID}" ]]' in environment

    executable = _uncommented(HERO_DEPLOYMENT)
    assert 'muster::env_entry MUSTER_HERO_CASE "${HERO_RUN_CASE_ID}"' in executable
    assert 'muster::env_entry MUSTER_HERO_CASE "${HERO_CASE_ID}"' not in executable


def test_the_gate_rules_are_enforced_by_a_function_and_not_by_sourcing() -> None:
    """The refusals live inside ``muster::require_gate_configuration``.

    Read structurally rather than by eye: every ``exit`` in env.sh is located,
    and the Gate-specific ones must not be among them -- because an ``exit`` at
    file scope in a sourced file kills the *caller*, and the caller is often a
    script with no Gate in it at all.

    The function itself is asserted to exist and to ``return`` rather than
    ``exit``, which is what lets a caller decide what a refused Gate
    configuration means for the rest of what it was doing.
    """
    environment = _uncommented(ENVIRONMENT)
    body = _shell_function(environment, "muster::require_gate_configuration")

    for refusal in (
        '[[ "${HERO_GATE_CASE_ID}" == "${HERO_CASE_ID}" ]]',
        "ANALYSIS_ONLY|CLOUD_SQL_ACTION_GATE_SANDBOX)",
    ):
        assert refusal in body, refusal
        #  And exactly once in the whole file: a second copy at file scope is
        #  precisely the coupling this test exists to forbid.
        assert environment.count(refusal) == 1, refusal

    assert "return 2" in body
    assert "exit 2" not in body


def test_an_unrelated_env_consumer_is_not_coupled_to_the_gate_check() -> None:
    """Sourcing env.sh with a colliding Gate case is not an error.

    The scenario is a real one: an operator who exported HERO_GATE_CASE_ID to
    match HERO_CASE_ID, and then ran a teardown.  Under the previous shape that
    teardown refused -- it sourced a file that called ``exit`` over a
    relationship between two case identifiers it does not use.

    Run as a real shell, against the real file, with the collision in place.
    The source must succeed, the derived run case must still be the analysis
    one, and calling the Gate's own check must then refuse with status 2.  A
    ``grep`` for ``exit`` would not say any of that.
    """
    script = (
        'set -euo pipefail\n'
        'source "$1"\n'
        'echo "sourced=${HERO_RUN_CASE_ID}"\n'
        'if muster::require_gate_configuration; then\n'
        '  echo "gate=accepted"\n'
        'else\n'
        '  echo "gate=refused-$?"\n'
        'fi\n'
    )
    collided = _sourcing(
        script,
        HERO_CASE_ID="CASE-COLLIDING",
        HERO_GATE_CASE_ID="CASE-COLLIDING",
        HERO_GATE_MODE="CLOUD_SQL_ACTION_GATE_SANDBOX",
    )

    assert collided.returncode == 0, collided.stderr
    #  Sourcing succeeded, and the analysis-only case is what was derived.
    assert "sourced=CASE-COLLIDING" in collided.stdout
    #  And the Gate's own check is the thing that refuses.
    assert "gate=refused-2" in collided.stdout
    assert "name one case" in collided.stderr


def test_the_gate_check_accepts_a_configuration_that_names_two_cases() -> None:
    """The other direction, so the test above is not passing vacuously."""
    script = (
        'set -euo pipefail\n'
        'source "$1"\n'
        'muster::require_gate_configuration\n'
        'echo "run=${HERO_RUN_CASE_ID}"\n'
    )
    accepted = _sourcing(
        script,
        HERO_CASE_ID="CASE-ANALYSIS",
        HERO_GATE_CASE_ID="CASE-GATE",
        HERO_GATE_MODE="CLOUD_SQL_ACTION_GATE_SANDBOX",
    )

    assert accepted.returncode == 0, accepted.stderr
    assert "run=CASE-GATE" in accepted.stdout


def test_the_deployment_that_wants_the_gate_calls_the_check() -> None:
    """A refusal nobody calls is not a refusal.

    Stage 90 is the script that asks for cloud execution, so it is the one that
    has to run the check -- and it has to run it before it writes the container
    environment, or a refused configuration would already have been deployed.
    """
    executable = _uncommented(HERO_DEPLOYMENT)
    assert "muster::require_gate_configuration || exit 2" in executable
    assert executable.index("muster::require_gate_configuration") < executable.index(
        'muster::env_entry MUSTER_HERO_GATE_MODE'
    )


def test_the_deployment_refuses_a_gate_mode_over_ephemeral_custody() -> None:
    """Checked before the deploy, because a refusal from inside costs a run."""
    executable = _uncommented(HERO_DEPLOYMENT)
    assert 'muster::env_entry MUSTER_HERO_GATE_MODE "${HERO_GATE_MODE}"' in executable
    assert 'muster::env_entry MUSTER_HERO_GATE_PRINCIPAL "${HERO_GATE_PRINCIPAL}"' in executable
    assert '"${HERO_DATABASE_DEPLOYMENT}" != "CLOUD_SQL"' in executable


def test_the_retry_execution_names_the_flag_and_not_the_script() -> None:
    """The image already names the script, so the override must not.

    ``--args`` replaces the container's *args*, which Cloud Run appends to the
    ENTRYPOINT.  The control-plane image entrypoints on
    ``python /app/demo/cloud_hero.py``, so an override that repeated the path
    would run the script with its own filename as the first positional
    argument -- a failure that deploys cleanly, executes, and dies in front of
    a cloud.  Its sibling in 85-database-bootstrap.sh legitimately names the
    path *and* overrides ``--command``; this one does neither.
    """
    executable = _uncommented(HERO_DEPLOYMENT)
    image = CONTROL_PLANE_IMAGE.read_text(encoding="utf-8")

    assert 'ENTRYPOINT ["python", "/app/demo/cloud_hero.py"]' in image
    assert '--args="--verify-gate-idempotency"' in executable
    assert "--args=/app/demo/cloud_hero.py" not in executable
    assert '--args="/app/demo/cloud_hero.py' not in executable


def test_the_retry_proof_is_a_second_execution_of_the_same_deployed_job() -> None:
    """A different process, not a different code path.

    The claim the mode makes is that a *second Cloud Run execution* can read
    what the first one recorded.  Running it in-process, or as a second job
    built differently, would be a claim about something else.
    """
    executable = _uncommented(HERO_DEPLOYMENT)
    assert 'muster::execute_job "${HERO_JOB}" --args="--verify-gate-idempotency"' in executable
    #  And the identity it names is the execution key the deploy just wrote, so
    #  the retry identifies one durable execution rather than a case, a
    #  proposal, or whatever the head currently says.
    assert (
        'muster::env_entry MUSTER_HERO_GATE_EXECUTION_ID "${HERO_GATE_EXECUTION_ID}"'
        in executable
    )
    assert '-z "${HERO_GATE_EXECUTION_ID}"' in executable


def test_the_retry_identity_is_the_execution_key_and_not_the_case_head() -> None:
    """The redesign, checked where it could silently regress.

    ``verify_gate_idempotency`` must build its ``ExecutionLookup`` from the
    configured execution key and nothing else.  A version that read the durable
    head to fill in a revision, a certificate or a pin would work perfectly --
    right up until somebody appended one transcript entry, at which point a
    confirmed payment would report as absent.

    Read off the call itself: the keywords the lookup is constructed with are
    exactly the two ``ExecutionLookup`` has, and neither of them is a digest
    taken from a head.
    """
    for node in ast.walk(_tree()):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ExecutionLookup"
        ):
            continue
        keywords = {keyword.arg for keyword in node.keywords}
        assert keywords == {"execution_key", "expected_case_id"}, sorted(
            name for name in keywords if name
        )
        break
    else:
        raise AssertionError("the cloud hero builds no ExecutionLookup")

    #  And the head repository's own reader is absent from the call graph.
    #  ``read_authorized_execution`` is the Gate's, and is what this path is
    #  allowed to reach; a bare ``read`` here would be ``scope.heads.read``.
    assert "read" not in _called_in("verify_gate_idempotency")


def test_the_gate_principal_is_the_control_plane_service_account() -> None:
    """The grant names one identity, and it is the one the job runs as."""
    environment = _uncommented(ENVIRONMENT)
    assert "HERO_GATE_PRINCIPAL:=${CONTROL_PLANE_SA}" in environment


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


#  ---- the retry proof is what the retry printed --------------------------


#: The exact line Stage 90 is allowed to print about duplicate prevention.
#: Nothing else in the branch makes that claim, so its presence or absence is
#: the whole assertion below.
_PROOF_LINE = "the durable execution was already CONFIRMED, and nothing was dispatched"


def _idempotency_branch() -> str:
    """The Stage-90 block that runs the retry, lifted verbatim from the script.

    Read out of the deployment rather than restated here, so this cannot go on
    passing against a copy of a branch the script no longer has.  The block is
    a top-level ``if``: every ``fi`` inside it is indented, and the one that
    closes it is the first at column zero.

    Anchored on the banner rather than on the mode test, because an earlier
    top-level block tests the same variable to refuse a misconfigured retry
    before anything is deployed.  That one is a precondition; this one is the
    run, and taking the first match would have tested the wrong block.
    """
    text = HERO_DEPLOYMENT.read_text(encoding="utf-8")
    opening = 'if [[ "${HERO_VERIFY_GATE_IDEMPOTENCY:-0}" == "1" ]]; then'
    banner = text.index('muster::banner "verifying gate idempotency')
    start = text.rindex(opening, 0, banner)
    end = text.index("\nfi\n", start)
    return text[start : end + len("\nfi\n")]


def _environment_custody() -> str:
    """``env.sh``'s real temporary-directory custody, lifted rather than imitated.

    ``muster::env_file`` makes a 0700 directory for the job's env-vars file and
    installs ``muster::env_cleanup`` on EXIT to remove it however the script
    ends.  Both functions come out of ``env.sh`` verbatim and are called the way
    Stage 90 calls them, because the defect these harnesses exist for is a
    *second* EXIT trap silently replacing that one -- and a stubbed cleanup
    would only have proved that the stub was reachable, which is not the claim.
    """
    text = ENVIRONMENT.read_text(encoding="utf-8")
    return "\n".join(
        (
            'MUSTER_ENV_DIR=""',
            'MUSTER_ENV_FILE=""',
            _shell_function(text, "muster::env_cleanup") + "\n}",
            _shell_function(text, "muster::env_file") + "\n}",
            'muster::env_file "${HERO_JOB}"',
            'printf "DATABASE_DSN: a pinned secret reference\n" > "${MUSTER_ENV_FILE}"',
        )
    )


def _sandboxed(inner: str) -> str:
    """Run ``inner`` with every temporary path confined to one directory.

    The block runs in a subshell so that its EXIT traps fire while this script
    is still alive to look at what they left behind.  "The branch cleaned up
    after itself" is a statement about the sandbox *after* the traps ran, and
    there is no way to ask it from inside the process whose exit is running
    them.

    Two lines are printed for the caller to read back: the subshell's exit
    status, which this script then exits with, and whatever survived.
    """
    return "\n".join(
        (
            "set -uo pipefail",
            'sandbox="$(mktemp -d "${TMPDIR:-/tmp}/muster-cleanup.XXXXXX")"',
            'export TMPDIR="${sandbox}"',
            "(",
            inner,
            ")",
            "code=$?",
            'echo "EXIT_CODE=${code}"',
            'echo "SURVIVORS=[$(ls -A "${sandbox}" 2>/dev/null | sort | tr "\n" " ")]"',
            'rm -rf "${sandbox}"',
            'exit "${code}"',
        )
    )


def _run_shell(script: str, **environment: str) -> subprocess.CompletedProcess[str]:
    shell = shutil.which("bash")
    if shell is None:
        pytest.skip("this asserts what a deployment branch does, which needs a shell")
    return subprocess.run(  # noqa: S603 - a resolved interpreter and a fixed argv
        [shell, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "PROJECT_ID": "muster-architecture-test",
            "REGION": "asia-south1",
            "CONTROL_PLANE_SA": "muster-control-plane@muster-test.iam.gserviceaccount.com",
            **environment,
        },
    )


def _survivors(run: subprocess.CompletedProcess[str]) -> list[str]:
    """What was still in the sandbox once the subshell's traps had run."""
    for line in run.stdout.splitlines():
        if line.startswith("SURVIVORS=["):
            return line[len("SURVIVORS=[") : line.rindex("]")].split()
    raise AssertionError(f"the harness printed no survivors:\n{run.stdout}\n{run.stderr}")


def _retry(*, status: int, readable: bool) -> subprocess.CompletedProcess[str]:
    """Run that block in a real shell against a stubbed Cloud Run.

    The two things it depends on are stubbed and nothing else is: whether the
    execution succeeded, and whether that execution's own output could be read
    back.  Those are the only two facts the proof rests on, and the point of
    running the real block is that the *combination* of them is what decides
    the exit status -- which no amount of reading the file can establish.

    ``env.sh``'s real temp-directory custody is installed first, exactly as the
    deployment installs it, so the branch runs against the EXIT trap it is at
    risk of replacing rather than against no trap at all.
    """
    inner = "\n".join(
        (
            "set -uo pipefail",
            "HERO_JOB=muster-control-plane-hero",
            "HERO_VERIFY_GATE_IDEMPOTENCY=1",
            _environment_custody(),
            "muster::banner() { :; }",
            'muster::execute_job() { MUSTER_EXECUTION="exec-1"; return "${STUB_STATUS}"; }',
            "muster::execution_output() {",
            '  if [[ "${STUB_READABLE}" == "1" ]]; then',
            "    printf 'state CONFIRMED\ndispatches this run 0\n'",
            "    return 0",
            "  fi",
            "  return 1",
            "}",
            _idempotency_branch(),
            'echo "FELL_THROUGH"',
        )
    )
    return _run_shell(
        _sandboxed(inner),
        STUB_STATUS=str(status),
        STUB_READABLE="1" if readable else "0",
    )

def test_the_retry_proves_idempotency_only_when_it_could_read_what_it_printed() -> None:
    """Succeeded *and* readable.  Both, or there is no proof to report."""
    proved = _retry(status=0, readable=True)

    assert proved.returncode == 0, proved.stderr
    assert _PROOF_LINE in proved.stdout
    assert "state CONFIRMED" in proved.stdout
    assert "FELL_THROUGH" not in proved.stdout


def test_a_succeeded_retry_whose_output_is_unreadable_is_undetermined() -> None:
    """The correction this test exists for.

    A Cloud Run execution that exited zero and left no readable output has told
    us that a process ended well.  It has not told us that a durable CONFIRMED
    row was read, and it has not told us that nothing was dispatched -- those
    live in the output, and the output is gone.  Printing the proof line off
    the exit status alone would be the demo asserting the one thing this stage
    exists to demonstrate.

    Exit 4 rather than 1: the same undetermined class the evidence path uses,
    because "we do not know" and "it said no" are different facts about a run.
    """
    undetermined = _retry(status=0, readable=False)

    assert undetermined.returncode == 4
    assert _PROOF_LINE not in undetermined.stdout
    assert _PROOF_LINE not in undetermined.stderr
    assert "FELL_THROUGH" not in undetermined.stdout


@pytest.mark.parametrize("readable", [True, False])
def test_a_failed_retry_reports_the_failure_and_claims_nothing(readable: bool) -> None:
    """A task that failed is a verdict, and it is not this one."""
    failed = _retry(status=1, readable=readable)

    assert failed.returncode == 1
    assert _PROOF_LINE not in failed.stdout
    assert "not established" in failed.stderr


def test_a_retry_that_never_completed_is_undetermined_rather_than_negative() -> None:
    """``muster::execute_job`` returns 2 for "we do not know", and so does this."""
    unknown = _retry(status=2, readable=False)

    assert unknown.returncode == 4
    assert _PROOF_LINE not in unknown.stdout
    assert "no verdict" in unknown.stderr


def test_the_retry_branch_does_not_discard_the_output_read() -> None:
    """``|| true`` on the evidence read is what the behaviour above forbids.

    Kept as a separate, literal check because the failure it guards against is
    a one-token edit that the stubbed run would still catch, and this says
    plainly which token.
    """
    branch = _idempotency_branch()
    assert "muster::execution_output" in branch
    assert "|| true" not in branch


#  ---- one EXIT trap, and everything it replaced -------------------------
#
#  ``muster::env_file`` makes a 0700 directory outside the repository for the
#  environment Cloud Run is handed, and installs ``muster::env_cleanup`` on EXIT
#  so it is removed however the script ends.  Stage 90 then installs its own
#  EXIT trap for a log temporary file, and bash keeps exactly one: the second
#  ``trap ... EXIT`` disarms the first.  The directory survived every run, which
#  is precisely what env.sh's own note says does not happen.
#
#  The tests below run the real branches and look at what they left, rather than
#  reading the trap lines, because "this handler does everything the one it
#  replaced did" is a claim about a process that has already exited.


def _log_custody(name: str) -> str:
    """The ``mktemp`` and its ``trap``, as one pair, out of the deployment.

    Lifted rather than restated for the same reason the idempotency branch is:
    a test carrying its own copy of a trap line goes on passing against a script
    that no longer has it.
    """
    text = HERO_DEPLOYMENT.read_text(encoding="utf-8")
    start = text.index(f'{name}="$(mktemp ')
    end = text.index("\n", text.index("trap ", start))
    return text[start:end]


def _exit_traps() -> list[str]:
    text = HERO_DEPLOYMENT.read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip().startswith("trap ")]


@pytest.mark.parametrize(
    ("status", "readable", "expected"),
    [(0, True, 0), (0, False, 4), (1, True, 1), (2, False, 4)],
)
def test_the_retry_branch_leaves_neither_its_log_nor_the_environment(
    status: int, readable: bool, expected: int
) -> None:
    """Every way out of the retry branch, including the ones that refuse.

    A cleanup that ran only on the happy path would be worse than none: the
    runs that leave the environment directory behind would be exactly the runs
    an operator repeats.
    """
    run = _retry(status=status, readable=readable)

    assert run.returncode == expected, run.stderr
    assert _survivors(run) == [], run.stdout


def test_the_evidence_path_leaves_neither_its_log_nor_the_environment() -> None:
    """The same claim about the normal Stage-90 run.

    This trap predates the retry branch and had the same defect.  Fixing only
    the newer one would have left the leak on the path every hero run takes.
    """
    inner = "\n".join(
        (
            "set -uo pipefail",
            "HERO_JOB=muster-control-plane-hero",
            _environment_custody(),
            _log_custody("trace_logs"),
            'printf "captured\n" > "${trace_logs}"',
            "exit 4",
        )
    )
    run = _run_shell(_sandboxed(inner))

    assert run.returncode == 4, run.stderr
    assert _survivors(run) == [], run.stdout


def test_the_environment_directory_is_what_would_have_survived() -> None:
    """The leak itself, so these tests are known to be able to see one.

    The same harness with the trap the deployment used to carry -- a bare
    ``rm -f`` on the log file -- and the directory holding the job's environment
    is still there when the subshell has finished exiting.  Without this, four
    passing cleanup tests would be equally consistent with a sandbox that never
    had anything in it.
    """
    inner = "\n".join(
        (
            "set -uo pipefail",
            "HERO_JOB=muster-control-plane-hero",
            _environment_custody(),
            'trace_logs="$(mktemp "${TMPDIR:-/tmp}/muster-case-trace.XXXXXX")"',
            "trap 'rm -f \"${trace_logs}\"' EXIT",
            "exit 4",
        )
    )
    run = _run_shell(_sandboxed(inner))

    assert run.returncode == 4, run.stderr
    assert [name.split(".")[0] for name in _survivors(run)] == ["muster-env"]


def test_no_exit_trap_in_the_deployment_disarms_the_environment_cleanup() -> None:
    """Said literally as well, because the fix is one token per trap.

    The behavioural tests above cover the two traps this script has today.  This
    one covers the third somebody adds.
    """
    traps = _exit_traps()
    assert traps, "the deployment installs no EXIT trap at all"
    for trap in traps:
        assert trap.endswith("EXIT"), trap
        assert "muster::env_cleanup" in trap, trap


def test_the_environment_cleanup_is_safe_to_run_more_than_once() -> None:
    """Which is what chaining it onto a second trap asks of it.

    ``muster::env_file``'s INT and TERM handlers call it and then ``exit``,
    which runs the EXIT trap -- and that now calls it again.  It must not fail
    the second time, under ``set -u``, with the directory already gone.
    """
    inner = "\n".join(
        (
            "set -euo pipefail",
            "HERO_JOB=muster-control-plane-hero",
            _environment_custody(),
            "muster::env_cleanup",
            "muster::env_cleanup",
            'echo "TWICE_OK"',
        )
    )
    run = _run_shell(_sandboxed(inner))

    assert run.returncode == 0, run.stderr
    assert "TWICE_OK" in run.stdout
    assert _survivors(run) == [], run.stdout
