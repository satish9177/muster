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
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
CLOUD_HERO = REPOSITORY / "demo" / "cloud_hero.py"
CONTROL_PLANE_IMAGE = REPOSITORY / "infra" / "docker" / "control-plane.Dockerfile"
AGENT_IMAGE = REPOSITORY / "infra" / "docker" / "agent.Dockerfile"
CLOUDBUILD = REPOSITORY / "infra" / "cloudbuild.yaml"

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

    Including inside a function.  A deferred import is still an import, and the
    two places this module does defer one -- the SQL adapter and the in-memory
    one -- are control-plane adapters chosen by configuration.
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
