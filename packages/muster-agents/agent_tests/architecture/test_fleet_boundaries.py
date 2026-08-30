"""What the agent fleet may reach, and what nothing may reach into it.

``import-linter`` enforces an overlapping set of rules from its own graph.
This module is deliberately a second, independent implementation: it parses
every production file with ``ast`` and answers questions a configuration cannot
express -- that the model appears in exactly the modules named for it, that the
control plane's semantic path holds no media type, that a confidence figure has
nowhere to become a truth, and that there are three agent profiles rather than
four.

Two of the rules here span distributions and are checked from this side because
this is the side that would break them: the kernel must stay free of a model,
and the control plane must stay free of an agent framework.  The other files'
suites check the same edges from theirs, and a defect in one graph does not
disable both.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
AGENTS = REPOSITORY / "packages" / "muster-agents" / "src" / "muster" / "agents"
KERNEL = REPOSITORY / "packages" / "muster-kernel" / "src" / "muster"
PLATFORM = REPOSITORY / "packages" / "muster-platform" / "src" / "muster" / "platform"

#: Where a model client, an agent framework or a cloud client may be imported.
#: Anything else reaching one is a second place a model could be called or
#: private material could be read, and both are the sort of thing that appears
#: by accident and stays.
MODEL_MODULES = frozenset(
    {
        "google.models",
        "google.storage",
        "profiles",
        "runtime.agent",
        "runtime.claimant",
        "runtime.interpret",
        "transport.identity",
    }
)

#: The one module allowed to hold a signing primitive.  A source key lives with
#: the source; a second module able to sign would be a second custody story.
SIGNING_MODULE = "keys"

#: The kernel seams an agent may see: the wire contract, and nothing above it.
PERMITTED_KERNEL_SEAMS = frozenset(
    {
        "muster.core.results",
        "muster.core.wire",
        "muster.core.values",
        "muster.core.expr",
        "muster.core.evidence",
        "muster.core.authority.scope",
        "muster.core.authority.signing",
    }
)

#: Vocabulary that must not appear as a declaration anywhere in the fleet.
#: The gate and settlement belong to a later milestone; a confidence field
#: belongs to no milestone at all.
FORBIDDEN_DECLARATIONS = (
    "authorizedaction",
    "gatedecision",
    "spendinglimit",
    "finality",
    "disbursement",
    "payout",
    "settlement",
    "actiongate",
    #  A number a model produces about its own output is not evidence about the
    #  world.  A field carrying one becomes a threshold, and a threshold
    #  becomes a truth.
    "confidence",
    "certainty",
    "probability",
    "score",
)

FORBIDDEN_TEXT = ("phase 0", "phase0", "phase 1", "phase1",  "blocker")


def _files(root: Path) -> Iterator[Path]:
    yield from sorted(root.rglob("*.py"))


def _module_of(path: Path, root: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    parts = [part for part in relative.parts if part != "__init__"]
    return ".".join(parts)


def _imports(path: Path) -> Iterator[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                pytest.fail(f"{path}: relative import at line {node.lineno}")
            if node.module:
                yield node.module


def _declared(path: Path) -> Iterator[str]:
    """Every name this module *declares*, and no local variable.

    Walking the whole tree would pick up annotated locals -- a dictionary
    called ``by_agent`` inside a function is not a component named "agent" --
    so declarations are read at module and class scope, which is where a name
    that describes the system lives.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bodies: list[list[ast.stmt]] = [tree.body]
    while bodies:
        for node in bodies.pop():
            if isinstance(node, ast.ClassDef):
                yield node.name
                bodies.append(node.body)
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                yield node.name
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                yield node.target.id


def _words(name: str) -> set[str]:
    """A declaration split into words, so ``preimage`` does not contain "image".

    A substring scan over identifiers reads ``preimage`` as a picture and
    ``scored`` as a confidence, and the false positives are exactly the ones
    that make somebody delete the rule.
    """
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return {word.lower() for word in spaced.split("_") if word}


#  ---- the tree is real ----------------------------------------------------


def test_the_fleet_tree_is_not_empty() -> None:
    """A scan that finds nothing would pass every check below."""
    assert len(list(_files(AGENTS))) > 15


#  ---- across the distributions --------------------------------------------


def test_the_kernel_imports_no_model_or_agent_framework() -> None:
    """The deterministic subsystem stays offline, and this is checked from here.

    The kernel's own suite bans the package roots; this one bans them from the
    side that would introduce them, and names the framework specifically --
    because the way a model gets into a kernel is somebody putting a helper
    "just for the agents" in ``core``.
    """
    for path in _files(KERNEL):
        for imported in _imports(path):
            root = imported.split(".")[0]
            assert root not in {"google", "openai", "anthropic"}, f"{path} imports {imported}"


def test_the_control_plane_imports_no_agent_framework() -> None:
    """No ADK and no model client in the process holding the case record.

    Checkable with ``pip show`` as well, which is the stronger form: the
    control-plane distribution does not depend on either, so this is the
    belt to that pair of braces.
    """
    for path in _files(PLATFORM):
        for imported in _imports(path):
            root = imported.split(".")[0]
            assert root not in {"google", "openai", "anthropic"}, f"{path} imports {imported}"


def test_the_fleet_never_imports_the_control_plane() -> None:
    """An agent holds a model client.  A path from it to the control plane
    would put one in reach of the case salt and a database connection."""
    for path in _files(AGENTS):
        for imported in _imports(path):
            assert not imported.startswith("muster.platform"), f"{path} imports {imported}"


def test_the_fleet_sees_the_wire_seam_of_the_kernel_and_no_more() -> None:
    """An agent has never heard of a policy, a solver or a case revision.

    A source that could read the pinned bundle could read the rule its own
    answer feeds, which is the shortest path from "interprets its own material"
    to "knows which answer would help".
    """
    for path in _files(AGENTS):
        for imported in _imports(path):
            if not imported.startswith("muster.") or imported.startswith("muster.agents"):
                continue
            assert any(
                imported == seam or imported.startswith(f"{seam}.")
                for seam in PERMITTED_KERNEL_SEAMS
            ), f"{_module_of(path, AGENTS)} imports {imported}"


#  ---- inside the fleet ----------------------------------------------------


def test_a_model_or_cloud_client_appears_only_where_it_is_declared() -> None:
    """And that each named module really does reach one.

    Both halves matter: a module reaching a client without being listed fails,
    and a listed module that stopped reaching one leaves an exemption behind
    that would quietly cover the next thing added there.
    """
    reached: set[str] = set()
    for path in _files(AGENTS):
        module = _module_of(path, AGENTS)
        for imported in _imports(path):
            if imported.split(".")[0] != "google":
                continue
            assert module in MODEL_MODULES, f"{module} imports {imported}"
            reached.add(module)
    assert reached == MODEL_MODULES, sorted(MODEL_MODULES ^ reached)


def test_the_signing_primitive_appears_in_exactly_one_module() -> None:
    reached: set[str] = set()
    for path in _files(AGENTS):
        module = _module_of(path, AGENTS)
        for imported in _imports(path):
            if imported.split(".")[0] != "cryptography":
                continue
            assert module == SIGNING_MODULE, f"{module} imports {imported}"
            reached.add(module)
    assert reached == {SIGNING_MODULE}


#  ---- WORKER_MODEL_CANNOT_CREATE_SITE_FACT --------------------------------


def test_the_worker_runtime_cannot_reach_evidence_authority_or_consequence_paths() -> None:
    """The property the worker agent exists to have, as an absence.

    Not a flag on a shared builder: a single ``build_agent`` with a
    ``claims_only`` boolean would make this a property of a branch, and a
    branch is something a later edit gets wrong.

    The import check below is over *direct* edges, which is all an import graph
    can honestly claim here -- the claim runtime reaches the shared wire seam
    through the interpreter's limits, and the wire seam reaches a coordinate
    type. So the substantive property is checked over the types as well, in the
    two tests below: no signer field, and no payload vocabulary.
    """
    forbidden = (
        "muster.agents.runtime.receipts",
        "muster.agents.runtime.agent",
        "muster.agents.sources",
        "muster.agents.keys",
        "muster.core.authority.check",
        "muster.core.authority.signing",
        "muster.core.evidence.signing",
        "muster.hinge",
        "muster.platform",
    )
    for name in ("runtime/claims.py", "runtime/claimant.py"):
        for imported in _imports(AGENTS / name):
            assert not imported.startswith(forbidden), f"{name} imports {imported}"


def test_the_worker_agent_holds_no_signer() -> None:
    """The absence that makes the import rule more than a filing convention.

    An acquisition agent has eight fields and one of them is a ``SourceSigner``.
    A claim agent has three, and none of them can sign anything.
    """
    from muster.agents.runtime.agent import AcquisitionAgent
    from muster.agents.runtime.claimant import ClaimAgent

    assert "signer" in AcquisitionAgent.__dataclass_fields__
    assert set(ClaimAgent.__dataclass_fields__) == {"model", "clock", "limits"}


def test_the_claim_modules_name_no_attestation_vocabulary() -> None:
    """Checked over the source, because a name is how a path starts.

    A claim module that mentioned an acquisition payload, a receipt or a
    signing preimage would be one edit from producing one, whatever the import
    graph said at that moment.
    """
    forbidden = (
        "AcquisitionPayload",
        "VerificationReceipt",
        "AttestationPreimage",
        "attestation_preimage",
        "SourceSigner",
    )
    for name in ("runtime/claims.py", "runtime/claimant.py"):
        text = (AGENTS / name).read_text(encoding="utf-8")
        for word in forbidden:
            assert word not in text, f"{name} names {word}"


def test_the_transport_cannot_reach_a_signing_path() -> None:
    """Network identity and source authority are two questions, in two places."""
    for name in ("transport/identity.py", "transport/service.py", "transport/inprocess.py"):
        for imported in _imports(AGENTS / name):
            assert "keys" not in imported.split(".")[-1], f"{name} imports {imported}"
            assert not imported.endswith("runtime.receipts"), f"{name} imports {imported}"


def test_the_evidence_store_port_is_the_only_way_to_reach_material() -> None:
    """One module opens files and one opens a bucket, and both satisfy the port.

    Anything else reading source material would be a second place private
    evidence could be loaded, outside the boundary the port draws.
    """
    readers: set[str] = set()
    for path in _files(AGENTS):
        module = _module_of(path, AGENTS)
        text = path.read_text(encoding="utf-8")
        if "read_bytes(" in text or "download_as_bytes(" in text or "read_text(" in text:
            readers.add(module)
    assert readers <= {"sources.local", "google.storage", "entrypoints.serve"}, sorted(readers)


#  ---- exactly three agents ------------------------------------------------


def test_there_are_exactly_three_agent_profiles() -> None:
    """Three, and no deterministic component promoted to a fourth.

    The hinge, the planner, the authority check, the catalog and the dispatcher
    are deterministic components; naming any of them an agent would inflate the
    count and describe the system wrongly.
    """
    declared = set(_declared(AGENTS / "profiles" / "__init__.py"))
    factories = {name for name in declared if name.endswith("_agent")}
    assert factories == {"site_agent", "employer_agent", "worker_agent"}, sorted(factories)


#: Names that would make a deterministic component *be* an agent.  A catalog
#: record ``AgentProfile`` is a routing fact about one and is legitimate; a
#: class called ``AgentRuntime`` in the control plane is a fourth agent, and
#: the difference is whether the name describes a thing that runs.
AGENT_SHAPED = ("agentruntime", "agentsession", "agentclient", "agentdispatcher")


def test_no_deterministic_component_is_named_an_agent() -> None:
    """The count stays three because nothing deterministic is called one.

    The kernel legitimately declares ``AgentProfile`` and its catalog
    siblings -- those are *records about* agents, published by the control
    plane, and naming them is the whole point of a fleet catalog.  What must
    not appear is a deterministic component that reads as an agent itself.
    """
    for root, name in ((KERNEL, "kernel"), (PLATFORM, "platform")):
        for path in _files(root):
            for declaration in _declared(path):
                lowered = declaration.lower()
                assert not lowered.endswith("agent"), f"{name}: {path.name} -> {declaration}"
                for shape in AGENT_SHAPED:
                    assert shape not in lowered, f"{name}: {path.name} -> {declaration}"


#  ---- what must not be here at all ----------------------------------------


def test_no_gate_or_settlement_concept_is_declared_in_the_fleet() -> None:
    for path in _files(AGENTS):
        for declaration in _declared(path):
            words = _words(declaration)
            for fragment in FORBIDDEN_DECLARATIONS:
                assert fragment not in words, f"{path.name} declares {declaration}"


def test_no_model_confidence_can_become_a_truth() -> None:
    """There is no field for one, in the fleet or in the wire contract.

    The strongest form the rule takes: a number a model produced about its own
    output cannot be converted into authority, because there is nowhere to put
    it on the way through.
    """
    for root in (AGENTS, KERNEL / "core" / "evidence"):
        for path in _files(root):
            for declaration in _declared(path):
                assert "confidence" not in _words(declaration), (
                    f"{path.name} declares {declaration}"
                )


def test_no_raw_media_type_reaches_the_control_plane() -> None:
    """The control plane's vocabulary has no word for a picture.

    Checked over declarations rather than over prose: a docstring may say
    "photograph", and a field may not.
    """
    forbidden = ("image", "clip", "frame", "footage", "media", "photograph", "footage")
    for path in _files(PLATFORM):
        for declaration in _declared(path):
            words = _words(declaration)
            for fragment in forbidden:
                assert fragment not in words, f"{path.name} declares {declaration}"


def test_production_vocabulary_carries_no_phase_or_tool_names() -> None:
    for path in _files(AGENTS):
        haystack = f"{path.name}\n{path.read_text(encoding='utf-8')}".lower()
        for fragment in FORBIDDEN_TEXT:
            assert fragment not in haystack, f"{path} mentions {fragment!r}"


def test_no_type_ignore_is_used_to_reach_a_green_typecheck() -> None:
    """Strict typing is worth nothing if it is silenced where it bites."""
    for path in _files(AGENTS):
        assert "type: ignore" not in path.read_text(encoding="utf-8"), path


def test_the_fleet_declares_the_dependencies_it_actually_has() -> None:
    """A dependency here is an architectural decision, not a convenience.

    In particular: the control plane is **not** among them, and a diff that
    added it would have to say so in the distribution's own metadata.
    """
    import tomllib

    manifest = tomllib.loads(
        (REPOSITORY / "packages" / "muster-agents" / "pyproject.toml").read_text(encoding="utf-8")
    )
    required = manifest["project"]["dependencies"]
    assert any(item.startswith("muster-kernel") for item in required)
    assert not any("muster-platform" in item for item in required)
    assert any(item.startswith("google-adk") for item in required)

    extras = manifest["project"]["optional-dependencies"]
    assert set(extras) == {"cloud"}
