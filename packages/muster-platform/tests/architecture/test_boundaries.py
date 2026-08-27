"""Architecture contracts for the control plane, checked against the source.

Two rules carry most of the weight and they point in opposite directions:

    muster.platform  ->  muster.kernel     allowed
    muster.kernel    ->  muster.platform   forbidden, and checked from both sides

and inside this package, the functional core / imperative shell line:
``orchestration`` is pure, ``casework`` never names an adapter, and a database
driver appears only under ``adapters.sql``.  A clock appears nowhere at all.

Everything here parses the source with ``ast``.  ``import-linter`` enforces an
overlapping set of rules from its own graph, and having two independent
implementations is deliberate: a defect in either tool's graph does not disable
both.
"""

from __future__ import annotations

import ast
import tomllib
from collections.abc import Iterator
from pathlib import Path

import pytest

from support.paths import PACKAGE_ROOT, REPOSITORY_ROOT

pytestmark = pytest.mark.architecture

PLATFORM_SOURCE = PACKAGE_ROOT / "src" / "muster" / "platform"
KERNEL_SOURCE = REPOSITORY_ROOT / "packages" / "muster-kernel" / "src" / "muster"

#  The dependency matrix, at module granularity rather than package
#  granularity, because the real shape is finer than the packages are.
#
#  ``casework.ports`` is the contract every other layer is written against, and
#  it is the *lowest* row here: it names protocols and value types and imports
#  nothing but the kernel. Keying this table on packages alone would report a
#  cycle where there is none -- ``casework.commands`` admits through
#  ``ingest.admission``, which is written against ``casework.ports`` -- and
#  a checker that cannot express the real rule would have to be relaxed until
#  it stopped expressing anything.
#
#  Every module gets a row. A module with no row fails, which is how a layering
#  discipline avoids dying quietly.
ALLOWED: dict[str, frozenset[str]] = {
    #  Package docstring modules. They import nothing, and they still get rows.
    "": frozenset(),
    "casework": frozenset(),
    "ingest": frozenset(),
    "adapters": frozenset(),
    "adapters.sql": frozenset(),
    #  The two adapters are peers and neither may reach the other. A memory
    #  adapter that imported the SQL one would be sharing an implementation
    #  rather than satisfying a contract, and the shared contract suite would
    #  stop being evidence of anything.
    "adapters.memory": frozenset({"casework.ports", "gate.model", "gate.ports"}),
    "orchestration": frozenset(),
    #  Pure. Reads kernel values, returns a decision. Does not know a database
    #  exists, and must not learn.
    "orchestration.decisions": frozenset(),
    "orchestration.decide": frozenset({"orchestration.decisions"}),
    "orchestration.status": frozenset(),
    #  The custody boundary: protocols and value types, and nothing below it.
    "casework.ports": frozenset({"gate.ports"}),
    #  Reaches ``authority.resolve`` because a snapshot of a case is not
    #  complete without the authority state the case pinned: every rebuild is
    #  judged against it, and resolving it later would mean resolving it after
    #  something had already been admitted.
    "casework.snapshot": frozenset({"authority.resolve", "casework.ports"}),
    "casework.advance": frozenset(
        {
            "casework.ports",
            "casework.snapshot",
            "orchestration.decide",
            "orchestration.decisions",
        }
    ),
    #  Reaches ``authority.resolve`` for the same reason ``casework.snapshot``
    #  does, and for a different question.  The snapshot resolves the authority
    #  a case *pinned*; the command additionally resolves what the tenant has
    #  *withdrawn since*, because a case's pin never moves and a key revoked
    #  after it was opened would otherwise go on establishing facts in it.
    "casework.commands": frozenset(
        {
            "authority.resolve",
            "casework.ports",
            "casework.snapshot",
            "casework.advance",
            "ingest.admission",
            "orchestration.status",
        }
    ),
    "ingest.admission": frozenset({"casework.ports"}),
    #  ---- source authority [G1] ------------------------------------------
    #
    #  Two rows and one rule between them: **``authority`` may not reach
    #  ``catalog``.**  It is stated as an absence in these two sets, checked as
    #  an absence by the edge test, and it is the structural half of "a catalog
    #  match never grants authority" -- Q-12 has no parameter a profile could
    #  arrive through, because there is no import by which one could.
    "authority": frozenset(),
    "authority.publish": frozenset({"casework.ports"}),
    "authority.resolve": frozenset({"casework.ports"}),
    #  ---- the fleet catalog ------------------------------------------------
    #
    #  The reverse direction *is* permitted, and the asymmetry is the design:
    #  routing may know what authority looks like, because knowing cannot
    #  confer it.  Nothing here is imported by anything that decides
    #  admissibility.
    "catalog": frozenset(),
    "catalog.publish": frozenset({"casework.ports"}),
    "catalog.route": frozenset({"casework.ports"}),
    #  The only layer allowed to know what a driver is.
    "adapters.sql.migrations": frozenset(),
    "adapters.sql.config": frozenset(),
    "adapters.sql.schema": frozenset({"adapters.sql.migrations"}),
    "adapters.sql.bootstrap": frozenset({"adapters.sql.schema"}),
    "adapters.sql.content": frozenset({"casework.ports"}),
    "adapters.sql.transcript": frozenset({"casework.ports"}),
    "adapters.sql.head": frozenset({"casework.ports"}),
    "adapters.sql.requests": frozenset({"casework.ports"}),
    "adapters.sql.executions": frozenset({"casework.ports", "gate.model", "gate.ports"}),
    "adapters.sql.sandbox_rail": frozenset({"gate.executor"}),
    "adapters.sql.database": frozenset(
        {
            "casework.ports",
            "adapters.sql.content",
            "adapters.sql.transcript",
            "adapters.sql.head",
            "adapters.sql.requests",
            "adapters.sql.executions",
            "adapters.sql.commitments",
            "adapters.sql.authority",
            "gate.ports",
        }
    ),
    "adapters.sql.commitments": frozenset({"casework.ports"}),
    #  One module, two repositories, and they are separate classes over
    #  separate tables.  Filed together because they are the same *kind* of
    #  storage -- immutable signed publications keyed by snapshot digest -- and
    #  a second file would be a second copy of one insert-if-absent statement.
    "adapters.sql.authority": frozenset({"casework.ports"}),
    #  The only module allowed to know what a cryptography library is. It
    #  implements the two commitment ports and orchestrates nothing.
    "adapters.crypto": frozenset({"commit.domains", "commit.envelope", "commit.salts"}),
    #  The commitment layer. The five rows below it are *pure* -- they compute
    #  octets from values and reach no database, no policy interpreter and no
    #  audience. Only ``commit.publish``, the imperative top of the package,
    #  knows that durable state or a disclosure policy exists.
    "commit": frozenset(),
    "commit.domains": frozenset(),
    "commit.paths": frozenset({"commit.domains"}),
    "commit.salts": frozenset({"commit.domains"}),
    "commit.envelope": frozenset(),
    "commit.record": frozenset({"commit.paths", "commit.salts"}),
    "commit.tree": frozenset({"commit.domains", "commit.paths", "commit.salts"}),
    "commit.build": frozenset(
        {"commit.envelope", "commit.paths", "commit.record", "commit.salts", "commit.tree"}
    ),
    #  Reaches ``disclose.policy`` and nothing else under ``disclose``: a
    #  commitment refuses to pin a policy that could over-disclose, so the
    #  validator has to run before the envelope is signed. It must never reach
    #  the view builder or the audience resolver -- those are decisions about a
    #  reader, and a commitment has no reader.
    "commit.publish": frozenset(
        {
            "casework.advance",
            "casework.ports",
            "casework.snapshot",
            "commit.build",
            "commit.envelope",
            "commit.record",
            "commit.salts",
            "disclose.policy",
        }
    ),
    #  The disclosure layer.
    "disclose": frozenset(),
    "disclose.audience": frozenset(),
    "disclose.policy": frozenset({"commit.paths"}),
    "disclose.views": frozenset(
        {"commit.build", "commit.envelope", "commit.tree", "disclose.audience", "disclose.policy"}
    ),
    "disclose.verify": frozenset(
        {
            "commit.envelope",
            "commit.paths",
            "commit.tree",
            "disclose.audience",
            "disclose.policy",
            "disclose.views",
        }
    ),
    "disclose.queries": frozenset(
        {
            "casework.snapshot",
            "commit.publish",
            "disclose.audience",
            "disclose.policy",
            "disclose.views",
        }
    ),
    #  ---- dispatch: the outbound edge ---------------------------------------
    #
    #  The one package that names *both* the fleet catalog and the admission
    #  path, and it is allowed to because it decides nothing with either.  It
    #  resolves an address, carries octets, checks a reply against what was
    #  asked, and hands each receipt to the ordinary command -- which judges it
    #  against the authority snapshot the case pinned, exactly as it would judge
    #  a receipt that arrived any other way.
    #
    #  It is deliberately *not* on the ``deciding`` list below: an admission
    #  decision must have no path to a routing record, and this package is a
    #  caller of both rather than a step inside either.
    "dispatch": frozenset(),
    "dispatch.assign": frozenset({"casework.ports", "catalog.route"}),
    "dispatch.acquire": frozenset(
        {
            "casework.advance",
            "casework.commands",
            "casework.ports",
            "casework.snapshot",
            "dispatch.assign",
        }
    ),
    #  A rendering of a report.  It emits nothing, writes nothing and reads no
    #  clock, which is why it sees the acquisition record and nothing else.
    "dispatch.observe": frozenset({"dispatch.acquire"}),
    #  The outbound HTTP client: the only module here that opens a socket, and
    #  the only one that names a URL.  Written against the kernel's delivery
    #  port, and against exactly one port of this package's own -- ``gate.cloud``
    #  asks "what identity is this workload running as", and the metadata server
    #  is where that is answered.  The same shape ``adapters.sql.executions``
    #  has: an adapter implementing a Gate port, never a Gate reaching an
    #  adapter.
    "adapters.http": frozenset({"gate.cloud"}),
    #  ---- deterministic Action Gate --------------------------------------
    "gate": frozenset(),
    "gate.model": frozenset(),
    "gate.authority": frozenset(),
    #  Who a *deployed* Gate accepts as its caller.  It builds the same
    #  ``ExecutionGrant`` the local authority holds, from an observed runtime
    #  identity, and it reaches nothing else: no case, no store, no executor,
    #  and above all no admission path.  A cloud identity decides who may ask;
    #  it must have no route to what a case is allowed to conclude.
    "gate.cloud": frozenset({"gate.authority"}),
    "gate.ports": frozenset({"gate.model"}),
    "gate.executor": frozenset({"gate.model"}),
    "gate.eligibility": frozenset(
        {"casework.commands", "gate.model", "orchestration.status"}
    ),
    "gate.service": frozenset(
        {
            "casework.advance",
            "casework.commands",
            "gate.authority",
            "gate.eligibility",
            "gate.executor",
            "gate.model",
            "gate.ports",
        }
    ),
}

#  Packages the final architecture contains and this milestone does not.
#  ``authority`` and ``catalog`` left this set at milestone E and ``dispatch``
#  left it here, which is what each milestone is: routing produced an address,
#  and this one sends a request to it and admits the reply.  What is still
#  absent is everything that decides whether MUSTER *acts* -- the gate, its
#  settlement adapter -- plus the inbound surfaces nothing yet needs.
NOT_YET_BUILT = frozenset({"api", "entrypoints"})

#  Third-party roots forbidden anywhere in this package. The database driver is
#  exempt under ``adapters`` alone -- listed by subtree, so a second module
#  reaching for it has to be added here in a diff somebody reviews.
FORBIDDEN_EXTERNAL = frozenset(
    {
        "fastapi",
        "starlette",
        "flask",
        "django",
        "sqlalchemy",
        "alembic",
        "pydantic",
        "httpx",
        "requests",
        "aiohttp",
        "urllib3",
        "google",
        "boto3",
        "grpc",
        "redis",
        "celery",
        "kombu",
        "kafka",
        "temporalio",
        "z3",
    }
)

#  Libraries confined to one adapter subtree each, and the subtree is named
#  after the concern it exists for. Widening either constant to a parent
#  package is the cheapest way to grant the exemption to everything, so both
#  halves are asserted below: that the subtree really does reach the library,
#  and that nothing else does.
DRIVER = "psycopg"
DRIVER_SUBTREE = "adapters.sql"

#  ``urllib`` is the standard library and is confined all the same, for the
#  same reason the driver is: the control plane has exactly one outbound
#  network edge, and a second module that opened a socket would be a second
#  place a case's content could leave from.
CONFINED: dict[str, str] = {
    DRIVER: DRIVER_SUBTREE,
    "cryptography": "adapters.crypto",
    "urllib": "adapters.http",
}

#  The subset ``import-linter`` also constrains.  ``urllib`` is not on its
#  forbidden list and could not be -- the contract bans third-party
#  distributions, and the standard library is not one -- so the socket rule is
#  enforced here alone, and the exemption comparison below is over the two
#  libraries both tools see.
#
#  What forces a decision about a *newly* confined package is the hand-written
#  equality on ``CONFINED`` further down, which fails until somebody writes the
#  new entry out.  This constant is stated separately so that the comparison
#  against the contract stays over the libraries the contract actually names.
CONFINED_EXTERNAL: frozenset[str] = frozenset({DRIVER, "cryptography"})

#  Nondeterminism and ambient state. Permitted nowhere in this package.
#
#  There used to be one exempt module, ``adapters.clock``, and the rule was
#  "the clock is confined to one file". Nothing ever imported that file: every
#  command takes ``now`` as an argument, so the reading is supplied by whoever
#  is at the imperative boundary. A confinement rule over an empty room proves
#  nothing, so the exemption went with the module and what is left is the
#  stronger statement -- no module here reads a clock at all. A milestone that
#  genuinely needs one adds a module and an entry here, in a reviewed diff.
AMBIENT_MODULES = frozenset({"time", "datetime", "random", "secrets", "uuid", "socket", "os"})
AMBIENT_EXEMPT: frozenset[str] = frozenset()

#  Milestone E+ vocabulary. Not reserved here, and not to be invented here.
#  The commitment and disclosure fragments this list used to carry were removed
#  when milestone D built them; what is left is the gate, settlement and the
#  authority registry, none of which this package may prepare for.
#  ``authorityregistrysnapshot`` and ``sourcedirectory`` left this list at
#  milestone E: the first is now a ratified kernel wire type this package
#  publishes and resolves, and the second turned out not to be a separate thing
#  at all -- the authority snapshot *is* the source directory, because a key's
#  expected principal is the one its own grants name.  What is still forbidden
#  is a *second* authority vocabulary in the control plane: the types live in
#  the kernel, this package moves octets and verifies signatures, and a control
#  plane declaring its own grant type would be a second answer to "who may
#  attest" with no wire contract behind it.
FORBIDDEN_DECLARATIONS = (
    "spendinglimit",
    "disbursement",
    "payout",
    "settlement",
    "evidencerequestdispatch",
    #  Agent runtime. Cataloguing an agent is milestone E; running one is not.
    "agentruntime",
    "agentsession",
    "agentdispatcher",
    "agentclient",
    "agenttransport",
)

FORBIDDEN_TEXT = ("phase 0", "phase0", "phase 1", "phase1", "codex", "blocker")


def _platform_files() -> Iterator[Path]:
    yield from sorted(PLATFORM_SOURCE.rglob("*.py"))


def _kernel_files() -> Iterator[Path]:
    yield from sorted(KERNEL_SOURCE.rglob("*.py"))


def _module_of(path: Path) -> str:
    """A module's contract row: its dotted path below ``muster.platform``."""
    relative = path.relative_to(PLATFORM_SOURCE).with_suffix("")
    parts = [part for part in relative.parts if part != "__init__"]
    return ".".join(parts)


def _package_of(path: Path) -> str:
    """The package a module belongs to, for the rules stated per package."""
    row = _module_of(path)
    return row.split(".")[0] if row else ""


def _dotted(path: Path) -> str:
    relative = path.relative_to(PLATFORM_SOURCE.parents[1]).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
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


def _platform_row(imported: str) -> str | None:
    parts = imported.split(".")
    if parts[:2] != ["muster", "platform"]:
        return None
    return ".".join(parts[2:])


def test_the_platform_tree_is_not_empty() -> None:
    """A scan that finds nothing would pass every check below."""
    assert len(list(_platform_files())) > 10


def test_the_kernel_never_imports_the_platform() -> None:
    """The dependency reversal that would end the design, checked at the source.

    A kernel that could reach the control plane could reach a database, a
    clock and a credential, and every claim about the decision path being pure
    would become a claim about discipline.
    """
    for path in _kernel_files():
        for imported in _imports(path):
            assert not imported.startswith("muster.platform"), f"{path} imports {imported}"


def test_the_kernel_source_does_not_mention_the_platform_at_all() -> None:
    """Read over raw text, so a dynamic import or a path trick is caught too."""
    for path in _kernel_files():
        assert "muster.platform" not in path.read_text(encoding="utf-8"), path


def test_cloud_sql_configuration_does_not_leak_into_the_kernel() -> None:
    for path in _kernel_files():
        text = path.read_text(encoding="utf-8").lower()
        assert "cloud_sql" not in text, path
        assert "muster_database_url" not in text, path


def test_the_kernel_declares_no_database_dependency() -> None:
    manifest = tomllib.loads(
        (KERNEL_SOURCE.parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert manifest["project"]["dependencies"] == []
    declared = [
        requirement
        for group in manifest["project"]["optional-dependencies"].values()
        for requirement in group
    ]
    for requirement in declared:
        assert DRIVER not in requirement
        assert "postgres" not in requirement.lower()


def test_the_platform_depends_on_the_kernel_and_says_so() -> None:
    manifest = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = manifest["project"]["dependencies"]
    assert any(requirement.startswith("muster-kernel") for requirement in dependencies)
    assert any(requirement.startswith(f"{DRIVER}[") for requirement in dependencies)
    #  Three dependencies, and the third arrived with the commitment layer: a
    #  signature a participant can check without holding the ability to forge
    #  one needs an asymmetric primitive, and the standard library has none.
    assert any(requirement.startswith("cryptography") for requirement in dependencies)
    assert len(dependencies) == 3
    for requirement in dependencies:
        for forbidden in FORBIDDEN_EXTERNAL:
            assert forbidden not in requirement, f"{forbidden} is declared as a dependency"


def _edges() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for path in _platform_files():
        source = _module_of(path)
        for imported in _imports(path):
            target = _platform_row(imported)
            if target is not None and target != source:
                found.add((source, target))
    return found


def test_every_internal_edge_is_permitted_by_the_matrix() -> None:
    for source, target in sorted(_edges()):
        assert source in ALLOWED, f"{source} has no contract row"
        assert target in ALLOWED, f"{target} has no contract row"
        assert target in ALLOWED[source], f"{source} may not import {target}"


def test_the_internal_graph_is_acyclic() -> None:
    """Direction, not only permission.

    The matrix could in principle permit a cycle; this rebuilds the graph and
    walks it, so a mutually-dependent pair fails even if both edges have rows.
    """
    outgoing: dict[str, set[str]] = {row: set() for row in ALLOWED}
    for source, target in _edges():
        outgoing[source].add(target)

    visiting: set[str] = set()
    settled: set[str] = set()

    def walk(row: str, path: tuple[str, ...]) -> None:
        if row in settled:
            return
        assert row not in visiting, f"cycle: {' -> '.join([*path, row])}"
        visiting.add(row)
        for neighbour in sorted(outgoing[row]):
            walk(neighbour, (*path, row))
        visiting.discard(row)
        settled.add(row)

    for row in sorted(outgoing):
        walk(row, ())


def test_every_platform_row_is_covered_by_a_contract() -> None:
    present = {_module_of(path) for path in _platform_files()}
    uncovered = present - set(ALLOWED) - NOT_YET_BUILT
    assert not uncovered, f"rows with no contract: {sorted(uncovered)}"
    stale = set(ALLOWED) - present
    assert not stale, f"contracts for absent rows: {sorted(stale)}"


def test_the_contract_names_no_module_from_a_later_milestone() -> None:
    """A contract naming a module nobody has written proves nothing and rots."""
    assert not (set(ALLOWED) & NOT_YET_BUILT)
    for row in NOT_YET_BUILT:
        assert not (PLATFORM_SOURCE / row).exists()


def test_orchestration_is_pure() -> None:
    """It reads kernel values and returns a decision. Nothing else is reachable.

    No adapter, no repository protocol, no driver, no clock, no file. The
    architecture calls this the functional core; this is the line that makes
    the phrase mean something.
    """
    for path in _platform_files():
        if _module_of(path) != "orchestration":
            continue
        for imported in _imports(path):
            root = imported.split(".")[0]
            if imported.startswith("muster.core"):
                continue
            if imported.startswith("muster.platform.orchestration"):
                continue
            assert root in {"__future__", "dataclasses", "enum", "typing", "collections"}, (
                f"{path} imports {imported}"
            )


def test_casework_and_ingest_never_name_an_adapter() -> None:
    """The shell depends on the protocols; only a composition root picks one."""
    for path in _platform_files():
        if _module_of(path) not in {"casework", "ingest"}:
            continue
        for imported in _imports(path):
            assert not imported.startswith("muster.platform.adapters"), (
                f"{_dotted(path)} names the adapter {imported}"
            )


@pytest.mark.parametrize("library", sorted(CONFINED))
def test_a_confined_library_is_reached_from_its_subtree_and_nowhere_else(library: str) -> None:
    """The exemption is a subtree, and both halves are asserted.

    That the adapter really does reach the library, so the exemption is not
    decoration -- and that nothing else does.
    """
    subtree = CONFINED[library]
    reached: set[str] = set()
    for path in _platform_files():
        row = _module_of(path)
        for imported in _imports(path):
            if imported.split(".")[0] != library:
                continue
            assert row == subtree or row.startswith(f"{subtree}."), f"{row} imports {imported}"
            reached.add(row)
    assert reached, f"nothing under {subtree} imports {library}"
    #  Named by hand rather than derived, so widening a constant to a parent
    #  package fails here instead of silently granting the exemption to
    #  everything below it.
    assert CONFINED == {
        "psycopg": "adapters.sql",
        "cryptography": "adapters.crypto",
        "urllib": "adapters.http",
    }


def _platform_contract_section() -> str:
    text = (REPOSITORY_ROOT / "importlinter-platform.ini").read_text(encoding="utf-8")
    return text.split("no-cloud-web-model-or-broker]")[1]


def test_the_confinement_exemptions_match_the_imports_that_exist() -> None:
    """Two tools, one exemption list, and no room for them to drift apart.

    ``import-linter`` names the exempt edges one by one. This asserts that the
    set it names is exactly the set that exists, so widening either side alone
    fails: an import added without an exemption breaks the contract, and an
    exemption left behind after an import is removed breaks this.
    """
    listed = _platform_contract_section().split("ignore_imports =")[1].split("source_modules =")[0]
    exempted = {line.strip() for line in listed.splitlines() if "->" in line}

    #  Compared at the root, because that is the granularity the ban is stated
    #  at: the contract forbids the distribution, not one of its submodules, and
    #  an exemption naming a submodule would leave the others banned.
    found = {
        f"{_dotted(path)} -> {imported.split('.')[0]}"
        for path in _platform_files()
        for imported in _imports(path)
        if imported.split(".")[0] in CONFINED_EXTERNAL
    }
    assert exempted == found
    assert set(CONFINED) > CONFINED_EXTERNAL, "every contract-exempt library is also confined"


def test_the_two_forbidden_lists_agree() -> None:
    """This file and ``importlinter-platform.ini`` must ban the same packages.

    Two independent checks of one rule are worth having; two checks of two
    slightly different rules are worth nothing.
    """
    listed = _platform_contract_section().split("forbidden_modules =")[1]
    declared = {
        line.strip()
        for line in listed.splitlines()
        if line.startswith("    ") and line.strip() and "=" not in line
    }
    #  A confined library is forbidden there and exempted per module; here it
    #  is handled by its own test, which asserts the subtree rather than the ban.
    assert declared - set(CONFINED) == FORBIDDEN_EXTERNAL


def test_no_platform_module_imports_a_forbidden_package() -> None:
    for path in _platform_files():
        for imported in _imports(path):
            root = imported.split(".")[0]
            assert root not in FORBIDDEN_EXTERNAL, f"{path} imports {imported}"


def test_no_module_reads_an_ambient_clock_or_source_of_entropy() -> None:
    """Time enters at the imperative boundary, which is outside this package.

    Every command takes ``now`` as an argument, so a decision is reproducible
    by supplying the reading it was made under. A module reaching for a clock
    would make that false without changing any signature -- and it would do it
    silently, because the argument would still be there and would still be
    honoured everywhere except the one place that stopped needing it.
    """
    for path in _platform_files():
        relative = _dotted(path).removeprefix("muster.platform.")
        for imported in _imports(path):
            root = imported.split(".")[0]
            if root not in AMBIENT_MODULES:
                continue
            assert relative in AMBIENT_EXEMPT, f"{relative} imports {imported}"


def test_no_module_declares_a_clock_of_its_own() -> None:
    """The import ban catches the library; this catches a hand-rolled one.

    Also the guard on the deletion itself: ``adapters.clock`` existed for a
    milestone with nothing importing it, and a protocol nobody implements
    outside its own test file is a decision taken without the information that
    would inform it.
    """
    for path in _platform_files():
        assert path.name != "clock.py", f"{path} is back"
        for name in _declared_names(path):
            lowered = name.lower()
            assert "clock" not in lowered, f"{path} declares {name}"


def test_every_time_argument_is_supplied_rather_than_read() -> None:
    """A ``now`` parameter on every operation whose answer depends on the time.

    Stated positively so the ban above is not the only evidence: the three
    commands and the advance all take a reading, none of them derives one, and
    the type of a reading is not the type of a length.
    """
    import inspect

    from muster.platform.casework.advance import advance_case
    from muster.platform.casework.commands import (
        append_transcript_entry,
        case_status,
        open_case,
    )
    from muster.platform.orchestration.decide import decide

    for function, parameter in (
        (append_transcript_entry, "now"),
        (case_status, "now"),
        (advance_case, "now"),
        (decide, "now"),
        (open_case, "as_of"),
    ):
        signature = inspect.signature(function)
        assert parameter in signature.parameters, f"{function.__name__} reads its own {parameter}"

    #  And the one length in the signatures is typed as a length.
    assert inspect.signature(decide).parameters["request_ttl"].annotation == "Duration"


def test_membership_is_inserted_from_exactly_one_place_and_it_holds_the_case() -> None:
    """The invariant is a command's, so the command has to be the only writer.

    ``transcript.add`` inserts a member, and a member cannot be removed. What
    makes an admission safe is not the repository -- the repository will insert
    whatever it is handed -- but that the one function which calls it holds the
    case first and rebuilds before it commits. A second caller would be a second
    admission policy, and the one that forgot the hold would be found by a
    production incident rather than by a suite.

    Checked over the source because that is where the rule lives. A test that
    exercised the current caller would say nothing about a future one.
    """
    callers = {
        _module_of(path)
        for path in _platform_files()
        if "transcript.add(" in path.read_text(encoding="utf-8")
    }
    assert callers == {"casework.commands"}, f"membership is inserted from {sorted(callers)}"

    #  And that caller takes the hold, in the same function, before it inserts.
    commands = (PLATFORM_SOURCE / "casework" / "commands.py").read_text(encoding="utf-8")
    body = commands.split("def _admit(")[1].split("\ndef ")[0]
    assert body.index("heads.hold(") < body.index("transcript.add("), (
        "_admit inserts membership before it holds the case"
    )
    assert body.index("heads.hold(") < body.index("admit_entry("), (
        "_admit writes octets before it holds the case: two lock orders, one deadlock"
    )


def test_the_publication_holds_the_case_before_it_writes_or_swaps() -> None:
    """Same rule from the other side, and for two reasons.

    The hold is what lets TX B re-read the membership and know it is the set
    that was analysed -- a head that has not moved is not a transcript that has
    not grown. And taking it *first*, before any content, is what puts an
    admission and a publication in one lock order so that neither can wait on
    the other.

    Checked over the source, because the order of two statements is the whole
    property and a test that exercised the current order would pass for either.
    """
    advance = (PLATFORM_SOURCE / "casework" / "advance.py").read_text(encoding="utf-8")
    body = advance.split("def _swap(")[1].split("\ndef ")[0]
    hold = body.index("heads.hold(")
    assert hold < body.index("transcript.members("), "TX B reads membership before holding"
    assert hold < body.index("_put("), "TX B writes content before holding: two lock orders"
    assert hold < body.index("heads.advance("), "TX B swaps before holding"


def test_no_unbuilt_payment_or_agent_runtime_concept_is_declared() -> None:
    """The Gate is here; real settlement and agent runtime remain absent.

    Not prepared for, either: a speculative abstraction for a component nobody
    has written is a design decision taken without the information that would
    make it.
    """
    for path in _platform_files():
        haystack = f"{path.name}\n{path.read_text(encoding='utf-8')}".lower()
        for fragment in FORBIDDEN_DECLARATIONS:
            for declaration in (f"class {fragment}", f"def {fragment}", f"{fragment} ="):
                assert declaration not in haystack, f"{path} declares {fragment}"


def _declared_names(path: Path) -> set[str]:
    """Every class, function and module-level binding a file introduces.

    Declarations rather than raw text, because prose is where a design says
    what it deliberately does *not* contain -- and a scan that cannot tell
    ``class Saga`` from "there is no saga" forces the explanation out of the
    code to keep the test green.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            names.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
    return names


def test_no_disclosure_module_can_reach_a_case_salt() -> None:
    """The privacy claim, stated as a reachability rule rather than a habit.

    ``commit.salts`` is the only module that holds a case salt or derives
    anything under one. Nothing that decides what a *reader* is shown may
    import it, directly or through the matrix -- so "the salt never reaches a
    view" is a property of the graph rather than of every future author
    remembering it.
    """
    salt_module = "commit.salts"
    for row, permitted in ALLOWED.items():
        if row.startswith("disclose"):
            assert salt_module not in permitted, f"{row} may import {salt_module}"

    #  And in the graph that actually exists, not only the one permitted.
    for source, target in _edges():
        if source.startswith("disclose"):
            assert target != salt_module, f"{source} imports {target}"


def test_only_one_module_under_commit_knows_that_durable_state_exists() -> None:
    """The pure half of the commitment layer computes octets and nothing else.

    Six modules turn a decided record into a tree and an envelope; one -- the
    imperative top -- reads a head and writes a row. Keeping that split is what
    makes the tree testable without a database and the envelope reproducible
    without one.
    """
    reaching = {
        row
        for row, permitted in ALLOWED.items()
        if row.startswith("commit")
        and any(other.startswith(("casework", "adapters")) for other in permitted)
    }
    assert reaching == {"commit.publish"}


def test_the_case_salt_is_constructed_in_exactly_two_places() -> None:
    """Where a secret comes into existence is worth naming out loud.

    One module *declares* the type; one adapter *derives* a value of it. A
    third construction site would be a second answer to "where does a case
    salt come from", and the interesting kind of wrong answer is a literal.
    """
    constructing = {
        _module_of(path)
        for path in _platform_files()
        if "CaseSalt(" in path.read_text(encoding="utf-8")
    }
    assert constructing == {"commit.salts", "adapters.crypto"}


def test_the_keyed_primitive_appears_only_where_a_key_does() -> None:
    """``hmac`` is a *keyed* operation, so its import list is a key inventory.

    Two sites, and each holds one key: the case salt, and the salt root the
    local adapter derives it from. A third would be a second answer to "what is
    keyed under what", which is the question the whole privacy argument rests
    on.

    ``hashlib`` is deliberately not confined the same way -- an unkeyed digest
    is not a secret operation, and the migration ledger legitimately hashes its
    own statements -- so the sites are named instead of derived.
    """
    keyed: set[str] = set()
    unkeyed: set[str] = set()
    for path in _platform_files():
        row = _module_of(path)
        for imported in _imports(path):
            root = imported.split(".")[0]
            if root == "hmac":
                keyed.add(row)
            elif root == "hashlib":
                unkeyed.add(row)

    assert keyed == {"commit.salts", "adapters.crypto"}
    assert unkeyed == {
        "commit.domains",
        "commit.salts",
        "adapters.crypto",
        "adapters.sql.migrations",
        #  The Action Gate's operational idempotency key hashes its canonical
        #  intent. It is unkeyed and deliberately outside the semantic digest
        #  namespace; no credential or case salt reaches this module.
        "gate.model",
    }


def test_no_broker_queue_or_workflow_engine_appears() -> None:
    """Persistence is the coordination mechanism at this stage, and only it.

    Checked as imports and declarations. The import half is the one that
    matters -- a broker cannot be used without being imported -- and the
    declaration half catches a hand-rolled one.
    """
    libraries = ("celery", "kombu", "kafka", "temporalio", "airflow", "redis", "pika")
    concepts = ("saga", "outbox", "deadletter", "dead_letter", "workflowengine", "eventbus")
    for path in _platform_files():
        for imported in _imports(path):
            root = imported.split(".")[0].lower()
            assert root not in libraries, f"{path} imports {imported}"
        for name in _declared_names(path):
            lowered = name.lower()
            for concept in concepts:
                assert concept not in lowered, f"{path} declares {name}"


def test_no_http_surface_exists() -> None:
    """A transport is an adapter over these commands and changes none of them.

    Building one now would mean testing the transport instead of the thing this
    milestone is about. The web frameworks are already banned by the import
    contract; what is checked here is that nothing hand-rolls one.
    """
    banned_text = ("@app.", "@router.", "APIRouter", "uvicorn", "wsgi_app", "asgi_app")
    for path in _platform_files():
        text = path.read_text(encoding="utf-8")
        for needle in banned_text:
            assert needle not in text, f"{path} looks like an HTTP surface: {needle}"
        for imported in _imports(path):
            root = imported.split(".")[0]
            assert root not in {"http", "socketserver", "wsgiref"}, f"{path} imports {imported}"


def test_production_vocabulary_carries_no_phase_review_or_tool_names() -> None:
    for path in _platform_files():
        haystack = f"{path.name}\n{path.read_text(encoding='utf-8')}".lower()
        for fragment in FORBIDDEN_TEXT:
            assert fragment not in haystack, f"{path} mentions {fragment!r}"


def test_no_platform_module_imports_the_reference_semantics() -> None:
    needles = ("reference-semantics", "reference_semantics", "muster_spec")
    for path in _platform_files():
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            assert needle not in text, f"{path} references {needle}"


def test_no_type_ignore_is_used_to_reach_a_green_typecheck() -> None:
    import re

    pattern = re.compile(r"#\s*type:\s*ignore")
    for path in _platform_files():
        assert not pattern.search(path.read_text(encoding="utf-8")), path


def test_no_sqlalchemy_type_can_reach_the_kernel() -> None:
    """Stated as the general rule it is an instance of.

    No persistence type crosses into a kernel signature, because the only
    persistence types that exist are the driver's and they appear in exactly
    one subtree, which the kernel cannot import and does not know about.
    """
    for path in _platform_files():
        relative = _dotted(path).removeprefix("muster.platform.")
        if relative.startswith(DRIVER_SUBTREE):
            continue
        text = path.read_text(encoding="utf-8")
        assert "psycopg" not in text, f"{relative} names the driver"
        assert "Connection" not in text, f"{relative} names a driver type"


def test_the_deciding_paths_cannot_name_the_catalog() -> None:
    """The separation as a type, not as an import rule.

    Both checkers constrain *imports*, and ``casework.ports`` is permitted to
    every module on the authority and admission paths -- so a line reading
    ``scope.catalog.latest()`` inside ``resolve_authority`` or inside the
    admission gate would add no import, keep both checkers green, and make an
    admission decision a function of a routing record.

    Two halves, and neither is sufficient alone.  The *protocol* those paths
    take declares no ``catalog`` member, so the attribute does not typecheck;
    and no module on those paths contains the attribute access, so the fact is
    checked over source as well as over types.
    """
    from muster.platform.casework.ports import DecidingScope

    members = set(DecidingScope.__annotations__) | {
        name for name in dir(DecidingScope) if not name.startswith("_")
    }
    assert "catalog" not in members
    assert "authority" in members

    #  Every file on the path from "an entry arrives" to "the head moves",
    #  not merely the gate itself: naming the catalog one frame above the
    #  gate makes the decision a function of a routing record just as
    #  surely, and would otherwise pass unremarked.
    deciding = (
        "authority",
        "ingest",
        "casework/snapshot.py",
        "casework/advance.py",
        "casework/commands.py",
    )
    assert "casework/advance.py" in deciding and "casework/commands.py" in deciding
    for path in _platform_files():
        relative = path.relative_to(PLATFORM_SOURCE).as_posix()
        if not any(relative.startswith(part) or relative == part for part in deciding):
            continue
        source = path.read_text(encoding="utf-8")
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"'):
                continue
            assert ".catalog" not in line, f"{relative}: {stripped}"


def test_only_open_case_may_ask_what_authority_is_in_force() -> None:
    """G7's freshness read is a publication-boundary call, not an authority read.

    ``in_force_authority`` answers "may a case be *opened* under this
    snapshot", which is a question about the present asked at the one instant a
    case is allowed to ask it.  It is one identifier away from being the
    ``latest`` accessor the port refuses to have -- and the difference between
    them is not in the code, it is in *who calls it*.  So the call site is the
    thing constrained, and it is constrained here rather than by a comment.

    A rebuild, an admission or an authority resolution that consulted it would
    be deciding by what is current instead of by what the revision pinned,
    which is exactly the substitution the pin exists to prevent.

    The sibling ``hold_publication_state`` is deliberately *not* restricted the
    same way: it takes the ordering lock and reports an epoch, and neither is a
    statement about which snapshot decides.  Admission is expected to call it.
    """
    permitted = "casework/commands.py"
    seen: list[str] = []
    for path in _platform_files():
        relative = path.relative_to(PLATFORM_SOURCE).as_posix()
        source = path.read_text(encoding="utf-8")
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"'):
                continue
            if "in_force_authority()" not in line:
                continue
            assert relative == permitted, (
                f"{relative} asks what authority is currently in force: {stripped}"
            )
            seen.append(relative)
    #  And the call exists at all.  A needle that matches nothing is a test
    #  that passes when the check it guards has been deleted.
    assert seen == [permitted], seen


def test_only_the_publisher_may_move_what_authority_is_in_force() -> None:
    """The write side of the same boundary, and the more dangerous half.

    ``set_in_force_authority`` decides what every case opened afterwards is
    allowed to pin.  It sits on the same repository the admission path holds --
    it has to, because it is the row admission locks -- so nothing but a call
    site rule keeps a future edit to ``ingest`` or ``casework`` from moving the
    tenant's authority forward as a side effect of admitting evidence.

    That would be worse than the staleness this milestone closed: a path that
    could *write* the in-force pointer could name a snapshot of its own
    choosing and then open cases under it.  Publication is a publisher's act,
    and this is where "publisher" stops being a word in a docstring.
    """
    permitted = "authority/publish.py"
    seen: list[str] = []
    for path in _platform_files():
        relative = path.relative_to(PLATFORM_SOURCE).as_posix()
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"'):
                continue
            if "set_in_force_authority(" not in line or stripped.startswith("def "):
                continue
            assert relative == permitted, f"{relative} moves the authority in force: {stripped}"
            seen.append(relative)
    assert seen == [permitted], seen


def test_the_publication_epoch_cannot_be_moved_on_its_own() -> None:
    """There is no operation that advances the epoch without publishing.

    The epoch is what makes the revocation/admission ordering observable, so it
    has to mean "authority state moved" and not "somebody took the lock".  Both
    setters advance it as part of naming a successor; a bare ``advance_epoch``
    would let the number move with nothing published behind it, and every
    reader comparing epochs would be comparing lock acquisitions.

    Checked as an absence on the *port*, which is what every adapter is written
    against -- an adapter that grew one privately would still be unreachable.
    """
    from muster.platform.casework.ports import AuthorityRepository

    members = {name for name in dir(AuthorityRepository) if not name.startswith("_")}
    assert "advance_epoch" not in members
    assert {"set_in_force_authority", "set_in_force_revocation"} <= members
    #  And still no ``latest``: the accessor whose absence is the whole reason
    #  a historical case cannot be re-decided under today's grants.
    assert "latest" not in members


def test_the_kernel_names_no_other_distribution() -> None:
    """Kernel prose may name a *role*; it may not name a package.

    "The control plane" is an architectural role the kernel legitimately
    describes -- a publisher is one, and a source is not.  What it must not do
    is point at a distribution it cannot import, because a reader who follows
    the pointer learns that the boundary is a filing convention.  The needle is
    therefore the possessive and the dotted path, not the role.
    """
    for path in _kernel_files():
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        for needle in ("muster.platform", "the platform's", "the platform module"):
            assert needle not in lowered, f"{path.name} names {needle!r}"


def test_no_wire_tag_is_declared_outside_the_kernel() -> None:
    """The replacement for two deleted ``FORBIDDEN_DECLARATIONS`` entries.

    ``authorityregistrysnapshot`` and ``sourcedirectory`` left that list when
    the first became a real kernel wire type -- correctly -- but the rule that
    replaced them lived only in a comment: *a second authority vocabulary in
    the control plane*.  Stated positively instead, over the tags themselves,
    so a platform module declaring its own ``AuthorityGrant`` fails here.
    """
    tags = (
        "AuthorityGrant/v1",
        "AuthorityRegistrySnapshot/v1",
        "RevocationSnapshot/v1",
        "ResourceScope/v1",
        "AgentProfile/v1",
        "AgentCatalogSnapshot/v1",
    )
    kernel = chr(10).join(path.read_text(encoding="utf-8") for path in _kernel_files())
    platform = {path: path.read_text(encoding="utf-8") for path in _platform_files()}
    for tag in tags:
        assert tag in kernel, f"{tag} is not declared in the kernel"
        for path, source in platform.items():
            assert tag not in source, f"{path.name} declares the wire tag {tag}"
