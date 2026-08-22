"""Architecture contracts, checked against a graph rebuilt from the source.

``import-linter`` enforces the same dependency matrix from its own graph.  This
module is deliberately a second, independent implementation: it parses every
production file with ``ast`` and answers questions the configuration cannot
express cleanly, so a defect in either tool's graph does not disable both.

It also enforces the matrix at the depth the frozen contract states it.  The
frozen table has eleven rows, four of which are below the top level --
``solve.z3``, ``solve.reference``, ``domains.workforce``, ``domains.procurement``
-- and a checker that keys on the top level cannot see the rule that keeps the
two domains independent of each other.  The core sub-seams are checked for the
same reason: ``core.wire``, ``core.values`` and ``core.evidence`` are the
pre-cut line for extracting a wire distribution, and that line only exists while
nothing below it reaches upward.
"""

from __future__ import annotations

import ast
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.conftest import REPOSITORY_ROOT, SOURCE_ROOT

pytestmark = pytest.mark.architecture

ROOT_PACKAGE = "muster"

#  The seams inside ``muster.core``, lowest first. Each may import the ones
#  before it and nothing after.
CORE_SEAMS: tuple[str, ...] = (
    "core.results",
    "core.wire",
    "core.values",
    "core.expr",
    #  Source authority sits below evidence because relation validation calls
    #  it: Q-12 runs before the content checks, so the check has to be beneath
    #  the module that runs them.  It is above ``core.values`` because a grant
    #  is a value with an interval and a symbol reference in it, and below
    #  everything that knows what a case is -- authority has never heard of one.
    "core.authority",
    #  And the fleet catalog above authority, never beside it.  The order is
    #  the separation: a catalog may know what a coordinate is, and no module
    #  under ``core.authority`` may import one, so "discovery cannot grant
    #  authority" is enforced by the same expansion that orders everything else.
    "core.catalog",
    "core.actions",
    "core.case",
    "core.evidence",
    "core.analysis",
)

#  What a wire-only consumer would be allowed to see. Naming it here is what
#  keeps the extraction mechanical rather than archaeological later.
WIRE_SEAM = frozenset(
    {
        "core.results",
        "core.wire",
        "core.values",
        "core.evidence",
        "core.expr",
        #  Authority and the catalog are wire types plus one pure function
        #  each.  A wire-only consumer that could read a receipt and not the
        #  snapshot deciding its admissibility would be a consumer that could
        #  see a signature and not an authorization, which is the confusion the
        #  whole milestone exists to prevent.
        "core.authority",
        "core.catalog",
    }
)

_ALL_CORE = frozenset(CORE_SEAMS)

#  What a package *above* core may see.  The catalog is removed, and removing it
#  here rather than row by row is the fix for a real hole: inserting
#  ``core.catalog`` into the ordered seam list silently widened ``_ALL_CORE``,
#  so every row built from it -- including the package literally named
#  ``admissibility`` -- gained permission to import a routing record.  The two
#  hand-trimmed rows below caught it for ``core.case`` and ``core.evidence`` and
#  for nothing else.
#
#  ``application`` is the exception and keeps the full set: it is the
#  composition root, and routing is one of the things a composition root
#  composes.
_ALL_CORE_DECIDING = _ALL_CORE - {"core.catalog"}


def _core_below(seam: str) -> frozenset[str]:
    return frozenset(CORE_SEAMS[: CORE_SEAMS.index(seam)])


#  The frozen dependency matrix, restricted to the packages that exist today and
#  expanded to the depth the frozen table states.
ALLOWED: dict[str, frozenset[str]] = {
    #  Package docstring modules. They import nothing, and they still get a
    #  row: a row that is trimmed away is a row nobody notices going missing.
    "core": frozenset(),
    "domains": frozenset(),
    **{seam: _core_below(seam) for seam in CORE_SEAMS},
    #  ``core.actions`` and ``core.case`` are siblings: neither may import the
    #  other, so the linear expansion above is trimmed for the two that would
    #  otherwise be permitted an edge they do not have.
    #  The two rows *inside* core that sit after ``core.catalog`` in the seam
    #  order and would otherwise inherit it.  ``_ALL_CORE_DECIDING`` only trims
    #  the rows above core; these are built by ``_core_below``, so each has to
    #  say so itself -- and the guard below is written over the whole table
    #  rather than over a list, because a list that has to be maintained is
    #  what let these two keep the edge after the first fix.
    "core.actions": _core_below("core.actions") - {"core.catalog"},
    "core.case": _core_below("core.case") - {"core.actions", "core.catalog"},
    #  Evidence reaches authority and **not** the catalog.  The linear
    #  expansion would permit both; trimming the catalog is what makes
    #  "no admission decision can see a routing record" a fact about the module
    #  graph rather than a claim in a docstring.
    "core.evidence": _core_below("core.evidence") - {"core.actions", "core.case", "core.catalog"},
    "core.analysis": _core_below("core.analysis") - {"core.catalog"},
    "policy": _ALL_CORE_DECIDING - {"core.analysis"},
    #  The solver port is the narrowest boundary in the system. It sees the
    #  expression IR and the values in it, and nothing above.
    "solve": frozenset({"core.results", "core.wire", "core.values", "core.expr"}),
    "solve.reference": frozenset(
        {"core.results", "core.wire", "core.values", "core.expr", "solve"}
    ),
    #  The SMT adapter does not see ``core.actions`` or ``core.analysis``: it is
    #  handed a query and returns a verdict, and it has never heard of a case.
    #  Narrower than the bounded oracle's row, which additionally needs
    #  ``core.wire`` for its canonical enumeration order.
    "solve.z3": frozenset({"core.results", "core.values", "core.expr", "solve"}),
    "admissibility": _ALL_CORE_DECIDING | {"policy"},
    "hinge": _ALL_CORE_DECIDING | {"policy", "solve"},
    "evidence": _ALL_CORE_DECIDING | {"hinge"},
    "domains.workforce": _ALL_CORE_DECIDING | {"policy"},
    "domains.procurement": _ALL_CORE_DECIDING | {"policy"},
    #  The frozen matrix gives the composition root "all of the above,
    #  **including solve.z3 and solve.reference**". Omitting an adapter here
    #  would forbid the only layer allowed to construct one from constructing
    #  it -- which is the defect the eleventh row was added to close.
    "application": _ALL_CORE
    | {
        "policy",
        "solve",
        "solve.reference",
        "solve.z3",
        "admissibility",
        "hinge",
        "evidence",
        "domains.workforce",
        "domains.procurement",
    },
}

#  Rows this matrix does not cover, and does not need to.
#
#  ``platform`` and ``agents`` are *other distributions*.  They exist now, and
#  they are absent from this graph on purpose: the scan below is rooted at the
#  kernel's own source tree, so "the kernel imports no database" is checked
#  against a graph the control plane is not in, and "the kernel imports no
#  model" against one the fleet is not in.  Each of those distributions carries
#  its own matrix, checked with its own set of importable packages.
#
#  ``domains.procurement`` is the one row here that is genuinely unwritten.
#  Naming it in a contract would assert something about code nobody has
#  written.
NOT_YET_BUILT = frozenset({"platform", "agents"})

#  The one production subtree permitted to import a solver library, and the one
#  library it may import. Both halves matter: a second adapter added elsewhere
#  fails, and this adapter reaching for a different library fails too.
SOLVER_ADAPTER = f"{ROOT_PACKAGE}.solve.z3"
SOLVER_LIBRARY = "z3"

#  Every third-party root a production module may not import. Kept in step with
#  ``importlinter.ini`` by :func:`test_the_two_forbidden_lists_agree`.
FORBIDDEN_EXTERNAL = frozenset(
    {
        "z3",
        "fastapi",
        "starlette",
        "flask",
        "django",
        "sqlalchemy",
        "alembic",
        "psycopg",
        "psycopg2",
        "pydantic",
        "httpx",
        "requests",
        "aiohttp",
        "urllib3",
        "google",
        "boto3",
        "grpc",
        "redis",
    }
)

#  The complete standard library surface the kernel is allowed to reach for.
#  Banning the *modules* rather than the call spellings is what makes the rule
#  survive ``from time import time as _t``.
PERMITTED_STDLIB = frozenset(
    {
        "__future__",
        "collections.abc",
        "dataclasses",
        "enum",
        "hashlib",
        "itertools",
        "json",
        "pathlib",
        "sys",
        "typing",
    }
)

#  Nondeterminism and ambient state, banned by module so an alias cannot hide it.
AMBIENT_MODULES = frozenset({"os", "time", "datetime", "random", "secrets", "uuid", "socket"})

#  Only the composition layer may touch a file or a console.
IO_CONFINED_TO = f"{ROOT_PACKAGE}.application"
IO_MODULES = frozenset({"json", "pathlib", "sys"})

#  Phase, review and tooling vocabulary, and Phase-0.G Gate concepts. Scanned
#  over all text: prose that dates the code is the thing being kept out.
FORBIDDEN_TEXT = ("phase 0", "phase0", "phase 1", "phase1", "codex", "blocker")
FORBIDDEN_DECLARATIONS = (
    "authorizedaction",
    "gatedecision",
    "spendinglimit",
    "executionreservation",
    "finality",
    "disbursement",
    "payout",
    "settlement",
)


def _production_files() -> Iterator[Path]:
    yield from sorted(SOURCE_ROOT.rglob("*.py"))


def _module_name(path: Path) -> str:
    relative = path.relative_to(SOURCE_ROOT.parent).with_suffix("")
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


def _reached_modules(path: Path) -> Iterator[str]:
    """Modules an import *reaches*, including the ones named after ``import``.

    ``from muster.solve import z3`` names ``muster.solve`` as its module and
    ``z3`` as a name, so a checker reading modules alone sees an import of the
    port where the code imported the adapter.  Kept separate from
    :func:`_imports` on purpose: feeding these into the standard-library
    allowlist would turn ``from typing import Protocol`` into ``typing.Protocol``
    and reject it.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            yield node.module
            for alias in node.names:
                yield f"{node.module}.{alias.name}"


def _within(module: str, package: str) -> bool:
    """Subtree membership, which a prefix test is not.

    ``muster.solve.z3_helpers`` starts with ``muster.solve.z3`` and is not
    inside it.  A sibling module would otherwise inherit the solver adapter's
    exemption from every check that grants it, which is seven of them.
    """
    return module == package or module.startswith(f"{package}.")


def _seam_of(module: str) -> str | None:
    """The contract row a module belongs to, at the depth the matrix states."""
    parts = module.split(".")
    if parts[0] != ROOT_PACKAGE or len(parts) < 2:
        return None
    if parts[1] == "core":
        return f"core.{parts[2]}" if len(parts) > 2 else "core"
    if parts[1] == "domains" and len(parts) > 2:
        return f"domains.{parts[2]}"
    if parts[1] == "solve" and len(parts) > 2 and parts[2] in {"reference", "z3"}:
        return f"solve.{parts[2]}"
    return parts[1]


def _edges() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for path in _production_files():
        source = _seam_of(_module_name(path))
        if source is None:
            continue
        for imported in _imports(path):
            target = _seam_of(imported)
            if target is not None and target != source:
                found.add((source, target))
    return found


def test_the_production_tree_is_not_empty() -> None:
    """A scan that finds nothing would pass every check below."""
    assert len(list(_production_files())) > 40


def test_no_production_module_imports_the_reference_semantics() -> None:
    """The production codec is written from the document and the vectors.

    A production codec validated against a reference it was copied from
    validates nothing: the same mistake passes both sides.  Checked over the raw
    text, not only over parsed imports, so a dynamic reference or a ``sys.path``
    manipulation is caught too.
    """
    needles = ("reference-semantics", "reference_semantics", "muster_spec")
    for path in _production_files():
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            assert needle not in text, f"{path} references {needle}"


def test_every_edge_is_permitted_by_the_matrix() -> None:
    for source, target in sorted(_edges()):
        assert source in ALLOWED, f"{source} has no contract row"
        assert target in ALLOWED, f"{target} has no contract row"
        assert target in ALLOWED[source], f"{source} may not import {target}"


def test_the_graph_is_acyclic() -> None:
    """Direction, not just permission: no cycle among the contract rows."""
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


def test_the_two_domains_are_independent_of_each_other() -> None:
    """Domain packages see generic seams, never each other."""
    assert {"domains.workforce", "domains.procurement"} <= set(ALLOWED)
    for row, allowed in ALLOWED.items():
        if row.startswith("domains."):
            assert not any(other.startswith("domains.") for other in allowed)
    assert _seam_of("muster.domains.workforce.bundle") == "domains.workforce"
    assert _seam_of("muster.domains.procurement.bundle") == "domains.procurement"


def test_the_wire_seam_reaches_nothing_above_itself() -> None:
    """The pre-cut line for extracting a wire-only distribution."""
    for source, target in sorted(_edges()):
        if source in WIRE_SEAM:
            assert target in WIRE_SEAM, f"{source} reaches {target}, above the wire seam"


def test_every_production_row_is_covered_by_a_contract() -> None:
    """A module with no rule is how a layering discipline dies quietly."""
    present = {
        row for path in _production_files() if (row := _seam_of(_module_name(path))) is not None
    }
    uncovered = present - set(ALLOWED) - NOT_YET_BUILT
    assert not uncovered, f"rows with no contract: {sorted(uncovered)}"
    stale = set(ALLOWED) - present
    assert not stale, f"contracts for absent rows: {sorted(stale)}"


def test_the_solver_abstraction_does_not_reach_its_own_adapters() -> None:
    """``hinge`` talks to the port; only the composition root names an adapter.

    Read over reached modules rather than imported ones, so
    ``from muster.solve import z3`` -- which names the *port* as its module --
    is caught alongside ``import muster.solve.z3.backend``.
    """
    adapters = (f"{ROOT_PACKAGE}.solve.reference", SOLVER_ADAPTER)
    composition = f"{ROOT_PACKAGE}.application"
    for path in _production_files():
        module = _module_name(path)
        if any(_within(module, package) for package in (*adapters, composition)):
            continue
        for reached in _reached_modules(path):
            assert not any(_within(reached, adapter) for adapter in adapters), (
                f"{module} reaches the adapter {reached}"
            )


def test_no_production_module_imports_a_forbidden_package() -> None:
    for path in _production_files():
        module = _module_name(path)
        for imported in _imports(path):
            root = imported.split(".")[0]
            if root == SOLVER_LIBRARY and _within(module, SOLVER_ADAPTER):
                continue
            assert root not in FORBIDDEN_EXTERNAL, f"{path} imports {imported}"


def test_only_the_approved_adapter_imports_the_solver_library() -> None:
    """The exemption is a subtree, not a habit.

    The blanket ban still names ``z3``; exactly one subtree is exempt from it,
    and this asserts both halves -- that the adapter really does reach the
    library, so the exemption is not decoration, and that nothing else does.
    """
    reached: set[str] = set()
    for path in _production_files():
        module = _module_name(path)
        for imported in _imports(path):
            if imported.split(".")[0] != SOLVER_LIBRARY:
                continue
            assert _within(module, SOLVER_ADAPTER), f"{module} imports {imported}"
            reached.add(module)
    assert reached, f"no module under {SOLVER_ADAPTER} imports {SOLVER_LIBRARY}"
    assert SOLVER_LIBRARY in FORBIDDEN_EXTERNAL
    #  The exempt subtree is the one named after the library it is exempt for.
    #  Widening the constant to a parent package is the cheapest way to grant
    #  the exemption to everything, so it is refused here by name.
    assert f"{ROOT_PACKAGE}.solve.{SOLVER_LIBRARY}" == SOLVER_ADAPTER


def test_the_solver_exemption_matches_the_import_contract() -> None:
    """Two tools, one exemption, and no room for them to drift apart.

    ``import-linter`` names the exempt edges one by one.  This asserts that the
    set it names is exactly the set that exists, so widening either side alone
    fails: an import added without an exemption breaks the contract, and an
    exemption left behind after an import is removed breaks this.
    """
    text = (REPOSITORY_ROOT / "importlinter.ini").read_text(encoding="utf-8")
    section = text.split("no-cloud-web-or-database-anywhere]")[1]
    listed = section.split("ignore_imports =")[1].split("forbidden_modules =")[0]
    exempted = {line.strip() for line in listed.splitlines() if "->" in line}

    found = {
        f"{_module_name(path)} -> {imported}"
        for path in _production_files()
        for imported in _imports(path)
        if imported.split(".")[0] == SOLVER_LIBRARY
    }
    assert exempted == found


def test_the_forbidden_contract_covers_every_kernel_package() -> None:
    """The blanket ban names the kernel's packages one by one, and misses none.

    It used to name the ``muster`` namespace, which stopped being the kernel
    alone the moment a second distribution shipped into it.  Enumerating is
    correct and it is also fragile in one specific way -- a new kernel package
    that nobody adds to the list would be silently uncovered -- so the list is
    checked against the tree here.
    """
    text = (REPOSITORY_ROOT / "importlinter.ini").read_text(encoding="utf-8")
    section = text.split("no-cloud-web-or-database-anywhere]")[1]
    listed = section.split("source_modules =")[1].split("ignore_imports =")[0]
    declared = {
        line.strip()
        for line in listed.splitlines()
        if line.startswith("    ") and line.strip() and not line.strip().startswith(";")
    }

    present = {
        f"{ROOT_PACKAGE}.{row.split('.')[0]}"
        for path in _production_files()
        if (row := _seam_of(_module_name(path))) is not None
    }
    assert declared == present, f"contract covers {sorted(declared)}, tree has {sorted(present)}"


def test_the_two_forbidden_lists_agree() -> None:
    """This test and ``importlinter.ini`` must ban the same packages.

    Two independent checks of one rule are worth having; two checks of two
    slightly different rules are worth nothing.
    """
    text = (REPOSITORY_ROOT / "importlinter.ini").read_text(encoding="utf-8")
    section = text.split("no-cloud-web-or-database-anywhere]")[1]
    listed = section.split("forbidden_modules =")[1]
    declared = {
        line.strip()
        for line in listed.splitlines()
        if line.startswith("    ") and line.strip() and "=" not in line
    }
    assert declared == FORBIDDEN_EXTERNAL


def test_production_imports_only_the_permitted_standard_library() -> None:
    """An allowlist, so a new module reaching for a clock fails on the import.

    Invariant: ``as_of`` is an input, so replaying a revision a year later
    reproduces it.  A substring scan for ``time.time`` would miss
    ``from time import time as _t``; banning the module does not.
    """
    for path in _production_files():
        module = _module_name(path)
        for imported in _imports(path):
            root = imported.split(".")[0]
            if root == ROOT_PACKAGE:
                continue
            if root == SOLVER_LIBRARY and _within(module, SOLVER_ADAPTER):
                continue
            assert imported in PERMITTED_STDLIB, f"{path} imports {imported}"
            assert root not in AMBIENT_MODULES, f"{path} imports {imported}"


def test_file_and_console_access_is_confined_to_the_composition_layer() -> None:
    """The decision path performs no I/O; the shell around it does."""
    for path in _production_files():
        module = _module_name(path)
        if module.startswith(IO_CONFINED_TO):
            continue
        for imported in _imports(path):
            assert imported not in IO_MODULES, f"{module} imports {imported}"


def test_the_kernel_declares_no_runtime_dependency() -> None:
    """A dependency here is an architectural decision, not a convenience.

    The decision path still installs with nothing behind it.  The solver
    library is declared as an extra, because it is needed by one adapter and
    by nothing the kernel does without that adapter -- so "the kernel has no
    runtime dependency" stays a fact about the base distribution.

    The extras table is checked as tightly as the required list, because a
    forbidden package declared there would be installable by the kernel's own
    metadata while every import contract stayed green.
    """
    manifest = tomllib.loads(
        (SOURCE_ROOT.parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = manifest["project"]
    assert project["dependencies"] == []

    extras = project["optional-dependencies"]
    assert set(extras) == {"smt"}
    requirements = [requirement for group in extras.values() for requirement in group]
    assert any(requirement.startswith("z3-solver") for requirement in requirements)
    for requirement in requirements:
        for forbidden in FORBIDDEN_EXTERNAL - {SOLVER_LIBRARY}:
            assert forbidden not in requirement, f"{forbidden} is declared as an extra"


def test_production_vocabulary_carries_no_phase_review_or_tool_names() -> None:
    """Responsibility-based names, and no document numbering, in production."""
    for path in _production_files():
        haystack = f"{path.name}\n{path.read_text(encoding='utf-8')}".lower()
        for fragment in FORBIDDEN_TEXT:
            assert fragment not in haystack, f"{path} mentions {fragment!r}"


def test_no_gate_concept_is_declared_in_production() -> None:
    """Phase-0.G types are not reserved here, and must not be invented here."""
    for path in _production_files():
        haystack = f"{path.name}\n{path.read_text(encoding='utf-8')}".lower()
        for fragment in FORBIDDEN_DECLARATIONS:
            for declaration in (f"class {fragment}", f"def {fragment}", f"{fragment} ="):
                assert declaration not in haystack, f"{path} declares {fragment}"


def test_no_persistence_network_or_subprocess_surface_exists() -> None:
    """The kernel is local, offline and stateless beyond its inputs.

    ``__import__`` is banned alongside them because it is the one spelling of
    an import that no parsed-import checker sees: the module name is a string
    argument, so a forbidden package reached that way is invisible to both this
    file's graph and to ``import-linter``'s.
    """
    banned = ("import sqlite3", "urllib.request", "subprocess", "socket.", "__import__")
    for path in _production_files():
        text = path.read_text(encoding="utf-8")
        for needle in banned:
            assert needle not in text, f"{path} uses {needle}"


def test_no_type_ignore_is_used_to_reach_a_green_typecheck() -> None:
    """Strict typing is worth nothing if it is silenced where it bites."""
    pattern = re.compile(r"#\s*type:\s*ignore")
    for path in _production_files():
        assert not pattern.search(path.read_text(encoding="utf-8")), path


def test_no_deciding_package_may_import_the_fleet_catalog() -> None:
    """The rule an ordered seam list widened by accident -- twice.

    ``core.catalog`` was inserted into ``CORE_SEAMS`` so the linear expansion
    would order it after authority, and the same insertion added it to every
    row built from that expansion.  The first fix trimmed the five rows above
    core and the two intra-core rows that were already hand-trimmed for other
    reasons -- and left ``core.actions`` and ``core.analysis``, which sit after
    the catalog in the seam order and inherit it from ``_core_below``.  Both
    are squarely on the decision path: one holds candidate actions, the other
    holds the analysis certificate and the planner.

    So the guard is written over the **whole table**, with two named
    exceptions, rather than over a list of rows somebody has to remember to
    extend.  A list that must be maintained is the mechanism that produced this
    defect both times.
    """
    exempt = {
        #  The composition root, which composes routing along with everything
        #  else.
        "application",
        #  The catalog itself.
        "core.catalog",
    }
    for row, allowed in sorted(ALLOWED.items()):
        if row in exempt:
            continue
        assert "core.catalog" not in allowed, row

    #  And the exemption is real rather than a hole: the composition root does
    #  keep it, so this is a rule about who *decides* rather than a blanket ban
    #  nothing could compose against.
    assert "core.catalog" in ALLOWED["application"]
