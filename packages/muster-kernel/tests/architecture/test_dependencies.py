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
    "core.actions",
    "core.case",
    "core.evidence",
    "core.analysis",
)

#  What a wire-only consumer would be allowed to see. Naming it here is what
#  keeps the extraction mechanical rather than archaeological later.
WIRE_SEAM = frozenset({"core.results", "core.wire", "core.values", "core.evidence", "core.expr"})

_ALL_CORE = frozenset(CORE_SEAMS)


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
    "core.case": _core_below("core.case") - {"core.actions"},
    "core.evidence": _core_below("core.evidence") - {"core.actions", "core.case"},
    "policy": _ALL_CORE - {"core.analysis"},
    #  The solver port is the narrowest boundary in the system. It sees the
    #  expression IR and the values in it, and nothing above.
    "solve": frozenset({"core.results", "core.wire", "core.values", "core.expr"}),
    "solve.reference": frozenset(
        {"core.results", "core.wire", "core.values", "core.expr", "solve"}
    ),
    "admissibility": _ALL_CORE | {"policy"},
    "hinge": _ALL_CORE | {"policy", "solve"},
    "evidence": _ALL_CORE | {"hinge"},
    "domains.workforce": _ALL_CORE | {"policy"},
    "application": _ALL_CORE
    | {
        "policy",
        "solve",
        "solve.reference",
        "admissibility",
        "hinge",
        "evidence",
        "domains.workforce",
    },
}

#  Packages the final architecture contains and this milestone does not. Naming
#  them in a contract would assert something about code nobody has written.
NOT_YET_BUILT = frozenset({"platform", "agents", "solve.z3", "domains.procurement"})

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


def test_the_two_domains_would_be_independent_of_each_other() -> None:
    """The rule that a top-level checker cannot see.

    Only one domain exists today, so this asserts the *checker* can express the
    rule -- otherwise it would start passing vacuously the moment the second
    domain lands.
    """
    assert "domains.procurement" in NOT_YET_BUILT
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
    """``hinge`` talks to the port; only the composition root names an adapter."""
    adapters = f"{ROOT_PACKAGE}.solve.reference"
    for path in _production_files():
        module = _module_name(path)
        if module.startswith(adapters) or module.startswith(f"{ROOT_PACKAGE}.application"):
            continue
        for imported in _imports(path):
            assert not imported.startswith(adapters), f"{module} imports the adapter"


def test_no_production_module_imports_a_forbidden_package() -> None:
    for path in _production_files():
        for imported in _imports(path):
            root = imported.split(".")[0]
            assert root not in FORBIDDEN_EXTERNAL, f"{path} imports {imported}"


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
        for imported in _imports(path):
            root = imported.split(".")[0]
            if root == ROOT_PACKAGE:
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
    """A dependency here is an architectural decision, not a convenience."""
    manifest = (SOURCE_ROOT.parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in manifest


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
    """Milestone A is local, offline and stateless beyond its inputs."""
    banned = ("import sqlite3", "urllib.request", "subprocess", "socket.")
    for path in _production_files():
        text = path.read_text(encoding="utf-8")
        for needle in banned:
            assert needle not in text, f"{path} uses {needle}"


def test_no_type_ignore_is_used_to_reach_a_green_typecheck() -> None:
    """Strict typing is worth nothing if it is silenced where it bites."""
    pattern = re.compile(r"#\s*type:\s*ignore")
    for path in _production_files():
        assert not pattern.search(path.read_text(encoding="utf-8")), path
