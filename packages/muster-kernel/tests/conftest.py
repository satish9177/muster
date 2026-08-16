"""Shared test fixtures.

The frozen Phase-0.8 corpus is read here as *requirements data*.  The production
codec was written from the documented grammar and these vectors, never by
porting the reference encoder, and no production module imports anything under
``spec/``.  Two independent implementations agreeing on the same octets is
evidence; one implementation agreeing with a copy of itself is not.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src" / "muster"
FIXTURES = PACKAGE_ROOT / "fixtures"
GOLDEN_VECTORS = REPOSITORY_ROOT / "spec" / "reference-semantics" / "generated"


@dataclass(frozen=True, slots=True)
class GoldenVector:
    name: str
    type_name: str
    octets: bytes
    digest: str | None
    digest_kind: str | None
    note: str


@pytest.fixture(scope="session")
def golden_vectors() -> dict[str, GoldenVector]:
    document = json.loads((GOLDEN_VECTORS / "golden_vectors.json").read_text(encoding="utf-8"))
    return {
        entry["name"]: GoldenVector(
            name=entry["name"],
            type_name=entry["type"],
            octets=bytes.fromhex(entry["hex"]),
            digest=entry.get("digest"),
            digest_kind=entry.get("digest_kind"),
            note=entry.get("note", ""),
        )
        for entry in document["vectors"]
    }


@pytest.fixture(scope="session")
def schema_inventory() -> dict[str, int]:
    """Frozen record tags and their arities, parsed from the generated inventory."""
    text = (GOLDEN_VECTORS / "schema_inventory.md").read_text(encoding="utf-8")
    arities: dict[str, int] = {}
    for line in text.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 3 or not cells[1].startswith("`") or not cells[2].isdigit():
            continue
        arities[cells[1].strip("`")] = int(cells[2])
    return arities


@pytest.fixture(scope="session")
def declared_digest_kinds() -> frozenset[str]:
    """Every digest kind the frozen inventory declares."""
    text = (GOLDEN_VECTORS / "schema_inventory.md").read_text(encoding="utf-8")
    section = text.split("## Digest kinds")[1].split("## Uniqueness")[0]
    kinds: set[str] = set()
    for line in section.splitlines():
        if line.startswith("| `"):
            kinds.add(line.strip("|").split("|")[0].strip().strip("`"))
    return frozenset(kinds)
