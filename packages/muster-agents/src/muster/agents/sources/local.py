"""A directory of source-local material, described by a manifest beside it.

What a site actually runs in development, and what the worked demo uses: a
folder holding a gate log and an attendance photograph, plus a manifest saying
what each file is, whom it is about and which resource it belongs to.

The manifest *format* lives here and is shared with the cloud store, because
the two describe the same thing and two parsers would be two formats: an
operator who moved a site's material from a laptop to a bucket would discover
the difference as a store that reads nothing.

**References are resolved through the manifest and never joined with input.**
A reference an assignment or a model supplies is looked up in the manifest and
answered with ``NOT_FOUND`` when it is not there; it is never appended to a
path.  A store whose lookup is a path join is a store where ``../`` is a
capability, and the material on the other side of that join is exactly the
private evidence this boundary exists for.

The manifest is read once per call rather than cached, because a site adding
today's footage should not have to restart an agent, and because a cache is
state and this runtime has none.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from muster.agents.sources.ports import (
    EvidenceHandle,
    EvidenceItem,
    EvidenceStoreError,
    EvidenceStoreFailure,
    SourceEvidenceStore,
)
from muster.core.authority.scope import ResourceScope
from muster.core.results import Err, InvariantViolation, Ok, Result

MANIFEST_NAME = "manifest.json"


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """One item a source declares it holds: what it is, whose, and where."""

    handle: EvidenceHandle
    file_name: str
    subject: str
    scope: tuple[ResourceScope, ...]


def parse_manifest(text: str) -> Result[tuple[ManifestEntry, ...], EvidenceStoreError]:
    """Read a manifest, refusing anything it cannot describe exactly.

    Every failure is a value, because a manifest is a file an operator edits
    and a site with a typo in it should report a typo rather than raise out of
    a request handler.  Keys are read individually rather than by unpacking, so
    a manifest with an extra field is accepted -- forward compatibility for the
    operator -- while one with a missing or wrongly typed field is refused.
    """
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as malformed:
        return Err(EvidenceStoreError(EvidenceStoreFailure.UNREADABLE, str(malformed)))
    if not isinstance(parsed, dict):
        return Err(
            EvidenceStoreError(EvidenceStoreFailure.UNREADABLE, "the manifest is not an object")
        )
    raw_items = parsed.get("items")
    if not isinstance(raw_items, list):
        return Err(
            EvidenceStoreError(EvidenceStoreFailure.UNREADABLE, "the manifest declares no items")
        )
    entries: list[ManifestEntry] = []
    for index, raw in enumerate(raw_items):
        built = _entry_of(raw, index)
        if isinstance(built, Err):
            return Err(built.error)
        entries.append(built.value)
    return Ok(tuple(entries))


@dataclass(frozen=True, slots=True)
class LocalDirectoryEvidenceStore(SourceEvidenceStore):
    """Material held on the source's own filesystem."""

    root: Path

    def handles(
        self, *, subject: str, coordinates: tuple[ResourceScope, ...]
    ) -> Result[tuple[EvidenceHandle, ...], EvidenceStoreError]:
        entries = self._entries()
        if isinstance(entries, Err):
            return Err(entries.error)
        required = set(coordinates)
        return Ok(
            tuple(
                entry.handle
                for entry in entries.value
                if entry.subject == subject and required <= set(entry.scope)
            )
        )

    def read(self, ref: str) -> Result[EvidenceItem, EvidenceStoreError]:
        entries = self._entries()
        if isinstance(entries, Err):
            return Err(entries.error)
        for entry in entries.value:
            if entry.handle.ref != ref:
                continue
            return self._octets(entry)
        return Err(EvidenceStoreError(EvidenceStoreFailure.NOT_FOUND, ref))

    def _octets(self, entry: ManifestEntry) -> Result[EvidenceItem, EvidenceStoreError]:
        path = self.root / entry.file_name
        try:
            octets = path.read_bytes()
        except FileNotFoundError:
            return Err(
                EvidenceStoreError(
                    EvidenceStoreFailure.NOT_FOUND, f"{entry.file_name} is not on disk"
                )
            )
        except PermissionError as denied:
            return Err(EvidenceStoreError(EvidenceStoreFailure.ACCESS_DENIED, str(denied)))
        except OSError as broken:  # pragma: no cover - filesystem specific
            return Err(EvidenceStoreError(EvidenceStoreFailure.UNREADABLE, str(broken)))
        if not octets:
            return Err(
                EvidenceStoreError(
                    EvidenceStoreFailure.UNREADABLE, f"{entry.handle.ref} holds no octets"
                )
            )
        return Ok(EvidenceItem(entry.handle, octets))

    def _entries(self) -> Result[tuple[ManifestEntry, ...], EvidenceStoreError]:
        manifest = self.root / MANIFEST_NAME
        try:
            text = manifest.read_text(encoding="utf-8")
        except FileNotFoundError:
            return Err(
                EvidenceStoreError(
                    EvidenceStoreFailure.STORE_UNAVAILABLE, f"{manifest} does not exist"
                )
            )
        except PermissionError as denied:
            return Err(EvidenceStoreError(EvidenceStoreFailure.ACCESS_DENIED, str(denied)))
        except (OSError, UnicodeDecodeError) as broken:  # pragma: no cover - platform specific
            return Err(EvidenceStoreError(EvidenceStoreFailure.STORE_UNAVAILABLE, str(broken)))
        return parse_manifest(text)


def _entry_of(raw: object, index: int) -> Result[ManifestEntry, EvidenceStoreError]:
    if not isinstance(raw, dict):
        return Err(_malformed(index, "is not an object"))
    fields: dict[str, str] = {}
    for name in ("ref", "media_type", "label", "file", "subject"):
        value = raw.get(name)
        if not isinstance(value, str) or not value:
            return Err(_malformed(index, f"declares no {name}"))
        fields[name] = value

    file_name = fields["file"]
    if "/" in file_name or "\\" in file_name or ".." in file_name:
        #  A manifest is operator-written and is still input.  A file name
        #  carrying a separator would make the manifest a way to read anything
        #  the agent's own account can reach, which is a much larger set than
        #  the material this store is meant to expose.
        return Err(_malformed(index, "names a file outside the store"))

    scope = raw.get("scope")
    if not isinstance(scope, list) or not scope:
        return Err(_malformed(index, "declares no resource scope"))
    coordinates: list[ResourceScope] = []
    for coordinate in scope:
        if not isinstance(coordinate, dict):
            return Err(_malformed(index, "has a malformed resource scope"))
        kind = coordinate.get("kind")
        value = coordinate.get("value")
        if not isinstance(kind, str) or not isinstance(value, str):
            return Err(_malformed(index, "has a malformed resource scope"))
        try:
            coordinates.append(ResourceScope(kind, value))
        except InvariantViolation as violation:
            return Err(_malformed(index, str(violation)))

    return Ok(
        ManifestEntry(
            handle=EvidenceHandle(
                ref=fields["ref"], media_type=fields["media_type"], label=fields["label"]
            ),
            file_name=file_name,
            subject=fields["subject"],
            scope=tuple(coordinates),
        )
    )


def _malformed(index: int, detail: str) -> EvidenceStoreError:
    return EvidenceStoreError(EvidenceStoreFailure.UNREADABLE, f"manifest item {index} {detail}")
