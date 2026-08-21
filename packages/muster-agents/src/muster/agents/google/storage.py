"""Private source material in Cloud Storage, read by the source's own identity.

This is where the isolation claim stops being architecture and becomes an IAM
policy.  The bucket holds one site's raw material; the *only* principal with a
read grant on it is that site's agent service account; the control plane's
service account has no grant at all and receives a real permission denial if it
tries.  Nothing in MUSTER withholds the material from the control plane -- it is
simply not reachable from there.

**A denial is a value, and that matters twice.**  Once because a runtime that
raised on a 403 would turn the most important observable in the demo into a
stack trace, and once because the *agent* can be denied too -- a rotated
binding, a wrong bucket, a revoked account -- and an operator needs to tell
"this source holds nothing" apart from "this source cannot read what it holds".

**The manifest lives beside the material, in the same private bucket.**  A
manifest somewhere the control plane could read would be a listing of one
site's holdings, by subject, outside the boundary -- which is a smaller leak
than the material and is still a leak.

**Credentials are ambient and never configured.**  On Cloud Run the client
picks up the attached service identity; there is no key file, no path to one,
and no parameter through which one could arrive.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from google.api_core import exceptions as api_exceptions
from google.cloud import storage

from muster.agents.sources.local import parse_manifest
from muster.agents.sources.ports import (
    EvidenceHandle,
    EvidenceItem,
    EvidenceStoreError,
    EvidenceStoreFailure,
    SourceEvidenceStore,
)
from muster.core.authority.scope import ResourceScope
from muster.core.results import Err, Ok, Result

MANIFEST_NAME = "manifest.json"


@dataclass(frozen=True)
class GcsEvidenceStore(SourceEvidenceStore):
    """One source's material, in one prefix of one private bucket.

    Not slotted, because the client is built lazily and cached on the instance:
    constructing a storage client reaches for credentials, and a store built at
    import time in a process that will never read anything would fail on a
    machine that has none.
    """

    bucket: str
    prefix: str = ""

    @cached_property
    def _client(self) -> storage.Client:
        return storage.Client()

    def handles(
        self, *, subject: str, coordinates: tuple[ResourceScope, ...]
    ) -> Result[tuple[EvidenceHandle, ...], EvidenceStoreError]:
        manifest = self.read_object(MANIFEST_NAME)
        if isinstance(manifest, Err):
            return Err(manifest.error)
        try:
            text = manifest.value.decode("utf-8")
        except UnicodeDecodeError as malformed:
            return Err(EvidenceStoreError(EvidenceStoreFailure.UNREADABLE, str(malformed)))
        entries = parse_manifest(text)
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
        manifest = self.handles_for_ref(ref)
        if isinstance(manifest, Err):
            return Err(manifest.error)
        handle, object_name = manifest.value
        octets = self.read_object(object_name)
        if isinstance(octets, Err):
            return Err(octets.error)
        if not octets.value:
            return Err(
                EvidenceStoreError(EvidenceStoreFailure.UNREADABLE, f"{ref} holds no octets")
            )
        return Ok(EvidenceItem(handle, octets.value))

    def handles_for_ref(self, ref: str) -> Result[tuple[EvidenceHandle, str], EvidenceStoreError]:
        """Resolve a reference through the manifest, never by joining a path.

        A reference reaches this store from an assignment or from a model, and
        both are input.  Looked up in the manifest it is a key that either
        exists or does not; appended to a prefix it would be a capability to
        read anything the agent's own account can reach, which is a much larger
        set than the material this store exists to expose.
        """
        manifest = self.read_object(MANIFEST_NAME)
        if isinstance(manifest, Err):
            return Err(manifest.error)
        try:
            text = manifest.value.decode("utf-8")
        except UnicodeDecodeError as malformed:
            return Err(EvidenceStoreError(EvidenceStoreFailure.UNREADABLE, str(malformed)))
        entries = parse_manifest(text)
        if isinstance(entries, Err):
            return Err(entries.error)
        for entry in entries.value:
            if entry.handle.ref == ref:
                return Ok((entry.handle, entry.file_name))
        return Err(EvidenceStoreError(EvidenceStoreFailure.NOT_FOUND, ref))

    def read_object(self, name: str) -> Result[bytes, EvidenceStoreError]:
        """Download one object by name, turning every Google failure into a value.

        Public, and not only because the manifest reader needs it: the
        deployment probe asks the *storage layer* whether the identity it is
        running under may have these octets, and routing that question
        through the manifest first would report a manifest denial when the
        interesting answer is about the object.
        """
        path = f"{self.prefix.rstrip('/')}/{name}" if self.prefix else name
        try:
            blob = self._client.bucket(self.bucket).blob(path)
            return Ok(blob.download_as_bytes())
        except api_exceptions.NotFound:
            return Err(
                EvidenceStoreError(
                    EvidenceStoreFailure.NOT_FOUND, f"gs://{self.bucket}/{path} does not exist"
                )
            )
        except (api_exceptions.Forbidden, api_exceptions.PermissionDenied) as denied:
            #  **The observable the whole isolation claim rests on.**  The
            #  identity making this call was not granted access to this object,
            #  and the storage layer said so.  Carried as a value with the
            #  denial's own message, so an operator sees which principal was
            #  refused and a test can assert on it -- rather than a traceback
            #  somebody would be tempted to catch and ignore.
            return Err(
                EvidenceStoreError(
                    EvidenceStoreFailure.ACCESS_DENIED,
                    f"gs://{self.bucket}/{path}: {denied}"[:400],
                )
            )
        except api_exceptions.GoogleAPIError as failure:
            return Err(
                EvidenceStoreError(
                    EvidenceStoreFailure.STORE_UNAVAILABLE,
                    f"{type(failure).__name__}: {failure}"[:400],
                )
            )
