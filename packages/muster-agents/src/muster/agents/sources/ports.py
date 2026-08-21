"""Reading source-local material: handles above, octets only at the last step.

Two operations, and the split between them is the privacy boundary made into a
type.  ``handles`` answers "what does this source hold about this subject at
this resource", and its answer carries no content at all -- an identifier, a
media type, a label an operator wrote.  ``read`` answers "give me the material",
and its answer is the raw octets.

Everything that can be done with a handle is therefore safe to log, to return
in a diagnostic and to show an operator.  Everything that can be done with an
:class:`EvidenceItem` is confined to the interpretation call.

**Access denial is a value, not an exception.**  A deployed site agent reads a
private bucket, and the identity that may read it is the site's own.  When
something else tries -- the control plane, an operator, a mis-configured
service -- the storage layer answers with a real permission denial, and that
denial is the observable the whole isolation claim rests on.  A typed
``ACCESS_DENIED`` is how it survives the trip up through the runtime instead of
becoming a stack trace nobody can assert on.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from muster.core.authority.scope import ResourceScope
from muster.core.results import InvariantViolation, Result


@dataclass(frozen=True, slots=True)
class EvidenceHandle:
    """What a source holds, described without disclosing any of it."""

    ref: str
    media_type: str
    #: A short operator-written label -- "north gate camera, Saturday" -- and
    #: never a summary of the content.  A description derived from the material
    #: would be an interpretation that escaped the boundary without passing
    #: through any of the validation that exists to bound one.
    label: str

    def __post_init__(self) -> None:
        for name, value in (
            ("ref", self.ref),
            ("media_type", self.media_type),
            ("label", self.label),
        ):
            if not value:
                raise InvariantViolation(f"an evidence handle names a {name}")


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """A handle together with its octets.  This value never leaves the source."""

    handle: EvidenceHandle
    octets: bytes

    def __post_init__(self) -> None:
        if not self.octets:
            raise InvariantViolation(f"{self.handle.ref} is empty")

    def __repr__(self) -> str:
        """Deliberately content-free.

        A dataclass ``repr`` would put raw private material into any log line,
        exception message or test failure that happened to interpolate one --
        which is precisely the leak this boundary exists to prevent, arriving
        through the most ordinary line of Python anybody writes.
        """
        return (
            f"EvidenceItem(ref={self.handle.ref!r}, media_type={self.handle.media_type!r}, "
            f"octets=<{len(self.octets)} withheld>)"
        )


class EvidenceStoreFailure(Enum):
    """Why source-local material could not be read."""

    #: Nothing is held under that reference.
    NOT_FOUND = "NOT_FOUND"
    #: The store answered and the identity making the call is not permitted to
    #: read it.  This is the real denial from the real storage layer, carried
    #: as a value so that a runtime can report it and a test can assert on it.
    ACCESS_DENIED = "ACCESS_DENIED"
    #: Held, reachable, and not readable: truncated, corrupt, empty.
    UNREADABLE = "UNREADABLE"
    #: The store itself is unavailable -- network, configuration, outage.
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class EvidenceStoreError:
    failure: EvidenceStoreFailure
    detail: str


class SourceEvidenceStore(Protocol):
    """The material one source holds, addressed by subject and resource.

    ``handles`` is scoped by both, and by both for different reasons: the
    subject keeps one worker's material from being offered while another's was
    asked about, and the coordinate keeps one site's material from being
    offered by an agent answering about a different site.  A store that ignored
    either would make the agent's own scope check decorative.
    """

    def handles(
        self, *, subject: str, coordinates: tuple[ResourceScope, ...]
    ) -> Result[tuple[EvidenceHandle, ...], EvidenceStoreError]: ...

    def read(self, ref: str) -> Result[EvidenceItem, EvidenceStoreError]: ...
