"""The internal analysis record: everything committed, plus the secret it is committed under.

This is the one value in the system that holds a decided case *and* its case
salt, and it crosses no boundary in any direction.  It is not a row, not a
payload, not an argument to anything under ``disclose``, and not persisted:
the certificate and the revision are already durable as content-addressed
cache artifacts, the salt is derived rather than stored, and the full action is
supplied or is not.  Assembling it is therefore cheap and repeatable, and a
table holding it would be a table holding a secret -- the exact thing the
architecture forbids.

**What belongs here and what does not.**  Committed material is the semantic and
audit record: the certificate the kernel assembled and the revision it was
derived from.  Presentation data, telemetry, solver transients, timings and the
diagnostic annex are not here and have no path in the inventory; the annex is
referenced by digest from inside the certificate, which is the whole of what a
commitment needs to say about it.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.actions import Action
from muster.core.analysis.certificate import AnalysisCertificate
from muster.core.case.revision import CaseRevision
from muster.core.results import InvariantViolation, Result
from muster.core.wire.codec import encode
from muster.platform.commit.paths import CommittedRecord, PathError, extract
from muster.platform.commit.salts import CaseSalt


@dataclass(frozen=True, slots=True)
class InternalAnalysisRecord:
    """A decided case, as the thing a commitment is taken over.

    ``full_action`` is the pre-projection action, and it is ``Option`` in the
    frozen contract for a reason this milestone runs into directly: the kernel
    record keeps the *projected* consequential action, because projection is
    what strips diagnostic fields that must never reach a consequence.  Nothing
    in this milestone reconstructs the unprojected one, so it is ``None`` here
    and ``action.full`` is simply not a leaf -- which the inventory allows, and
    which the reader-side check knows not to demand.
    """

    certificate: AnalysisCertificate
    revision: CaseRevision
    full_action: Action | None
    salt: CaseSalt

    def __post_init__(self) -> None:
        #  The certificate cites a revision by digest.  Assembling a record from
        #  a certificate and a *different* revision would commit leaves drawn
        #  from two cases, each internally consistent, under one root.
        if self.certificate.revision_semantic_digest != self.revision.digest():
            raise InvariantViolation(
                "the certificate does not cite the revision it is being committed with"
            )
        if (self.certificate.tenant_id, self.certificate.case_id) != (
            self.revision.tenant_id,
            self.revision.case_id,
        ):
            raise InvariantViolation("the certificate and the revision name different cases")

    def committed(self) -> Result[CommittedRecord, PathError]:
        """The leaf set.  There is no discretion here, only extraction."""
        full_action = self.full_action
        return extract(
            certificate=self.certificate,
            revision=self.revision,
            full_action_octets=None if full_action is None else encode(full_action.to_node()),
        )

    def __repr__(self) -> str:
        #  The salt redacts itself, and this stays explicit anyway: a record
        #  printed in a log line is the most likely way for one to escape, and
        #  the default dataclass repr would also carry the whole decided case.
        return (
            f"InternalAnalysisRecord(case={self.revision.tenant_id}/{self.revision.case_id}, "
            f"revision={self.revision.digest().hex}, salt=<redacted>)"
        )
