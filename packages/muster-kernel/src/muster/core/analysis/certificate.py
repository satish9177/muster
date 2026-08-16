"""The analysis certificate: what was decided, under what, and why.

Assembled by the composition layer, never by the kernel.  ``analyze`` cannot
return a certificate that contains the irredundant support and the evidence plan
computed downstream of it -- attempting that is what makes the dependency graph
cyclic -- so the kernel returns its record, planning returns its record, and
this is the value that binds them to a revision and a bundle.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.analysis.outcomes import KernelAnalysisRecord
from muster.core.analysis.planning import PlanningRecord
from muster.core.wire.digests import Digest, DigestKind, digest_node, digest_node_of
from muster.core.wire.nodes import NAtom, NInt, NRec
from muster.core.wire.shape import option_node

TAG_ANALYSIS_CERTIFICATE = "AnalysisCertificate/v1"

CERTIFICATE_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class AnalysisCertificate:
    certificate_schema_version: int
    tenant_id: str
    case_id: str
    revision_semantic_digest: Digest
    bundle_manifest_digest: Digest
    kernel: KernelAnalysisRecord
    planning: PlanningRecord
    diagnostic_annex_digest: Digest | None = None

    def to_node(self) -> NRec:
        return NRec(
            TAG_ANALYSIS_CERTIFICATE,
            (
                NInt(self.certificate_schema_version),
                NAtom(self.tenant_id),
                NAtom(self.case_id),
                self.revision_semantic_digest.to_node(),
                self.bundle_manifest_digest.to_node(),
                self.kernel.to_node(),
                self.planning.to_node(),
                option_node(
                    None
                    if self.diagnostic_annex_digest is None
                    else digest_node_of(self.diagnostic_annex_digest)
                ),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.ANALYSIS_CERTIFICATE, self.to_node())
