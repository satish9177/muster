"""The analysis certificate: what was decided, under what, and why.

Assembled by the composition layer, never by the kernel.  ``analyze`` cannot
return a certificate that contains the irredundant support and the evidence plan
computed downstream of it -- attempting that is what makes the dependency graph
cyclic -- so the kernel returns its record, planning returns its record, and
this is the value that binds them to a revision and a bundle.

**A certificate is read back, not recomputed.**  It is an immutable derived
artifact: it records what a particular solver, at a particular version, under a
particular budget, answered about one revision.  Re-deriving it therefore asks
*today's* engine to reproduce yesterday's answer, and a certificate binds the
solver fingerprint precisely because that is not something to take for granted.
:func:`read_analysis_certificate` is the other direction -- the octets that were
stored, turned back into the value that was assembled -- so that a historical
artifact stays readable across a configuration change that legitimately moves
what a fresh analysis would produce.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.analysis.outcomes import (
    AnalysisOutcome,
    Infeasible,
    Invariant,
    KernelAnalysisRecord,
    read_kernel_analysis_record,
)
from muster.core.analysis.planning import NoActionReason, PlanningRecord, read_planning_record
from muster.core.wire.digests import Digest, DigestKind, digest_node, digest_node_of
from muster.core.wire.nodes import NAtom, NInt, Node, NRec
from muster.core.wire.shape import (
    option_node,
    read_atom,
    read_digest,
    read_int,
    read_option,
    read_rec,
)

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


def no_action_reason(outcome: AnalysisOutcome) -> NoActionReason | None:
    """Why a planner asked for nothing, given what the kernel answered.

    The planner's own mapping, read in the one direction the wire format leaves
    open.  ``NoActionRequired`` encodes without its reason, so a reader has to
    recover it from the outcome -- which is where the planner took it from.

    ``None`` is not a default and not a third reason: it is "this outcome does
    not explain a silence".  The planner requests evidence for a divergent case
    and reports indeterminacy for an indeterminate one, so neither can be paired
    with ``NoActionRequired`` by anything that produced a certificate.  A reader
    that met the pairing anyway would be inventing a field, and the field is one
    that decides a case status and a dispatch -- so the read is refused instead.
    """
    match outcome:
        case Invariant():
            return NoActionReason.ACTION_INVARIANT
        case Infeasible():
            return NoActionReason.INFEASIBLE
        case _:
            return None


def read_analysis_certificate(node: Node) -> AnalysisCertificate:
    """The inverse of :meth:`AnalysisCertificate.to_node`.

    Lossless for every field the encoding carries, and the one field it does not
    carry is refused rather than guessed -- see :func:`no_action_reason`.

    Nothing here checks that the certificate belongs anywhere.  A reader turns
    octets into a value; deciding whether *this* value is the one a head names,
    over the revision that was replayed, under the bundle that was pinned, is a
    question about custody, and it is answered where custody lives.  The two
    halves are separate on purpose: a reader that also validated bindings would
    need the head, and would then be unusable by anything holding only the
    artifact.
    """
    version, tenant_id, case_id, revision, bundle, kernel, planning, annex = read_rec(
        node, TAG_ANALYSIS_CERTIFICATE, 8
    )
    record = read_kernel_analysis_record(kernel)
    return AnalysisCertificate(
        certificate_schema_version=read_int(version),
        tenant_id=read_atom(tenant_id),
        case_id=read_atom(case_id),
        revision_semantic_digest=read_digest(revision),
        bundle_manifest_digest=read_digest(bundle),
        kernel=record,
        planning=read_planning_record(planning, no_action_reason=no_action_reason(record.outcome)),
        diagnostic_annex_digest=read_option(annex, read_digest),
    )
