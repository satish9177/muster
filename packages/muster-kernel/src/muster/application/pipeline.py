"""The composition root: rebuild, prepare, project, analyse, plan, assemble.

Every step is a pure function of the previous one, so the whole pipeline is a
pure function of ``RebuildInputs``.  There is nothing to recover after a crash
except the inputs, and nothing to mock in a test.

This is also the only module that constructs a concrete backend.  The kernel
depends on the port; the choice of adapter is a composition decision and lives
here, where it can be seen.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.actions import ConsequentialAction
from muster.core.analysis.certificate import CERTIFICATE_SCHEMA_VERSION, AnalysisCertificate
from muster.core.analysis.outcomes import KernelAnalysisRecord
from muster.core.analysis.outcomes import proposed_action as read_action
from muster.core.case.revision import CaseRevision
from muster.core.evidence.requests import EvidenceTarget
from muster.core.results import Err, Ok, Result
from muster.core.values.classification import AcquisitionClass
from muster.core.values.symbols import SymbolRef
from muster.evidence.planning import Planning, plan_evidence
from muster.hinge.analyze import analyze
from muster.hinge.oracle import Oracle
from muster.hinge.prepare import EngineLimits, PrepareRejection, prepare
from muster.hinge.project import ProjectedCase, project
from muster.policy.manifest import LoadedBundle
from muster.policy.predicates import PredicateSpec
from muster.solve.backend import SolverBackend


@dataclass(frozen=True, slots=True)
class CaseAnalysis:
    """Everything one run produced, assembled but not published."""

    revision: CaseRevision
    projected: ProjectedCase
    kernel: KernelAnalysisRecord
    planning: Planning
    certificate: AnalysisCertificate
    #  Which unresolved variables a source could be asked for -- resolved from
    #  the pinned schema, so a report never has to infer it from what happened
    #  to be requested.
    acquirable: tuple[EvidenceTarget, ...]


def analyse_revision(
    revision: CaseRevision,
    bundle: LoadedBundle,
    backend: SolverBackend,
    limits: EngineLimits,
) -> Result[CaseAnalysis, PrepareRejection]:
    """Validate, project, decide, plan and assemble -- in that order, once."""
    prepared = prepare(revision, bundle, backend.capabilities(), limits)
    if isinstance(prepared, Err):
        return prepared

    projected = project(prepared.value)
    oracle = Oracle(backend, projected)
    kernel = analyze(projected, oracle, limits)

    acquirable = acquirable_targets(prepared.value.specs, projected.unresolved())
    planning = plan_evidence(
        oracle=oracle,
        outcome=kernel.outcome,
        unresolved=projected.unresolved(),
        candidates=acquirable,
        tenant_id=revision.tenant_id,
        case_id=revision.case_id,
        revision_digest=revision.digest(),
    )

    certificate = assemble_certificate(revision, kernel, planning)
    return Ok(CaseAnalysis(revision, projected, kernel, planning, certificate, acquirable))


def acquirable_targets(
    specs: dict[SymbolRef, PredicateSpec], unresolved: tuple[SymbolRef, ...]
) -> tuple[EvidenceTarget, ...]:
    """The unresolved variables a source could actually be asked for.

    A normative conclusion is DERIVED, so it never appears here.  The engine
    cannot request it, and the absence is structural rather than a rule someone
    has to remember.
    """
    targets: list[EvidenceTarget] = []
    for ref in unresolved:
        spec = specs.get(ref)
        if spec is None:  # pragma: no cover - prepare guarantees every unresolved ref
            continue
        if spec.acquisition is not AcquisitionClass.ATTESTABLE:
            continue
        targets.append(EvidenceTarget(ref, spec.acquisition, tuple(spec.permitted_source_classes)))
    return tuple(targets)


def assemble_certificate(
    revision: CaseRevision, kernel: KernelAnalysisRecord, planning: Planning
) -> AnalysisCertificate:
    """Bind the kernel record and the planning record to a revision and a bundle."""
    return AnalysisCertificate(
        certificate_schema_version=CERTIFICATE_SCHEMA_VERSION,
        tenant_id=revision.tenant_id,
        case_id=revision.case_id,
        revision_semantic_digest=revision.digest(),
        bundle_manifest_digest=revision.bundle_pin,
        kernel=kernel,
        planning=planning.record,
        diagnostic_annex_digest=None,
    )


def proposed_action(analysis: CaseAnalysis) -> ConsequentialAction | None:
    """The action a certificate proposes, if any. Only ``Invariant`` carries one."""
    return read_action(analysis.kernel.outcome)
