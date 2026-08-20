"""The walking CLI: one deterministic analysis from local files.

No network, no clock, no database, no model.  Two files in, one report out, and
the same two files always produce byte-identical output -- which is the point of
running it twice.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from muster.application.case_file import (
    CaseFile,
    EngineConfiguration,
    load_case_file,
    load_engine_limits,
)
from muster.application.pipeline import CaseAnalysis, analyse_revision
from muster.application.rebuild import RebuildError, rebuild, transcript_prefix
from muster.core.actions import ConsequentialAction
from muster.core.analysis.outcomes import (
    Divergent,
    ExactReachable,
    Indeterminate,
    Infeasible,
    Invariant,
    NotComputed,
    ReachableActions,
    TruncatedReachable,
    outcome_class,
)
from muster.core.analysis.planning import (
    EvidenceRequested,
    NoActionRequired,
    NoSufficientSetAcquirable,
    PlanningIndeterminate,
    PlanningRecord,
    ProvenIrredundantSupport,
    SufficientSupportIrredundanceUnproved,
)
from muster.core.evidence.requests import EvidenceTarget
from muster.core.results import Err, Ok, Result
from muster.domains.workforce.bundle import workforce_bundle
from muster.hinge.prepare import PrepareRejection
from muster.policy.manifest import LoadedBundle
from muster.policy.registry import BundleRegistry, RegistryError
from muster.solve.reference.bounded import BoundedEnumerationBackend

USAGE = "usage: muster analyse --case <case.json> --config <engine-limits.json>"

EXIT_OK = 0
EXIT_USAGE = 64
EXIT_REJECTED = 65

_LABEL_WIDTH = 22


@dataclass(frozen=True, slots=True)
class _Arguments:
    case: Path
    config: Path


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse(list(sys.argv[1:] if argv is None else argv))
    if arguments is None:
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE

    limits = load_engine_limits(arguments.config)
    if isinstance(limits, Err):
        #  Absent or malformed configuration is a startup failure. There is no
        #  default case-size bound to fall back to, deliberately.
        print(f"engine limits rejected: {limits.error}", file=sys.stderr)
        return EXIT_REJECTED

    case = load_case_file(arguments.case)
    if isinstance(case, Err):
        print(f"case file rejected: {case.error}", file=sys.stderr)
        return EXIT_REJECTED

    report = analyse_case_file(case.value, limits.value)
    if isinstance(report, Err):
        print(f"analysis rejected: {report.error}", file=sys.stderr)
        return EXIT_REJECTED

    for line in report.value:
        print(line)
    return EXIT_OK


type CliRejection = RegistryError | RebuildError | PrepareRejection


def analyse_case_file(
    case: CaseFile, configuration: EngineConfiguration
) -> Result[tuple[str, ...], CliRejection]:
    """Resolve the policy, rebuild the revision, analyse it, and render a report."""
    registry = BundleRegistry((workforce_bundle(),))
    resolved = registry.resolve(case.policy_id, case.as_of)
    if isinstance(resolved, Err):
        return resolved
    loaded = registry.load_by_digest(resolved.value)
    if isinstance(loaded, Err):
        return loaded
    bundle = loaded.value

    prefix = transcript_prefix(case.construction.tenant_id, case.construction.case_id, case.entries)
    inputs = case.rebuild_inputs(bundle.digest(), prefix.digest())

    revision = rebuild(
        inputs,
        case.construction,
        case.entries,
        bundle,
        case.authorization_context,
        case.authority_snapshot,
        case.revocation_snapshot,
        case.solicitations,
    )
    if isinstance(revision, Err):
        return revision

    #  The composition root is the one place that chooses an adapter and
    #  configures it. The kernel is handed the port and its own bounds.
    analysis = analyse_revision(
        revision.value,
        bundle,
        BoundedEnumerationBackend(configuration.enumeration_budget),
        configuration.limits,
    )
    if isinstance(analysis, Err):
        return analysis

    return Ok(render(analysis.value, bundle))


def render(analysis: CaseAnalysis, bundle: LoadedBundle) -> tuple[str, ...]:
    """The report. Free of clocks, paths and iteration order, so it is stable."""
    lines: list[str] = [
        "MUSTER milestone A -- local deterministic analysis",
        "signatures: NOT VERIFIED -- this milestone holds no keyring and is offline",
        "",
        "case",
    ]
    revision = analysis.revision
    lines += [
        _row("tenant", revision.tenant_id),
        _row("case", revision.case_id),
        _row("as_of", str(revision.as_of)),
        _row("mode", revision.mode.value),
        _row("authorizability", revision.authorizability.value),
        _row("revision digest", revision.digest().hex),
        _row("transcript prefix", revision.transcript_prefix_digest.hex),
        "",
        "policy",
        _row("policy id", bundle.manifest.policy_id),
        _row("human version", bundle.manifest.human_version),
        _row("manifest digest", bundle.digest().hex),
        _row("predicate schema", bundle.predicate_schema.digest().hex),
        _row("decision program", bundle.program.digest().hex),
        _row("action schema", bundle.action_schema.digest().hex),
        "",
        "analysis",
        _row("outcome", outcome_class(analysis.kernel.outcome)),
        _row("logical case", analysis.kernel.logical_case_digest.hex),
        _row(
            "solver",
            f"{analysis.kernel.fingerprint.backend} {analysis.kernel.fingerprint.version} "
            f"({analysis.kernel.fingerprint.logic}, budget {analysis.kernel.fingerprint.budget})",
        ),
        _row("determinism", analysis.kernel.determinism_class.value),
        _row("queries issued", str(len(analysis.kernel.query_digests))),
    ]
    lines += _outcome_lines(analysis)
    lines += ["", *_unresolved_lines(analysis)]
    lines += ["", *_necessity_lines(analysis)]
    lines += ["", *_plan_lines(analysis)]
    lines += ["", *_non_effect_lines(analysis)]
    lines += ["", _row("certificate digest", analysis.certificate.digest().hex)]
    return tuple(lines)


def _outcome_lines(analysis: CaseAnalysis) -> list[str]:
    outcome = analysis.kernel.outcome
    match outcome:
        case Invariant(action, _, _):
            return [
                _row("proposed action", action.render()),
                _row("", "a proposal, not an authorization"),
            ]
        case Divergent(reachable, _, _):
            lines = [_row("reachable actions", _reachable_kind(reachable))]
            for action in _reachable_actions(reachable):
                lines.append(_row("", action.render()))
            return lines
        case Infeasible(contributing):
            return [_row("contributing", ", ".join(contributing) or "none reported")]
        case Indeterminate(reason):
            return [_row("reason", reason.value)]


def _reachable_kind(reachable: ReachableActions) -> str:
    match reachable:
        case ExactReachable(actions):
            return f"EXACT ({len(actions)})"
        case TruncatedReachable(_, cap):
            return f"TRUNCATED (cap {cap})"
        case NotComputed(reason):
            return f"NOT COMPUTED ({reason.value})"


def _reachable_actions(reachable: ReachableActions) -> tuple[ConsequentialAction, ...]:
    match reachable:
        case ExactReachable(actions):
            return tuple(sorted(actions, key=lambda action: action.render()))
        case TruncatedReachable(sample, _):
            return tuple(sorted(sample, key=lambda action: action.render()))
        case _:
            return ()


def _unresolved_lines(analysis: CaseAnalysis) -> list[str]:
    unresolved = analysis.projected.unresolved()
    requested = {target.proposition for target in _targets(analysis.planning.record)}
    acquirable = {target.proposition: target for target in analysis.acquirable}
    lines = [f"unresolved ({len(unresolved)})"]
    for ref in unresolved:
        target = acquirable.get(ref)
        if target is None:
            source = "DERIVED -- not attestable by anyone"
        else:
            asked = "requested" if ref in requested else "acquirable, not requested"
            source = f"{', '.join(sorted(target.permitted_source_classes))} ({asked})"
        lines.append(f"  {ref!s:<46} {source}")
    return lines


def _targets(record: PlanningRecord) -> tuple[EvidenceTarget, ...]:
    outcome = record.planning_outcome
    return outcome.request.targets if isinstance(outcome, EvidenceRequested) else ()


def _necessity_lines(analysis: CaseAnalysis) -> list[str]:
    necessary = analysis.planning.necessary
    if necessary is None:
        #  Not computed is not the same as "nothing is necessary". Saying the
        #  second when the first is true would be a false statement in an
        #  auditable report.
        return [
            "necessary variables",
            "  not computed -- the action is already determined, so no evidence",
            "  question was asked.",
        ]
    if not necessary:
        return [
            "necessary variables",
            "  none -- and evidence is still required.",
            "  Dropping any single unresolved variable leaves the rest sufficient,",
            "  yet fixing nothing at all is not. A per-variable relevance flag",
            "  reports 'nothing matters' here and authorizes the wrong payment.",
        ]
    return ["necessary variables", *(f"  {ref}" for ref in necessary)]


def _plan_lines(analysis: CaseAnalysis) -> list[str]:
    record = analysis.planning.record
    lines = ["evidence plan"]
    match record.planning_outcome:
        case NoActionRequired(reason):
            lines.append(_row("no request because", reason.value))
        case EvidenceRequested(request):
            lines.append(_row("outcome", "EVIDENCE_REQUESTED"))
            lines.append(_row("request digest", request.digest().hex))
            lines.append(_row("targets", str(len(request.targets))))
            for target in request.targets:
                lines.append(
                    f"    {target.proposition!s:<44} "
                    f"from {', '.join(sorted(target.permitted_source_classes))}"
                )
        case NoSufficientSetAcquirable(escalation):
            lines.append(_row("escalation", escalation.reason))
            lines += [f"    {ref}" for ref in escalation.unacquirable]
        case PlanningIndeterminate(reason):
            lines.append(_row("indeterminate", reason))

    support = record.support
    match support:
        case ProvenIrredundantSupport(members, _, witnesses):
            lines.append(
                _row(
                    "support",
                    f"IRREDUNDANT -- {len(members)} members, {len(witnesses)} deletion witnesses",
                )
            )
        case SufficientSupportIrredundanceUnproved(members, inconclusive, reasons):
            lines.append(
                _row(
                    "support",
                    f"SUFFICIENT, IRREDUNDANCE UNPROVED -- {len(members)} members, "
                    f"{len(inconclusive)} inconclusive ({', '.join(reasons)})",
                )
            )
        case None:
            pass
    return lines


def _non_effect_lines(analysis: CaseAnalysis) -> list[str]:
    non_effects = analysis.revision.non_effects
    if not non_effects:
        return ["recorded non-effects", "  none"]
    lines = ["recorded non-effects"]
    for effect in non_effects:
        lines.append(f"  {effect.rule_id}  {effect.subject}  {effect.reason}")
    return lines


def _row(label: str, value: str) -> str:
    return f"  {label:<{_LABEL_WIDTH}}{value}"


def _parse(argv: list[str]) -> _Arguments | None:
    if not argv or argv[0] != "analyse":
        return None
    case: Path | None = None
    config: Path | None = None
    rest = argv[1:]
    while rest:
        flag = rest[0]
        if len(rest) < 2:
            return None
        value = rest[1]
        rest = rest[2:]
        if flag == "--case":
            case = Path(value)
        elif flag == "--config":
            config = Path(value)
        else:
            return None
    if case is None or config is None:
        return None
    return _Arguments(case, config)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
