"""The worked run, end to end, through the production-oriented path.

    Ravi's message            -> Worker Agent  -> an inert claim
    the payroll export        -> Employer Agent -> one attested record
    rebuild and analyse       -> Divergent, and a plan naming three variables
    the fleet catalog         -> two agents, one per source class
    the site's own material   -> Site Agent    -> presence, and a lower bound
    admission, Q-12, rebuild  -> Invariant

Run it:

    python demo/hero.py                    the deterministic interpreters
    python demo/hero.py --live             explicit configured Gemini model calls
    python demo/hero.py --postgres DSN     against a real database

**Every step below uses the production-oriented application path.** ``open_case``,
``append_transcript_entry``, ``acquire_outstanding`` and ``case_status`` are the
functions the control plane exposes; the agents are the ADK runtimes a
deployment runs; the receipts are signed by source keys and admitted through
check Q-12.  There is no branch anywhere in this file that a demo takes and a
deployment does not, no answer written down in advance, and no path that skips
authorization.  What differs between this and a cloud run is *where the
processes are* and *which store the site reads* -- and both are behind ports.

**The fixtures are the suite's.**  Keys, grants, the published catalog, the
officer-signed construction record and the worked week come from the same
fixtures the acceptance suite uses, because a demo with its own seed would be a
second definition of the case and the first thing to drift.  Seeding is an
operator's act in production and a fixture's here; everything after it is not.

**And what it does not claim.**  It does not decide, or say, that Ravi worked.
It decides that his Saturday shift is payable under the pinned policy on
attested grounds.  The stronger sentence is not ours to say.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
for _entry in (
    REPOSITORY / "packages" / "muster-kernel" / "src",
    REPOSITORY / "packages" / "muster-kernel",
    REPOSITORY / "packages" / "muster-platform" / "src",
    REPOSITORY / "packages" / "muster-platform" / "tests",
    REPOSITORY / "packages" / "muster-agents" / "src",
    REPOSITORY / "packages" / "muster-agents",
):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from google.adk.models.base_llm import BaseLlm  # noqa: E402

from agent_tests.support import fleet  # noqa: E402
from muster.agents.runtime.claimant import ClaimRejection  # noqa: E402
from muster.core.analysis.outcomes import outcome_class  # noqa: E402
from muster.core.evidence.delivery import AcquisitionTransport  # noqa: E402
from muster.core.evidence.requests import EvidenceRequest  # noqa: E402
from muster.core.evidence.transcript import Statement, StatementRecord  # noqa: E402
from muster.core.results import Err, Ok  # noqa: E402
from muster.core.values.scalars import render  # noqa: E402
from muster.core.values.times import Instant  # noqa: E402
from muster.platform.casework.advance import Casework  # noqa: E402
from muster.platform.casework.commands import (  # noqa: E402
    CaseReport,
    append_transcript_entry,
    case_status,
)
from muster.platform.dispatch.acquire import (  # noqa: E402
    AcquisitionReport,
    Answered,
    acquire_outstanding,
)
from muster.platform.orchestration.decisions import Dispatch  # noqa: E402
from support import ravi  # noqa: E402
from support.authority import publish_fleet  # noqa: E402
from support.fixtures import open_ravi  # noqa: E402


@dataclass(frozen=True, slots=True)
class HeroRun:
    """Everything the run produced, so a caller can assert on it or print it."""

    claims: tuple[StatementRecord, ...]
    #: The plan the case arrived at before anything was acquired.
    solicited: EvidenceRequest
    reports: tuple[AcquisitionReport, ...]
    report: CaseReport


def run_hero(
    casework: Casework,
    transport: AcquisitionTransport,
    *,
    tenant_id: str,
    case_id: str,
    worker_model: BaseLlm | None = None,
    now: Instant = ravi.NOW,
) -> HeroRun:
    """Drive the whole case and return what happened at each step.

    Deliberately returns rather than prints: the acceptance suite calls this
    and asserts on the result, so the thing demonstrated on stage and the thing
    checked on every commit are one code path.
    """
    case = fleet.without(
        ravi.ravi(tenant_id, case_id),
        *fleet.ACQUIRED_BY_THE_FLEET,
        ("present_on_site", (fleet.WORKER, fleet.SATURDAY)),
    )
    open_ravi(casework, case)
    publish_fleet(casework.database, tenant_id, case.authority_snapshot)

    #  1. The week that is not in dispute, exactly as the employer and the site
    #     already reported it.  Nothing about the Saturday is here.
    for entry in case.entries:
        appended = append_transcript_entry(
            casework, tenant_id=tenant_id, case_id=case_id, entry=entry, now=now
        )
        _require(appended, "appending the undisputed week")

    #  2. Ravi says something, in his own words, to his own agent.
    worker = fleet.worker(model=worker_model)
    brief = fleet.worker_brief(tenant_id, case_id)
    claimed = asyncio.run(worker.interpret(brief, fleet.WORKER_ACCOUNT))
    if isinstance(claimed, ClaimRejection):
        raise SystemExit(f"the worker agent produced no claim: {claimed}")

    #  3. Appending it is what produces the analysis this run turns on: still
    #     divergent, with a plan naming what nobody has attested yet.  The
    #     decision is read from the *advance*, which is where a decision is
    #     produced -- a status read reports what a case is, and the plan is
    #     what the case decided to do about it.
    decision: object = None
    for statement in claimed:
        appended = append_transcript_entry(
            casework,
            tenant_id=tenant_id,
            case_id=case_id,
            entry=Statement(statement),
            now=now,
        )
        _require(appended, "appending the worker's claim")
        assert isinstance(appended, Ok)
        advanced = appended.value.advanced
        _require(advanced, "analysing the case with the claim in it")
        assert isinstance(advanced, Ok)
        decision = advanced.value.decision
    if not isinstance(decision, Dispatch):
        raise SystemExit(f"the case did not ask for evidence: {decision}")

    #  4. Ask the fleet.  Routing, interpretation, signing, Q-12, rebuild.
    acquired = acquire_outstanding(
        casework, transport, tenant_id=tenant_id, case_id=case_id, now=now
    )
    _require(acquired, "acquiring evidence")
    assert isinstance(acquired, Ok)

    return HeroRun(
        claims=tuple(claimed),
        solicited=decision.request,
        reports=acquired.value,
        report=_status(casework, tenant_id=tenant_id, case_id=case_id, now=now),
    )


def _status(casework: Casework, *, tenant_id: str, case_id: str, now: Instant) -> CaseReport:
    read = case_status(casework, tenant_id=tenant_id, case_id=case_id, now=now)
    _require(read, "reading the case")
    assert isinstance(read, Ok)
    return read.value


def _require(outcome: object, what: str) -> None:
    if isinstance(outcome, Err):
        raise SystemExit(f"{what} failed: {outcome.error}")


#  ---- narration -----------------------------------------------------------


_ADK_METRICS_LOGGER = "google_adk.google.adk.telemetry._metrics"


class _ScriptedInterpreterTelemetryFilter(logging.Filter):
    """Hide only the expected no-token-metadata warning from scripted models."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not (
            record.levelno == logging.WARNING
            and record.msg
            == "Skipping missing token usage metadata for agent %s and model %s"
        )


def _configure_scripted_demo_logging() -> None:
    """Keep deterministic demo telemetry noise out without muting other logs."""
    logging.getLogger(_ADK_METRICS_LOGGER).addFilter(_ScriptedInterpreterTelemetryFilter())


def narrate(run: HeroRun, write: Callable[[str], None] = print) -> None:
    """What happened, in the order it happened, with no adjectives."""
    write("")
    write("WORKER AGENT")
    for statement in run.claims:
        write(f"  claim      {statement.proposition} = {render(statement.asserted_value)}")
        write(f"  by         {statement.claimant} as {statement.role_in_case}")
        write("  effect     none: a claim is not a justification variant")

    write("")
    write("ANALYSIS BEFORE ACQUISITION")
    write(f"  request    {run.solicited.digest().hex[:16]}")
    for target in run.solicited.targets:
        write(
            f"  needs      {target.proposition} from {', '.join(target.permitted_source_classes)}"
        )

    write("")
    write("FLEET")
    for report in run.reports:
        for exchange in report.exchanges:
            write(f"  agent      {exchange.assignment.agent_id}  at {exchange.endpoint_ref}")
            result = exchange.result
            if not isinstance(result, Answered):
                write(f"  outcome    {type(result).__name__}: {result}")
                continue
            for admitted in result.admitted:
                write(f"  attested   {admitted.proposition}  admitted through Q-12")
            for refused in result.refused:
                write(f"  refused    {refused.proposition}  {refused.error.failure.value}")
        for unroutable in report.unroutable:
            write(f"  unrouted   {unroutable.target.proposition}  {unroutable.error.failure.value}")

    write("")
    write("RESULT")
    write(f"  status     {run.report.status.value}")
    analysis = run.report.analysis
    if analysis is None:
        write("  outcome    the case has never been analysed")
        return
    write(f"  outcome    {outcome_class(analysis.kernel.outcome)}")
    action = getattr(analysis.kernel.outcome, "action", None)
    if action is not None:
        fields = "  ".join(
            f"{field.name}={render(field.value)}" for field in action.consequential_fields
        )
        write(f"  action     {action.kind}  {fields}")
    unresolved = sorted(str(reference) for reference in analysis.projected.unresolved())
    write(f"  unresolved {', '.join(unresolved) if unresolved else 'nothing'}")
    write("")
    write("  MUSTER has not decided that Ravi worked.  It has decided that his")
    write("  Saturday shift is payable under the pinned policy, on attested grounds.")
    write("")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument(
        "--live",
        action="store_true",
        help="call the configured Gemini model instead of the deterministic interpreters",
    )
    parser.add_argument(
        "--postgres",
        metavar="DSN",
        help="run against a real database instead of the in-memory adapter",
    )
    parser.add_argument("--tenant", default="DEMO", help="tenant identifier")
    parser.add_argument("--case", default="CASE-RAVI-SAT-DEMO", help="case identifier")
    arguments = parser.parse_args(argv)

    if not arguments.live:
        _configure_scripted_demo_logging()

    if arguments.postgres:
        from muster.platform.adapters.sql.database import SqlDatabase
        from muster.platform.adapters.sql.schema import migrate

        migrate(arguments.postgres)
        database = SqlDatabase(arguments.postgres)
    else:
        from muster.platform.adapters.memory import MemoryDatabase

        database = MemoryDatabase()  # type: ignore[assignment]

    site_model, employer_model, worker_model = (
        _live_models() if arguments.live else (None, None, None)
    )
    transport = fleet.transport(
        {
            fleet.SITE_ENDPOINT: fleet.site(arguments.tenant, model=site_model),
            fleet.EMPLOYER_ENDPOINT: fleet.employer(arguments.tenant, model=employer_model),
        }
    )
    run = run_hero(
        ravi.casework(database),
        transport,
        tenant_id=arguments.tenant,
        case_id=arguments.case,
        worker_model=worker_model,
    )
    narrate(run)
    return 0


def _live_models() -> tuple[BaseLlm, BaseLlm, BaseLlm]:
    """Three Gemini models, from the same configuration a deployment reads.

    Built here rather than inside the fleet fixture so that ``--live`` is the
    only thing in this file that reaches a network, and so that a run without
    it cannot reach one by accident.
    """
    from muster.agents.config import from_environment
    from muster.agents.google.models import build_model

    configuration = from_environment()
    if isinstance(configuration, Err):
        raise SystemExit(
            f"--live needs an agent configuration: {configuration.error.failure.value}: "
            f"{configuration.error.detail}"
        )
    model = configuration.value.model
    return (build_model(model), build_model(model), build_model(model))


if __name__ == "__main__":
    raise SystemExit(main())
