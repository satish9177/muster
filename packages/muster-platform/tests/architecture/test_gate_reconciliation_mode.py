"""The Stage-90 reconciliation path can inspect, but cannot execute or redispatch."""

from __future__ import annotations

import ast
import builtins
import copy
import os
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from support.shell import posix_shell

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
CLOUD_HERO = REPOSITORY / "demo" / "cloud_hero.py"
ENVIRONMENT = REPOSITORY / "infra" / "scripts" / "env.sh"
HERO_DEPLOYMENT = REPOSITORY / "infra" / "scripts" / "90-hero-job.sh"

#: The generated programs below are POSIX shell and are written as such,
#: whatever the host's line-ending convention is.
_LF = chr(10)


def _function_source(name: str) -> str:
    tree = ast.parse(CLOUD_HERO.read_text(encoding="utf-8"), filename=str(CLOUD_HERO))
    function = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    )
    if (
        function.body
        and isinstance(function.body[0], ast.Expr)
        and isinstance(function.body[0].value, ast.Constant)
        and isinstance(function.body[0].value.value, str)
    ):
        # This guard constrains executable behavior, while a docstring documenting an
        # absence must name the absent construct. Scanning that prose would make an
        # honest contract indistinguishable from the defect it rules out.
        function = copy.copy(function)
        function.body = function.body[1:] or [ast.Pass()]
    return ast.unparse(function)


def test_reconciliation_names_only_the_observational_gate_boundary() -> None:
    source = _function_source("reconcile_gate_execution")
    tree = ast.parse(source)
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names.update(node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute))

    assert "reconcile_execution" in names
    for forbidden in (
        "execute",
        "reserve",
        "begin_dispatch",
        "dispatch",
        "open_case",
        "append_transcript_entry",
        "acquire_outstanding",
        "case_status",
        "migrate",
    ):
        assert forbidden not in names, forbidden


def _shell_function(text: str, name: str) -> str:
    start = text.index(f"{name}() {{")
    end = text.index("\n}", start)
    return text[start : end + 2]


def _run_shell(script: str, **environment: str) -> subprocess.CompletedProcess[str]:
    """Run one generated program, from a file rather than from ``-c``.

    **``bash -c`` is not usable here, and the reason is a silent truncation.**
    Git Bash passes the script through the Windows command line, where an
    argument is cut off past roughly 8191 characters -- without an error, and
    without a shortened exit status to notice.  What comes back is
    ``unexpected EOF while looking for matching '}'`` pointing at a line that
    is perfectly balanced, because the closing half was simply never delivered.

    ``muster::require_gate_configuration`` is already over that boundary, and
    it grows every time a proof request is added to it.  A harness that fails
    the moment the *contract it tests* gets one rule longer would be a harness
    that pushes back on writing the rule down -- and it fails by reporting the
    refusal it was checking for, which is the shape of a green test that proves
    nothing.  A temporary file has no such limit.
    """
    shell = posix_shell()
    if shell is None:
        pytest.skip("the deployment contract requires bash")
    with tempfile.NamedTemporaryFile(
        "w", suffix=".sh", delete=False, encoding="utf-8", newline=_LF
    ) as handle:
        handle.write(script + _LF)
        program = handle.name
    try:
        return subprocess.run(  # noqa: S603 - resolved interpreter and generated program
            [shell, Path(program).as_posix()],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, **environment},
        )
    finally:
        os.unlink(program)


def _configuration(**overrides: str) -> subprocess.CompletedProcess[str]:
    settings = {
        "HERO_CASE_ID": "analysis-case",
        "HERO_GATE_CASE_ID": "gate-case",
        "HERO_RUN_CASE_ID": "gate-case",
        "HERO_GATE_MODE": "CLOUD_SQL_ACTION_GATE_SANDBOX",
        "HERO_GATE_REPEAT": "0",
        "HERO_VERIFY_GATE_IDEMPOTENCY": "0",
        "HERO_VERIFY_CASE_REVALIDATION": "0",
        "HERO_VERIFY_GATE_RECONCILIATION": "0",
        "HERO_DATABASE_DEPLOYMENT": "CLOUD_SQL",
    }
    settings.update(overrides)
    return _run_shell(
        "\n".join(
            (
                _shell_function(
                    ENVIRONMENT.read_text(encoding="utf-8"),
                    "muster::require_gate_configuration",
                ),
                *(f'{name}="{value}"' for name, value in settings.items()),
                "muster::require_gate_configuration",
            )
        )
    )


def test_reconciliation_configuration_is_strict_exported_and_gate_scoped() -> None:
    source = ENVIRONMENT.read_text(encoding="utf-8")
    function = _shell_function(source, "muster::require_gate_configuration")

    assert ': "${HERO_VERIFY_GATE_RECONCILIATION=0}"' in source
    assert ': "${HERO_VERIFY_GATE_RECONCILIATION:=0}"' not in source
    assert "export HERO_VERIFY_GATE_RECONCILIATION" in source
    assert "HERO_VERIFY_GATE_RECONCILIATION" in function


@pytest.mark.parametrize("accepted", ("0", "1"))
def test_reconciliation_accepts_only_the_two_closed_values(accepted: str) -> None:
    result = _configuration(HERO_VERIFY_GATE_RECONCILIATION=accepted)

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("malformed", ("true", "yes", "2", "", "01"))
def test_malformed_reconciliation_requests_are_refused(malformed: str) -> None:
    result = _configuration(HERO_VERIFY_GATE_RECONCILIATION=malformed)

    assert result.returncode == 2
    assert "expected 0 or 1" in result.stderr


def test_ephemeral_reconciliation_is_refused() -> None:
    result = _configuration(
        HERO_VERIFY_GATE_RECONCILIATION="1",
        HERO_DATABASE_DEPLOYMENT="EPHEMERAL",
    )

    assert result.returncode == 2
    assert "requires durable custody" in result.stderr


@pytest.mark.parametrize(
    "other",
    (
        "HERO_GATE_REPEAT",
        "HERO_VERIFY_GATE_IDEMPOTENCY",
        "HERO_VERIFY_CASE_REVALIDATION",
    ),
)
def test_reconciliation_is_mutually_exclusive_with_other_proofs(other: str) -> None:
    result = _configuration(
        HERO_VERIFY_GATE_RECONCILIATION="1",
        **{other: "1"},
    )

    assert result.returncode == 2
    assert "cannot be combined" in result.stderr


def test_reconciliation_requires_the_gate_mode() -> None:
    result = _configuration(
        HERO_VERIFY_GATE_RECONCILIATION="1",
        HERO_GATE_MODE="ANALYSIS_ONLY",
        HERO_RUN_CASE_ID="analysis-case",
    )

    assert result.returncode == 2
    assert "CLOUD_SQL_ACTION_GATE_SANDBOX" in result.stderr


def _reconciliation_branch() -> str:
    source = HERO_DEPLOYMENT.read_text(encoding="utf-8")
    opening = 'if [[ "${HERO_VERIFY_GATE_RECONCILIATION:-0}" == "1" ]]; then'
    start = source.index(opening, source.index("gcloud run jobs deploy"))
    end = source.index("\nfi\n", start)
    return source[start : end + len("\nfi\n")]


def _run_reconciliation_branch(
    *,
    status: int = 0,
    readable: bool = True,
    complete: bool = True,
    state: str = "CONFIRMED",
    finality: str = "DEFINITELY_EXECUTED",
    reconciled_from: str = "DISPATCHED",
    dispatches: str = "0",
) -> subprocess.CompletedProcess[str]:
    return _run_shell(
        "\n".join(
            (
                "set -uo pipefail",
                'HERO_VERIFY_GATE_RECONCILIATION="1"',
                'HERO_JOB="hero-job"',
                'CONTROL_PLANE_SA="control-plane@example.invalid"',
                "muster::banner() { :; }",
                'muster::execute_job() { MUSTER_EXECUTION="execution-1"; return "${JOB_STATUS}"; }',
                "muster::execution_output() {",
                '  [[ "${READABLE}" == "1" ]] || return 1',
                '  [[ "${COMPLETE}" == "1" ]] || return 0',
                '  printf "state %s\\n" "${STATE}"',
                '  printf "finality %s\\n" "${FINALITY}"',
                '  printf "reconciled from %s\\n" "${RECONCILED_FROM}"',
                '  printf "dispatches this run %s\\n" "${DISPATCHES}"',
                "}",
                _reconciliation_branch(),
            )
        ),
        JOB_STATUS=str(status),
        READABLE="1" if readable else "0",
        COMPLETE="1" if complete else "0",
        STATE=state,
        FINALITY=finality,
        RECONCILED_FROM=reconciled_from,
        DISPATCHES=dispatches,
    )


def test_stage_ninety_invokes_one_observational_reconciliation_execution() -> None:
    branch = _reconciliation_branch()

    invocation = (
        'muster::execute_job "${HERO_JOB}" '
        '--args="--reconcile-gate-execution"'
    )
    assert invocation in branch
    assert branch.count("muster::execute_job") == 1
    assert "gcloud run jobs deploy" not in branch


def test_stage_ninety_accepts_a_final_reconciliation_without_redispatch() -> None:
    proved = _run_reconciliation_branch()

    assert proved.returncode == 0, proved.stderr
    assert "reconciled from DISPATCHED with no redispatch" in proved.stdout


def test_stage_ninety_refuses_a_reconciliation_that_redispatched() -> None:
    result = _run_reconciliation_branch(dispatches="1")

    assert result.returncode == 1


def test_stage_ninety_refuses_an_unknown_reconciliation_outcome() -> None:
    result = _run_reconciliation_branch(finality="OUTCOME_UNKNOWN")

    assert result.returncode == 1


def test_stage_ninety_refuses_a_row_that_was_already_final() -> None:
    result = _run_reconciliation_branch(reconciled_from="none")

    assert result.returncode == 1


def test_unreadable_reconciliation_output_is_undetermined() -> None:
    result = _run_reconciliation_branch(readable=False)

    assert result.returncode == 4
    assert "UNDETERMINED" in result.stderr


def test_incomplete_reconciliation_output_is_undetermined() -> None:
    result = _run_reconciliation_branch(complete=False)

    assert result.returncode == 4
    assert "UNDETERMINED" in result.stderr


#  ---- the parser and the projection, held to each other ---------------------
#
#  Every shell test above feeds the branch hand-written ``printf`` lines that
#  *look* like the job's output.  That checks the classification and proves
#  nothing about the coupling: renaming a label in ``ReconciledExecution.lines``
#  would leave all of them green while Stage 90 read four empty fields and
#  returned UNDETERMINED forever -- a proof that can never be established, and
#  no test saying so.  So these render the real projection and feed *that*
#  through the real branch.  The import is what binds the two halves; it is the
#  only reason this architecture module imports the composition root.
from demo.cloud_hero import ReconciledExecution, _print_reconciliation  # noqa: E402

PROVING_PROJECTION = ReconciledExecution(
    execution_key="7c" * 32,
    state="CONFIRMED",
    finality="DEFINITELY_EXECUTED",
    outcome_code="CONFIRMED",
    external_reference="sandbox-pay-" + "7c" * 32,
    reconciled_from="UNCERTAIN",
    reconciled_at=2,
    real_funds=False,
    gate_id="cloud-action-gate/v1",
    executor_id="sandbox-payment-cloud/v1",
    principal_id="control-plane@example.invalid",
    dispatch_count=0,
    inspection_count=1,
)


def _rendered(reconciled: ReconciledExecution) -> str:
    """Exactly what the deployed job prints for this reconciliation."""
    printed: list[str] = []
    original = builtins.print

    def capture(*values: object) -> None:
        printed.append(" ".join(str(value) for value in values))

    builtins.print = capture  # type: ignore[assignment]
    try:
        _print_reconciliation(reconciled, heading="rendered for the parser contract")
    finally:
        builtins.print = original
    return "\n".join(printed)


def _run_branch_over(rendered: str, *, status: int = 0) -> subprocess.CompletedProcess[str]:
    """Drive the real Stage-90 branch with the real projection's own bytes."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False, encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(rendered + "\n")
        output_path = handle.name
    try:
        return _run_shell(
            "\n".join(
                (
                    "set -uo pipefail",
                    'HERO_VERIFY_GATE_RECONCILIATION="1"',
                    'HERO_JOB="hero-job"',
                    'CONTROL_PLANE_SA="control-plane@example.invalid"',
                    "muster::banner() { :; }",
                    'muster::execute_job() { MUSTER_EXECUTION="execution-1"; '
                    'return "${JOB_STATUS}"; }',
                    'muster::execution_output() { cat "${RENDERED}"; }',
                    _reconciliation_branch(),
                )
            ),
            JOB_STATUS=str(status),
            RENDERED=Path(output_path).as_posix(),
        )
    finally:
        os.unlink(output_path)


def test_stage_ninety_reads_the_projection_the_job_actually_prints() -> None:
    """The four fields the branch requires are the four the projection emits."""
    rendered = _rendered(PROVING_PROJECTION)

    #  Stated here as well as asserted through the shell, so a failure says
    #  which label moved rather than only that four fields came back empty.
    assert "  state                  CONFIRMED" in rendered
    assert "  finality               DEFINITELY_EXECUTED" in rendered
    assert "  reconciled from        UNCERTAIN" in rendered
    assert "  dispatches this run    0" in rendered

    proved = _run_branch_over(rendered)

    assert proved.returncode == 0, proved.stderr
    assert "reconciled from UNCERTAIN with no redispatch" in proved.stdout


def test_the_projection_of_an_already_final_row_cannot_prove_anything() -> None:
    """``reconciled from none`` is what a CONFIRMED row renders, and it is refused."""
    rendered = _rendered(
        replace(PROVING_PROJECTION, reconciled_from=None, reconciled_at=None)
    )

    assert "  reconciled from        none" in rendered
    assert _run_branch_over(rendered).returncode == 1


def test_the_projection_of_an_unresolved_row_cannot_prove_anything() -> None:
    """An observation that left the outcome unknown is not the proof."""
    rendered = _rendered(
        replace(
            PROVING_PROJECTION,
            state="UNCERTAIN",
            finality="OUTCOME_UNKNOWN",
            external_reference=None,
            outcome_code="SANDBOX_ATTEMPT_IN_PROGRESS",
        )
    )

    assert "  finality               OUTCOME_UNKNOWN" in rendered
    assert _run_branch_over(rendered).returncode == 1


def test_a_projection_that_dispatched_cannot_prove_anything() -> None:
    """Any dispatch by the observing process disproves the observation outright."""
    rendered = _rendered(replace(PROVING_PROJECTION, dispatch_count=1))

    assert "  dispatches this run    1" in rendered
    assert _run_branch_over(rendered).returncode == 1


def test_an_absent_inspection_counter_never_reads_as_a_proof() -> None:
    """``none`` is the honest absence of a counter and must not parse as zero.

    The branch does not read this field, which is the point: the proof rests on
    ``dispatches this run``, a counter every composition keeps.  Rendering it
    absent must therefore change nothing, and must not silently become ``0``.
    """
    rendered = _rendered(replace(PROVING_PROJECTION, inspection_count=None))

    assert "  inspections this run   none" in rendered
    assert "  inspections this run   0" not in rendered
    assert _run_branch_over(rendered).returncode == 0
