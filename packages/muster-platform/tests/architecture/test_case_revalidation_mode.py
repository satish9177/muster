"""The durable revalidation path is structurally unable to execute or write."""

from __future__ import annotations

import ast
import copy
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
CLOUD_HERO = REPOSITORY / "demo" / "cloud_hero.py"
ENVIRONMENT = REPOSITORY / "infra" / "scripts" / "env.sh"
HERO_DEPLOYMENT = REPOSITORY / "infra" / "scripts" / "90-hero-job.sh"


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


def test_revalidation_constructs_no_gate_and_opens_no_write_scope() -> None:
    source = _function_source("revalidate_durable_case")

    for forbidden in (
        "ActionGate",
        "executor",
        "GateCaller",
        "writing",
        "acquire_outstanding",
        "ExecutionKey",
    ):
        assert forbidden not in source, forbidden


def _shell_function(text: str, name: str) -> str:
    start = text.index(f"{name}() {{")
    end = text.index("\n}", start)
    return text[start : end + 2]


def _run_shell(script: str, **environment: str) -> subprocess.CompletedProcess[str]:
    shell = shutil.which("bash")
    if shell is None:
        pytest.skip("the deployment contract requires bash")
    return subprocess.run(  # noqa: S603 - resolved interpreter and fixed test program
        [shell, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **environment},
    )


def _configuration(**overrides: str) -> subprocess.CompletedProcess[str]:
    settings = {
        "HERO_CASE_ID": "analysis-case",
        "HERO_GATE_CASE_ID": "gate-case",
        "HERO_RUN_CASE_ID": "analysis-case",
        "HERO_GATE_MODE": "ANALYSIS_ONLY",
        "HERO_GATE_REPEAT": "0",
        "HERO_VERIFY_GATE_IDEMPOTENCY": "0",
        "HERO_VERIFY_CASE_REVALIDATION": "0",
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


def test_revalidation_configuration_is_strict_and_scoped_to_the_gate_check() -> None:
    source = ENVIRONMENT.read_text(encoding="utf-8")
    function = _shell_function(source, "muster::require_gate_configuration")

    assert ': "${HERO_VERIFY_CASE_REVALIDATION=0}"' in source
    assert ': "${HERO_VERIFY_CASE_REVALIDATION:=0}"' not in source
    assert "export HERO_VERIFY_CASE_REVALIDATION" in source
    assert "HERO_VERIFY_CASE_REVALIDATION" in function


@pytest.mark.parametrize("accepted", ("0", "1"))
def test_revalidation_accepts_only_the_two_closed_values(accepted: str) -> None:
    result = _configuration(HERO_VERIFY_CASE_REVALIDATION=accepted)

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("malformed", ("true", "yes", "2", "", "01"))
def test_malformed_revalidation_requests_are_refused(malformed: str) -> None:
    result = _configuration(HERO_VERIFY_CASE_REVALIDATION=malformed)

    assert result.returncode == 2
    assert "expected 0 or 1" in result.stderr


def test_ephemeral_revalidation_is_refused() -> None:
    result = _configuration(
        HERO_VERIFY_CASE_REVALIDATION="1",
        HERO_DATABASE_DEPLOYMENT="EPHEMERAL",
    )

    assert result.returncode == 2
    assert "requires durable custody" in result.stderr


@pytest.mark.parametrize(
    "other",
    ("HERO_GATE_REPEAT", "HERO_VERIFY_GATE_IDEMPOTENCY"),
)
def test_revalidation_is_mutually_exclusive_with_other_proofs(other: str) -> None:
    result = _configuration(
        HERO_VERIFY_CASE_REVALIDATION="1",
        **{other: "1"},
    )

    assert result.returncode == 2
    assert "cannot be combined" in result.stderr


def _revalidation_branch() -> str:
    source = HERO_DEPLOYMENT.read_text(encoding="utf-8")
    opening = 'if [[ "${HERO_VERIFY_CASE_REVALIDATION:-0}" == "1" ]]; then'
    start = source.index(opening)
    end = source.index("\nfi\n", start)
    return source[start : end + len("\nfi\n")]


def _run_revalidation_branch(
    *,
    status: int = 0,
    readable: bool = True,
    reproduced: str = "true",
    writes: str = "0",
    dispatches: str = "0",
) -> subprocess.CompletedProcess[str]:
    return _run_shell(
        "\n".join(
            (
                "set -uo pipefail",
                'HERO_VERIFY_CASE_REVALIDATION="1"',
                'HERO_JOB="hero-job"',
                'CONTROL_PLANE_SA="control-plane@example.invalid"',
                "muster::banner() { :; }",
                'muster::execute_job() { MUSTER_EXECUTION="execution-1"; return "${JOB_STATUS}"; }',
                "muster::execution_output() {",
                '  [[ "${READABLE}" == "1" ]] || return 1',
                '  printf "certificate reproduced %s\\n" "${REPRODUCED}"',
                '  printf "writes %s\\n" "${WRITES}"',
                '  printf "dispatches %s\\n" "${DISPATCHES}"',
                "}",
                _revalidation_branch(),
            )
        ),
        JOB_STATUS=str(status),
        READABLE="1" if readable else "0",
        REPRODUCED=reproduced,
        WRITES=writes,
        DISPATCHES=dispatches,
    )


def test_stage_ninety_invokes_one_read_only_revalidation_execution() -> None:
    branch = _revalidation_branch()
    deployment = HERO_DEPLOYMENT.read_text(encoding="utf-8")

    assert 'muster::execute_job "${HERO_JOB}" --args="--revalidate-durable-case"' in branch
    assert branch.count("muster::execute_job") == 1
    assert "gcloud run jobs deploy" not in branch
    assert deployment.index("muster::require_gate_configuration || exit 2") < deployment.index(
        "gcloud run jobs deploy"
    )


def test_stage_ninety_accepts_only_a_reproduced_side_effect_free_result() -> None:
    proved = _run_revalidation_branch()
    not_reproduced = _run_revalidation_branch(reproduced="false")
    wrote = _run_revalidation_branch(writes="1")

    assert proved.returncode == 0, proved.stderr
    assert "zero writes and zero dispatches" in proved.stdout
    assert not_reproduced.returncode == 1
    assert wrote.returncode == 1


def test_unreadable_revalidation_output_is_undetermined() -> None:
    result = _run_revalidation_branch(readable=False)

    assert result.returncode == 4
    assert "UNDETERMINED" in result.stderr
