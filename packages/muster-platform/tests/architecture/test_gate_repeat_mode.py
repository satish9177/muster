"""The cloud repeat is a guarded re-entry to the one existing Gate path."""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
CLOUD_HERO = REPOSITORY / "demo" / "cloud_hero.py"
ENVIRONMENT = REPOSITORY / "infra" / "scripts" / "env.sh"

#: The generated programs below are POSIX shell and are written as such,
#: whatever the host's line-ending convention is.
_LF = chr(10)
HERO_DEPLOYMENT = REPOSITORY / "infra" / "scripts" / "90-hero-job.sh"


def _function(name: str) -> ast.FunctionDef:
    tree = ast.parse(CLOUD_HERO.read_text(encoding="utf-8"), filename=str(CLOUD_HERO))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} is absent")


def _calls(function: ast.FunctionDef) -> set[str]:
    return {
        node.func.id
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }


def test_repeat_runs_the_full_path_then_the_existing_gate_entry() -> None:
    function = _function("repeat_gate_execution")
    calls = _calls(function)

    assert {"build_casework", "cloud_case", "run_cloud_hero", "execute_cloud_gate"} <= calls
    assert "verify_gate_idempotency" not in calls
    assert "ActionGate" not in calls


def test_repeat_accepts_no_execution_identity() -> None:
    rendered = ast.unparse(_function("repeat_gate_execution"))

    assert "GATE_EXECUTION_ID" not in rendered
    assert "gate_execution_key" not in rendered
    assert "ExecutionKey" not in rendered


def test_repeat_carries_its_own_mode_and_cloud_sql_guards() -> None:
    rendered = ast.unparse(_function("repeat_gate_execution"))

    assert "HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX" in rendered
    assert "DatabaseDeployment.CLOUD_SQL" in rendered


def test_repeat_flag_is_a_distinct_entry_point() -> None:
    source = CLOUD_HERO.read_text(encoding="utf-8")

    assert '"--repeat-gate-execution"' in source
    assert '"--verify-gate-idempotency"' in source


def _shell_function(text: str, name: str) -> str:
    start = text.index(f"{name}() {{")
    end = text.index("\n}", start)
    return text[start : end + 2]


def _run_shell(script: str, **environment: str) -> subprocess.CompletedProcess[str]:
    """Run one generated program, from a file rather than from ``-c``.

    Git Bash truncates a ``-c`` argument past roughly 8191 characters without
    an error and without a distinguishable exit status, and
    ``muster::require_gate_configuration`` is already longer than that.  The
    truncation surfaces as ``unexpected EOF while looking for matching '}'``
    on a balanced line -- and, worse for these tests, as exit status 2, which
    is the refusal several of them are checking for.  A temporary file has no
    such limit, so the contract can keep growing a rule at a time.
    """
    shell = shutil.which("bash")
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


def test_repeat_configuration_is_defaulted_exported_and_ruled_on_in_the_function() -> None:
    source = ENVIRONMENT.read_text(encoding="utf-8")
    function = _shell_function(source, "muster::require_gate_configuration")
    executable_repeat_conditions = [
        line
        for line in source.splitlines()
        if line.lstrip().startswith("if [[") and "HERO_GATE_REPEAT" in line
    ]

    #  ``=`` and not ``:=``.  The default applies to an *unset* variable only, so
    #  an operator who exported an empty one reaches the closed-set refusal
    #  below instead of being handed ``0`` and the ordinary single run.
    assert ': "${HERO_GATE_REPEAT=0}"' in source
    assert ': "${HERO_GATE_REPEAT:=0}"' not in source
    assert "export HERO_GATE_PRINCIPAL HERO_GATE_EXECUTION_ID HERO_GATE_REPEAT" in source
    assert '[[ "${HERO_GATE_REPEAT}" == "1" ]]' in function
    assert 'case "${HERO_GATE_REPEAT}" in' in function
    assert executable_repeat_conditions
    assert all(line in function for line in executable_repeat_conditions)


def _gate_configuration(**overrides: str) -> subprocess.CompletedProcess[str]:
    """Run ``env.sh``'s real refusal function over one candidate configuration.

    The function is lifted out of ``env.sh`` rather than restated, for the
    reason every harness in this file lifts what it runs: a test carrying its
    own copy of a refusal goes on passing against a script that no longer has
    it.  ``HERO_VERIFY_GATE_IDEMPOTENCY`` is set explicitly on every call rather
    than left to the ambient environment, because the mutual-exclusion rule
    below is precisely a rule about its value.
    """
    settings = {
        "HERO_CASE_ID": "analysis-case",
        "HERO_GATE_CASE_ID": "gate-case",
        "HERO_RUN_CASE_ID": "analysis-case",
        "HERO_GATE_MODE": "CLOUD_SQL_ACTION_GATE_SANDBOX",
        "HERO_GATE_REPEAT": "0",
        "HERO_VERIFY_GATE_IDEMPOTENCY": "0",
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


def test_gate_configuration_refuses_repeat_outside_the_gate_mode() -> None:
    refused = _gate_configuration(HERO_GATE_MODE="ANALYSIS_ONLY", HERO_GATE_REPEAT="1")
    accepted = _gate_configuration(HERO_GATE_REPEAT="1")

    assert refused.returncode == 2
    assert "requires" in refused.stderr
    assert accepted.returncode == 0, accepted.stderr


@pytest.mark.parametrize("requested", ("0", "1"))
def test_the_two_repeat_values_a_run_may_ask_for_are_accepted(requested: str) -> None:
    accepted = _gate_configuration(HERO_GATE_REPEAT=requested)

    assert accepted.returncode == 0, accepted.stderr


@pytest.mark.parametrize("malformed", ("true", "yes", "TRUE", "2", "01", " 1", ""))
def test_a_repeat_value_outside_the_closed_set_refuses_rather_than_running_once(
    malformed: str,
) -> None:
    """The failure this refusal exists for, and why it is not pedantry.

    Every reader of ``HERO_GATE_REPEAT`` tests for exactly ``1``.  So ``true``,
    ``yes`` and ``2`` all mean "the ordinary single execution" -- which exits
    **zero**.  An operator who asked for the repeat proof and mistyped it would
    get a green Stage 90 that never ran the second execution, and nothing in the
    log or the exit status would distinguish that from never having asked.

    The empty string is in this list deliberately: it is why the default is
    written ``=`` rather than ``:=``.  Under ``:=`` an exported empty value is
    silently promoted back to ``0`` and this refusal is unreachable.
    """
    refused = _gate_configuration(HERO_GATE_REPEAT=malformed)

    assert refused.returncode == 2
    assert "expected 0 or 1" in refused.stderr


def test_the_two_proof_modes_are_refused_together_rather_than_ordered() -> None:
    """Stage 90 tests the branches in file order; the refusal is what stops that.

    Asking for both proofs is a configuration error, not a priority question.
    The repeat branch is written above the retry branch in ``90-hero-job.sh``, so
    a run configured for both would perform the repeat, exit 0, and say nothing
    about the retry -- and the retry is the one the operator would then believe
    had run.  Refused here, once, rather than silently ordered there.
    """
    refused = _gate_configuration(
        HERO_GATE_REPEAT="1", HERO_VERIFY_GATE_IDEMPOTENCY="1"
    )

    assert refused.returncode == 2
    assert "two" in refused.stderr
    assert "HERO_GATE_REPEAT=1 and HERO_VERIFY_GATE_IDEMPOTENCY=1" in refused.stderr


@pytest.mark.parametrize(
    ("repeat", "verify"),
    (("1", "0"), ("0", "1"), ("0", "0")),
)
def test_either_proof_alone_is_still_accepted(repeat: str, verify: str) -> None:
    """The refusal above must not have made the ordinary configurations illegal."""
    accepted = _gate_configuration(
        HERO_GATE_REPEAT=repeat, HERO_VERIFY_GATE_IDEMPOTENCY=verify
    )

    assert accepted.returncode == 0, accepted.stderr


def _repeat_branch() -> str:
    source = HERO_DEPLOYMENT.read_text(encoding="utf-8")
    opening = 'if [[ "${HERO_GATE_REPEAT:-0}" == "1" ]]; then'
    banner = source.index('muster::banner "running the first gate execution')
    start = source.rindex(opening, 0, banner)
    end = source.index("\nfi\n", start)
    return source[start : end + len("\nfi\n")]


def _sandboxed(inner: str) -> str:
    return "\n".join(
        (
            "set -uo pipefail",
            'sandbox="$(mktemp -d "${TMPDIR:-/tmp}/muster-repeat-test.XXXXXX")"',
            'export TMPDIR="${sandbox}"',
            "(",
            inner,
            ")",
            "code=$?",
            'echo "EXIT_CODE=${code}"',
            'echo "SURVIVORS=[$(ls -A "${sandbox}" 2>/dev/null | sort | tr "\n" " ")]"',
            'rm -rf "${sandbox}"',
            'exit "${code}"',
        )
    )


def _environment_custody() -> str:
    """``env.sh``'s real temporary-directory custody, lifted rather than imitated.

    ``muster::env_file`` makes a 0700 directory for the job's env-vars file and
    installs ``muster::env_cleanup`` on EXIT -- and on INT and TERM -- to remove
    it however the script ends.  Both functions come out of ``env.sh`` verbatim
    and are called the way Stage 90 calls them, because the defect this harness
    exists for is a *second* EXIT trap silently replacing that one: bash keeps
    exactly one handler per signal, so the repeat branch's own ``trap ... EXIT``
    disarms env.sh's unless it re-installs what it replaced.

    A stubbed ``muster::env_cleanup`` would only ever have proved that the stub
    was reachable.  It cannot fail the way the real one can, because the thing
    at risk is the directory ``muster::env_file`` actually created -- so that is
    the directory this harness makes, and the survivor check below is what asks
    whether it is still there.
    """
    text = ENVIRONMENT.read_text(encoding="utf-8")
    return "\n".join(
        (
            'MUSTER_ENV_DIR=""',
            'MUSTER_ENV_FILE=""',
            _shell_function(text, "muster::env_cleanup"),
            _shell_function(text, "muster::env_file"),
            'muster::env_file "${HERO_JOB}"',
            'printf "DATABASE_DSN: a pinned secret reference\n" > "${MUSTER_ENV_FILE}"',
        )
    )


def _repeat(
    *,
    repeat_readable: bool = True,
    matching: bool = True,
    branch: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the real repeat branch against a stubbed Cloud Run and real custody.

    ``branch`` overrides the lifted text for one purpose only: the control below
    runs a *deliberately broken* copy, so that "the sandbox was empty afterwards"
    is a claim with something to fail against rather than a claim about a
    harness that could never have noticed.
    """
    repeat_key = "a1" if matching else "b2"
    inner = "\n".join(
        (
            "set -uo pipefail",
            'HERO_JOB="hero-job"',
            'HERO_GATE_REPEAT="1"',
            'CONTROL_PLANE_SA="control-plane@example.invalid"',
            _environment_custody(),
            'muster::banner() { :; }',
            "calls=0",
            "muster::execute_job() {",
            "  calls=$((calls + 1))",
            '  MUSTER_EXECUTION="exec-${calls}"',
            "  return 0",
            "}",
            "muster::execution_output() {",
            '  if [[ "$2" == "exec-2" && "${REPEAT_READABLE}" != "1" ]]; then',
            "    return 1",
            "  fi",
            '  local key="a1" dispatches="1"',
            '  if [[ "$2" == "exec-2" ]]; then key="${REPEAT_KEY}"; dispatches="0"; fi',
            "  printf 'state                  CONFIRMED\\n'",
            "  printf 'execution id           %s\\n' \"${key}\"",
            "  printf 'external reference     sandbox-ref\\n'",
            "  printf 'dispatches this run    %s\\n' \"${dispatches}\"",
            "}",
            _repeat_branch() if branch is None else branch,
            'echo "FELL_THROUGH"',
        )
    )
    return _run_shell(
        _sandboxed(inner),
        REPEAT_READABLE="1" if repeat_readable else "0",
        REPEAT_KEY=repeat_key,
    )


def _survivors(run: subprocess.CompletedProcess[str]) -> list[str]:
    for line in run.stdout.splitlines():
        if line.startswith("SURVIVORS=["):
            return line[len("SURVIVORS=[") : line.rindex("]")].split()
    raise AssertionError(f"no survivor record:\n{run.stdout}\n{run.stderr}")


def test_repeat_executes_the_same_job_twice_without_redeploying() -> None:
    branch = _repeat_branch()
    deployment = HERO_DEPLOYMENT.read_text(encoding="utf-8")

    assert 'muster::execute_job "${HERO_JOB}"' in branch
    assert (
        'muster::execute_job "${HERO_JOB}" --args="--repeat-gate-execution"' in branch
    )
    assert "gcloud run jobs deploy" not in branch
    assert deployment.index("gcloud run jobs deploy") < deployment.index(branch)
    assert '"${CONTROL_PLANE_IMAGE}" != *@sha256:*' in deployment
    assert "HERO_GATE_EXECUTION_ID" not in branch


def test_repeat_reads_and_compares_both_execution_outputs() -> None:
    branch = _repeat_branch()

    assert branch.count("muster::execution_output") == 2
    for field in (
        "execution id",
        "external reference",
        "state",
        "dispatches this run",
    ):
        assert branch.count(field) >= 2
    assert '"${first_dispatches}" != "1"' in branch
    assert '"${repeat_dispatches}" != "0"' in branch


def test_repeat_proof_accepts_one_then_zero_dispatches_and_cleans_up() -> None:
    proved = _repeat()

    assert proved.returncode == 0, proved.stderr
    assert "one dispatch across both executions" in proved.stdout
    assert "FELL_THROUGH" not in proved.stdout
    assert _survivors(proved) == []


def test_unreadable_repeat_output_is_undetermined_and_cleans_up() -> None:
    undetermined = _repeat(repeat_readable=False)

    assert undetermined.returncode == 4
    assert "UNDETERMINED" in undetermined.stderr
    assert "one dispatch across both executions" not in undetermined.stdout
    assert _survivors(undetermined) == []


def test_a_different_rederived_identity_is_a_negative_verdict() -> None:
    mismatched = _repeat(matching=False)

    assert mismatched.returncode == 1
    assert "did not establish" in mismatched.stderr
    assert _survivors(mismatched) == []


#  ---- the one EXIT trap, and what the repeat branch replaced ---------------


_CHAINED_TRAP = "; muster::env_cleanup' EXIT"


def test_the_repeat_branch_chains_the_cleanup_its_own_trap_replaces() -> None:
    """Literal, because the regression is a one-token deletion.

    ``muster::env_file`` installs ``muster::env_cleanup`` on EXIT when it makes
    the 0700 directory holding this job's env-vars file.  The repeat branch then
    installs its own EXIT trap for two log temporaries, and bash keeps exactly
    one -- so dropping the chained call would leave that directory behind on
    every run.  The behavioural pair below is what proves it; this says which
    token they are about.
    """
    branch = _repeat_branch()

    assert branch.count("trap ") == 1
    assert _CHAINED_TRAP in branch


def test_the_repeat_branch_leaves_no_environment_directory_behind() -> None:
    """Every way out of the branch, against ``env.sh``'s real custody.

    A cleanup that ran only on the happy path would be worse than none: the runs
    that leave the environment directory behind would be exactly the runs an
    operator repeats.
    """
    for run in (_repeat(), _repeat(repeat_readable=False), _repeat(matching=False)):
        assert _survivors(run) == [], run.stdout


def test_a_repeat_branch_that_dropped_the_chain_would_be_caught() -> None:
    """The control, without which the three assertions above prove nothing.

    "The sandbox was empty afterwards" is only evidence if a branch that failed
    to clean up would have left something in it.  So this runs the same harness
    over a copy of the branch with the chained call removed -- the exact defect
    U2 found and fixed on the retry path -- and requires the directory to
    survive.  If this test ever starts passing an empty survivor list, the
    harness has stopped watching and the other three are decoration.
    """
    disarmed = _repeat_branch().replace(_CHAINED_TRAP, "' EXIT")
    assert disarmed != _repeat_branch()

    leaked = _repeat(branch=disarmed)

    assert leaked.returncode == 0, leaked.stderr
    assert _survivors(leaked) != []
