"""The demo-only unknown-after-acceptance simulation, and where it may not reach.

This flag is the only one in the deployment that asks a run to *fail*, so every
test here is about a way it must not be able to arrive: not by a truthy
spelling, not under analysis-only custody, not alongside a proof that reads
durable state, and not through the composition an observation uses.
"""

from __future__ import annotations

import ast
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from support.shell import posix_shell

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
CLOUD_HERO = REPOSITORY / "demo" / "cloud_hero.py"
ENVIRONMENT = REPOSITORY / "infra" / "scripts" / "env.sh"
HERO_DEPLOYMENT = REPOSITORY / "infra" / "scripts" / "90-hero-job.sh"

FLAG = "HERO_GATE_SIMULATE_UNKNOWN_AFTER_ACCEPTANCE"
CONTAINER_FLAG = "MUSTER_HERO_GATE_SIMULATE_UNKNOWN_AFTER_ACCEPTANCE"

#: The generated programs below are POSIX shell and are written as such,
#: whatever the host's line-ending convention is.
_LF = chr(10)


def _shell_function(text: str, name: str) -> str:
    start = text.index(f"{name}() {{")
    end = text.index("\n}", start)
    return text[start : end + 2]


def _run_shell(script: str, **environment: str) -> subprocess.CompletedProcess[str]:
    """Run one generated program, from a file rather than from ``-c``.

    See the identical note in ``test_gate_reconciliation_mode``: Git Bash
    truncates a ``-c`` argument past roughly 8191 characters without saying so,
    and the configuration function this file exercises is already longer than
    that.  The truncation surfaces as the very refusal these tests look for,
    which would make them pass while checking nothing.
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
        FLAG: "0",
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


#  ---- the value itself ----------------------------------------------------


def test_the_simulation_flag_is_strict_exported_and_gate_scoped() -> None:
    source = ENVIRONMENT.read_text(encoding="utf-8")
    function = _shell_function(source, "muster::require_gate_configuration")

    #  ``=`` and not ``:=``: an explicit empty value must reach the refusal
    #  rather than being promoted back to the default.
    assert f': "${{{FLAG}=0}}"' in source
    assert f': "${{{FLAG}:=0}}"' not in source
    assert f"export {FLAG}" in source or f"{FLAG}\n" in source
    assert FLAG in function


@pytest.mark.parametrize("accepted", ("0", "1"))
def test_the_simulation_accepts_only_the_two_closed_values(accepted: str) -> None:
    result = _configuration(**{FLAG: accepted})

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("malformed", ("true", "yes", "2", "", "01", "on"))
def test_a_malformed_simulation_request_is_refused(malformed: str) -> None:
    """Including the empty string, which is the one a shell produces by accident."""
    result = _configuration(**{FLAG: malformed})

    assert result.returncode == 2
    assert "expected 0 or 1" in result.stderr


def test_the_simulation_requires_durable_custody() -> None:
    result = _configuration(
        **{FLAG: "1", "HERO_DATABASE_DEPLOYMENT": "EPHEMERAL"},
    )

    assert result.returncode == 2
    assert "requires CLOUD_SQL custody" in result.stderr


def test_the_simulation_requires_the_gate_mode() -> None:
    result = _configuration(
        **{
            FLAG: "1",
            "HERO_GATE_MODE": "ANALYSIS_ONLY",
            "HERO_RUN_CASE_ID": "analysis-case",
        },
    )

    assert result.returncode == 2
    assert "CLOUD_SQL_ACTION_GATE_SANDBOX" in result.stderr


@pytest.mark.parametrize(
    "proof",
    (
        "HERO_VERIFY_GATE_RECONCILIATION",
        "HERO_GATE_REPEAT",
        "HERO_VERIFY_GATE_IDEMPOTENCY",
        "HERO_VERIFY_CASE_REVALIDATION",
    ),
)
def test_the_simulation_cannot_be_combined_with_a_proof_request(proof: str) -> None:
    """A run that manufactured the state it reported would prove the opposite."""
    result = _configuration(**{FLAG: "1", proof: "1"})

    assert result.returncode == 2
    assert "cannot be combined" in result.stderr


#  ---- and where the decision travels --------------------------------------


def test_the_deployment_carries_the_decision_into_the_container() -> None:
    """The job cannot inherit the operator's shell; the value is written by name."""
    source = HERO_DEPLOYMENT.read_text(encoding="utf-8")

    assert f'muster::env_entry {CONTAINER_FLAG} \\\n    "${{{FLAG}}}"' in source


def test_the_setup_run_is_the_ordinary_run_and_not_a_new_job_execution() -> None:
    """No branch, no second execution: the flag changes the composition, not the flow.

    Stage 90 gains no ``--args`` for this.  The setup is the hero job's own
    entry point with one environment variable set, which is what keeps the
    UNCERTAIN row a product of the ordinary path rather than of a code path
    that exists only to produce it.
    """
    source = HERO_DEPLOYMENT.read_text(encoding="utf-8")

    assert "--simulate-unknown" not in source
    assert f'muster::execute_job "${{HERO_JOB}}" --args="--{FLAG.lower()}"' not in source
    #  The only place the flag decides anything in this script is the published
    #  UI copy, and the case-trace capture it guards.
    deciding = [
        line
        for line in source.splitlines()
        if FLAG in line and line.lstrip().startswith(("if", "&&", "||"))
    ]
    assert len(deciding) == 2, deciding


def test_the_setup_run_does_not_publish_its_unresolved_execution_to_the_ui() -> None:
    """An unreconciled row must not become the trace an audience is shown."""
    source = HERO_DEPLOYMENT.read_text(encoding="utf-8")
    start = source.index('artifact_output="${EVIDENCE_DIR}/case-traces/')
    end = source.index("the case reached the invariant answer", start)
    capture = source[start:end]

    assert "ravi-cloud-execution.json" in capture
    assert f'if [[ "${{{FLAG}:-0}}" == "1" ]]; then' in capture
    assert "ui_capture=()" in capture
    #  The evidence trace is still written: it is this execution's own record,
    #  and an UNCERTAIN one is as real as a CONFIRMED one.
    assert '--output "${artifact_output}"' in capture


#  ---- and the one place in Python that may read it ------------------------


def test_only_the_composition_root_reads_the_simulation_decision() -> None:
    """The Gate never learns which simulation the composition root selected."""
    gate = REPOSITORY / "packages" / "muster-platform" / "src" / "muster" / "platform" / "gate"
    adapters = (
        REPOSITORY
        / "packages"
        / "muster-platform"
        / "src"
        / "muster"
        / "platform"
        / "adapters"
    )
    for module in (*gate.rglob("*.py"), *adapters.rglob("*.py")):
        text = module.read_text(encoding="utf-8")
        assert CONTAINER_FLAG not in text, module
        assert "gate_simulate_unknown" not in text, module


def test_the_injection_raises_only_after_the_inherited_dispatch_returned() -> None:
    """The ordering is the proof, and it is checked in the source, not narrated.

    ``super().dispatch`` must be *called and bound* before the raise, because
    its return is what establishes that the simulated external system committed.
    A raise that preceded it would leave nothing to reconcile.
    """
    tree = ast.parse(CLOUD_HERO.read_text(encoding="utf-8"), filename=str(CLOUD_HERO))
    injector = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "_LosesTheAnswerAfterAcceptance"
    )
    dispatch = next(
        node
        for node in injector.body
        if isinstance(node, ast.FunctionDef) and node.name == "dispatch"
    )
    statements = [
        node
        for node in dispatch.body
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
    ]

    #  The first statement binds the inherited dispatch's result.
    first = statements[0]
    assert isinstance(first, ast.Assign)
    call = first.value
    assert isinstance(call, ast.Call)
    assert isinstance(call.func, ast.Attribute) and call.func.attr == "dispatch"
    assert isinstance(call.func.value, ast.Call)
    assert isinstance(call.func.value.func, ast.Name)
    assert call.func.value.func.id == "super"

    #  The raise is the last statement, and there is exactly one.
    raises = [node for node in ast.walk(dispatch) if isinstance(node, ast.Raise)]
    assert len(raises) == 1
    assert isinstance(statements[-1], ast.Raise)

    #  Nothing in it writes to the simulated external system or names the Gate.
    body = ast.unparse(dispatch)
    for forbidden in ("psycopg", "sandbox_rail", "INSERT", "UPDATE", "ActionGate"):
        assert forbidden not in body, forbidden
