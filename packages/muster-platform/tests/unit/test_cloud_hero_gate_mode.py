"""Which run the deployed control plane was asked for, and what it refuses.

One property this file exists for: **a control plane told to analyse never
executes, and a control plane told to execute never does so on evidence or
custody it does not have.**  The Gate is a mode an operator names; it is not a
capability that switches itself on when the configuration happens to allow it.

Nothing here connects to a database, a metadata server or an agent.  What is
under test is the configuration boundary -- the point at which a set of
environment variables becomes, or fails to become, a run that can pay somebody.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace
from typing import cast

import pytest
from demo.cloud_hero import (
    CASE,
    CLOUD_EXECUTOR_ID,
    CLOUD_GATE_ID,
    EMPLOYER_ENDPOINT,
    EMPLOYER_KEY_REF,
    EMPLOYER_PUBLIC_KEY,
    GATE_EXECUTION_ID,
    GATE_MODE,
    GATE_PRINCIPAL,
    SITE_ENDPOINT,
    SITE_KEY_REF,
    SITE_PUBLIC_KEY,
    TENANT,
    CloudFleet,
    CloudGateExecution,
    HeroMode,
    _configuration_lines,
    build_transport,
    cloud_executor,
    from_environment,
    main,
    repeat_gate_execution,
)

from muster.core.evidence.delivery import AcquisitionTransport
from muster.platform.adapters.memory import MemoryDatabase
from muster.platform.adapters.sql.config import (
    DATABASE_DEPLOYMENT,
    DATABASE_URL,
    DatabaseDeployment,
)

SERVER_CA = "/var/run/muster/cloud-sql/server-ca.pem"
CLOUD_SQL_DSN = (
    "postgresql://muster-runtime:not-a-real-secret@10.20.30.40:5432/muster"
    f"?sslmode=verify-ca&sslrootcert={SERVER_CA}"
    "&connect_timeout=10&application_name=muster-control-plane"
)
PRINCIPAL = "muster-control-plane@muster-project.iam.gserviceaccount.com"
EXECUTION_KEY = "3f" * 32


def _environment(**overrides: str) -> dict[str, str]:
    keys = base64.b64encode(b"-----BEGIN PUBLIC KEY-----\n").decode("ascii")
    environment = {
        TENANT: "ALPHA",
        CASE: "CASE-RAVI-SAT-CLOUD-GATE",
        SITE_ENDPOINT: "https://site.example.run.app",
        EMPLOYER_ENDPOINT: "https://employer.example.run.app",
        SITE_KEY_REF: "site-key/1",
        EMPLOYER_KEY_REF: "employer-key/1",
        SITE_PUBLIC_KEY: keys,
        EMPLOYER_PUBLIC_KEY: keys,
    }
    environment.update(overrides)
    return environment


def _gate_environment(**overrides: str) -> dict[str, str]:
    return _environment(
        **{
            DATABASE_DEPLOYMENT: DatabaseDeployment.CLOUD_SQL.value,
            DATABASE_URL: CLOUD_SQL_DSN,
            GATE_MODE: HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX.value,
            GATE_PRINCIPAL: PRINCIPAL,
            **overrides,
        }
    )


#  ---- the default is the run U1 verified ----------------------------------


def test_a_deployment_that_names_no_mode_gets_the_analysis() -> None:
    """The absence of a decision is not permission to act."""
    fleet = from_environment(
        _environment(**{DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value})
    )
    assert fleet.gate_mode is HeroMode.ANALYSIS_ONLY
    assert fleet.gate_principal is None
    assert fleet.gate_execution_key is None


def test_a_mode_this_deployment_does_not_have_is_refused_rather_than_ignored() -> None:
    """A mistyped mode must not silently become the default.

    Falling back would be the worse failure in *both* directions: an operator
    who meant to execute gets an analysis they describe afterwards as a
    payment, and the vocabulary that decides it is a string from a shell.
    """
    for spelling in ("action_gate", "CLOUD_SQL", "cloud_sql_action_gate_sandbox", "1"):
        with pytest.raises(SystemExit, match="MALFORMED"):
            from_environment(
                _environment(
                    **{
                        DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value,
                        GATE_MODE: spelling,
                    }
                )
            )


#  ---- the Gate's two preconditions ----------------------------------------


def test_the_gate_mode_requires_durable_custody() -> None:
    """An execution lifecycle kept in memory is a proof about one process.

    The whole claim of the mode is that a *second* process can read what the
    first one did.  Ephemeral custody cannot support that sentence, so the mode
    is refused rather than downgraded.
    """
    with pytest.raises(SystemExit, match="GATE REFUSED"):
        from_environment(
            _environment(
                **{
                    DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value,
                    GATE_MODE: HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX.value,
                    GATE_PRINCIPAL: PRINCIPAL,
                }
            )
        )


def test_the_gate_mode_requires_a_named_principal() -> None:
    """An absent grant is refused, never defaulted.

    A Gate that supplied its own expected principal would be a Gate asserting
    both halves of the comparison it exists to make.
    """
    environment = _gate_environment()
    del environment[GATE_PRINCIPAL]
    with pytest.raises(SystemExit, match=f"MISSING: {GATE_PRINCIPAL}"):
        from_environment(environment)


def test_a_complete_gate_deployment_is_assembled() -> None:
    fleet = from_environment(_gate_environment(**{GATE_EXECUTION_ID: EXECUTION_KEY}))

    assert fleet.gate_mode is HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX
    assert fleet.deployment is DatabaseDeployment.CLOUD_SQL
    assert fleet.gate_principal == PRINCIPAL
    assert fleet.gate_execution_key is not None
    assert fleet.gate_execution_key.octets == bytes.fromhex(EXECUTION_KEY)


#  ---- the retry's durable identity ----------------------------------------


@pytest.mark.parametrize(
    "malformed",
    [
        "3F" * 32,
        "3f" * 31,
        "3f" * 33,
        "not-a-digest",
        f"{'3f' * 31}zz",
        f"{'3f' * 16} {'3f' * 16}",
    ],
)
def test_a_malformed_execution_key_is_a_configuration_refusal(malformed: str) -> None:
    """Uppercase and interior whitespace included, and deliberately.

    ``bytes.fromhex`` accepts both, and the value has to be the exact key the
    first execution printed.  A retry that silently normalised would be a retry
    whose identity depended on how an operator happened to paste it.
    """
    with pytest.raises(SystemExit, match=f"MALFORMED: {GATE_EXECUTION_ID}"):
        from_environment(_gate_environment(**{GATE_EXECUTION_ID: malformed}))


def test_surrounding_whitespace_is_trimmed_like_every_other_variable() -> None:
    """Trimmed at the edges, refused in the middle.

    A deployment script, a container spec and a shell all add trailing
    whitespace, and every other value this module reads is stripped for that
    reason.  What is *not* forgiven is a value whose interior differs from the
    stored one, which the length and alphabet checks above already refuse.
    """
    fleet = from_environment(_gate_environment(**{GATE_EXECUTION_ID: f"  {EXECUTION_KEY}\n"}))
    assert fleet.gate_execution_key is not None
    assert fleet.gate_execution_key.octets == bytes.fromhex(EXECUTION_KEY)


def test_an_absent_execution_key_is_absent_rather_than_empty() -> None:
    fleet = from_environment(_gate_environment(**{GATE_EXECUTION_ID: "   "}))
    assert fleet.gate_execution_key is None


#  ---- the full repeat derives identity rather than accepting one ---------


def test_repeat_flag_requires_the_named_gate_mode() -> None:
    fleet = from_environment(
        _environment(**{DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value})
    )

    with pytest.raises(SystemExit, match="GATE REPEAT REFUSED"):
        repeat_gate_execution(MemoryDatabase(), fleet, build_transport(fleet))


def test_repeat_flag_requires_cloud_sql_even_when_the_mode_is_claimed() -> None:
    inconsistent = cast(
        CloudFleet,
        SimpleNamespace(
            gate_mode=HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX,
            deployment=DatabaseDeployment.EPHEMERAL,
        ),
    )

    with pytest.raises(SystemExit, match="CLOUD_SQL custody"):
        repeat_gate_execution(
            MemoryDatabase(), inconsistent, cast(AcquisitionTransport, object())
        )


def test_repeat_flag_needs_no_configured_execution_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in _gate_environment().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(GATE_EXECUTION_ID, raising=False)
    seen: list[CloudFleet] = []

    def repeated(
        _database: object, fleet: CloudFleet, _transport: object
    ) -> CloudGateExecution:
        seen.append(fleet)
        return cast(CloudGateExecution, SimpleNamespace(state="CONFIRMED"))

    monkeypatch.setattr("demo.cloud_hero.open_database", lambda _fleet: MemoryDatabase())
    monkeypatch.setattr("demo.cloud_hero.repeat_gate_execution", repeated)
    monkeypatch.setattr(
        "demo.cloud_hero._print_execution", lambda _execution, *, heading: None  # noqa: ARG005
    )

    assert main(["--repeat-gate-execution"]) == 0
    assert len(seen) == 1
    assert seen[0].gate_execution_key is None


#  ---- a fleet built by hand cannot claim what it has not got ---------------


def test_a_directly_constructed_fleet_cannot_claim_a_gate_over_memory() -> None:
    """``from_environment`` is not the only door, so the value closes the other.

    A fleet assembled in a test or in a later composition root must not be able
    to say "durable execution proof" while carrying no database.
    """
    with pytest.raises(ValueError, match="CLOUD_SQL custody"):
        CloudFleet(
            tenant_id="ALPHA",
            case_id="CASE-RAVI-SAT-CLOUD-GATE",
            site_endpoint="https://site.example.run.app",
            employer_endpoint="https://employer.example.run.app",
            site_key_ref="site-key/1",
            employer_key_ref="employer-key/1",
            site_public_key=b"",
            employer_public_key=b"",
            timeout_seconds=None,
            raw_object=None,
            postgres=None,
            gate_mode=HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX,
            gate_principal=PRINCIPAL,
        )


def test_a_directly_constructed_fleet_cannot_claim_a_gate_with_no_principal() -> None:
    with pytest.raises(ValueError, match="names the principal"):
        CloudFleet(
            tenant_id="ALPHA",
            case_id="CASE-RAVI-SAT-CLOUD-GATE",
            site_endpoint="https://site.example.run.app",
            employer_endpoint="https://employer.example.run.app",
            site_key_ref="site-key/1",
            employer_key_ref="employer-key/1",
            site_public_key=b"",
            employer_public_key=b"",
            timeout_seconds=None,
            raw_object=None,
            postgres=CLOUD_SQL_DSN,
            deployment=DatabaseDeployment.CLOUD_SQL,
            gate_mode=HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX,
        )


#  ---- the executor, and what it says about itself --------------------------


def test_the_cloud_executor_is_the_sandbox_and_moves_no_funds() -> None:
    """Read from the composed value rather than from a label.

    ``transfers_real_funds`` is what the published trace reports, so a
    composition that ever named a real executor could not print ``false``.
    """
    executor = cloud_executor()
    assert executor.executor_id == CLOUD_EXECUTOR_ID
    assert executor.trusted_gate_id == CLOUD_GATE_ID
    assert executor.transfers_real_funds is False
    assert executor.dispatch_count == 0
    assert executor.execution_count == 0


#  ---- what an operator is told before anything runs ------------------------


def test_the_configuration_report_names_the_mode_the_gate_and_the_principal() -> None:
    fleet = from_environment(_gate_environment())
    lines = _configuration_lines(fleet, build_transport(fleet))
    report = "\n".join(lines)

    assert "CLOUD_SQL + ACTION_GATE_SANDBOX" in report
    assert "SANDBOX: NO REAL FUNDS TRANSFERRED" in report
    assert CLOUD_GATE_ID in report
    assert CLOUD_EXECUTOR_ID in report
    assert PRINCIPAL in report
    #  And no credential, under either mode.
    assert "not-a-real-secret" not in report


def test_the_analysis_report_says_the_run_stops_rather_than_naming_a_gate() -> None:
    """A configuration report that made an analysis sound like an execution is
    how a run that paid nobody gets described afterwards as one that did."""
    fleet = from_environment(
        _environment(**{DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value})
    )
    report = "\n".join(_configuration_lines(fleet, build_transport(fleet)))

    assert "ANALYSIS ONLY" in report
    assert "no gate" in report
    assert "not configured" in report
