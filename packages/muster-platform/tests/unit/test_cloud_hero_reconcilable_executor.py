"""Which synthetic executor the cloud composition selects, without opening SQL."""

from __future__ import annotations

import pytest
from demo.cloud_hero import (
    CLOUD_EXECUTOR_ID,
    CLOUD_GATE_ID,
    GATE_MODE,
    GATE_SIMULATE_UNKNOWN,
    CloudFleet,
    HeroMode,
    cloud_executor,
    from_environment,
)

from muster.core.values.times import Instant
from muster.platform.adapters.sql.config import (
    DATABASE_DEPLOYMENT,
    DatabaseDeployment,
)
from muster.platform.adapters.sql.sandbox_rail import DurableSandboxPaymentExecutor
from muster.platform.gate.executor import ReconcilableExecutor, SandboxPaymentExecutor
from unit.test_cloud_hero_gate_mode import _environment, _gate_environment


def test_gate_mode_over_cloud_sql_selects_the_reconcilable_simulation() -> None:
    """Durability changes inspectability, never the claim about real funds."""
    fleet = from_environment(_gate_environment())

    executor = cloud_executor(fleet)

    assert isinstance(executor, DurableSandboxPaymentExecutor)
    assert isinstance(executor, ReconcilableExecutor)
    assert executor.executor_id == CLOUD_EXECUTOR_ID
    assert executor.trusted_gate_id == CLOUD_GATE_ID
    assert executor.transfers_real_funds is False


def test_analysis_over_ephemeral_custody_keeps_the_in_memory_simulation() -> None:
    """An analysis does not acquire a reconciliation boundary by accident."""
    fleet = from_environment(
        _environment(**{DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value})
    )

    executor = cloud_executor(fleet)

    assert isinstance(executor, SandboxPaymentExecutor)
    assert not isinstance(executor, ReconcilableExecutor)
    assert executor.executor_id == CLOUD_EXECUTOR_ID
    assert executor.trusted_gate_id == CLOUD_GATE_ID
    assert executor.transfers_real_funds is False


def test_the_durable_simulation_receives_only_the_fleets_configured_dsn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The composition root forwards custody; it does not discover another store."""
    fleet = from_environment(_gate_environment())
    received: list[str] = []

    def durable_executor(
        dsn: str,
        *,
        accepted_at: Instant,
        executor_id: str,
        trusted_gate_id: str,
    ) -> DurableSandboxPaymentExecutor:
        received.append(dsn)
        return DurableSandboxPaymentExecutor(
            dsn,
            accepted_at=accepted_at,
            executor_id=executor_id,
            trusted_gate_id=trusted_gate_id,
        )

    monkeypatch.setattr(
        "demo.cloud_hero.DurableSandboxPaymentExecutor", durable_executor
    )

    cloud_executor(fleet)

    assert fleet.postgres is not None
    assert received == [fleet.postgres]


#  ---- the demo-only unknown-after-acceptance simulation --------------------
#
#  The selection is tested here rather than only end-to-end because it is the
#  one place a failure injection could reach a composition nobody asked to
#  inject into.  Every negative below is a way that must not happen.


def test_an_unrequested_simulation_keeps_the_ordinary_durable_executor() -> None:
    """The default composition is the one that reports what it observed."""
    fleet = from_environment(_gate_environment())

    executor = cloud_executor(fleet)

    assert fleet.gate_simulate_unknown is False
    assert type(executor) is DurableSandboxPaymentExecutor


def test_an_explicit_zero_keeps_the_ordinary_durable_executor() -> None:
    """Asking for no simulation is not the same as asking for one."""
    fleet = from_environment(_gate_environment(**{GATE_SIMULATE_UNKNOWN: "0"}))

    executor = cloud_executor(fleet)

    assert fleet.gate_simulate_unknown is False
    assert type(executor) is DurableSandboxPaymentExecutor


def test_the_requested_simulation_selects_the_unknown_after_acceptance_executor() -> None:
    """Gate mode over CLOUD_SQL, and the flag, select the injecting simulation."""
    fleet = from_environment(_gate_environment(**{GATE_SIMULATE_UNKNOWN: "1"}))

    executor = cloud_executor(fleet)

    assert fleet.gate_simulate_unknown is True
    #  A subclass of the durable simulation, so it is still reconcilable, still
    #  identified as this deployment's executor, and still moves no money.
    assert type(executor) is not DurableSandboxPaymentExecutor
    assert isinstance(executor, DurableSandboxPaymentExecutor)
    assert isinstance(executor, ReconcilableExecutor)
    assert executor.executor_id == CLOUD_EXECUTOR_ID
    assert executor.trusted_gate_id == CLOUD_GATE_ID
    assert executor.transfers_real_funds is False


@pytest.mark.parametrize("malformed", ("true", "yes", "2", "", "01", "1 1"))
def test_a_simulation_request_that_is_not_zero_or_one_is_refused(malformed: str) -> None:
    """A misspelt injection request must not read as the ordinary run."""
    with pytest.raises(SystemExit, match="expected 0 or 1"):
        from_environment(_gate_environment(**{GATE_SIMULATE_UNKNOWN: malformed}))


def test_the_simulation_is_refused_without_the_gate_mode() -> None:
    """An analysis-only run composes no executor to inject anything into."""
    environment = _environment(
        **{
            DATABASE_DEPLOYMENT: DatabaseDeployment.EPHEMERAL.value,
            GATE_SIMULATE_UNKNOWN: "1",
        }
    )

    with pytest.raises(SystemExit, match=GATE_MODE):
        from_environment(environment)


def test_a_fleet_built_by_hand_cannot_carry_the_simulation_without_the_mode() -> None:
    """The constructor closes the door ``from_environment`` closes."""
    with pytest.raises(ValueError, match="unknown-after-acceptance"):
        CloudFleet(
            tenant_id="tenant",
            case_id="case",
            site_endpoint="https://site.example.invalid",
            employer_endpoint="https://employer.example.invalid",
            site_key_ref="site-key/test",
            employer_key_ref="employer-key/test",
            site_public_key=b"",
            employer_public_key=b"",
            timeout_seconds=None,
            raw_object=None,
            postgres=None,
            deployment=DatabaseDeployment.EPHEMERAL,
            gate_mode=HeroMode.ANALYSIS_ONLY,
            gate_simulate_unknown=True,
        )
