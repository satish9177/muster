"""The deployed composition, end to end, against a real PostgreSQL.

Not the pieces: the exact functions Stage 90 calls, in the order it calls them,
over a database that outlives the objects.  ``execute_cloud_gate`` authorizes
and runs the Gate; ``verify_gate_idempotency`` is then given a *fresh*
database handle, a fresh executor and a fresh Gate, and asked the question a
second Cloud Run execution asks.

The one thing substituted is the metadata server, because a test process has
no cloud identity.  Everything else -- the authority resolution, the exact
grant, the proposal derived from the case, the reservation, the dispatch
compare-and-swap, the durable lifecycle and the idempotency read -- is the
deployed code path.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

import psycopg
import pytest
from demo.cloud_hero import (
    CLOUD_EXECUTOR_ID,
    CLOUD_GATE_ID,
    CloudFleet,
    HeroMode,
    RawAccess,
    RawAttempt,
    build_casework,
    cloud_case,
    execute_cloud_gate,
    repeat_gate_execution,
    run_cloud_hero,
    verify_gate_idempotency,
)

from muster.core.results import Err, Ok, Result
from muster.platform.adapters.sql.config import DatabaseDeployment
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.advance import Casework
from muster.platform.casework.commands import (
    CaseReport,
    append_transcript_entry,
    case_status,
)
from muster.platform.gate.cloud import CloudPrincipalError, CloudPrincipalFailure
from muster.platform.gate.model import ExecutionKey
from support import ravi
from support.fixtures import append_all, open_ravi, split_at_the_inert_claim

pytestmark = pytest.mark.postgres

PRINCIPAL = "muster-control-plane@muster-project.iam.gserviceaccount.com"
OTHER = "muster-migrator@muster-project.iam.gserviceaccount.com"


@dataclass(frozen=True, slots=True)
class _Runtime:
    """The metadata server, as this process is pretending to be one."""

    answer: Result[str, CloudPrincipalError]

    def principal_id(self) -> Result[str, CloudPrincipalError]:
        return self.answer


#: What the metadata server is currently answering.  Installed by the fixture
#: below, which starts every test as the provisioned principal and hands back
#: the setter so a test can become somebody else.
type RunningAs = Callable[[Result[str, CloudPrincipalError]], None]


@pytest.fixture
def running_as(monkeypatch: pytest.MonkeyPatch) -> RunningAs:
    def _running_as(answer: Result[str, CloudPrincipalError]) -> None:
        monkeypatch.setattr(
            "demo.cloud_hero.MetadataServerPrincipal", lambda: _Runtime(answer)
        )

    _running_as(Ok(PRINCIPAL))
    return _running_as


def _fleet(
    dsn: str | None,
    tenant_id: str,
    case_id: str,
    *,
    deployment: DatabaseDeployment = DatabaseDeployment.CLOUD_SQL,
    gate_execution_key: ExecutionKey | None = None,
) -> CloudFleet:
    """A deployed fleet in the Gate mode, with only what a test needs to vary.

    The endpoints and keys are inert here: the composition under test never
    contacts an agent, and the retry path builds a verifier it never asks.
    What matters is the custody, the mode, the principal and -- for a retry --
    the execution key that names the durable lifecycle.
    """
    return CloudFleet(
        tenant_id=tenant_id,
        case_id=case_id,
        site_endpoint="https://site.example.run.app",
        employer_endpoint="https://employer.example.run.app",
        site_key_ref="site-key/cloud-1",
        employer_key_ref="employer-key/cloud-1",
        site_public_key=b"-----BEGIN PUBLIC KEY-----\n",
        employer_public_key=b"-----BEGIN PUBLIC KEY-----\n",
        timeout_seconds=None,
        raw_object=None,
        postgres=dsn,
        deployment=deployment,
        gate_mode=HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX,
        gate_principal=PRINCIPAL,
        gate_execution_key=gate_execution_key,
    )


def _analysed(dsn: str, tenant_id: str, case_id: str) -> tuple[Casework, CaseReport]:
    """A case in durable custody that has reached the invariant answer."""
    casework = ravi.casework(SqlDatabase(dsn))
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    append_all(casework, case, now=ravi.NOW)
    reported = case_status(casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(reported, Ok), reported
    return casework, reported.value


def _rows(dsn: str, tenant_id: str, case_id: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT execution_id, state, external_reference, gate_id, executor_id "
            "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchall()


@pytest.mark.usefixtures("running_as")
def test_the_deployed_composition_confirms_once_and_a_retry_reads_it(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The whole U2 sequence, through the code Stage 90 runs.

    PROPOSED -> RESERVED -> DISPATCHED -> CONFIRMED, and then a second process
    that reads the confirmation instead of paying again.  The retry's own
    executor is the proof: it was constructed inside ``verify_gate_idempotency``
    and its dispatch counter never left zero.
    """
    casework, report = _analysed(migrated_dsn, tenant_id, case_id)
    fleet = _fleet(migrated_dsn, tenant_id, case_id)

    execution = execute_cloud_gate(casework, fleet, report)

    assert execution.state == "CONFIRMED"
    assert execution.outcome_code == "CONFIRMED"
    assert execution.gate_id == CLOUD_GATE_ID
    assert execution.executor_id == CLOUD_EXECUTOR_ID
    assert execution.principal_id == PRINCIPAL
    assert execution.real_funds is False
    assert execution.external_reference is not None
    assert execution.external_reference.startswith("sandbox-pay-")
    assert execution.dispatch_count == 1
    assert execution.execution_count == 1
    assert len(execution.execution_key) == 64
    assert len(execution.action_digest) == 64
    #  The durable lifecycle instants, read off the row rather than derived.
    #  CONFIRMED implies the row passed through RESERVED and DISPATCHED, so all
    #  three are present -- and they are ordered, which is a fact about what the
    #  database recorded rather than about what the state machine permits.
    assert execution.dispatched_at is not None
    assert execution.finalized_at is not None
    assert execution.reserved_at <= execution.dispatched_at <= execution.finalized_at

    rows = _rows(migrated_dsn, tenant_id, case_id)
    assert len(rows) == 1
    assert rows[0][1] == "CONFIRMED"
    assert rows[0][2] == execution.external_reference
    assert rows[0][3] == CLOUD_GATE_ID
    assert rows[0][4] == CLOUD_EXECUTOR_ID

    #  A second execution of the same job: a new database handle, a new
    #  casework, a new Gate and a new executor, sharing only Cloud SQL.
    retry = verify_gate_idempotency(
        SqlDatabase(migrated_dsn),
        _fleet(
            migrated_dsn,
            tenant_id,
            case_id,
            gate_execution_key=ExecutionKey(bytes.fromhex(execution.execution_key)),
        ),
    )

    assert retry.state == "CONFIRMED"
    assert retry.execution_key == execution.execution_key
    assert retry.external_reference == execution.external_reference
    assert retry.outcome_code == execution.outcome_code
    assert retry.real_funds is False
    #  The lifecycle instants come back exactly as the first execution wrote
    #  them.  A retry that reconstructed a timeline instead of reading one
    #  would differ here.
    assert retry.reserved_at == execution.reserved_at
    assert retry.dispatched_at == execution.dispatched_at
    assert retry.finalized_at == execution.finalized_at
    #  Zero.  This process never crossed the executor boundary.
    assert retry.dispatch_count == 0
    assert retry.execution_count == 0
    assert _rows(migrated_dsn, tenant_id, case_id) == rows


@pytest.mark.usefixtures("running_as")
def test_the_principal_check_leaves_a_content_free_trace(
    migrated_dsn: str, tenant_id: str, case_id: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two lines a proof can quote, and nothing in them worth redacting.

    ``gate.principal.source`` says the observed identity came from the instance
    metadata server -- the whole basis for the claim that no caller of this
    deployment can change who the Gate thinks is asking.  ``gate.principal.
    status`` says the observed identity matched the provisioned one; it is only
    ever printed on that path, because every other outcome is a refusal that
    ends the run before a Gate exists.

    Both are closed tokens.  What is asserted below is that the trace carries
    no bearer token, no key material and no header -- the identity itself is a
    service-account address and appears on its own labelled line, which is what
    an operator reading a job log needs and is not a credential.
    """
    casework, report = _analysed(migrated_dsn, tenant_id, case_id)
    capsys.readouterr()

    execution = execute_cloud_gate(casework, _fleet(migrated_dsn, tenant_id, case_id), report)
    printed = capsys.readouterr().out

    assert "gate.principal.source = METADATA_SERVER" in printed
    assert "gate.principal.status = MATCHED" in printed
    assert execution.principal_id == PRINCIPAL
    for forbidden in ("Bearer", "Authorization", "Metadata-Flavor", "BEGIN", "token"):
        assert forbidden not in printed, forbidden


def test_a_refused_principal_leaves_no_matched_line(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    running_as: RunningAs,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """MATCHED is not printed when nothing matched.

    Without this, the assertion above would pass against a Gate that printed
    the line unconditionally -- which would make the trace a decoration rather
    than a claim.
    """
    casework, report = _analysed(migrated_dsn, tenant_id, case_id)
    running_as(Ok(OTHER))
    capsys.readouterr()

    with pytest.raises(SystemExit, match="GATE AUTHORITY REFUSED"):
        execute_cloud_gate(casework, _fleet(migrated_dsn, tenant_id, case_id), report)

    assert "gate.principal.status = MATCHED" not in capsys.readouterr().out


@pytest.mark.usefixtures("running_as")
def test_running_the_gate_twice_in_one_process_dispatches_once(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The first-execution path is itself idempotent over the durable row.

    Two full ``execute_cloud_gate`` calls, each composing its own executor.  The
    second finds the durable lifecycle already final and returns it, so its own
    dispatch counter -- which the first could not have touched -- stays at zero.
    """
    casework, report = _analysed(migrated_dsn, tenant_id, case_id)
    fleet = _fleet(migrated_dsn, tenant_id, case_id)

    first = execute_cloud_gate(casework, fleet, report)
    second = execute_cloud_gate(casework, fleet, report)

    assert first.execution_key == second.execution_key
    assert first.external_reference == second.external_reference
    assert first.dispatch_count == 1
    assert second.dispatch_count == 0
    assert len(_rows(migrated_dsn, tenant_id, case_id)) == 1


@pytest.mark.usefixtures("running_as")
def test_full_cloud_repeat_rederives_the_same_execution_and_dispatches_zero(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_tests.support import cloud

    fleet = replace(
        cloud.configuration(tenant_id, case_id),
        postgres=migrated_dsn,
        deployment=DatabaseDeployment.CLOUD_SQL,
        gate_mode=HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX,
        gate_principal=PRINCIPAL,
    )
    monkeypatch.setattr(
        "demo.cloud_hero.raw_object_access",
        lambda reference: RawAttempt(RawAccess.DENIED, reference or "gs://hero/raw", 403),
    )
    first_casework = build_casework(fleet, SqlDatabase(migrated_dsn))
    first_run = run_cloud_hero(
        first_casework,
        cloud.transport(tenant_id),
        case=cloud_case(fleet),
        site_endpoint=fleet.site_endpoint,
        employer_endpoint=fleet.employer_endpoint,
        raw_object=fleet.raw_object,
    )
    assert first_run.report is not None
    first = execute_cloud_gate(first_casework, fleet, first_run.report)
    before = _rows(migrated_dsn, tenant_id, case_id)

    repeated = repeat_gate_execution(
        SqlDatabase(migrated_dsn), fleet, cloud.transport(tenant_id)
    )

    assert first.state == repeated.state == "CONFIRMED"
    assert repeated.execution_key == first.execution_key
    assert repeated.external_reference == first.external_reference
    assert first.dispatch_count == 1
    assert repeated.dispatch_count == 0
    assert repeated.execution_count == 0
    assert _rows(migrated_dsn, tenant_id, case_id) == before


def test_a_workload_running_as_another_identity_executes_nothing(
    migrated_dsn: str, tenant_id: str, case_id: str, running_as: RunningAs
) -> None:
    """The commonest real misdeployment, and it must create no row."""
    casework, report = _analysed(migrated_dsn, tenant_id, case_id)
    running_as(Ok(OTHER))

    with pytest.raises(SystemExit, match="GATE AUTHORITY REFUSED"):
        execute_cloud_gate(casework, _fleet(migrated_dsn, tenant_id, case_id), report)

    assert _rows(migrated_dsn, tenant_id, case_id) == []


def test_a_workload_with_no_runtime_identity_executes_nothing(
    migrated_dsn: str, tenant_id: str, case_id: str, running_as: RunningAs
) -> None:
    """Not on Google Cloud is a refusal, never a fallback to configuration."""
    casework, report = _analysed(migrated_dsn, tenant_id, case_id)
    running_as(
        Err(
            CloudPrincipalError(
                CloudPrincipalFailure.RUNTIME_IDENTITY_UNAVAILABLE, "no metadata server"
            )
        )
    )

    with pytest.raises(SystemExit, match="RUNTIME_IDENTITY_UNAVAILABLE"):
        execute_cloud_gate(casework, _fleet(migrated_dsn, tenant_id, case_id), report)

    assert _rows(migrated_dsn, tenant_id, case_id) == []


@pytest.mark.usefixtures("running_as")
def test_a_retry_that_names_another_execution_finds_nothing(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The retry names one execution, and a key nobody stored has no row."""
    casework, report = _analysed(migrated_dsn, tenant_id, case_id)
    executed = execute_cloud_gate(casework, _fleet(migrated_dsn, tenant_id, case_id), report)
    assert executed.state == "CONFIRMED"

    with pytest.raises(SystemExit, match="GATE IDEMPOTENCY REFUSED"):
        verify_gate_idempotency(
            SqlDatabase(migrated_dsn),
            _fleet(
                migrated_dsn,
                tenant_id,
                case_id,
                gate_execution_key=ExecutionKey(b"\x11" * 32),
            ),
        )
    assert len(_rows(migrated_dsn, tenant_id, case_id)) == 1


@pytest.mark.usefixtures("running_as")
def test_a_retry_before_any_execution_is_refused_and_creates_nothing(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """An idempotency read has no path that could reserve or dispatch."""
    casework, report = _analysed(migrated_dsn, tenant_id, case_id)
    del casework, report

    with pytest.raises(SystemExit, match="GATE IDEMPOTENCY REFUSED"):
        verify_gate_idempotency(
            SqlDatabase(migrated_dsn),
            _fleet(
                migrated_dsn,
                tenant_id,
                case_id,
                gate_execution_key=ExecutionKey(b"\x22" * 32),
            ),
        )
    assert _rows(migrated_dsn, tenant_id, case_id) == []


@pytest.mark.usefixtures("running_as")
def test_a_retry_that_names_no_execution_key_is_a_configuration_refusal(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    with pytest.raises(SystemExit, match="MISSING: MUSTER_HERO_GATE_EXECUTION_ID"):
        verify_gate_idempotency(
            SqlDatabase(migrated_dsn), _fleet(migrated_dsn, tenant_id, case_id)
        )


@pytest.mark.usefixtures("running_as")
def test_the_deployed_retry_still_reads_the_execution_after_the_case_advances(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """The deployment's own version of the case-advancement proof.

    Not a repeat of the Gate-level test: this goes through the two functions
    Stage 90 actually calls, so what is proved is that *the deployed retry
    path* -- ``verify_gate_idempotency``, with a fresh database handle, a fresh
    Gate and a fresh executor -- is independent of the case's current head.

    A retry that read the head to build its identity would report this
    execution absent here, and the operator's proof would have quietly become
    "run the retry job before anybody touches the case".
    """
    casework = ravi.casework(SqlDatabase(migrated_dsn))
    case = ravi.ravi(tenant_id, case_id, attested=True)
    open_ravi(casework, case)
    analysed, held = split_at_the_inert_claim(case)
    for entry in analysed:
        appended = append_transcript_entry(
            casework, tenant_id=tenant_id, case_id=case_id, entry=entry, now=ravi.NOW
        )
        assert isinstance(appended, Ok), appended
    before = case_status(casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(before, Ok), before

    execution = execute_cloud_gate(
        casework, _fleet(migrated_dsn, tenant_id, case_id), before.value
    )
    assert execution.state == "CONFIRMED"
    rows = _rows(migrated_dsn, tenant_id, case_id)
    assert len(rows) == 1

    advanced = append_transcript_entry(
        casework, tenant_id=tenant_id, case_id=case_id, entry=held, now=ravi.NOW
    )
    assert isinstance(advanced, Ok), advanced
    after = case_status(casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(after, Ok), after
    assert after.value.head.revision_digest != before.value.head.revision_digest

    retry = verify_gate_idempotency(
        SqlDatabase(migrated_dsn),
        _fleet(
            migrated_dsn,
            tenant_id,
            case_id,
            gate_execution_key=ExecutionKey(bytes.fromhex(execution.execution_key)),
        ),
    )

    assert retry.state == "CONFIRMED"
    assert retry.execution_key == execution.execution_key
    assert retry.external_reference == execution.external_reference
    assert retry.reserved_at == execution.reserved_at
    assert retry.dispatched_at == execution.dispatched_at
    assert retry.finalized_at == execution.finalized_at
    assert retry.dispatch_count == 0
    assert retry.execution_count == 0
    assert _rows(migrated_dsn, tenant_id, case_id) == rows


@pytest.mark.usefixtures("running_as")
def test_the_gate_reconstructs_the_amount_and_recipient_from_the_case(
    migrated_dsn: str, tenant_id: str, case_id: str
) -> None:
    """Ravi, and the corrected weekly total, taken from the analysis.

    Nothing on this path accepts a recipient, an amount, a currency or an
    action kind: the proposal carries digests, the Gate re-derives the action
    from the current head, and the executor receives that exact intent.  What
    is asserted here is the value that reached the durable row.
    """
    from muster.core.wire.codec import decode
    from muster.platform.gate.model import read_action_intent

    casework, report = _analysed(migrated_dsn, tenant_id, case_id)
    execution = execute_cloud_gate(casework, _fleet(migrated_dsn, tenant_id, case_id), report)
    assert execution.state == "CONFIRMED"

    with psycopg.connect(migrated_dsn) as connection:
        row = connection.execute(
            "SELECT intent_octets FROM action_gate.execution "
            "WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchone()
    assert row is not None
    decoded = decode(bytes(row[0]))
    assert isinstance(decoded, Ok)
    intent = read_action_intent(decoded.value)

    assert intent.action.kind == "PAY"
    fields = {field.name: field.value for field in intent.action.consequential_fields}
    recipient = fields["recipient"]
    amount = fields["amount"]
    assert getattr(recipient, "member", None) == "RAVI"
    assert getattr(amount, "unit_tag", None) == "INR"
    #  ₹5,100 as minor units at the fixture's scale.  The corrected weekly
    #  total the case actually reached, not a number this test chose.
    assert amount == report.analysis.kernel.outcome.action.consequential_fields[1].value  # type: ignore[union-attr]
    assert intent.gate_id == CLOUD_GATE_ID
    assert intent.executor_id == CLOUD_EXECUTOR_ID


def test_a_gate_over_ephemeral_custody_is_unrepresentable(
    tenant_id: str, case_id: str
) -> None:
    """Stated on the value, so no composition root can assemble one."""
    with pytest.raises(ValueError, match="CLOUD_SQL custody"):
        _fleet(None, tenant_id, case_id, deployment=DatabaseDeployment.EPHEMERAL)
