"""The complete cloud repeat survives the loss of its writing process.

The children share PostgreSQL and immutable deployment inputs, but no Python
state.  The first drives acquisition, admission, Q-12, replay, certificate
production and the Gate.  The second calls ``repeat_gate_execution`` from a
fresh interpreter and must reproduce the same execution without contacting an
agent or dispatching its fresh executor.

The regression control selects the pre-U4 composition inside each child: the
fixture attestations and fixture source verifier then use that process's random
``support.authority`` keys.  Its second interpreter is refused while reading
the existing hero case, demonstrating that stable fixture-source composition
is what makes the positive proof possible.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest

pytestmark = pytest.mark.postgres

REPOSITORY = Path(__file__).resolve().parents[4]

_CHILD = r"""
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agent_tests.support import cloud
from demo import cloud_hero as hero
from muster.agents.keys import LocalSourceSigner
from muster.agents.transport.inprocess import InProcessAcquisitionTransport
from muster.core.results import Ok
from muster.platform.adapters.sql.config import DatabaseDeployment
from muster.platform.adapters.sql.database import SqlDatabase
from support import ravi
from support.authority import source_keyring

dsn, tenant_id, case_id, output_name, phase, composition = sys.argv[1:]
principal = "muster-control-plane@muster-project.iam.gserviceaccount.com"


def deployment_key(key_ref, scalar):
    # A reproducible stand-in for one externally configured agent key.
    private = ec.derive_private_key(scalar, ec.SECP256R1())
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return LocalSourceSigner(key_ref, private_pem), public_pem


site_signer, site_public = deployment_key(cloud.SITE_KEY_REF, 101)
employer_signer, employer_public = deployment_key(cloud.EMPLOYER_KEY_REF, 103)
fleet = replace(
    cloud.configuration(tenant_id, case_id),
    site_public_key=site_public,
    employer_public_key=employer_public,
    postgres=dsn,
    deployment=DatabaseDeployment.CLOUD_SQL,
    gate_mode=hero.HeroMode.CLOUD_SQL_ACTION_GATE_SANDBOX,
    gate_principal=principal,
)

agents = {
    cloud.SITE_ENDPOINT: replace(cloud.site(tenant_id), signer=site_signer),
    cloud.EMPLOYER_ENDPOINT: replace(cloud.employer(tenant_id), signer=employer_signer),
}


class CountingTransport:
    def __init__(self):
        self.requests = 0
        self.delegate = InProcessAcquisitionTransport(agents)

    def deliver(self, *, endpoint_ref, assignment):
        self.requests += 1
        return self.delegate.deliver(endpoint_ref=endpoint_ref, assignment=assignment)


@dataclass(frozen=True)
class RuntimePrincipal:
    def principal_id(self):
        return Ok(principal)


hero.MetadataServerPrincipal = RuntimePrincipal
hero.raw_object_access = lambda reference: hero.RawAttempt(
    hero.RawAccess.DENIED, reference or "gs://muster-test/raw", 403
)

if composition == "pre_u4":
    hero._stable_hero_sources = lambda case: case

    def pre_u4_casework(configured_fleet, database):
        configured = ravi.casework(
            database,
            sources=source_keyring(
                **{
                    configured_fleet.site_key_ref: configured_fleet.site_public_key,
                    configured_fleet.employer_key_ref: configured_fleet.employer_public_key,
                }
            ),
        )
        return hero._stable_hero_trust(configured)

    hero.build_casework = pre_u4_casework

transport = CountingTransport()
if phase == "first":
    casework = hero.build_casework(fleet, SqlDatabase(dsn))
    run = hero.run_cloud_hero(
        casework,
        transport,
        case=hero.cloud_case(fleet),
        site_endpoint=fleet.site_endpoint,
        employer_endpoint=fleet.employer_endpoint,
        raw_object=fleet.raw_object,
    )
    assert run.report is not None
    execution = hero.execute_cloud_gate(casework, fleet, run.report)
elif phase == "repeat":
    observed_runs = []
    actual_run_cloud_hero = hero.run_cloud_hero

    def observe_run(*args, **kwargs):
        completed_run = actual_run_cloud_hero(*args, **kwargs)
        observed_runs.append(completed_run)
        return completed_run

    hero.run_cloud_hero = observe_run
    execution = hero.repeat_gate_execution(SqlDatabase(dsn), fleet, transport)
    assert len(observed_runs) == 1
    run = observed_runs[0]
    assert run.report is not None
else:
    raise AssertionError(phase)

report = run.report
assert report is not None
assert report.head.revision_digest is not None
assert report.head.certificate_digest is not None
Path(output_name).write_text(
    json.dumps(
        {
            "tenant_id": tenant_id,
            "case_id": report.head.case_id,
            "revision_digest": report.head.revision_digest.hex,
            "certificate_digest": report.head.certificate_digest.hex,
            "certificate_reproduced": report.certificate_reproduced,
            "execution_key": execution.execution_key,
            "external_reference": execution.external_reference,
            "state": execution.state,
            "dispatch_count": execution.dispatch_count,
            "execution_count": execution.execution_count,
            "acquired_count": len(run.reports),
            "transport_requests": transport.requests,
        }
    ),
    encoding="utf-8",
)
"""


def _environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("MUSTER_HERO_GATE_EXECUTION_ID", None)
    environment.pop("HERO_GATE_EXECUTION_ID", None)
    pythonpath = [
        REPOSITORY,
        REPOSITORY / "packages" / "muster-kernel" / "src",
        REPOSITORY / "packages" / "muster-kernel",
        REPOSITORY / "packages" / "muster-platform" / "src",
        REPOSITORY / "packages" / "muster-platform" / "tests",
        REPOSITORY / "packages" / "muster-agents" / "src",
        REPOSITORY / "packages" / "muster-agents",
    ]
    environment["PYTHONPATH"] = os.pathsep.join(map(str, pythonpath))
    return environment


def _child(
    dsn: str,
    tenant_id: str,
    case_id: str,
    output: Path,
    *,
    phase: str,
    composition: str = "stable",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter and local test program
        [
            sys.executable,
            "-c",
            _CHILD,
            dsn,
            tenant_id,
            case_id,
            str(output),
            phase,
            composition,
        ],
        cwd=REPOSITORY,
        env=_environment(),
        capture_output=True,
        text=True,
        check=False,
    )


def _successful_child(
    dsn: str,
    tenant_id: str,
    case_id: str,
    output: Path,
    *,
    phase: str,
    composition: str = "stable",
) -> dict[str, Any]:
    completed = _child(
        dsn,
        tenant_id,
        case_id,
        output,
        phase=phase,
        composition=composition,
    )
    assert completed.returncode == 0, completed.stderr
    loaded: object = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, Any], loaded)


def _execution_rows(dsn: str, tenant_id: str, case_id: str) -> list[tuple[object, ...]]:
    with psycopg.connect(dsn) as connection:
        return connection.execute(
            "SELECT execution_id, intent_octets, state, reserved_at, dispatched_at, "
            "finalized_at, external_reference, outcome_code, detail "
            "FROM action_gate.execution WHERE tenant_id = %s AND case_id = %s "
            "ORDER BY execution_id",
            (tenant_id, case_id),
        ).fetchall()


def test_cloud_repeat_reproduces_and_dispatches_nothing_in_a_second_process(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    first = _successful_child(
        migrated_dsn,
        tenant_id,
        case_id,
        tmp_path / "cloud-first.json",
        phase="first",
    )
    before_repeat = _execution_rows(migrated_dsn, tenant_id, case_id)
    repeat = _successful_child(
        migrated_dsn,
        tenant_id,
        case_id,
        tmp_path / "cloud-repeat.json",
        phase="repeat",
    )
    after_repeat = _execution_rows(migrated_dsn, tenant_id, case_id)

    assert first["tenant_id"] == repeat["tenant_id"] == tenant_id
    assert first["case_id"] == repeat["case_id"] == case_id
    assert first["revision_digest"] == repeat["revision_digest"]
    assert first["certificate_digest"] == repeat["certificate_digest"]
    assert first["certificate_reproduced"] is True
    assert repeat["certificate_reproduced"] is True
    assert first["execution_key"] == repeat["execution_key"]
    assert first["external_reference"] == repeat["external_reference"]
    assert first["state"] == repeat["state"] == "CONFIRMED"
    assert first["dispatch_count"] == 1
    assert repeat["dispatch_count"] == 0
    assert repeat["execution_count"] == 0

    # The counter is live on A, while B's completed acquisition pass had
    # neither an outstanding assignment nor a delivery across the transport.
    assert first["acquired_count"] > 0
    assert first["transport_requests"] > 0
    assert repeat["acquired_count"] == 0
    assert repeat["transport_requests"] == 0

    assert len(before_repeat) == len(after_repeat) == 1
    execution_id = before_repeat[0][0]
    assert isinstance(execution_id, bytes)
    assert execution_id.hex() == first["execution_key"]
    assert before_repeat[0][2] == "CONFIRMED"
    assert before_repeat[0][6] == first["external_reference"]
    # Includes the key, canonical intent octets, all lifecycle timestamps and
    # the final outcome: the second process did not mutate the finalized row.
    assert after_repeat == before_repeat


def test_pre_u4_random_fixture_source_keys_refuse_the_second_process(
    migrated_dsn: str,
    tenant_id: str,
    case_id: str,
    tmp_path: Path,
) -> None:
    first = _successful_child(
        migrated_dsn,
        tenant_id,
        case_id,
        tmp_path / "pre-u4-first.json",
        phase="first",
        composition="pre_u4",
    )
    assert first["state"] == "CONFIRMED"

    refused = _child(
        migrated_dsn,
        tenant_id,
        case_id,
        tmp_path / "pre-u4-repeat.json",
        phase="repeat",
        composition="pre_u4",
    )

    assert refused.returncode != 0
    assert "reading the existing hero case failed" in refused.stderr
    assert not (tmp_path / "pre-u4-repeat.json").exists()
