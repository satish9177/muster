"""Durable cloud cases reproduce from fresh readers without side effects."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
from demo import cloud_hero as hero
from demo.durable_ravi import durable_case, durable_casework, open_durable_case

from agent_tests.support import cloud
from muster.core.results import Ok
from muster.platform.adapters.sql.config import DatabaseDeployment
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import CaseReport, append_transcript_entry, case_status
from muster.platform.casework.ports import TenantScope
from support import ravi
from support.fixtures import append_all, split_at_the_inert_claim

pytestmark = pytest.mark.postgres

REPOSITORY = Path(__file__).resolve().parents[4]

_CHILD = r"""
import base64
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path

from agent_tests.support import cloud
from demo.cloud_hero import revalidate_durable_case
from muster.platform.adapters.sql.config import DatabaseDeployment
from muster.platform.adapters.sql.database import SqlDatabase

dsn, tenant_id, case_id, site_key, employer_key, output_name = sys.argv[1:]
fleet = replace(
    cloud.configuration(tenant_id, case_id),
    site_public_key=base64.b64decode(site_key),
    employer_public_key=base64.b64decode(employer_key),
    postgres=dsn,
    deployment=DatabaseDeployment.CLOUD_SQL,
)
result = revalidate_durable_case(SqlDatabase(dsn), fleet)
Path(output_name).write_text(json.dumps(asdict(result)), encoding="utf-8")
"""

_TABLES = (
    "store.content",
    "authority.registry_snapshot",
    "authority.revocation_snapshot",
    "authority.publication_state",
    "catalog.agent_snapshot",
    "casework.case_head",
    "casework.transcript_entry",
    "casework.evidence_request",
    "casework.case_commitment",
    "action_gate.execution",
)


@dataclass(frozen=True, slots=True)
class _WrittenCase:
    fleet: hero.CloudFleet
    report: CaseReport
    transcript_entries: int


@pytest.fixture(scope="module")
def written_case(migrated_dsn: str) -> _WrittenCase:
    tenant_id = f"tenant-u4-revalidation-{uuid.uuid4().hex[:12]}"
    case_id = f"case-u4-revalidation-{uuid.uuid4().hex[:12]}"
    fleet = replace(
        cloud.configuration(tenant_id, case_id),
        postgres=migrated_dsn,
        deployment=DatabaseDeployment.CLOUD_SQL,
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            hero,
            "raw_object_access",
            lambda reference: hero.RawAttempt(
                hero.RawAccess.DENIED, reference or "gs://muster-test/raw", 403
            ),
        )
        casework = hero.build_casework(fleet, SqlDatabase(migrated_dsn))
        run = hero.run_cloud_hero(
            casework,
            cloud.transport(tenant_id),
            case=hero.cloud_case(fleet),
            site_endpoint=fleet.site_endpoint,
            employer_endpoint=fleet.employer_endpoint,
            raw_object=fleet.raw_object,
        )
    assert run.report is not None
    with psycopg.connect(migrated_dsn) as connection:
        row = connection.execute(
            "SELECT count(*) FROM casework.transcript_entry WHERE tenant_id = %s AND case_id = %s",
            (tenant_id, case_id),
        ).fetchone()
    assert row is not None
    transcript_entries = row[0]
    assert isinstance(transcript_entries, int) and transcript_entries > 0
    return _WrittenCase(fleet, run.report, transcript_entries)


def _durable_state(dsn: str, tenant_id: str) -> dict[str, object]:
    with psycopg.connect(dsn) as connection:
        rows: dict[str, object] = {}
        for table in _TABLES:
            row = connection.execute(
                f"SELECT count(*) FROM {table} WHERE tenant_id = %s",  # noqa: S608
                (tenant_id,),
            ).fetchone()
            assert row is not None
            rows[table] = row[0]
        content = connection.execute(
            "SELECT kind, count(*) FROM store.content WHERE tenant_id = %s "
            "GROUP BY kind ORDER BY kind",
            (tenant_id,),
        ).fetchall()
    return {"rows": rows, "content": content}


def _child_environment() -> dict[str, str]:
    environment = os.environ.copy()
    pythonpath = (
        REPOSITORY,
        REPOSITORY / "packages" / "muster-kernel" / "src",
        REPOSITORY / "packages" / "muster-kernel",
        REPOSITORY / "packages" / "muster-platform" / "src",
        REPOSITORY / "packages" / "muster-platform" / "tests",
        REPOSITORY / "packages" / "muster-agents" / "src",
        REPOSITORY / "packages" / "muster-agents",
    )
    environment["PYTHONPATH"] = os.pathsep.join(map(str, pythonpath))
    return environment


def test_fresh_casework_reproduces_the_durable_certificate(
    migrated_dsn: str,
    written_case: _WrittenCase,
) -> None:
    revalidated = hero.revalidate_durable_case(SqlDatabase(migrated_dsn), written_case.fleet)
    head = written_case.report.head
    assert head.revision_digest is not None
    assert head.certificate_digest is not None

    assert revalidated.revision_number == head.revision_number
    assert revalidated.revision_digest == head.revision_digest.hex
    assert revalidated.certificate_digest == head.certificate_digest.hex
    assert revalidated.construction_digest == head.inputs.construction_digest.hex
    assert revalidated.authorization_context_digest == (
        head.inputs.authorization_context_digest.hex
    )
    assert revalidated.certificate_reproduced is True
    assert revalidated.entries_reverified == revalidated.transcript_entries
    assert revalidated.entries_reverified == written_case.transcript_entries
    assert revalidated.writes == revalidated.dispatches == 0


def test_revalidation_writes_nothing_and_remains_repeatable(
    migrated_dsn: str,
    written_case: _WrittenCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _durable_state(migrated_dsn, written_case.fleet.tenant_id)

    def refuse(*_: object, **__: object) -> None:
        raise AssertionError("revalidation opened a writing scope")

    monkeypatch.setattr(SqlDatabase, "writing", refuse)
    first = hero.revalidate_durable_case(SqlDatabase(migrated_dsn), written_case.fleet)
    second = hero.revalidate_durable_case(SqlDatabase(migrated_dsn), written_case.fleet)

    assert second == first
    assert _durable_state(migrated_dsn, written_case.fleet.tenant_id) == before


def test_concurrent_advance_cannot_tear_revalidation_snapshot(
    migrated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = f"tenant-u4-snapshot-{uuid.uuid4().hex[:12]}"
    case_id = f"case-u4-snapshot-{uuid.uuid4().hex[:12]}"
    case = durable_case(tenant_id, case_id)
    analysed, held = split_at_the_inert_claim(case)
    writer = durable_casework(SqlDatabase(migrated_dsn))
    open_durable_case(writer, case)
    append_all(writer, replace(case, entries=analysed), now=ravi.NOW)
    before = case_status(writer, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(before, Ok), before
    assert before.value.head.revision_digest is not None
    assert before.value.head.certificate_digest is not None

    fleet = replace(
        cloud.configuration(tenant_id, case_id),
        postgres=migrated_dsn,
        deployment=DatabaseDeployment.CLOUD_SQL,
    )
    original = hero._read_durable_case
    advanced = False

    def advance_after_durable_read(
        scope: TenantScope, *, tenant_id: str, case_id: str
    ) -> hero.DurableCase:
        nonlocal advanced
        durable = original(scope, tenant_id=tenant_id, case_id=case_id)
        assert not advanced
        appended = append_transcript_entry(
            writer,
            tenant_id=tenant_id,
            case_id=case_id,
            entry=held,
            now=ravi.NOW,
        )
        assert isinstance(appended, Ok), appended
        assert isinstance(appended.value.advanced, Ok), appended.value.advanced
        advanced = True
        return durable

    monkeypatch.setattr(hero, "_read_durable_case", advance_after_durable_read)
    revalidated = hero.revalidate_durable_case(SqlDatabase(migrated_dsn), fleet)
    current = case_status(writer, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(current, Ok), current
    assert advanced is True

    assert revalidated.revision_number == before.value.head.revision_number
    assert revalidated.revision_digest == before.value.head.revision_digest.hex
    assert revalidated.certificate_digest == before.value.head.certificate_digest.hex
    assert revalidated.transcript_entries == len(analysed)
    assert revalidated.entries_reverified == len(analysed)
    assert revalidated.certificate_reproduced is True
    assert current.value.head.revision_number == before.value.head.revision_number + 1
    assert current.value.head.revision_digest != before.value.head.revision_digest


def test_second_process_revalidates_the_same_certificate(
    migrated_dsn: str,
    written_case: _WrittenCase,
    tmp_path: Path,
) -> None:
    output = tmp_path / "revalidated.json"
    fleet = written_case.fleet
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and local test program
        [
            sys.executable,
            "-c",
            _CHILD,
            migrated_dsn,
            fleet.tenant_id,
            fleet.case_id,
            base64.b64encode(fleet.site_public_key).decode("ascii"),
            base64.b64encode(fleet.employer_public_key).decode("ascii"),
            str(output),
        ],
        cwd=REPOSITORY,
        env=_child_environment(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    loaded: object = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    child = cast(dict[str, Any], loaded)
    head = written_case.report.head
    assert head.revision_digest is not None
    assert head.certificate_digest is not None

    assert child["revision_digest"] == head.revision_digest.hex
    assert child["certificate_digest"] == head.certificate_digest.hex
    assert child["certificate_reproduced"] is True
    assert child["entries_reverified"] == written_case.transcript_entries
    assert child["writes"] == child["dispatches"] == 0
