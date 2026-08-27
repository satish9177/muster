"""Durable revalidation fails closed over corrupted or incomplete custody."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from typing import cast

import psycopg
import pytest
from demo.cloud_hero import CloudFleet, HeroMode, build_casework, revalidate_durable_case
from demo.durable_ravi import durable_case, durable_casework, open_durable_case
from demo.stable_keys import _SourceSigner

from muster.core.case.revision import TranscriptPrefix
from muster.core.evidence.signing import attestation_preimage
from muster.core.evidence.transcript import Attestation, entry_digest, entry_node
from muster.core.results import Err, Ok
from muster.core.wire.codec import encode
from muster.core.wire.digests import DigestKind
from muster.platform.adapters.sql.config import DatabaseDeployment
from muster.platform.adapters.sql.database import SqlDatabase
from muster.platform.casework.commands import StatusFailure, StatusRejection, case_status
from muster.platform.casework.ports import CaseworkDatabase
from support import ravi
from support.authority import source_public_key
from support.fixtures import append_all, forge_content, insert_content
from support.ravi import RaviCase

pytestmark = pytest.mark.postgres

@dataclass(frozen=True, slots=True)
class _Prepared:
    fleet: CloudFleet
    case: RaviCase


def _identity() -> tuple[str, str]:
    token = uuid.uuid4().hex[:12]
    return f"tenant-u4-refusal-{token}", f"case-u4-refusal-{token}"


def _fleet(
    dsn: str | None,
    tenant_id: str,
    case_id: str,
    *,
    deployment: DatabaseDeployment = DatabaseDeployment.CLOUD_SQL,
) -> CloudFleet:
    return CloudFleet(
        tenant_id=tenant_id,
        case_id=case_id,
        site_endpoint="https://site.example.run.app",
        employer_endpoint="https://employer.example.run.app",
        site_key_ref="site-key/deployed-u4",
        employer_key_ref="employer-key/deployed-u4",
        site_public_key=source_public_key("site-key/deployed-u4"),
        employer_public_key=source_public_key("employer-key/deployed-u4"),
        timeout_seconds=None,
        raw_object=None,
        postgres=dsn,
        deployment=deployment,
        gate_mode=HeroMode.ANALYSIS_ONLY,
        gate_principal=None,
        gate_execution_key=None,
    )


def _prepare(dsn: str) -> _Prepared:
    tenant_id, case_id = _identity()
    case = durable_case(tenant_id, case_id)
    casework = durable_casework(SqlDatabase(dsn))
    open_durable_case(casework, case)
    append_all(casework, case, now=ravi.NOW)
    reported = case_status(casework, tenant_id=tenant_id, case_id=case_id, now=ravi.NOW)
    assert isinstance(reported, Ok), reported
    assert reported.value.certificate_reproduced is True
    return _Prepared(_fleet(dsn, tenant_id, case_id), case)


def _state(dsn: str, tenant_id: str) -> tuple[tuple[object, ...], ...]:
    statements = (
        "SELECT 'content', kind, digest, octets FROM store.content "
        "WHERE tenant_id = %s ORDER BY kind, digest",
        "SELECT 'head', case_id, revision_number, revision_digest, certificate_digest, "
        "transcript_prefix_digest FROM casework.case_head WHERE tenant_id = %s "
        "ORDER BY case_id",
        "SELECT 'entry', case_id, entry_digest FROM casework.transcript_entry "
        "WHERE tenant_id = %s ORDER BY case_id, entry_digest",
        "SELECT 'authority', snapshot_digest, signed_octets, published_at "
        "FROM authority.registry_snapshot WHERE tenant_id = %s ORDER BY snapshot_digest",
        "SELECT 'revocation', snapshot_digest, signed_octets, published_at "
        "FROM authority.revocation_snapshot WHERE tenant_id = %s ORDER BY snapshot_digest",
        "SELECT 'execution', execution_id, state, intent_octets, reserved_at, dispatched_at, "
        "finalized_at, external_reference, outcome_code FROM action_gate.execution "
        "WHERE tenant_id = %s ORDER BY execution_id",
    )
    with psycopg.connect(dsn) as connection:
        return tuple(
            row
            for statement in statements
            for row in connection.execute(statement, (tenant_id,)).fetchall()
        )


def _status_rejection(dsn: str, fleet: CloudFleet) -> StatusRejection:
    reported = case_status(
        build_casework(fleet, SqlDatabase(dsn)),
        tenant_id=fleet.tenant_id,
        case_id=fleet.case_id,
        now=ravi.NOW,
    )
    assert isinstance(reported, Err), reported
    assert reported.error.failure is StatusFailure.SNAPSHOT_REFUSED
    return reported.error


def _assert_refusal_is_read_only(
    dsn: str,
    fleet: CloudFleet,
    monkeypatch: pytest.MonkeyPatch,
    match: str,
) -> None:
    before = _state(dsn, fleet.tenant_id)

    def refuse(*_: object, **__: object) -> None:
        raise AssertionError("a refusal opened a writing scope")

    monkeypatch.setattr(SqlDatabase, "writing", refuse)
    with pytest.raises(SystemExit, match=match) as raised:
        revalidate_durable_case(SqlDatabase(dsn), fleet)

    assert isinstance(raised.value.code, str)
    assert "detail" not in raised.value.code
    assert _state(dsn, fleet.tenant_id) == before


def test_absent_durable_case_is_refused_without_creating_it(
    migrated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id, case_id = _identity()
    _assert_refusal_is_read_only(
        migrated_dsn,
        _fleet(migrated_dsn, tenant_id, case_id),
        monkeypatch,
        "DURABLE CASE ABSENT",
    )


def test_unanalysed_durable_case_is_refused(
    migrated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id, case_id = _identity()
    case = durable_case(tenant_id, case_id)
    open_durable_case(durable_casework(SqlDatabase(migrated_dsn)), case)
    _assert_refusal_is_read_only(
        migrated_dsn,
        _fleet(migrated_dsn, tenant_id, case_id),
        monkeypatch,
        "DURABLE CASE NOT ANALYSED",
    )


def test_malformed_stored_attestation_is_refused(
    migrated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(migrated_dsn)
    entry = next(item for item in prepared.case.entries if isinstance(item, Attestation))
    forge_content(
        migrated_dsn,
        prepared.fleet.tenant_id,
        entry_digest(entry),
        DigestKind.TRANSCRIPT_ENTRY.value,
        b"not a canonical transcript entry",
    )
    rejection = _status_rejection(migrated_dsn, prepared.fleet)
    assert "CONTENT_CORRUPT" in rejection.detail
    _assert_refusal_is_read_only(
        migrated_dsn, prepared.fleet, monkeypatch, "REVALIDATION REFUSED: SNAPSHOT_REFUSED"
    )


def test_stored_attestation_signature_failure_is_refused(
    migrated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(migrated_dsn)
    entry = next(item for item in prepared.case.entries if isinstance(item, Attestation))
    other = next(
        item
        for item in prepared.case.entries
        if isinstance(item, Attestation)
        and item.receipt.payload.signer_key_ref != entry.receipt.payload.signer_key_ref
    )
    substituted = replace(
        prepared.fleet,
        site_key_ref=entry.receipt.payload.signer_key_ref,
        site_public_key=source_public_key(other.receipt.payload.signer_key_ref),
    )
    rejection = _status_rejection(migrated_dsn, substituted)
    assert rejection.detail.startswith("CONTENT_UNREADABLE: the stored attestation over ")
    assert f"is not signed by {entry.receipt.payload.signer_key_ref}" in rejection.detail
    _assert_refusal_is_read_only(
        migrated_dsn, substituted, monkeypatch, "REVALIDATION REFUSED: SNAPSHOT_REFUSED"
    )


def test_substituted_authority_publication_is_refused(
    migrated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(migrated_dsn)
    other = _prepare(migrated_dsn)
    with psycopg.connect(migrated_dsn) as connection:
        substituted = connection.execute(
            "SELECT signed_octets FROM authority.registry_snapshot WHERE tenant_id = %s LIMIT 1",
            (other.fleet.tenant_id,),
        ).fetchone()
        assert substituted is not None
        connection.execute(
            "UPDATE authority.registry_snapshot SET signed_octets = %s "
            "WHERE tenant_id = %s AND snapshot_digest = %s",
            (
                substituted[0],
                prepared.fleet.tenant_id,
                prepared.case.authority_snapshot.digest().octets,
            ),
        )
    _assert_refusal_is_read_only(
        migrated_dsn, prepared.fleet, monkeypatch, "REVALIDATION REFUSED: SNAPSHOT_REFUSED"
    )


def test_missing_pinned_transcript_entry_is_refused(
    migrated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(migrated_dsn)
    entry = next(item for item in prepared.case.entries if isinstance(item, Attestation))
    digest = entry_digest(entry)
    with psycopg.connect(migrated_dsn) as connection:
        connection.execute(
            "DELETE FROM casework.transcript_entry "
            "WHERE tenant_id = %s AND case_id = %s AND entry_digest = %s",
            (prepared.fleet.tenant_id, prepared.fleet.case_id, digest.octets),
        )
        connection.execute(
            "DELETE FROM store.content WHERE tenant_id = %s AND digest = %s",
            (prepared.fleet.tenant_id, digest.octets),
        )
    _assert_refusal_is_read_only(
        migrated_dsn, prepared.fleet, monkeypatch, "REVALIDATION REFUSED: SNAPSHOT_REFUSED"
    )


def test_cross_case_transcript_binding_is_refused(
    migrated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(migrated_dsn)
    casework = durable_casework(SqlDatabase(migrated_dsn))
    with casework.database.reading(prepared.fleet.tenant_id) as scope:
        members = scope.transcript.members(prepared.fleet.case_id)
        head = scope.heads.read(prepared.fleet.case_id)
    assert isinstance(members, Ok), members
    assert isinstance(head, Ok), head
    entry = next(item for item in prepared.case.entries if isinstance(item, Attestation))
    payload = replace(entry.receipt.payload, case_id=f"{prepared.fleet.case_id}-other")
    rebound_entry = Attestation(
        replace(
            entry.receipt,
            payload=payload,
            signature=_SourceSigner(payload.signer_key_ref).sign(attestation_preimage(payload)),
        )
    )
    rebound_entry_digest = entry_digest(rebound_entry)
    rebound_members = tuple(
        sorted(
            (
                rebound_entry_digest if member == entry_digest(entry) else member
                for member in members.value
            ),
            key=lambda digest: digest.octets,
        )
    )
    rebound = TranscriptPrefix(
        prepared.fleet.tenant_id,
        prepared.fleet.case_id,
        rebound_members,
    )
    insert_content(
        migrated_dsn,
        prepared.fleet.tenant_id,
        rebound_entry_digest,
        DigestKind.TRANSCRIPT_ENTRY.value,
        encode(entry_node(rebound_entry)),
    )
    insert_content(
        migrated_dsn,
        prepared.fleet.tenant_id,
        rebound.digest(),
        DigestKind.TRANSCRIPT_PREFIX.value,
        encode(rebound.to_node()),
    )
    with psycopg.connect(migrated_dsn) as connection:
        connection.execute(
            "UPDATE casework.case_head SET transcript_prefix_digest = %s "
            "WHERE tenant_id = %s AND case_id = %s",
            (rebound.digest().octets, prepared.fleet.tenant_id, prepared.fleet.case_id),
        )
    rejection = _status_rejection(migrated_dsn, prepared.fleet)
    assert rejection.detail.startswith("BINDING_MISMATCH: TranscriptEntry names ")
    assert f"/{payload.case_id!r}" in rejection.detail
    _assert_refusal_is_read_only(
        migrated_dsn, prepared.fleet, monkeypatch, "REVALIDATION REFUSED: SNAPSHOT_REFUSED"
    )


def test_certificate_reproduction_mismatch_is_refused(
    migrated_dsn: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(migrated_dsn)
    with psycopg.connect(migrated_dsn) as connection:
        connection.execute(
            "UPDATE casework.case_head SET certificate_digest = %s "
            "WHERE tenant_id = %s AND case_id = %s",
            (b"\x55" * 32, prepared.fleet.tenant_id, prepared.fleet.case_id),
        )
    _assert_refusal_is_read_only(
        migrated_dsn, prepared.fleet, monkeypatch, "CERTIFICATE NOT REPRODUCED"
    )


def test_ephemeral_custody_is_refused_before_any_read() -> None:
    tenant_id, case_id = _identity()
    fleet = _fleet(
        None,
        tenant_id,
        case_id,
        deployment=DatabaseDeployment.EPHEMERAL,
    )
    with pytest.raises(SystemExit, match="REVALIDATION REFUSED: EPHEMERAL"):
        revalidate_durable_case(cast(CaseworkDatabase, object()), fleet)
