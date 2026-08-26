"""Process-stable cryptographic binding for the synthetic durable Ravi demo.

The authoritative case data and grants still come from ``support.ravi``. The
test fixture normally generates fresh ECDSA keys per Python session, which is
right for an isolated suite but makes its signed artifacts unverifiable after
an actual process restart. This local-only composition derives predictable,
role-separated synthetic keys and uses deterministic ECDSA so the same fixture
has the same durable identity in every demo process.

These keys protect no real system and grant no execution authority. Q-12 still
checks source, officer, and publisher signatures; Action Gate execution remains
a separate local allowlist in ``action_gate_api``.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from demo.stable_keys import _OfficerSigner, _public_key, _PublisherSigner, _SourceSigner
elif __package__:
    from demo.stable_keys import (  # type: ignore[no-redef]
        _OfficerSigner,
        _public_key,
        _PublisherSigner,
        _SourceSigner,
    )
else:
    from stable_keys import (  # type: ignore[import-not-found,no-redef]
        _OfficerSigner,
        _public_key,
        _PublisherSigner,
        _SourceSigner,
    )

from muster.core.authority.signing import PublisherRole
from muster.core.evidence.relations import ClosedLowerBound
from muster.core.evidence.signing import attestation_preimage, case_construction_preimage
from muster.core.evidence.transcript import Attestation, TranscriptEntry
from muster.core.results import Err, InvariantViolation
from muster.core.values.scalars import VInt
from muster.domains.workforce.bundle import on_site_duration
from muster.platform.adapters.crypto import (
    LocalEcdsaOfficerVerifier,
    LocalEcdsaPublisherVerifier,
    LocalEcdsaSourceVerifier,
)
from muster.platform.authority.publish import (
    AuthorityPublisher,
    publish_authority_snapshot,
    publish_revocation_snapshot,
)
from muster.platform.casework.advance import Casework
from muster.platform.casework.commands import open_case
from muster.platform.casework.ports import CaseworkDatabase
from support import ravi
from support.authority import AUTHORITY_PUBLISHER_KEY, OFFICER_KEY, SOURCE_KEYS, WORKER
from support.ravi import RaviCase


def durable_casework(database: CaseworkDatabase) -> Casework:
    """Compose Ravi's real casework with process-stable synthetic verifiers."""
    source_keys = {key_ref: _public_key("source", key_ref) for key_ref in SOURCE_KEYS}
    publisher_key = _public_key("publisher", AUTHORITY_PUBLISHER_KEY)
    configured = ravi.casework(
        database,
        sources=LocalEcdsaSourceVerifier(source_keys),
    )
    return replace(
        configured,
        officer_verifier=LocalEcdsaOfficerVerifier(
            {OFFICER_KEY: _public_key("officer", OFFICER_KEY)}
        ),
        publisher_verifier=LocalEcdsaPublisherVerifier(
            {
                PublisherRole.AUTHORITY: {AUTHORITY_PUBLISHER_KEY: publisher_key},
                PublisherRole.REVOCATION: {AUTHORITY_PUBLISHER_KEY: publisher_key},
                PublisherRole.CATALOG: {},
            }
        ),
    )


def durable_case(
    tenant_id: str,
    case_id: str,
    *,
    duration_floor_minutes: int | None = None,
) -> RaviCase:
    """Rebind the authoritative fixture and give it process-stable signatures."""
    case = ravi.ravi(tenant_id, case_id, attested=True)
    construction = case.construction
    officer = _OfficerSigner(construction.signer_key_ref)
    signed_construction = replace(
        construction,
        signature=officer.sign(case_construction_preimage(construction.body())),
    )
    return replace(
        case,
        construction=signed_construction,
        entries=tuple(
            _signed_entry(
                _with_duration_floor(entry, duration_floor_minutes)
                if duration_floor_minutes is not None
                else entry
            )
            for entry in case.entries
        ),
    )


def _with_duration_floor(entry: TranscriptEntry, minutes: int) -> TranscriptEntry:
    """Shape the synthetic Site observation before applying its stable signature."""
    if minutes < 0:
        raise ValueError("duration floor must be non-negative")
    if not isinstance(entry, Attestation):
        return entry
    payload = entry.receipt.payload
    if payload.proposition != on_site_duration(WORKER, ravi.SATURDAY):
        return entry
    return Attestation(
        replace(
            entry.receipt,
            payload=replace(payload, relation=ClosedLowerBound(VInt(minutes))),
        )
    )


def open_durable_case(casework: Casework, case: RaviCase) -> None:
    """Publish stable authority and idempotently open the exact authored case."""
    publisher = AuthorityPublisher(
        database=casework.database,
        signer=_PublisherSigner(AUTHORITY_PUBLISHER_KEY),
        verifier=casework.publisher_verifier,
    )
    published = publish_authority_snapshot(
        publisher,
        tenant_id=case.tenant_id,
        snapshot=case.authority_snapshot,
        now=ravi.NOW,
    )
    if isinstance(published, Err):
        raise InvariantViolation(
            f"durable Ravi authority publication failed: {published.error.failure.value}: "
            f"{published.error.detail}"
        )
    revoked = publish_revocation_snapshot(
        publisher,
        tenant_id=case.tenant_id,
        snapshot=case.revocation_snapshot,
        now=ravi.NOW,
    )
    if isinstance(revoked, Err):
        raise InvariantViolation(
            f"durable Ravi revocation publication failed: {revoked.error.failure.value}: "
            f"{revoked.error.detail}"
        )
    opened = open_case(
        casework,
        tenant_id=case.tenant_id,
        construction=case.construction,
        authorization_context=case.authorization_context,
        policy_id=case.policy_id,
        as_of=case.as_of,
    )
    if isinstance(opened, Err):
        raise InvariantViolation(
            f"durable Ravi case open failed: {opened.error.failure.value}: {opened.error.detail}"
        )


def _signed_entry(entry: TranscriptEntry) -> TranscriptEntry:
    match entry:
        case Attestation(receipt):
            signer = _SourceSigner(receipt.payload.signer_key_ref)
            return Attestation(
                replace(
                    receipt,
                    signature=signer.sign(attestation_preimage(receipt.payload)),
                )
            )
        case _:
            return entry
